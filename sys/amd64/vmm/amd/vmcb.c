/*-
 * Copyright (c) 2013 Anish Gupta (akgupt3@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cpuset.h>

#include <machine/segments.h>
#include <machine/specialreg.h>
#include <machine/vmm.h>

#include "vmcb.h"
#include "svm.h"

/*
 * The VMCB aka Virtual Machine Control Block is a 4KB aligned page
 * in memory that describes the virtual machine.
 *
 * The VMCB contains:
 * - instructions or events in the guest to intercept
 * - control bits that modify execution environment of the guest
 * - guest processor state (e.g. general purpose registers)
 */

/*
 * Initialize SVM h/w context i.e. the VMCB control and saved state areas.
 */
int
svm_init_vmcb(struct vmcb *vmcb, uint64_t iopm_base_pa, uint64_t msrpm_base_pa,
    uint64_t np_pml4, uint32_t asid)
{
	struct vmcb_ctrl *ctrl;
	struct vmcb_state *state;
	uint16_t cr_shadow;

	ctrl = &vmcb->ctrl;
	state = &vmcb->state;

	ctrl->iopm_base_pa = iopm_base_pa;
	ctrl->msrpm_base_pa = msrpm_base_pa;

	/* Enable nested paging */
	ctrl->np_enable = 1;
	ctrl->n_cr3 = np_pml4;

	/*
	 * Intercept accesses to the control registers that are not shadowed
	 * in the VMCB - i.e. all except cr0, cr2, cr3, cr4 and cr8.
	 */
	cr_shadow = BIT(0) | BIT(2) | BIT(3) | BIT(4) | BIT(8);
	ctrl->cr_write = ctrl->cr_read = ~cr_shadow;

	/* Intercept Machine Check exceptions. */
	ctrl->exception = BIT(IDT_MC);

	/* Intercept various events (for e.g. I/O, MSR and CPUID accesses) */
	ctrl->ctrl1 =  VMCB_INTCPT_IO |
		       VMCB_INTCPT_MSR |
		       VMCB_INTCPT_HLT |
		       VMCB_INTCPT_CPUID |
		       VMCB_INTCPT_INTR |
		       VMCB_INTCPT_VINTR |
		       VMCB_INTCPT_INIT |
		       VMCB_INTCPT_NMI |
		       VMCB_INTCPT_SMI |
		       VMCB_INTCPT_FERR_FREEZE |
		       VMCB_INTCPT_SHUTDOWN;

	/*
	 * From section "Canonicalization and Consistency Checks" in APMv2
	 * the VMRUN intercept bit must be set to pass the consistency check.
	 */
	ctrl->ctrl2 = VMCB_INTCPT_VMRUN;

	ctrl->asid = asid;

	/*
	 * Section 15.21.1, Interrupt Masking in EFLAGS
	 * Section 15.21.2, Virtualizing APIC.TPR
	 *
	 * This must be set for %rflag and %cr8 isolation of guest and host.
	 */
	ctrl->v_intr_masking = 1;

	/* Enable Last Branch Record aka LBR for debugging */
	ctrl->lbr_virt_en = 1;
	state->dbgctl = BIT(0);

	/* EFER_SVM must always be set when the guest is executing */
	state->efer = EFER_SVM;

	/* Set up the PAT to power-on state */
	state->g_pat = PAT_VALUE(0, PAT_WRITE_BACK)	|
	    PAT_VALUE(1, PAT_WRITE_THROUGH)	|
	    PAT_VALUE(2, PAT_UNCACHED)		|
	    PAT_VALUE(3, PAT_UNCACHEABLE)	|
	    PAT_VALUE(4, PAT_WRITE_BACK)	|
	    PAT_VALUE(5, PAT_WRITE_THROUGH)	|
	    PAT_VALUE(6, PAT_UNCACHED)		|
	    PAT_VALUE(7, PAT_UNCACHEABLE);

	return (0);
}

/*
 * Read from segment selector, control and general purpose register of VMCB.
 */
int
vmcb_read(struct vmcb *vmcb, int ident, uint64_t *retval)
{
	struct vmcb_state *state;
	struct vmcb_segment *seg;
	int err;

	state = &vmcb->state;
	err = 0;

	switch (ident) {
	case VM_REG_GUEST_CR0:
		*retval = state->cr0;
		break;

	case VM_REG_GUEST_CR2:
		*retval = state->cr2;
		break;

	case VM_REG_GUEST_CR3:
		*retval = state->cr3;
		break;

	case VM_REG_GUEST_CR4:
		*retval = state->cr4;
		break;

	case VM_REG_GUEST_DR7:
		*retval = state->dr7;
		break;

	case VM_REG_GUEST_EFER:
		*retval = state->efer;
		break;

	case VM_REG_GUEST_RAX:
		*retval = state->rax;
		break;

	case VM_REG_GUEST_RFLAGS:
		*retval = state->rflags;
		break;

	case VM_REG_GUEST_RIP:
		*retval = state->rip;
		break;

	case VM_REG_GUEST_RSP:
		*retval = state->rsp;
		break;

	case VM_REG_GUEST_CS:
	case VM_REG_GUEST_DS:
	case VM_REG_GUEST_ES:
	case VM_REG_GUEST_FS:
	case VM_REG_GUEST_GS:
	case VM_REG_GUEST_SS:
	case VM_REG_GUEST_GDTR:
	case VM_REG_GUEST_IDTR:
	case VM_REG_GUEST_LDTR:
	case VM_REG_GUEST_TR:
		seg = vmcb_seg(vmcb, ident);
		if (seg == NULL) {
			ERR("Invalid seg type %d\n", ident);
			err = EINVAL;
			break;
		}

		*retval = seg->selector;
		break;

	default:
		err =  EINVAL;
		break;
	}

	return (err);
}

/*
 * Write to segment selector, control and general purpose register of VMCB.
 */
int
vmcb_write(struct vmcb *vmcb, int ident, uint64_t val)
{
	struct vmcb_state *state;
	struct vmcb_segment *seg;
	int err;

	state = &vmcb->state;
	err = 0;

	switch (ident) {
	case VM_REG_GUEST_CR0:
		state->cr0 = val;
		break;

	case VM_REG_GUEST_CR2:
		state->cr2 = val;
		break;

	case VM_REG_GUEST_CR3:
		state->cr3 = val;
		break;

	case VM_REG_GUEST_CR4:
		state->cr4 = val;
		break;

	case VM_REG_GUEST_DR7:
		state->dr7 = val;
		break;

	case VM_REG_GUEST_EFER:
		/* EFER_SVM must always be set when the guest is executing */
		state->efer = val | EFER_SVM;
		break;

	case VM_REG_GUEST_RAX:
		state->rax = val;
		break;

	case VM_REG_GUEST_RFLAGS:
		state->rflags = val;
		break;

	case VM_REG_GUEST_RIP:
		state->rip = val;
		break;

	case VM_REG_GUEST_RSP:
		state->rsp = val;
		break;

	case VM_REG_GUEST_CS:
	case VM_REG_GUEST_DS:
	case VM_REG_GUEST_ES:
	case VM_REG_GUEST_FS:
	case VM_REG_GUEST_GS:
	case VM_REG_GUEST_SS:
	case VM_REG_GUEST_GDTR:
	case VM_REG_GUEST_IDTR:
	case VM_REG_GUEST_LDTR:
	case VM_REG_GUEST_TR:
		seg = vmcb_seg(vmcb, ident);
		if (seg == NULL) {
			ERR("Invalid segment type %d\n", ident);
			err = EINVAL;
			break;
		}

		seg->selector = val;
		break;

	default:
		err = EINVAL;
	}

	return (err);
}

/*
 * Return VMCB segment area.
 */
struct vmcb_segment *
vmcb_seg(struct vmcb *vmcb, int type)
{
	struct vmcb_state *state;
	struct vmcb_segment *seg;

	state = &vmcb->state;

	switch (type) {
	case VM_REG_GUEST_CS:
		seg = &state->cs;
		break;

	case VM_REG_GUEST_DS:
		seg = &state->ds;
		break;

	case VM_REG_GUEST_ES:
		seg = &state->es;
		break;

	case VM_REG_GUEST_FS:
		seg = &state->fs;
		break;

	case VM_REG_GUEST_GS:
		seg = &state->gs;
		break;

	case VM_REG_GUEST_SS:
		seg = &state->ss;
		break;

	case VM_REG_GUEST_GDTR:
		seg = &state->gdt;
		break;

	case VM_REG_GUEST_IDTR:
		seg = &state->idt;
		break;

	case VM_REG_GUEST_LDTR:
		seg = &state->ldt;
		break;

	case VM_REG_GUEST_TR:
		seg = &state->tr;
		break;

	default:
		seg = NULL;
		break;
	}

	return (seg);
}

/*
 * Inject an event to vcpu as described in section 15.20, "Event injection".
 */
void
vmcb_eventinject(struct vmcb_ctrl *ctrl, int intr_type, int vector,
		 uint32_t error, bool ec_valid)
{
	KASSERT((ctrl->eventinj & VMCB_EVENTINJ_VALID) == 0,
	    ("%s: event already pending %#lx", __func__, ctrl->eventinj));

	KASSERT(vector >=0 && vector <= 255, ("%s: invalid vector %d",
	    __func__, vector));

	switch (intr_type) {
	case VMCB_EVENTINJ_TYPE_INTR:
	case VMCB_EVENTINJ_TYPE_NMI:
	case VMCB_EVENTINJ_TYPE_INTn:
		break;
	case VMCB_EVENTINJ_TYPE_EXCEPTION:
		if (vector >= 0 && vector <= 31 && vector != 2)
			break;
		/* FALLTHROUGH */
	default:
		panic("%s: invalid intr_type/vector: %d/%d", __func__,
		    intr_type, vector);
	}
	ctrl->eventinj = vector | (intr_type << 8) | VMCB_EVENTINJ_VALID;
	if (ec_valid) {
		ctrl->eventinj |= VMCB_EVENTINJ_EC_VALID;
		ctrl->eventinj |= (uint64_t)error << 32;
	}
}
