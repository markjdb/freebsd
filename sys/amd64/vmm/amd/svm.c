/*-
 * Copyright (c) 2013, Anish Gupta (akgupt3@gmail.com)
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
#include <sys/smp.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/pcpu.h>
#include <sys/proc.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <machine/cpufunc.h>
#include <machine/psl.h>
#include <machine/pmap.h>
#include <machine/md_var.h>
#include <machine/vmparam.h>
#include <machine/specialreg.h>
#include <machine/segments.h>
#include <machine/vmm.h>

#include <x86/apicreg.h>

#include "vmm_lapic.h"
#include "vmm_msr.h"
#include "vmm_stat.h"
#include "vmm_ktr.h"

#include "x86.h"
#include "vmcb.h"
#include "svm.h"
#include "svm_softc.h"
#include "npt.h"

/*
 * SVM CPUID function 0x8000_000Ai, edx bit decoding.
 */
#define AMD_CPUID_SVM_NP		BIT(0)  /* Nested paging or RVI */
#define AMD_CPUID_SVM_LBR		BIT(1)  /* Last branch virtualization */
#define AMD_CPUID_SVM_SVML		BIT(2)  /* SVM lock */
#define AMD_CPUID_SVM_NRIP_SAVE		BIT(3)  /* Next RIP is saved */
#define AMD_CPUID_SVM_TSC_RATE		BIT(4)  /* TSC rate control. */
#define AMD_CPUID_SVM_VMCB_CLEAN	BIT(5)  /* VMCB state caching */
#define AMD_CPUID_SVM_ASID_FLUSH	BIT(6)  /* Flush by ASID */
#define AMD_CPUID_SVM_DECODE_ASSIST	BIT(7)  /* Decode assist */
#define AMD_CPUID_SVM_PAUSE_INC		BIT(10) /* Pause intercept filter. */
#define AMD_CPUID_SVM_PAUSE_FTH		BIT(12) /* Pause filter threshold */

MALLOC_DEFINE(M_SVM, "svm", "svm");

/* Per-CPU context area. */
extern struct pcpu __pcpu[];

static int svm_vmexit(struct svm_softc *svm_sc, int vcpu,
			struct vm_exit *vmexit);
static int svm_msr_rw_ok(uint8_t *btmap, uint64_t msr);
static int svm_msr_index(uint64_t msr, int *index, int *bit);

static uint32_t svm_feature; /* AMD SVM features. */

/*
 * Starting guest ASID, 0 is reserved for host.
 * Each guest will have its own unique ASID.
 */
static uint32_t guest_asid = 1;

/*
 * Max ASID processor can support.
 * This limit the maximum number of virtual machines that can be created.
 */
static int max_asid;

/*
 * Statistics
 */
static VMM_STAT_AMD(VMEXIT_NPF_LAPIC, "vm exits due to Local APIC access");

/* 
 * SVM host state saved area of size 4KB for each core.
 */
static uint8_t hsave[MAXCPU][PAGE_SIZE] __aligned(PAGE_SIZE);

/*
 * S/w saved host context.
 */
static struct svm_regctx host_ctx[MAXCPU];

/* 
 * Common function to enable or disabled SVM for a CPU.
 */
static int
cpu_svm_enable_disable(boolean_t enable)
{
	uint64_t efer_msr;
	
	efer_msr = rdmsr(MSR_EFER);

	if (enable) {
		efer_msr |= EFER_SVM;
	} else {
		efer_msr &= ~EFER_SVM;
	}

	wrmsr(MSR_EFER, efer_msr);

	if(rdmsr(MSR_EFER) != efer_msr) {
		ERR("SVM couldn't be enabled on CPU%d.\n", curcpu);
		return (EIO);
	}

	return(0);
}

/*
 * Disable SVM on a CPU.
 */
static void
svm_disable(void *arg __unused)
{

	(void)cpu_svm_enable_disable(FALSE);
}

/*
 * Disable SVM for all CPUs.
 */
static int
svm_cleanup(void)
{

	smp_rendezvous(NULL, svm_disable, NULL, NULL);
	return (0);
}

/*
 * Check for required BHyVe SVM features in a CPU.
 */
static int
svm_cpuid_features(void)
{
	u_int regs[4];

	/* CPUID Fn8000_000A is for SVM */
	do_cpuid(0x8000000A, regs);
	svm_feature = regs[3];

	printf("SVM rev: 0x%x NASID:0x%x\n", regs[0] & 0xFF, regs[1]);
	max_asid = regs[1];
	
	printf("SVM Features:0x%b\n", svm_feature,
		"\020"
		"\001NP"		/* Nested paging */
		"\002LbrVirt"		/* LBR virtualization */
		"\003SVML"		/* SVM lock */
		"\004NRIPS"		/* NRIP save */
		"\005TscRateMsr"	/* MSR based TSC rate control */
		"\006VmcbClean"		/* VMCB clean bits */
		"\007FlushByAsid"	/* Flush by ASID */
		"\010DecodeAssist"	/* Decode assist */
		"\011<b20>"
		"\012<b20>"
		"\013PauseFilter"	
		"\014<b20>"
		"\013PauseFilterThreshold"	
		);

	/* SVM Lock */ 
	if (!(svm_feature & AMD_CPUID_SVM_SVML)) {
		printf("SVM is disabled by BIOS, please enable in BIOS.\n");
		return (ENXIO);
	}

	/*
	 * XXX: BHyVe need EPT or RVI to work.
	 */
	if (!(svm_feature & AMD_CPUID_SVM_NP)) {
		printf("Missing Nested paging or RVI SVM support in processor.\n");
		return (EIO);
	}
	
	if (svm_feature & (AMD_CPUID_SVM_NRIP_SAVE |
			AMD_CPUID_SVM_DECODE_ASSIST)) {
		return (0);
	}
	/* XXX: Should never be here? */
	printf("Processor doesn't support nRIP or decode assist, can't"
		"run BhyVe.\n");
	return (EIO);
}

/*
 * Enable SVM for a CPU.
 */
static void
svm_enable(void *arg __unused)
{
	uint64_t hsave_pa;

	(void)cpu_svm_enable_disable(TRUE);

	hsave_pa = vtophys(hsave[curcpu]);
	wrmsr(MSR_VM_HSAVE_PA, hsave_pa);
	
	if (rdmsr(MSR_VM_HSAVE_PA) != hsave_pa) {
		panic("VM_HSAVE_PA is wrong on CPU%d\n", curcpu);
	}
}

/*
 * Check if a processor support SVM.
 */
static int
is_svm_enabled(void)
{
	uint64_t msr;

	 /* Section 15.4 Enabling SVM from APM2. */
	if ((amd_feature2 & AMDID2_SVM) == 0) {
		printf("SVM is not supported on this processor.\n");
		return (ENXIO);
	}

	msr = rdmsr(MSR_VM_CR);
	/* Make sure SVM is not disabled by BIOS. */
	if ((msr & VM_CR_SVMDIS) == 0) {
		return svm_cpuid_features();
	}

	printf("SVM disabled by Key, consult TPM/BIOS manual.\n");
	return (ENXIO);
}

/*
 * Enable SVM on CPU and initialize nested page table h/w.
 */
static int
svm_init(void)
{
	int err;

	err = is_svm_enabled();
	if (err) {
		return (err);
	}

	svm_npt_init();
	
	/* Start SVM on all CPUs */
	smp_rendezvous(NULL, svm_enable, NULL, NULL);
		
	return(0);
}

/*
 * Get index and bit position for a MSR in MSR permission
 * bitmap. Two bits are used for each MSR, lower bit is
 * for read and higher bit is for write.
 */
static int
svm_msr_index(uint64_t msr, int *index, int *bit)
{
	uint32_t base, off;

/* Pentium compatible MSRs */
#define MSR_PENTIUM_START 	0	
#define MSR_PENTIUM_END 	0x1FFF
/* AMD 6th generation and Intel compatible MSRs */
#define MSR_AMD6TH_START 	0xC0000000UL	
#define MSR_AMD6TH_END 		0xC0001FFFUL	
/* AMD 7th and 8th generation compatible MSRs */
#define MSR_AMD7TH_START 	0xC0010000UL	
#define MSR_AMD7TH_END 		0xC0011FFFUL	
	
	*index = -1;
	*bit = (msr % 4) * 2;
	base = 0;

	if (msr >= MSR_PENTIUM_START && msr <= MSR_PENTIUM_END) {
		*index = msr / 4;
		return (0);
	}
	
	base += (MSR_PENTIUM_END - MSR_PENTIUM_START + 1); 
	if (msr >= MSR_AMD6TH_START && msr <= MSR_AMD6TH_END) {
		off = (msr - MSR_AMD6TH_START); 
		*index = (off + base) / 4;
		return (0);
	} 
	
	base += (MSR_AMD6TH_END - MSR_AMD6TH_START + 1);
	if (msr >= MSR_AMD7TH_START && msr <= MSR_AMD7TH_END) {
		off = (msr - MSR_AMD7TH_START);
		*index = (off + base) / 4;
		return (0);
	}

	return (EIO);
}

/*
 * Give virtual cpu the complete access to MSR(read & write).
 */
static int
svm_msr_rw_ok(uint8_t *perm_bitmap, uint64_t msr)
{
	int index, bit, err;

	err = svm_msr_index(msr, &index, &bit);
	if (err) {
		ERR("MSR 0x%lx is not writeable by guest.\n", msr);
		return (err);
	}
	
	if (index < 0 || index > (SVM_MSR_BITMAP_SIZE)) {
		ERR("MSR 0x%lx index out of range(%d).\n", msr, index);
		return (EINVAL);
	}
	if (bit < 0 || bit > 8) {
		ERR("MSR 0x%lx bit out of range(%d).\n", msr, bit);
		return (EINVAL);
	}

	/* Disable intercept for read and write. */
	perm_bitmap[index] &= ~(3 << bit);
	CTR1(KTR_VMM, "Guest has full control on SVM:MSR(0x%lx).\n", msr);
	
	return (0);
}

/*
 * Initialise VCPU.
 */
static int
svm_init_vcpu(struct svm_vcpu *vcpu, vm_paddr_t iopm_pa, vm_paddr_t msrpm_pa,
		vm_paddr_t pml4_pa, uint8_t asid)
{
	
	vcpu->lastcpu = NOCPU;
	vcpu->vmcb_pa = vtophys(&vcpu->vmcb);
	
	/* 
	 * Initiaise VMCB persistent area of vcpu.
	 * 1. Permission bitmap for MSR and IO space.
	 * 2. Nested paging.
	 * 3. ASID of virtual machine. 
	 */
	if (svm_init_vmcb(&vcpu->vmcb, iopm_pa, msrpm_pa, pml4_pa)) {
			return (EIO);
	}
	
	return (0);
}
		
/*
 * Initialise a virtual machine.
 */
static void *
svm_vminit(struct vm *vm)
{
	struct svm_softc *svm_sc;
	vm_paddr_t msrpm_pa, iopm_pa, pml4_pa;	
	int i;

	if (guest_asid >= max_asid) {
		ERR("Host support max ASID:%d, can't create more guests.\n",
			max_asid);
		return (NULL);
	}
	
	svm_sc = (struct svm_softc *)malloc(sizeof (struct svm_softc),
			M_SVM, M_WAITOK | M_ZERO);

	svm_sc->vm = vm;
	svm_sc->svm_feature = svm_feature;
	svm_sc->vcpu_cnt = VM_MAXCPU;

	/*
	 * Each guest has its own unique ASID.
	 * ASID(Addres Space Identifier) are used by TLB entries.
	 */
	svm_sc->asid = guest_asid++;
	
	/*
	 * Intercept MSR access to all MSRs except GSBASE, FSBASE,... etc.
	 */	
	 memset(svm_sc->msr_bitmap, 0xFF, sizeof(svm_sc->msr_bitmap));

	/*
	 * Following MSR can be completely controlled by virtual machines
	 * since access to following are translated to access to VMCB.
	 */
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_GSBASE);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_FSBASE);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_KGSBASE);
	
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_STAR);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_LSTAR);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_CSTAR);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_SF_MASK);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_SYSENTER_CS_MSR);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_SYSENTER_ESP_MSR);
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_SYSENTER_EIP_MSR);
	
	/* For Nested Paging/RVI only. */
	svm_msr_rw_ok(svm_sc->msr_bitmap, MSR_PAT);

	 /* Intercept access to all I/O ports. */
	memset(svm_sc->iopm_bitmap, 0xFF, sizeof(svm_sc->iopm_bitmap));

	/* Cache physical address for multiple vcpus. */
	iopm_pa = vtophys(svm_sc->iopm_bitmap);
	msrpm_pa = vtophys(svm_sc->msr_bitmap);
	pml4_pa = vtophys(svm_sc->np_pml4);

	for (i = 0; i < svm_sc->vcpu_cnt; i++) {
		if (svm_init_vcpu(svm_get_vcpu(svm_sc, i), iopm_pa, msrpm_pa,
				pml4_pa, svm_sc->asid)) {
			ERR("SVM couldn't initialise VCPU%d\n", i);
			goto cleanup;
		}
	}
	
	return (svm_sc);

cleanup:
	free(svm_sc, M_SVM);
	return (NULL);
}

/*
 * Handle guest I/O intercept.
 */
static int
svm_handle_io(struct svm_softc *svm_sc, int vcpu, struct vm_exit *vmexit)
{
	struct vmcb_ctrl *ctrl;
	struct vmcb_state *state;
	uint64_t info1;
	
	state = svm_get_vmcb_state(svm_sc, vcpu);
	ctrl  = svm_get_vmcb_ctrl(svm_sc, vcpu);
	info1 = ctrl->exitinfo1;
	
	vmexit->exitcode 	= VM_EXITCODE_INOUT;
	vmexit->u.inout.in 	= (info1 & BIT(0)) ? 1 : 0;
	vmexit->u.inout.string 	= (info1 & BIT(2)) ? 1 : 0;
	vmexit->u. inout.rep 	= (info1 & BIT(3)) ? 1 : 0;
	vmexit->u.inout.bytes 	= (info1 >> 4) & 0x7;
	vmexit->u.inout.port 	= (uint16_t)(info1 >> 16);
	vmexit->u.inout.eax 	= (uint32_t)(state->rax);

	return (1);
}

/*
 * SVM Nested Page(RVI) Fault handler.
 * Nested page fault handler used by local APIC emulation.
 */
static int
svm_handle_npf(struct vm *vm, int vcpu, uint64_t gpa, uint64_t rip,
		uint64_t exitinfo1, uint64_t cr3, struct vie *vie)
{
	int err;

	if (exitinfo1 & VMCB_NPF_INFO1_ID) {
 		VMM_CTR0(vm, vcpu, "SVM:NPF for code access.");
		return (0);
	}
	
	if (exitinfo1 & VMCB_NPF_INFO1_RSV) {
 		VMM_CTR0(vm, vcpu, "SVM:NPF reserved bits are set.");
		return (0);
	}
	
	if (exitinfo1 & VMCB_NPF_INFO1_GPT) {
 		VMM_CTR0(vm, vcpu, "SVM:NPF during guest page table walk.");
		return (0);
	}

	/*
	 * nRIP is NULL for NPF so we don't have the length of instruction,
	 * we rely on instruction decode s/w to determine the size of
	 * instruction.
	 *
	 * XXX: DecodeAssist can use instruction from buffer.
	 */
	if (vmm_fetch_instruction(vm, vcpu, rip, VIE_INST_SIZE,
				cr3, vie) != 0) {
 		ERR("SVM:NPF instruction fetch failed, RIP:0x%lx\n", rip);
		return (EINVAL);
	}

	KASSERT(vie->num_valid, ("No instruction to emulate."));
	/*
	 * SVM doesn't provide GLA unlike Intel VM-x. VIE_INVALID_GLA
	 * which is a non-cannonical address indicate that GLA is not
	 * available to instruction emulation.
	 *
	 * XXX: Which SVM capability can provided GLA?
	 */
	if(vmm_decode_instruction(vm, vcpu, VIE_INVALID_GLA, vie)) {
		ERR("SVM: Couldn't decode instruction.\n");
		return (0);
	}

	/*
	 * XXX: Decoding for user space(IOAPIC) should be done in
	 * user space.
	 */	
	if (gpa < DEFAULT_APIC_BASE || gpa >= (DEFAULT_APIC_BASE + PAGE_SIZE)) {
		VMM_CTR2(vm, vcpu, "SVM:NPF GPA(0x%lx) outside of local APIC"
			" range(0x%x)\n", gpa, DEFAULT_APIC_BASE);
		return (0);
	}

	err = vmm_emulate_instruction(vm, vcpu, gpa, vie, lapic_mmio_read,
		lapic_mmio_write, 0);

	return (err ? 0 : 1);
}

/*
 * Special handling of EFER MSR.
 * SVM guest must have SVM EFER bit set, prohibit guest from cleareing SVM
 * enable bit in EFER.
 */
static void
svm_efer(struct svm_softc *svm_sc, int vcpu, boolean_t write)
{
	struct svm_regctx *swctx;
	struct vmcb_state *state;
	
	state = svm_get_vmcb_state(svm_sc, vcpu);
	swctx = svm_get_guest_regctx(svm_sc, vcpu);

	if (write) {
		state->efer = ((swctx->e.g.sctx_rdx & (uint32_t)~0) << 32) |
				((uint32_t)state->rax) | EFER_SVM;
	} else {
		state->rax = (uint32_t)state->efer;
		swctx->e.g.sctx_rdx = (uint32_t)(state->efer >> 32);
	}
}

/*
 * Determine the cause of virtual cpu exit and return to user space if exit
 * demand so.
 * Return: 1 - Return to user space.
 *	   0 - Continue vcpu run.
 */
static int
svm_vmexit(struct svm_softc *svm_sc, int vcpu, struct vm_exit *vmexit)
{
	struct vmcb_state *state;
	struct vmcb_ctrl *ctrl;
	struct svm_regctx *ctx;
	uint64_t code, info1, info2, val;
	uint32_t eax, ecx, edx;
	int user;		/* Flag for user mode */
	int update_rip;		/* Flag for updating RIP */
	int inst_len;

	KASSERT(vcpu < svm_sc->vcpu_cnt, ("Guest doesn't have VCPU%d", vcpu));

	state = svm_get_vmcb_state(svm_sc, vcpu);
	ctrl  = svm_get_vmcb_ctrl(svm_sc, vcpu);
	ctx   = svm_get_guest_regctx(svm_sc, vcpu);
	update_rip = 1;
	user = 0;
	
	vmexit->exitcode = VM_EXITCODE_VMX;
	vmexit->u.vmx.error = 0;
	code = ctrl->exitcode;
	info1 = ctrl->exitinfo1;
	info2 = ctrl->exitinfo2;

	if (ctrl->nrip) {
		inst_len = ctrl->nrip - state->rip;
	} else {
		inst_len = ctrl->inst_decode_size;
	}

	switch (code) {
		case	VMCB_EXIT_MC: /* Machine Check. */
			vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_MTRAP, 1);
			vmexit->exitcode = VM_EXITCODE_MTRAP;
			user = 1;
			break;

		case	VMCB_EXIT_MSR:	/* MSR access. */
			eax = state->rax;
			ecx = ctx->sctx_rcx;
			edx = ctx->e.g.sctx_rdx;
			
			if (ecx == MSR_EFER) {
				VMM_CTR0(svm_sc->vm, vcpu,"VMEXIT EFER\n");
				svm_efer(svm_sc, vcpu, info1);
				break;
			}

			if (info1) {
				/* VM exited because of write MSR */
				vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_WRMSR, 1);
				vmexit->exitcode = VM_EXITCODE_WRMSR;
				vmexit->u.msr.code = ecx;
				val = (uint64_t)edx << 32 | eax;
				if (emulate_wrmsr(svm_sc->vm, vcpu, ecx, val)) {
					vmexit->u.msr.wval = val;
					user = 1;
				}
				VMM_CTR3(svm_sc->vm, vcpu,
					"VMEXIT WRMSR(%s handling) 0x%lx @0x%x",
					user ? "user" : "kernel", val, ecx);
			} else {
				vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_RDMSR, 1);
				vmexit->exitcode = VM_EXITCODE_RDMSR;
				vmexit->u.msr.code = ecx;
				if (emulate_rdmsr(svm_sc->vm, vcpu, ecx)) {
					user = 1; 
				}
				VMM_CTR3(svm_sc->vm, vcpu, "SVM:VMEXIT RDMSR"
					" 0x%lx,%lx @0x%x", ctx->e.g.sctx_rdx, 
					state->rax, ecx);
			}

#define MSR_AMDK8_IPM           0xc0010055
			/*
			 * We can't hide AMD C1E idle capability since its
			 * based on CPU generation, for now ignore access to
			 * this MSR by vcpus
			 * XXX: special handling of AMD C1E - Ignore.
			 */
			 if (ecx == MSR_AMDK8_IPM)
				user = 0;
			break;

		case 	VMCB_EXIT_INTR:
			/*
			 * Exit on External Interrupt.
			 * Give host interrupt handler to run and if its guest
			 * interrupt, local APIC will inject event in guest.
			 */
				user = 0;
			update_rip = 0;
			VMM_CTR1(svm_sc->vm, vcpu, "SVM:VMEXIT ExtInt"
				" RIP:0x%lx.\n", state->rip);
			vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_EXTINT, 1);
			break;

		case VMCB_EXIT_IO:
			vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_INOUT, 1);
			user = svm_handle_io(svm_sc, vcpu, vmexit);
			break;

		case VMCB_EXIT_CPUID:
			vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_CPUID, 1);
			(void)x86_emulate_cpuid(svm_sc->vm, vcpu,
					(uint32_t *)&state->rax,
					(uint32_t *)&ctx->sctx_rbx,
					(uint32_t *)&ctx->sctx_rcx,
					(uint32_t *)&ctx->e.g.sctx_rdx);
			VMM_CTR0(svm_sc->vm, vcpu, "SVM:VMEXIT CPUID\n");
			user = 0;
			break;

			case VMCB_EXIT_HLT:
			vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_HLT, 1);
 			if (ctrl->v_irq) {
				 /* Interrupt is pending, can't halt guest. */
				user = 0;
				vmm_stat_incr(svm_sc->vm, vcpu,
					VMEXIT_HLT_IGNORED, 1);
				VMM_CTR0(svm_sc->vm, vcpu, 
					"VMEXIT halt ignored.");
			} else {
				VMM_CTR0(svm_sc->vm, vcpu,
					"VMEXIT halted CPU.");
				vmexit->exitcode = VM_EXITCODE_HLT;
				user = 1;

			}
			break;

			case VMCB_EXIT_PAUSE:
			VMM_CTR0(svm_sc->vm, vcpu, "SVM:VMEXIT pause");
			vmexit->exitcode = VM_EXITCODE_PAUSE;
			vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_PAUSE, 1);

			break;

		case VMCB_EXIT_NPF:
			 /* EXITINFO2 has the physical fault address (GPA). */
			if (!svm_handle_npf(svm_sc->vm, vcpu, info2,
					state->rip, info1, state->cr3,
					&vmexit->u.paging.vie)) {
				/* I/O APIC for MSI/X. */
				vmexit->exitcode = VM_EXITCODE_PAGING;
				user = 1;
				vmexit->u.paging.gpa = info2;
			} else {
				/* Local APIC NPF */
				update_rip = 1;
				vmm_stat_incr(svm_sc->vm, vcpu,
						VMEXIT_NPF_LAPIC, 1);
			}
			
			vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_EPT_FAULT, 1);
			inst_len = vmexit->u.paging.vie.num_processed;
 			VMM_CTR3(svm_sc->vm, vcpu, "VMEXIT NPF, GPA:0x%lx "
				"user=%d instr len=%d.\n", info2, user,
				inst_len);
			break;

		case VMCB_EXIT_SHUTDOWN:
			VMM_CTR0(svm_sc->vm, vcpu, "SVM:VMEXIT guest shutdown.");
			user = 1;
			vmexit->exitcode = VM_EXITCODE_VMX;
			break;

		case VMCB_EXIT_INVALID:
			VMM_CTR0(svm_sc->vm, vcpu, "SVM:VMEXIT INVALID.");
			user = 1;
			vmexit->exitcode = VM_EXITCODE_VMX;
			break;

		default:
			 /* Return to user space. */
			user = 1;
			update_rip = 0;
			VMM_CTR3(svm_sc->vm, vcpu, "VMEXIT=0x%lx"
				" EXITINFO1: 0x%lx EXITINFO2:0x%lx\n",
		 		ctrl->exitcode, info1, info2);
			VMM_CTR3(svm_sc->vm, vcpu, "SVM:RIP: 0x%lx nRIP:0x%lx"
				" Inst decoder len:%d\n", state->rip,
				ctrl->nrip, ctrl->inst_decode_size);
			vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_UNKNOWN, 1);
			break;
	}	

	if (ctrl->v_irq) {
		VMM_CTR2(svm_sc->vm, vcpu, "SVM:SVM intr pending vector:0x%x"
		" priority:0x%x", ctrl->v_intr_vector, ctrl->v_intr_prio);
	}

	vmexit->rip = state->rip;
	if (update_rip) {
		vmexit->rip += inst_len;
	}

	/* Return to userland for APs to start. */
	if (vmexit->exitcode == VM_EXITCODE_SPINUP_AP) {
 		VMM_CTR1(svm_sc->vm, vcpu, "SVM:Starting APs, RIP0x%lx.\n",
			vmexit->rip);
		user = 1;
	}

	 /* XXX: Set next RIP before restarting virtual cpus. */
	if (ctrl->nrip == 0) {
		ctrl->nrip = state->rip;
	}
	
	return (user);
}

/*
 * Inject NMI to virtual cpu.
 */
static int
svm_inject_nmi(struct svm_softc *svm_sc, int vcpu)
{
	struct vmcb_ctrl *ctrl;

	KASSERT(vcpu < svm_sc->vcpu_cnt, ("Guest doesn't have VCPU%d", vcpu));

	ctrl  = svm_get_vmcb_ctrl(svm_sc, vcpu);
	 /* Can't inject another NMI if last one is pending.*/
	if (!vm_nmi_pending(svm_sc->vm, vcpu))
		return (0);

	 /* Inject NMI, vector number is not used.*/
	if (vmcb_eventinject(ctrl, VM_NMI, IDT_NMI, 0, FALSE)) {
		VMM_CTR0(svm_sc->vm, vcpu, "SVM:NMI injection failed.\n");
		return (EIO);
	}

	/* Acknowledge the request is accepted.*/
	vm_nmi_clear(svm_sc->vm, vcpu);

	VMM_CTR0(svm_sc->vm, vcpu, "SVM:Injected NMI.\n");

	return (1);
}

/*
 * Inject event to virtual cpu.
 */
static void
svm_inj_interrupts(struct svm_softc *svm_sc, int vcpu)
{
	struct vmcb_ctrl *ctrl;
	struct vmcb_state *state;
	int vector;
	
	KASSERT(vcpu < svm_sc->vcpu_cnt, ("Guest doesn't have VCPU%d", vcpu));

	state = svm_get_vmcb_state(svm_sc, vcpu);
	ctrl  = svm_get_vmcb_ctrl(svm_sc, vcpu);

	/* Can't inject multiple events at once. */
	if (ctrl->eventinj & VMCB_EVENTINJ_VALID) {
		VMM_CTR1(svm_sc->vm, vcpu,
			"SVM:Last event(0x%lx) is pending.\n", ctrl->eventinj);
		return ;
	}

	/* Wait for guest to come out of interrupt shadow. */
	if (ctrl->intr_shadow) {
		VMM_CTR0(svm_sc->vm, vcpu, "SVM:Guest in interrupt shadow.\n");
		goto inject_failed;
	}
	
	/* Make sure no interrupt is pending.*/
	if (ctrl->v_irq) {
		VMM_CTR0(svm_sc->vm, vcpu, 
			"SVM:virtual interrupt is pending.\n");
		goto inject_failed;
	}

	/* NMI event has priority over interrupts.*/
	if (svm_inject_nmi(svm_sc, vcpu)) {
		return;
	}

	vector = lapic_pending_intr(svm_sc->vm, vcpu);
	if (vector < 0) {
		return;
	}

	if (vector < 32 || vector > 255) {
		ERR("Invalid vector number:%d\n", vector);
		return;
	}

	if ((state->rflags & PSL_I) == 0) {
		VMM_CTR0(svm_sc->vm, vcpu, "SVM:Interrupt is disabled\n");
		goto inject_failed;
	}

	if(vmcb_eventinject(ctrl, VM_HW_INTR, vector, 0, FALSE)) {
		VMM_CTR2(svm_sc->vm, vcpu, "SVM:Event injection failed to"
			" VCPU%d,vector=%d.\n", vcpu, vector);
		return;
	}	

	/* Acknowledge that event is accepted.*/
	lapic_intr_accepted(svm_sc->vm, vcpu, vector);
	VMM_CTR1(svm_sc->vm, vcpu, "SVM:event injected,vector=%d.\n", vector);
	
inject_failed:
	return;
}

/*
 * Restore host Task Register selector type after every vcpu exit.
 */
static void
setup_tss_type(void)
{
	struct system_segment_descriptor *desc;

	desc = (struct system_segment_descriptor *)&gdt[curcpu * NGDT +
		GPROC0_SEL];
	/*
	 * Task selector that should be restored in host is
	 * 64-bit available(9), not what is read(0xb), see
	 * APMvol2 Rev3.21 4.8.3 System Descriptors table.
	 */
	desc->sd_type = 9;
}

/*
 * Start vcpu with specified RIP.
 */
static int
svm_vmrun(void *arg, int vcpu, register_t rip)
{
	struct svm_regctx *hctx, *gctx;
	struct svm_softc *svm_sc;
	struct svm_vcpu *vcpustate;
	struct vmcb_state *state;
	struct vmcb_ctrl *ctrl;
	struct vm_exit *vmexit;
	int user;
	uint64_t vmcb_pa;
	static uint64_t host_cr2;

	user = 0;
	svm_sc = arg;
	
	KASSERT(vcpu < svm_sc->vcpu_cnt, ("Guest doesn't have VCPU%d", vcpu));

	vcpustate = svm_get_vcpu(svm_sc, vcpu);
	state	= svm_get_vmcb_state(svm_sc, vcpu);
	ctrl  	= svm_get_vmcb_ctrl(svm_sc, vcpu);
	vmexit  = vm_exitinfo(svm_sc->vm , vcpu);
	if (vmexit->exitcode == VM_EXITCODE_VMX) {
		ERR("vcpu%d shouldn't run again.\n", vcpu);
		return(EIO);
	}

	gctx = svm_get_guest_regctx(svm_sc, vcpu);
	hctx = &host_ctx[curcpu]; 
	vmcb_pa = svm_sc->vcpu[vcpu].vmcb_pa;

	if (vcpustate->lastcpu != curcpu) {
		/* Virtual CPU is running on a diiferent CPU now.*/
		vmm_stat_incr(svm_sc->vm, vcpu, VCPU_MIGRATIONS, 1);

		/*
		 * Flush all TLB mapping for this guest on this CPU,
		 * it might have stale entries.
		 */
		ctrl->tlb_ctrl = VMCB_TLB_FLUSH_GUEST;

		/* Can't use any cached VMCB state by cpu.*/
		ctrl->vmcb_clean = VMCB_CACHE_NONE;
	} else {
		/* Don't flush TLB since guest ASID is unchanged. */
		ctrl->tlb_ctrl = VMCB_TLB_FLUSH_NOTHING;
		
		/* 
		 * This is the same cpu on which vcpu last ran so don't
		 * need to reload all VMCB state.
		 * ASID is unique for a guest.
		 * IOPM is unchanged.
		 * RVI/EPT is unchanged.
		 *
		 */
		ctrl->vmcb_clean = VMCB_CACHE_ASID |
				VMCB_CACHE_IOPM |
				VMCB_CACHE_NP;

	}

	vcpustate->lastcpu = curcpu;
	
	/* Update Guest RIP */
	state->rip = rip;
	
	do {
		lapic_timer_tick(svm_sc->vm, vcpu);
		
		(void)svm_set_vmcb(svm_get_vmcb(svm_sc, vcpu), svm_sc->asid);
		
		(void)svm_inj_interrupts(svm_sc, vcpu);
	
		/* Change TSS type to available.*/
		setup_tss_type();

		/*
		 * Disable global interrupt to guarantee atomicity
		 * during loading of guest state.
		 * See 15.5.1 "Loading guest state" APM2.
		 */	
		disable_gintr();

		save_cr2(&host_cr2);
		load_cr2(&state->cr2);

		/* Launch Virtual Machine. */
		svm_launch(vmcb_pa, gctx, hctx);

		save_cr2(&state->cr2);
		load_cr2(&host_cr2);

		/*
		 * Only GDTR and IDTR of host is saved and restore by SVM,
		 * LDTR and TR need to be restored by VMM.
		 * XXX: kernel doesn't use LDT, only user space.
		 */
		ltr(GSEL(GPROC0_SEL, SEL_KPL));
		
		/*
		 * Guest FS and GS selector are stashed by vmload and vmsave.
		 * Host FS and GS selector are stashed by svm_launch().
		 * Host GS base that holds per-cpu need to be restored before
		 * enabling global interrupt.
		 * FS is not used by FreeBSD kernel and kernel does restore
		 * back FS selector and base of user before returning to
		 * userland.
		 *
		 * Note: You can't use 'curcpu' which uses pcpu.
		 */
		wrmsr(MSR_GSBASE, (uint64_t)&__pcpu[vcpustate->lastcpu]);
		wrmsr(MSR_KGSBASE, (uint64_t)&__pcpu[vcpustate->lastcpu]);
		

		/* vcpu exit with glbal interrupt disabled. */
		enable_gintr();
		
		/* Handle #VMEXIT and if required return to user space. */
		user = svm_vmexit(svm_sc, vcpu, vmexit);
		vcpustate->loop++;
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_COUNT, 1);

		 /* We are asked to give the cpud by scheduler.*/
		if (curthread->td_flags & (TDF_ASTPENDING | TDF_NEEDRESCHED)) {
			vmexit->exitcode = VM_EXITCODE_BOGUS;
			vmexit->inst_length = 0;
			break;
		}

		/* Update RIP since we are continuing vcpu execution.*/
		state->rip = vmexit->rip;
	} while (!user);
		
	return (0);
}

/*
 * Cleanup for virtual machine.
 */
static void
svm_vmcleanup(void *arg)
{
	struct svm_softc *svm_sc;

	svm_sc = arg;
	
	VMM_CTR0(svm_sc->vm, 0, "SVM:cleanup\n");

	svm_npt_cleanup(svm_sc);
	free(svm_sc, M_SVM);
}

/*
 * Return pointer to hypervisor saved register state.
 */
static register_t *
swctx_regptr(struct svm_regctx *regctx, int reg)
{

	switch (reg) {
		case VM_REG_GUEST_RBX:
			return (&regctx->sctx_rbx);
		case VM_REG_GUEST_RCX:
			return (&regctx->sctx_rcx);
		case VM_REG_GUEST_RDX:
			return (&regctx->e.g.sctx_rdx);
		case VM_REG_GUEST_RDI:
			return (&regctx->e.g.sctx_rdi);
		case VM_REG_GUEST_RSI:
			return (&regctx->e.g.sctx_rsi);
		case VM_REG_GUEST_RBP:
			return (&regctx->sctx_rbp);
		case VM_REG_GUEST_R8:
			return (&regctx->sctx_r8);
		case VM_REG_GUEST_R9:
			return (&regctx->sctx_r9);
		case VM_REG_GUEST_R10:
			return (&regctx->sctx_r10);
		case VM_REG_GUEST_R11:
			return (&regctx->sctx_r11);
		case VM_REG_GUEST_R12:
			return (&regctx->sctx_r12);
		case VM_REG_GUEST_R13:
			return (&regctx->sctx_r13);
		case VM_REG_GUEST_R14:
			return (&regctx->sctx_r14);
		case VM_REG_GUEST_R15:
			return (&regctx->sctx_r15);
		default:
			ERR("Unknown register requested.\n");
			break;
	}

	return (NULL);
}

/*
 * Interface to read guest registers.
 * This can be SVM h/w saved or hypervisor saved register.
 */
static int
svm_getreg(void *arg, int vcpu, int ident, uint64_t *val)
{
	struct svm_softc *svm_sc;
	struct vmcb *vmcb;
	register_t *reg;
	
	svm_sc = arg;
	KASSERT(vcpu < svm_sc->vcpu_cnt, ("Guest doesn't have VCPU%d", vcpu));
	
	vmcb = svm_get_vmcb(svm_sc, vcpu);

	if (vmcb_read(vmcb, ident, val) == 0) {
		return (0);
	}

	reg = swctx_regptr(svm_get_guest_regctx(svm_sc, vcpu), ident);
	if (reg != NULL) {
		*val = *reg;
		return (0);
	}

	ERR("reg type %x is not saved n VMCB\n", ident);
	return (EINVAL);
}

/*
 * Interface to write to guest registers.
 * This can be SVM h/w saved or hypervisor saved register.
 */
static int
svm_setreg(void *arg, int vcpu, int ident, uint64_t val)
{
	struct svm_softc *svm_sc;
	struct vmcb *vmcb;
	register_t *reg;

	svm_sc = arg;
	KASSERT(vcpu < svm_sc->vcpu_cnt, ("Guest doesn't have VCPU%d", vcpu));

	vmcb = svm_get_vmcb(svm_sc, vcpu);
	if (vmcb_write(vmcb, ident, val) == 0) {
		return (0);
	}

	reg = swctx_regptr(svm_get_guest_regctx(svm_sc, vcpu), ident);
	
	if (reg != NULL) {
		*reg = val;
		return (0);
	}

	ERR("reg type %x is not saved n VMCB\n", ident);
	return (EINVAL);
}


/*
 * Inteface to set various descriptors.
 */
static int
svm_setdesc(void *arg, int vcpu, int type, struct seg_desc *desc)
{
	struct svm_softc *svm_sc;
	struct vmcb *vmcb;
	struct vmcb_segment *seg;
	uint16_t attrib;

	svm_sc = arg;
	KASSERT(vcpu < svm_sc->vcpu_cnt, ("Guest doesn't have VCPU%d", vcpu));

	vmcb = svm_get_vmcb(svm_sc, vcpu);

	VMM_CTR1(svm_sc->vm, vcpu, "SVM:set_desc: Type%d\n", type);

	seg = vmcb_seg(vmcb, type);
	if (seg == NULL) {
		ERR("Unsupported seg type %d\n", type);
		return (EINVAL);
	}

	/* Map seg_desc access to VMCB attribute format.*/
	attrib = ((desc->access & 0xF000) >> 4) | (desc->access & 0xFF);
	VMM_CTR3(svm_sc->vm, vcpu, "SVM:[sel %d attribute 0x%x limit:0x%x]\n",
		type, desc->access, desc->limit);
	seg->attrib = attrib;
	seg->base = desc->base;
	seg->limit = desc->limit;

	return (0);
}

/*
 * Interface to get guest descriptor.
 */
static int
svm_getdesc(void *arg, int vcpu, int type, struct seg_desc *desc)
{
	struct svm_softc *svm_sc;
	struct vmcb_segment	*seg;

	svm_sc = arg;
	KASSERT(vcpu < svm_sc->vcpu_cnt, ("Guest doesn't have VCPU%d", vcpu));

	VMM_CTR1(svm_sc->vm, vcpu, "SVM:get_desc: Type%d\n", type);

	seg = vmcb_seg(svm_get_vmcb(svm_sc, vcpu), type);
	if (!seg) {
		ERR("Unsupported seg type %d\n", type);
		return (EINVAL);
	}
	
	/* Map seg_desc access to VMCB attribute format.*/
	desc->access = ((seg->attrib & 0xF00) << 4) | (seg->attrib & 0xFF);
	desc->base = seg->base;
	desc->limit = seg->limit;

	return (0);
}

static int
svm_inject_event(void *arg, int vcpu, int type, int vector,
		  uint32_t error, int ec_valid)
{
	struct svm_softc *svm_sc;
	struct vmcb_ctrl *ctrl;

	svm_sc = arg;
	KASSERT(vcpu < svm_sc->vcpu_cnt, ("Guest doesn't have VCPU%d", vcpu));

	ctrl = svm_get_vmcb_ctrl(svm_sc, vcpu);
	VMM_CTR3(svm_sc->vm, vcpu, "Injecting event type:0x%x vector:0x%x"
		"error:0x%x\n", type, vector, error);

	return (vmcb_eventinject(ctrl, type, vector, error,
		ec_valid ? TRUE : FALSE));
}

static int
svm_setcap(void *arg, int vcpu, int type, int val)
{
	struct svm_softc *svm_sc;
	struct vmcb_ctrl *ctrl;
	int ret = ENOENT;

	svm_sc = arg;
	KASSERT(vcpu < svm_sc->vcpu_cnt, ("Guest doesn't have VCPU%d", vcpu));

	ctrl = svm_get_vmcb_ctrl(svm_sc, vcpu);

	switch (type) {
	case VM_CAP_HALT_EXIT:
			if (val)
				ctrl->ctrl1 |= VMCB_INTCPT_HLT;
			else
				ctrl->ctrl1 &= ~VMCB_INTCPT_HLT;
			ret = 0;
			VMM_CTR1(svm_sc->vm, vcpu, "SVM:Set_gap:Halt exit %s.\n",
				val ? "enabled": "disabled");
			break;

		case VM_CAP_PAUSE_EXIT:
			if (val)
				ctrl->ctrl1 |= VMCB_INTCPT_PAUSE;
			else
				ctrl->ctrl1 &= ~VMCB_INTCPT_PAUSE;
			ret = 0;
			VMM_CTR1(svm_sc->vm, vcpu, "SVM:Set_gap:Pause exit %s.\n",
				val ? "enabled": "disabled");
			break;

		case VM_CAP_MTRAP_EXIT:
			if (val)
				ctrl->exception |= BIT(IDT_MC);
			else
				ctrl->exception &= ~BIT(IDT_MC);
			ret = 0;
			VMM_CTR1(svm_sc->vm, vcpu, "SVM:Set_gap:MC exit %s.\n",
				val ? "enabled": "disabled"); 
			break;

		case VM_CAP_UNRESTRICTED_GUEST:
			/* SVM doesn't need special capability for SMP.*/
			VMM_CTR0(svm_sc->vm, vcpu, "SVM:Set_gap:Unrestricted "
			"always enabled.\n");
			ret = 0;
			break;
		
		default:
			break;
		}

	return (ret);
}

static int
svm_getcap(void *arg, int vcpu, int type, int *retval)
{
	struct svm_softc *svm_sc;
	struct vmcb_ctrl *ctrl;

	svm_sc = arg;
	KASSERT(vcpu < svm_sc->vcpu_cnt, ("Guest doesn't have VCPU%d", vcpu));

	ctrl = svm_get_vmcb_ctrl(svm_sc, vcpu);

	switch (type) {
		case VM_CAP_HALT_EXIT:
		*retval = (ctrl->ctrl1 & VMCB_INTCPT_HLT) ? 1 : 0;
		VMM_CTR1(svm_sc->vm, vcpu, "SVM:get_cap:Halt exit %s.\n",
			*retval ? "enabled": "disabled");
		break;

		case VM_CAP_PAUSE_EXIT:
		*retval = (ctrl->ctrl1 & VMCB_INTCPT_PAUSE) ? 1 : 0;
		VMM_CTR1(svm_sc->vm, vcpu, "SVM:get_cap:Pause exit %s.\n",
			*retval ? "enabled": "disabled");
		break;

		case VM_CAP_MTRAP_EXIT:
		*retval = (ctrl->exception & BIT(IDT_MC)) ? 1 : 0;
		VMM_CTR1(svm_sc->vm, vcpu, "SVM:get_cap:MC exit %s.\n",
			*retval ? "enabled": "disabled");
		break;

	case VM_CAP_UNRESTRICTED_GUEST:
		VMM_CTR0(svm_sc->vm, vcpu, "SVM:get_cap:Unrestricted.\n");
		*retval = 1;
		break;
		default:
		break;
	}

	return (0);
}

struct vmm_ops vmm_ops_amd = {
	svm_init,
	svm_cleanup,
	svm_vminit,
	svm_vmrun,
	svm_vmcleanup,
	svm_npt_vmmap_set,
	svm_npt_vmmap_get,
	svm_getreg,
	svm_setreg,
	svm_getdesc,
	svm_setdesc,
	svm_inject_event,
	svm_getcap,
	svm_setcap
};
