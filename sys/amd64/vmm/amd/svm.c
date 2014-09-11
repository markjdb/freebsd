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
#include <machine/smp.h>
#include <machine/vmm.h>
#include <machine/vmm_dev.h>
#include <machine/vmm_instruction_emul.h>

#include <x86/apicreg.h>

#include "vmm_lapic.h"
#include "vmm_msr.h"
#include "vmm_stat.h"
#include "vmm_ktr.h"
#include "vmm_ioport.h"
#include "vatpic.h"
#include "vlapic.h"
#include "vlapic_priv.h"

#include "x86.h"
#include "vmcb.h"
#include "svm.h"
#include "svm_softc.h"
#include "npt.h"

/*
 * SVM CPUID function 0x8000_000A, edx bit decoding.
 */
#define AMD_CPUID_SVM_NP		BIT(0)  /* Nested paging or RVI */
#define AMD_CPUID_SVM_LBR		BIT(1)  /* Last branch virtualization */
#define AMD_CPUID_SVM_SVML		BIT(2)  /* SVM lock */
#define AMD_CPUID_SVM_NRIP_SAVE		BIT(3)  /* Next RIP is saved */
#define AMD_CPUID_SVM_TSC_RATE		BIT(4)  /* TSC rate control. */
#define AMD_CPUID_SVM_VMCB_CLEAN	BIT(5)  /* VMCB state caching */
#define AMD_CPUID_SVM_FLUSH_BY_ASID	BIT(6)  /* Flush by ASID */
#define AMD_CPUID_SVM_DECODE_ASSIST	BIT(7)  /* Decode assist */
#define AMD_CPUID_SVM_PAUSE_INC		BIT(10) /* Pause intercept filter. */
#define AMD_CPUID_SVM_PAUSE_FTH		BIT(12) /* Pause filter threshold */

#define	VMCB_CACHE_DEFAULT	(VMCB_CACHE_ASID 	|	\
				VMCB_CACHE_IOPM		|	\
				VMCB_CACHE_I		|	\
				VMCB_CACHE_TPR		|	\
				VMCB_CACHE_NP)

MALLOC_DEFINE(M_SVM, "svm", "svm");
MALLOC_DEFINE(M_SVM_VLAPIC, "svm-vlapic", "svm-vlapic");

/* Per-CPU context area. */
extern struct pcpu __pcpu[];

static int svm_getdesc(void *arg, int vcpu, int type, struct seg_desc *desc);

static uint32_t svm_feature;	/* AMD SVM features. */

/* Maximum ASIDs supported by the processor */
static uint32_t nasid;

/* Current ASID generation for each host cpu */
static struct asid asid[MAXCPU];

/* 
 * SVM host state saved area of size 4KB for each core.
 */
static uint8_t hsave[MAXCPU][PAGE_SIZE] __aligned(PAGE_SIZE);

/*
 * S/w saved host context.
 */
static struct svm_regctx host_ctx[MAXCPU];

static VMM_STAT_AMD(VCPU_EXITINTINFO, "VM exits during event delivery");
static VMM_STAT_AMD(VCPU_INTINFO_INJECTED, "Events pending at VM entry");
static VMM_STAT_AMD(VMEXIT_VINTR, "VM exits due to interrupt window");

/* 
 * Common function to enable or disabled SVM for a CPU.
 */
static int
cpu_svm_enable_disable(boolean_t enable)
{
	uint64_t efer_msr;

	efer_msr = rdmsr(MSR_EFER);

	if (enable) 
		efer_msr |= EFER_SVM;
	else 
		efer_msr &= ~EFER_SVM;

	wrmsr(MSR_EFER, efer_msr);

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
	nasid = regs[1];
	KASSERT(nasid > 1, ("Insufficient ASIDs for guests: %#x", nasid));

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
		"\015PauseFilterThreshold"	
		"\016AVIC"	
		);

	/* SVM Lock */ 
	if (!(svm_feature & AMD_CPUID_SVM_SVML)) {
		printf("SVM is disabled by BIOS, please enable in BIOS.\n");
		return (ENXIO);
	}

	/*
	 * bhyve need RVI to work.
	 */
	if (!(svm_feature & AMD_CPUID_SVM_NP)) {
		printf("Missing Nested paging or RVI SVM support in processor.\n");
		return (EIO);
	}

	if (svm_feature & AMD_CPUID_SVM_NRIP_SAVE) 
		return (0);

	return (EIO);
}

static __inline int
flush_by_asid(void)
{
	return (svm_feature & AMD_CPUID_SVM_FLUSH_BY_ASID);
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
svm_init(int ipinum)
{
	int err, cpu;

	err = is_svm_enabled();
	if (err) 
		return (err);

	for (cpu = 0; cpu < MAXCPU; cpu++) {
		/*
		 * Initialize the host ASIDs to their "highest" valid values.
		 *
		 * The next ASID allocation will rollover both 'gen' and 'num'
		 * and start off the sequence at {1,1}.
		 */
		asid[cpu].gen = ~0UL;
		asid[cpu].num = nasid - 1;
	}

	svm_npt_init(ipinum);

	/* Start SVM on all CPUs */
	smp_rendezvous(NULL, svm_enable, NULL, NULL);

	return (0);
}

static void
svm_restore(void)
{
	svm_enable(NULL);
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
svm_msr_perm(uint8_t *perm_bitmap, uint64_t msr, bool read, bool write)
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
	if (read)
		perm_bitmap[index] &= ~(1UL << bit);
	if (write)
		perm_bitmap[index] &= ~(2UL << bit);
	CTR2(KTR_VMM, "Guest has control:0x%x on SVM:MSR(0x%lx).\n", 
		(perm_bitmap[index] >> bit) & 0x3, msr);

	return (0);
}

static int
svm_msr_rw_ok(uint8_t *perm_bitmap, uint64_t msr)
{
	return svm_msr_perm(perm_bitmap, msr, true, true);
}

static int
svm_msr_rd_ok(uint8_t *perm_bitmap, uint64_t msr)
{
	return svm_msr_perm(perm_bitmap, msr, true, false);
}

static __inline void
vcpu_set_dirty(struct svm_softc *sc, int vcpu, uint32_t dirtybits)
{
	struct svm_vcpu *vcpustate;

	vcpustate = svm_get_vcpu(sc, vcpu);

	vcpustate->dirty |= dirtybits;
}

static __inline int
svm_get_intercept(struct svm_softc *sc, int vcpu, int idx, uint32_t bitmask)
{
	struct vmcb_ctrl *ctrl;

	KASSERT(idx >=0 && idx < 5, ("invalid intercept index %d", idx));

	ctrl = svm_get_vmcb_ctrl(sc, vcpu);
	return (ctrl->intercept[idx] & bitmask ? 1 : 0);
}

static __inline void
svm_set_intercept(struct svm_softc *sc, int vcpu, int idx, uint32_t bitmask,
    int enabled)
{
	struct vmcb_ctrl *ctrl;
	uint32_t oldval;

	KASSERT(idx >=0 && idx < 5, ("invalid intercept index %d", idx));

	ctrl = svm_get_vmcb_ctrl(sc, vcpu);
	oldval = ctrl->intercept[idx];

	if (enabled)
		ctrl->intercept[idx] |= bitmask;
	else
		ctrl->intercept[idx] &= ~bitmask;

	if (ctrl->intercept[idx] != oldval) {
		vcpu_set_dirty(sc, vcpu, VMCB_CACHE_I);
		VCPU_CTR3(sc->vm, vcpu, "intercept[%d] modified "
		    "from %#x to %#x", idx, oldval, ctrl->intercept[idx]);
	}
}

static __inline void
svm_disable_intercept(struct svm_softc *sc, int vcpu, int off, uint32_t bitmask)
{
	svm_set_intercept(sc, vcpu, off, bitmask, 0);
}

static __inline void
svm_enable_intercept(struct svm_softc *sc, int vcpu, int off, uint32_t bitmask)
{
	svm_set_intercept(sc, vcpu, off, bitmask, 1);
}

static void
vmcb_init(struct svm_softc *sc, int vcpu, uint64_t iopm_base_pa,
    uint64_t msrpm_base_pa, uint64_t np_pml4)
{
	struct vmcb_ctrl *ctrl;
	struct vmcb_state *state;
	uint32_t mask;
	int n;

	ctrl = svm_get_vmcb_ctrl(sc, vcpu);
	state = svm_get_vmcb_state(sc, vcpu);

	ctrl->iopm_base_pa = iopm_base_pa;
	ctrl->msrpm_base_pa = msrpm_base_pa;

	/* Enable nested paging */
	ctrl->np_enable = 1;
	ctrl->n_cr3 = np_pml4;

	/*
	 * Intercept accesses to the control registers that are not shadowed
	 * in the VMCB - i.e. all except cr0, cr2, cr3, cr4 and cr8.
	 */
	for (n = 0; n < 16; n++) {
		mask = (BIT(n) << 16) | BIT(n);
		if (n == 0 || n == 2 || n == 3 || n == 4 || n == 8)
			svm_disable_intercept(sc, vcpu, VMCB_CR_INTCPT, mask);
		else
			svm_enable_intercept(sc, vcpu, VMCB_CR_INTCPT, mask);
	}

	/* Intercept Machine Check exceptions. */
	svm_enable_intercept(sc, vcpu, VMCB_EXC_INTCPT, BIT(IDT_MC));

	/* Intercept various events (for e.g. I/O, MSR and CPUID accesses) */
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_IO);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_MSR);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_HLT);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_CPUID);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_INTR);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_INIT);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_NMI);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_SMI);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT, VMCB_INTCPT_SHUTDOWN);
	svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT,
	    VMCB_INTCPT_FERR_FREEZE);

	/*
	 * From section "Canonicalization and Consistency Checks" in APMv2
	 * the VMRUN intercept bit must be set to pass the consistency check.
	 */
	svm_enable_intercept(sc, vcpu, VMCB_CTRL2_INTCPT, VMCB_INTCPT_VMRUN);

	/*
	 * The ASID will be set to a non-zero value just before VMRUN.
	 */
	ctrl->asid = 0;

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
}

/*
 * Initialise a virtual machine.
 */
static void *
svm_vminit(struct vm *vm, pmap_t pmap)
{
	struct svm_softc *svm_sc;
	struct svm_vcpu *vcpu;
	vm_paddr_t msrpm_pa, iopm_pa, pml4_pa;	
	int i;

	svm_sc = (struct svm_softc *)malloc(sizeof (struct svm_softc),
			M_SVM, M_WAITOK | M_ZERO);

	svm_sc->vm = vm;
	svm_sc->svm_feature = svm_feature;
	svm_sc->vcpu_cnt = VM_MAXCPU;
	svm_sc->nptp = (vm_offset_t)vtophys(pmap->pm_pml4);

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

	svm_msr_rd_ok(svm_sc->msr_bitmap, MSR_TSC);
	svm_msr_rd_ok(svm_sc->msr_bitmap, MSR_EFER);

	 /* Intercept access to all I/O ports. */
	memset(svm_sc->iopm_bitmap, 0xFF, sizeof(svm_sc->iopm_bitmap));

	/* Cache physical address for multiple vcpus. */
	iopm_pa = vtophys(svm_sc->iopm_bitmap);
	msrpm_pa = vtophys(svm_sc->msr_bitmap);
	pml4_pa = svm_sc->nptp;

	for (i = 0; i < svm_sc->vcpu_cnt; i++) {
		vcpu = svm_get_vcpu(svm_sc, i);
		vcpu->lastcpu = NOCPU;
		vcpu->vmcb_pa = vtophys(&vcpu->vmcb);
		vmcb_init(svm_sc, i, iopm_pa, msrpm_pa, pml4_pa);
	}
	return (svm_sc);
}

static int
svm_cpl(struct vmcb_state *state)
{

	/*
	 * From APMv2:
	 *   "Retrieve the CPL from the CPL field in the VMCB, not
	 *    from any segment DPL"
	 */
	return (state->cpl);
}

static enum vm_cpu_mode
svm_vcpu_mode(struct vmcb *vmcb)
{
	struct vmcb_segment *seg;
	struct vmcb_state *state;

	state = &vmcb->state;

	if (state->efer & EFER_LMA) {
		seg = vmcb_seg(vmcb, VM_REG_GUEST_CS);
		/*
		 * Section 4.8.1 for APM2, check if Code Segment has
		 * Long attribute set in descriptor.
		 */
		if (seg->attrib & VMCB_CS_ATTRIB_L)
			return (CPU_MODE_64BIT);
		else
			return (CPU_MODE_COMPATIBILITY);
	} else  if (state->cr0 & CR0_PE) {
		return (CPU_MODE_PROTECTED);
	} else {
		return (CPU_MODE_REAL);
	}
}

static enum vm_paging_mode
svm_paging_mode(uint64_t cr0, uint64_t cr4, uint64_t efer)
{

	if ((cr0 & CR0_PG) == 0)
		return (PAGING_MODE_FLAT);
	if ((cr4 & CR4_PAE) == 0)
		return (PAGING_MODE_32);
	if (efer & EFER_LME)
		return (PAGING_MODE_64);
	else
		return (PAGING_MODE_PAE);
}

/*
 * ins/outs utility routines
 */
static uint64_t
svm_inout_str_index(struct svm_regctx *regs, int in)
{
	uint64_t val;

	val = in ? regs->e.g.sctx_rdi : regs->e.g.sctx_rsi;

	return (val);
}

static uint64_t
svm_inout_str_count(struct svm_regctx *regs, int rep)
{
	uint64_t val;

	val = rep ? regs->sctx_rcx : 1;

	return (val);
}

static void
svm_inout_str_seginfo(struct svm_softc *svm_sc, int vcpu, int64_t info1,
    int in, struct vm_inout_str *vis)
{
	int error, s;

	if (in) {
		vis->seg_name = VM_REG_GUEST_ES;
	} else {
		/* The segment field has standard encoding */
		s = (info1 >> 10) & 0x7;
		vis->seg_name = vm_segment_name(s);
	}

	error = svm_getdesc(svm_sc, vcpu, vis->seg_name, &vis->seg_desc);
	KASSERT(error == 0, ("%s: svm_getdesc error %d", __func__, error));
}

static int
svm_inout_str_addrsize(uint64_t info1)
{
        uint32_t size;

        size = (info1 >> 7) & 0x7;
        switch (size) {
        case 1:
                return (2);     /* 16 bit */
        case 2:
                return (4);     /* 32 bit */
        case 4:
                return (8);     /* 64 bit */
        default:
                panic("%s: invalid size encoding %d", __func__, size);
        }
}

static void
svm_paging_info(struct vmcb *vmcb, struct vm_guest_paging *paging)
{
	struct vmcb_state *state;

	state = &vmcb->state;
	paging->cr3 = state->cr3;
	paging->cpl = svm_cpl(state);
	paging->cpu_mode = svm_vcpu_mode(vmcb);
	paging->paging_mode = svm_paging_mode(state->cr0, state->cr4,
	    state->efer);
}


/*
 * Handle guest I/O intercept.
 */
static bool
svm_handle_io(struct svm_softc *svm_sc, int vcpu, struct vm_exit *vmexit)
{
	struct vmcb_ctrl *ctrl;
	struct vmcb_state *state;
	struct svm_regctx *regs;
	struct vm_inout_str *vis;
	uint64_t info1;

	state = svm_get_vmcb_state(svm_sc, vcpu);
	ctrl  = svm_get_vmcb_ctrl(svm_sc, vcpu);
	regs  = svm_get_guest_regctx(svm_sc, vcpu);
	info1 = ctrl->exitinfo1;
	
	vmexit->exitcode 	= VM_EXITCODE_INOUT;
	vmexit->u.inout.in 	= (info1 & BIT(0)) ? 1 : 0;
	vmexit->u.inout.string 	= (info1 & BIT(2)) ? 1 : 0;
	vmexit->u.inout.rep 	= (info1 & BIT(3)) ? 1 : 0;
	vmexit->u.inout.bytes 	= (info1 >> 4) & 0x7;
	vmexit->u.inout.port 	= (uint16_t)(info1 >> 16);
	vmexit->u.inout.eax 	= (uint32_t)(state->rax);

	if (vmexit->u.inout.string) {
		vmexit->exitcode = VM_EXITCODE_INOUT_STR;
		vis = &vmexit->u.inout_str;
		svm_paging_info(svm_get_vmcb(svm_sc, vcpu), &vis->paging);
		vis->rflags = state->rflags;
		vis->cr0 = state->cr0;
		vis->index = svm_inout_str_index(regs, vmexit->u.inout.in);
		vis->count = svm_inout_str_count(regs, vmexit->u.inout.rep);
		vis->addrsize = svm_inout_str_addrsize(info1);
		svm_inout_str_seginfo(svm_sc, vcpu, info1,
		    vmexit->u.inout.in, vis);
	}
	
	return (false);
}

static int
svm_npf_paging(uint64_t exitinfo1)
{

	if (exitinfo1 & VMCB_NPF_INFO1_W)
		return (VM_PROT_WRITE);

	return (VM_PROT_READ);
}

static bool
svm_npf_emul_fault(uint64_t exitinfo1)
{
	
	if (exitinfo1 & VMCB_NPF_INFO1_ID) {
		return (false);
	}

	if (exitinfo1 & VMCB_NPF_INFO1_GPT) {
		return (false);
	}

	if ((exitinfo1 & VMCB_NPF_INFO1_GPA) == 0) {
		return (false);
	}

	return (true);	
}

static void
svm_handle_inst_emul(struct vmcb *vmcb, uint64_t gpa, struct vm_exit *vmexit)
{
	struct vm_guest_paging *paging;
	struct vmcb_segment *seg;

	paging = &vmexit->u.inst_emul.paging;
	vmexit->exitcode = VM_EXITCODE_INST_EMUL;
	vmexit->u.inst_emul.gpa = gpa;
	vmexit->u.inst_emul.gla = VIE_INVALID_GLA;
	svm_paging_info(vmcb, paging);

	/*
	 * If DecodeAssist SVM feature doesn't exist, we don't have NPF 
	 * instuction length. RIP will be calculated based on the length 
	 * determined by instruction emulation.
	 */
	vmexit->inst_length = VIE_INST_SIZE;

	seg = vmcb_seg(vmcb, VM_REG_GUEST_CS);
	switch(paging->cpu_mode) {
	case CPU_MODE_PROTECTED:
	case CPU_MODE_COMPATIBILITY:
		/*
		 * Section 4.8.1 of APM2, Default Operand Size or D bit.
		 */
		vmexit->u.inst_emul.cs_d = (seg->attrib & VMCB_CS_ATTRIB_D) ?
		    1 : 0;
		break;
	default:
		vmexit->u.inst_emul.cs_d = 0;
		break;	
	}
}

/*
 * Intercept access to MSR_EFER to prevent the guest from clearing the
 * SVM enable bit.
 */
static void
svm_write_efer(struct svm_softc *sc, int vcpu, uint32_t edx, uint32_t eax)
{
	struct vmcb_state *state;
	uint64_t oldval;

	state = svm_get_vmcb_state(sc, vcpu);

	oldval = state->efer;
	state->efer = (uint64_t)edx << 32 | eax | EFER_SVM;
	if (state->efer != oldval) {
		VCPU_CTR2(sc->vm, vcpu, "Guest EFER changed from %#lx to %#lx",
		    oldval, state->efer);
		vcpu_set_dirty(sc, vcpu, VMCB_CACHE_CR);
	}
}

#ifdef KTR
static const char *
intrtype_to_str(int intr_type)
{
	switch (intr_type) {
	case VMCB_EVENTINJ_TYPE_INTR:
		return ("hwintr");
	case VMCB_EVENTINJ_TYPE_NMI:
		return ("nmi");
	case VMCB_EVENTINJ_TYPE_INTn:
		return ("swintr");
	case VMCB_EVENTINJ_TYPE_EXCEPTION:
		return ("exception");
	default:
		panic("%s: unknown intr_type %d", __func__, intr_type);
	}
}
#endif

/*
 * Inject an event to vcpu as described in section 15.20, "Event injection".
 */
static void
svm_eventinject(struct svm_softc *sc, int vcpu, int intr_type, int vector,
		 uint32_t error, bool ec_valid)
{
	struct vmcb_ctrl *ctrl;

	ctrl = svm_get_vmcb_ctrl(sc, vcpu);

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
		VCPU_CTR3(sc->vm, vcpu, "Injecting %s at vector %d errcode %#x",
		    intrtype_to_str(intr_type), vector, error);
	} else {
		VCPU_CTR2(sc->vm, vcpu, "Injecting %s at vector %d",
		    intrtype_to_str(intr_type), vector);
	}
}

static void
svm_save_intinfo(struct svm_softc *svm_sc, int vcpu)
{
	struct vmcb_ctrl *ctrl;
	uint64_t intinfo;

	ctrl  = svm_get_vmcb_ctrl(svm_sc, vcpu);
	intinfo = ctrl->exitintinfo;	
	if (!VMCB_EXITINTINFO_VALID(intinfo))
		return;

	/*
	 * From APMv2, Section "Intercepts during IDT interrupt delivery"
	 *
	 * If a #VMEXIT happened during event delivery then record the event
	 * that was being delivered.
	 */
	VCPU_CTR2(svm_sc->vm, vcpu, "SVM:Pending INTINFO(0x%lx), vector=%d.\n",
		intinfo, VMCB_EXITINTINFO_VECTOR(intinfo));
	vmm_stat_incr(svm_sc->vm, vcpu, VCPU_EXITINTINFO, 1);
	vm_exit_intinfo(svm_sc->vm, vcpu, intinfo);
}

static __inline void
enable_intr_window_exiting(struct svm_softc *sc, int vcpu)
{
	struct vmcb_ctrl *ctrl;

	ctrl = svm_get_vmcb_ctrl(sc, vcpu);

	if (ctrl->v_irq == 0) {
		VCPU_CTR0(sc->vm, vcpu, "Enable intr window exiting");
		ctrl->v_irq = 1;
		ctrl->v_ign_tpr = 1;
		vcpu_set_dirty(sc, vcpu, VMCB_CACHE_TPR);
		svm_enable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT,
		    VMCB_INTCPT_VINTR);
	}
}

static __inline void
disable_intr_window_exiting(struct svm_softc *sc, int vcpu)
{
	struct vmcb_ctrl *ctrl;

	ctrl = svm_get_vmcb_ctrl(sc, vcpu);

	if (ctrl->v_irq) {
		VCPU_CTR0(sc->vm, vcpu, "Disable intr window exiting");
		ctrl->v_irq = 0;
		vcpu_set_dirty(sc, vcpu, VMCB_CACHE_TPR);
		svm_disable_intercept(sc, vcpu, VMCB_CTRL1_INTCPT,
		    VMCB_INTCPT_VINTR);
	}
}

static int
nmi_blocked(struct svm_softc *sc, int vcpu)
{
	/* XXX need to track NMI blocking */
	return (0);
}

static void
enable_nmi_blocking(struct svm_softc *sc, int vcpu)
{
	/* XXX enable iret intercept */
}

#ifdef notyet
static void
clear_nmi_blocking(struct svm_softc *sc, int vcpu)
{
	/* XXX disable iret intercept */
}
#endif

#ifdef KTR
static const char *
exit_reason_to_str(uint64_t reason)
{
	static char reasonbuf[32];

	switch (reason) {
	case VMCB_EXIT_INVALID:
		return ("invalvmcb");
	case VMCB_EXIT_SHUTDOWN:
		return ("shutdown");
	case VMCB_EXIT_NPF:
		return ("nptfault");
	case VMCB_EXIT_PAUSE:
		return ("pause");
	case VMCB_EXIT_HLT:
		return ("hlt");
	case VMCB_EXIT_CPUID:
		return ("cpuid");
	case VMCB_EXIT_IO:
		return ("inout");
	case VMCB_EXIT_MC:
		return ("mchk");
	case VMCB_EXIT_INTR:
		return ("extintr");
	case VMCB_EXIT_VINTR:
		return ("vintr");
	case VMCB_EXIT_MSR:
		return ("msr");
	default:
		snprintf(reasonbuf, sizeof(reasonbuf), "%#lx", reason);
		return (reasonbuf);
	}
}
#endif	/* KTR */

/*
 * Determine the cause of virtual cpu exit and handle VMEXIT.
 * Return: false - Break vcpu execution loop and handle vmexit
 *		   in kernel or user space.
 *	   true  - Continue vcpu run.
 */
static bool 
svm_vmexit(struct svm_softc *svm_sc, int vcpu, struct vm_exit *vmexit)
{
	struct vmcb_state *state;
	struct vmcb_ctrl *ctrl;
	struct svm_regctx *ctx;
	uint64_t code, info1, info2, val;
	uint32_t eax, ecx, edx;
	bool update_rip, loop, retu;

	KASSERT(vcpu < svm_sc->vcpu_cnt, ("Guest doesn't have VCPU%d", vcpu));

	state = svm_get_vmcb_state(svm_sc, vcpu);
	ctrl  = svm_get_vmcb_ctrl(svm_sc, vcpu);
	ctx   = svm_get_guest_regctx(svm_sc, vcpu);
	code  = ctrl->exitcode;
	info1 = ctrl->exitinfo1;
	info2 = ctrl->exitinfo2;

	update_rip = true;
	loop = true;
	vmexit->exitcode = VM_EXITCODE_VMX;
	vmexit->u.vmx.status = 0;

	vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_COUNT, 1);

	KASSERT((ctrl->eventinj & VMCB_EVENTINJ_VALID) == 0, ("%s: event "
	    "injection valid bit is set %#lx", __func__, ctrl->eventinj));

	svm_save_intinfo(svm_sc, vcpu);

	switch (code) {
	case VMCB_EXIT_VINTR:
		update_rip = false;
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_VINTR, 1);
		break;
	case VMCB_EXIT_MC:	/* Machine Check. */
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_MTRAP, 1);
		vmexit->exitcode = VM_EXITCODE_MTRAP;
		loop = false;
		break;
	case VMCB_EXIT_MSR:	/* MSR access. */
		eax = state->rax;
		ecx = ctx->sctx_rcx;
		edx = ctx->e.g.sctx_rdx;

		if (ecx == MSR_EFER) {
			KASSERT(info1 != 0, ("rdmsr(MSR_EFER) is not "
			    "emulated: info1(%#lx) info2(%#lx)",
			    info1, info2));
			svm_write_efer(svm_sc, vcpu, edx, eax);
			break;
		}

		retu = false;	
		if (info1) {
			/* VM exited because of write MSR */
			vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_WRMSR, 1);
			vmexit->exitcode = VM_EXITCODE_WRMSR;
			vmexit->u.msr.code = ecx;
			val = (uint64_t)edx << 32 | eax;
			if (emulate_wrmsr(svm_sc->vm, vcpu, ecx, val, &retu)) {
				vmexit->u.msr.wval = val;
				loop = false;
			} else
				loop = retu ? false : true;
			VCPU_CTR3(svm_sc->vm, vcpu,
			    "VMEXIT WRMSR(%s handling) 0x%lx @0x%x",
			    loop ? "kernel" : "user", val, ecx);
		} else {
			vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_RDMSR, 1);
			vmexit->exitcode = VM_EXITCODE_RDMSR;
			vmexit->u.msr.code = ecx;
			if (emulate_rdmsr(svm_sc->vm, vcpu, ecx, &retu))
				loop = false; 
			else
				loop = retu ? false : true;
			VCPU_CTR3(svm_sc->vm, vcpu, "SVM:VMEXIT RDMSR"
			    " MSB=0x%08x, LSB=%08x @0x%x", 
			    ctx->e.g.sctx_rdx, state->rax, ecx);
		}

#define MSR_AMDK8_IPM           0xc0010055
		/*
		 * We can't hide AMD C1E idle capability since its
		 * based on CPU generation, for now ignore access to
		 * this MSR by vcpus
		 * XXX: special handling of AMD C1E - Ignore.
		 */
		 if (ecx == MSR_AMDK8_IPM)
			loop = true;
		break;
	case VMCB_EXIT_INTR:
		/*
		 * Exit on External Interrupt.
		 * Give host interrupt handler to run and if its guest
		 * interrupt, local APIC will inject event in guest.
		 */
		update_rip = false;
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_EXTINT, 1);
		break;
	case VMCB_EXIT_IO:
		loop = svm_handle_io(svm_sc, vcpu, vmexit);
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_INOUT, 1);
		break;
	case VMCB_EXIT_CPUID:
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_CPUID, 1);
		loop = x86_emulate_cpuid(svm_sc->vm, vcpu,
		    (uint32_t *)&state->rax,
		    (uint32_t *)&ctx->sctx_rbx,
		    (uint32_t *)&ctx->sctx_rcx,
		    (uint32_t *)&ctx->e.g.sctx_rdx);
		break;
	case VMCB_EXIT_HLT:
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_HLT, 1);
		vmexit->exitcode = VM_EXITCODE_HLT;
		vmexit->u.hlt.rflags = state->rflags;
		loop = false;
		break;
	case VMCB_EXIT_PAUSE:
		vmexit->exitcode = VM_EXITCODE_PAUSE;
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_PAUSE, 1);
		loop = false;
		break;
	case VMCB_EXIT_NPF:
		loop = false;
		update_rip = false;
		if (info1 & VMCB_NPF_INFO1_RSV) {
			VCPU_CTR2(svm_sc->vm, vcpu, "nested page fault with "
			    "reserved bits set: info1(%#lx) info2(%#lx)",
			    info1, info2);
			break;
		}

		/* EXITINFO2 has the physical fault address (GPA). */
		if(vm_mem_allocated(svm_sc->vm, info2)) {
			vmexit->exitcode = VM_EXITCODE_PAGING;
			vmexit->u.paging.gpa = info2;
			vmexit->u.paging.fault_type = svm_npf_paging(info1);
			vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_NESTED_FAULT, 1);
			VCPU_CTR3(svm_sc->vm, vcpu, "nested page fault "
			    "on gpa %#lx/%#lx at rip %#lx",
			    info2, info1, state->rip);
		} else if (svm_npf_emul_fault(info1)) {
			svm_handle_inst_emul(svm_get_vmcb(svm_sc, vcpu),
				info2, vmexit);
			vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_INST_EMUL, 1);
			VCPU_CTR3(svm_sc->vm, vcpu, "inst_emul fault "
			    "for gpa %#lx/%#lx at rip %#lx",
			    info2, info1, state->rip);
		}
		break;
	case VMCB_EXIT_SHUTDOWN:
		loop = false;
		break;
	case VMCB_EXIT_INVALID:
		loop = false;
		break;
	default:
		 /* Return to user space. */
		loop = false;
		update_rip = false;
		VCPU_CTR3(svm_sc->vm, vcpu, "VMEXIT=0x%lx"
			" EXITINFO1: 0x%lx EXITINFO2:0x%lx\n",
			ctrl->exitcode, info1, info2);
		VCPU_CTR3(svm_sc->vm, vcpu, "SVM:RIP: 0x%lx nRIP:0x%lx"
			" Inst decoder len:%d\n", state->rip,
			ctrl->nrip, ctrl->inst_decode_size);
		vmm_stat_incr(svm_sc->vm, vcpu, VMEXIT_UNKNOWN, 1);
		break;
	}	

	VCPU_CTR4(svm_sc->vm, vcpu, "%s %s vmexit at %#lx nrip %#lx",
	    loop ? "handled" : "unhandled", exit_reason_to_str(code),
	    state->rip, update_rip ? ctrl->nrip : state->rip);

	vmexit->rip = state->rip;
	if (update_rip) {
		if (ctrl->nrip == 0) {
 			VCPU_CTR1(svm_sc->vm, vcpu, "SVM_ERR:nRIP is not set "
				 "for RIP0x%lx.\n", state->rip);
			vmexit->exitcode = VM_EXITCODE_VMX;
		} else 
			vmexit->rip = ctrl->nrip;
	}

	/* If vcpu execution is continued, update RIP. */
	if (loop) {
		state->rip = vmexit->rip;
	}

	return (loop);
}

static void
svm_inj_intinfo(struct svm_softc *svm_sc, int vcpu)
{
	uint64_t intinfo;

	if (!vm_entry_intinfo(svm_sc->vm, vcpu, &intinfo))
		return;

	KASSERT(VMCB_EXITINTINFO_VALID(intinfo), ("%s: entry intinfo is not "
	    "valid: %#lx", __func__, intinfo));

	svm_eventinject(svm_sc, vcpu, VMCB_EXITINTINFO_TYPE(intinfo),
		VMCB_EXITINTINFO_VECTOR(intinfo),
		VMCB_EXITINTINFO_EC(intinfo),
		VMCB_EXITINTINFO_EC_VALID(intinfo));
	vmm_stat_incr(svm_sc->vm, vcpu, VCPU_INTINFO_INJECTED, 1);
	VCPU_CTR1(svm_sc->vm, vcpu, "Injected entry intinfo: %#lx", intinfo);
}

/*
 * Inject event to virtual cpu.
 */
static void
svm_inj_interrupts(struct svm_softc *sc, int vcpu, struct vlapic *vlapic)
{
	struct vmcb_ctrl *ctrl;
	struct vmcb_state *state;
	int extint_pending;
	int vector, need_intr_window;

	state = svm_get_vmcb_state(sc, vcpu);
	ctrl  = svm_get_vmcb_ctrl(sc, vcpu);

	need_intr_window = 0;

	/*
	 * Inject pending events or exceptions for this vcpu.
	 *
	 * An event might be pending because the previous #VMEXIT happened
	 * during event delivery (i.e. ctrl->exitintinfo).
	 *
	 * An event might also be pending because an exception was injected
	 * by the hypervisor (e.g. #PF during instruction emulation).
	 */
	svm_inj_intinfo(sc, vcpu);

	/* NMI event has priority over interrupts. */
	if (vm_nmi_pending(sc->vm, vcpu)) {
		if (nmi_blocked(sc, vcpu)) {
			/*
			 * Can't inject another NMI if the guest has not
			 * yet executed an "iret" after the last NMI.
			 */
			VCPU_CTR0(sc->vm, vcpu, "Cannot inject NMI due "
			    "to NMI-blocking");
		} else if (ctrl->eventinj & VMCB_EVENTINJ_VALID) {
			/*
			 * If there is already an exception/interrupt pending
			 * then defer the NMI until after that.
			 */
			VCPU_CTR1(sc->vm, vcpu, "Cannot inject NMI due to "
			    "eventinj %#lx", ctrl->eventinj);

			/*
			 * Use self-IPI to trigger a VM-exit as soon as
			 * possible after the event injection is completed.
			 *
			 * This works only if the external interrupt exiting
			 * is at a lower priority than the event injection.
			 *
			 * Although not explicitly specified in APMv2 the
			 * relative priorities were verified empirically.
			 */
			ipi_cpu(curcpu, IPI_AST);	/* XXX vmm_ipinum? */
		} else {
			vm_nmi_clear(sc->vm, vcpu);

			/* Inject NMI, vector number is not used */
			svm_eventinject(sc, vcpu, VMCB_EVENTINJ_TYPE_NMI,
			    IDT_NMI, 0, false);

			/* virtual NMI blocking is now in effect */
			enable_nmi_blocking(sc, vcpu);

			VCPU_CTR0(sc->vm, vcpu, "Injecting vNMI");
		}
	}

	extint_pending = vm_extint_pending(sc->vm, vcpu);

	if (!extint_pending) {
		/* Ask the local apic for a vector to inject */
		if (!vlapic_pending_intr(vlapic, &vector)) {
			goto done;	/* nothing to inject */
		}
		KASSERT(vector >= 16 && vector <= 255,
		    ("invalid vector %d from local APIC", vector));
	} else {
                /* Ask the legacy pic for a vector to inject */
                vatpic_pending_intr(sc->vm, &vector);
		KASSERT(vector >= 0 && vector <= 255,
		    ("invalid vector %d from local APIC", vector));
	}

	/*
	 * If the guest has disabled interrupts or is in an interrupt shadow
	 * then we cannot inject the pending interrupt.
	 */
	if ((state->rflags & PSL_I) == 0) {
		VCPU_CTR2(sc->vm, vcpu, "Cannot inject vector %d due to "
		    "rflags %#lx", vector, state->rflags);
		need_intr_window = 1;
		goto done;
	}

	if (ctrl->intr_shadow) {
		VCPU_CTR1(sc->vm, vcpu, "Cannot inject vector %d due to "
		    "interrupt shadow", vector);
		need_intr_window = 1;
		goto done;
	}

	if (ctrl->eventinj & VMCB_EVENTINJ_VALID) {
		VCPU_CTR2(sc->vm, vcpu, "Cannot inject vector %d due to "
		    "eventinj %#lx", vector, ctrl->eventinj);
		need_intr_window = 1;
		goto done;
	}

	svm_eventinject(sc, vcpu, VMCB_EVENTINJ_TYPE_INTR, vector, 0, false);

        if (!extint_pending) {
                /* Update the Local APIC ISR */
                vlapic_intr_accepted(vlapic, vector);
        } else {
                vm_extint_clear(sc->vm, vcpu);
                vatpic_intr_accepted(sc->vm, vector);
		/*
		 * Force a VM-exit as soon as the vcpu is ready to accept
		 * another interrupt. This is done because the PIC might
		 * have another vector that it wants to inject. Also, if
		 * the vlapic has a pending interrupt that was preempted
		 * by the ExtInt then it allows us to inject the APIC
		 * vector as soon as possible.
		 */
		need_intr_window = 1;
        }
done:
	if (need_intr_window) {
		/*
		 * We use V_IRQ in conjunction with the VINTR intercept to
		 * trap into the hypervisor as soon as a virtual interrupt
		 * can be delivered.
		 *
		 * Since injected events are not subject to intercept checks
		 * we need to ensure that the V_IRQ is not actually going to
		 * be delivered on VM entry. The KASSERT below enforces this.
		 */
		KASSERT((ctrl->eventinj & VMCB_EVENTINJ_VALID) != 0 ||
		    (state->rflags & PSL_I) == 0 || ctrl->intr_shadow,
		    ("Bogus intr_window_exiting: eventinj (%#lx), "
		    "intr_shadow (%u), rflags (%#lx)",
		    ctrl->eventinj, ctrl->intr_shadow, state->rflags));
		enable_intr_window_exiting(sc, vcpu);
	} else {
		disable_intr_window_exiting(sc, vcpu);
	}
}

static __inline void
restore_host_tss(void)
{
	struct system_segment_descriptor *tss_sd;

	/*
	 * The TSS descriptor was in use prior to launching the guest so it
	 * has been marked busy.
	 *
	 * 'ltr' requires the descriptor to be marked available so change the
	 * type to "64-bit available TSS".
	 */
	tss_sd = PCPU_GET(tss);
	tss_sd->sd_type = SDT_SYSTSS;
	ltr(GSEL(GPROC0_SEL, SEL_KPL));
}

static void
check_asid(struct svm_softc *sc, int vcpuid, pmap_t pmap, u_int thiscpu)
{
	struct svm_vcpu *vcpustate;
	struct vmcb_ctrl *ctrl;
	long eptgen;
	bool alloc_asid;

	KASSERT(CPU_ISSET(thiscpu, &pmap->pm_active), ("%s: nested pmap not "
	    "active on cpu %u", __func__, thiscpu));

	vcpustate = svm_get_vcpu(sc, vcpuid);
	ctrl = svm_get_vmcb_ctrl(sc, vcpuid);

	/*
	 * The TLB entries associated with the vcpu's ASID are not valid
	 * if either of the following conditions is true:
	 *
	 * 1. The vcpu's ASID generation is different than the host cpu's
	 *    ASID generation. This happens when the vcpu migrates to a new
	 *    host cpu. It can also happen when the number of vcpus executing
	 *    on a host cpu is greater than the number of ASIDs available.
	 *
	 * 2. The pmap generation number is different than the value cached in
	 *    the 'vcpustate'. This happens when the host invalidates pages
	 *    belonging to the guest.
	 *
	 *	asidgen		eptgen	      Action
	 *	mismatch	mismatch
	 *	   0		   0		(a)
	 *	   0		   1		(b1) or (b2)
	 *	   1		   0		(c)
	 *	   1		   1		(d)
	 *
	 * (a) There is no mismatch in eptgen or ASID generation and therefore
	 *     no further action is needed.
	 *
	 * (b1) If the cpu supports FlushByAsid then the vcpu's ASID is
	 *      retained and the TLB entries associated with this ASID
	 *      are flushed by VMRUN.
	 *
	 * (b2) If the cpu does not support FlushByAsid then a new ASID is
	 *      allocated.
	 *
	 * (c) A new ASID is allocated.
	 *
	 * (d) A new ASID is allocated.
	 */

	alloc_asid = false;
	eptgen = pmap->pm_eptgen;
	ctrl->tlb_ctrl = VMCB_TLB_FLUSH_NOTHING;

	if (vcpustate->asid.gen != asid[thiscpu].gen) {
		alloc_asid = true;	/* (c) and (d) */
	} else if (vcpustate->eptgen != eptgen) {
		if (flush_by_asid())
			ctrl->tlb_ctrl = VMCB_TLB_FLUSH_GUEST;	/* (b1) */
		else
			alloc_asid = true;			/* (b2) */
	} else {
		/*
		 * This is the common case (a).
		 */
		KASSERT(!alloc_asid, ("ASID allocation not necessary"));
		KASSERT(ctrl->tlb_ctrl == VMCB_TLB_FLUSH_NOTHING,
		    ("Invalid VMCB tlb_ctrl: %#x", ctrl->tlb_ctrl));
	}

	if (alloc_asid) {
		if (++asid[thiscpu].num >= nasid) {
			asid[thiscpu].num = 1;
			if (++asid[thiscpu].gen == 0)
				asid[thiscpu].gen = 1;
			/*
			 * If this cpu does not support "flush-by-asid"
			 * then flush the entire TLB on a generation
			 * bump. Subsequent ASID allocation in this
			 * generation can be done without a TLB flush.
			 */
			if (!flush_by_asid())
				ctrl->tlb_ctrl = VMCB_TLB_FLUSH_ALL;
		}
		vcpustate->asid.gen = asid[thiscpu].gen;
		vcpustate->asid.num = asid[thiscpu].num;

		ctrl->asid = vcpustate->asid.num;
		vcpu_set_dirty(sc, vcpuid, VMCB_CACHE_ASID);
		/*
		 * If this cpu supports "flush-by-asid" then the TLB
		 * was not flushed after the generation bump. The TLB
		 * is flushed selectively after every new ASID allocation.
		 */
		if (flush_by_asid())
			ctrl->tlb_ctrl = VMCB_TLB_FLUSH_GUEST;
	}
	vcpustate->eptgen = eptgen;

	KASSERT(ctrl->asid != 0, ("Guest ASID must be non-zero"));
	KASSERT(ctrl->asid == vcpustate->asid.num,
	    ("ASID mismatch: %u/%u", ctrl->asid, vcpustate->asid.num));
}

/*
 * Start vcpu with specified RIP.
 */
static int
svm_vmrun(void *arg, int vcpu, register_t rip, pmap_t pmap, 
	void *rend_cookie, void *suspended_cookie)
{
	struct svm_regctx *hctx, *gctx;
	struct svm_softc *svm_sc;
	struct svm_vcpu *vcpustate;
	struct vmcb_state *state;
	struct vmcb_ctrl *ctrl;
	struct vm_exit *vmexit;
	struct vlapic *vlapic;
	struct vm *vm;
	uint64_t vmcb_pa;
	u_int thiscpu;
	bool loop;	/* Continue vcpu execution loop. */

	loop = true;
	svm_sc = arg;
	vm = svm_sc->vm;

	vcpustate = svm_get_vcpu(svm_sc, vcpu);
	state = svm_get_vmcb_state(svm_sc, vcpu);
	ctrl = svm_get_vmcb_ctrl(svm_sc, vcpu);
	vmexit = vm_exitinfo(vm, vcpu);
	vlapic = vm_lapic(vm, vcpu);

	/*
	 * Stash 'curcpu' on the stack as 'thiscpu'.
	 *
	 * The per-cpu data area is not accessible until MSR_GSBASE is restored
	 * after the #VMEXIT. Since VMRUN is executed inside a critical section
	 * 'curcpu' and 'thiscpu' are guaranteed to identical.
	 */
	thiscpu = curcpu;

	gctx = svm_get_guest_regctx(svm_sc, vcpu);
	hctx = &host_ctx[thiscpu]; 
	vmcb_pa = svm_sc->vcpu[vcpu].vmcb_pa;

	if (vcpustate->lastcpu != thiscpu) {
		/*
		 * Force new ASID allocation by invalidating the generation.
		 */
		vcpustate->asid.gen = 0;

		/*
		 * Invalidate the VMCB state cache by marking all fields dirty.
		 */
		vcpu_set_dirty(svm_sc, vcpu, 0xffffffff);

		/*
		 * XXX
		 * Setting 'vcpustate->lastcpu' here is bit premature because
		 * we may return from this function without actually executing
		 * the VMRUN  instruction. This could happen if a rendezvous
		 * or an AST is pending on the first time through the loop.
		 *
		 * This works for now but any new side-effects of vcpu
		 * migration should take this case into account.
		 */
		vcpustate->lastcpu = thiscpu;
		vmm_stat_incr(vm, vcpu, VCPU_MIGRATIONS, 1);
	}

	/* Update Guest RIP */
	state->rip = rip;

	do {
		vmexit->inst_length = 0;

		/*
		 * Disable global interrupts to guarantee atomicity during
		 * loading of guest state. This includes not only the state
		 * loaded by the "vmrun" instruction but also software state
		 * maintained by the hypervisor: suspended and rendezvous
		 * state, NPT generation number, vlapic interrupts etc.
		 */
		disable_gintr();

		if (vcpu_suspended(suspended_cookie)) {
			enable_gintr();
			vm_exit_suspended(vm, vcpu, state->rip);
			break;
		}

		if (vcpu_rendezvous_pending(rend_cookie)) {
			enable_gintr();
			vm_exit_rendezvous(vm, vcpu, state->rip);
			break;
		}

		/* We are asked to give the cpu by scheduler. */
		if (curthread->td_flags & (TDF_ASTPENDING | TDF_NEEDRESCHED)) {
			enable_gintr();
			vm_exit_astpending(vm, vcpu, state->rip);
			break;
		}

		svm_inj_interrupts(svm_sc, vcpu, vlapic);

		/* Activate the nested pmap on 'thiscpu' */
		CPU_SET_ATOMIC_ACQ(thiscpu, &pmap->pm_active);

		/*
		 * Check the pmap generation and the ASID generation to
		 * ensure that the vcpu does not use stale TLB mappings.
		 */
		check_asid(svm_sc, vcpu, pmap, thiscpu);

		ctrl->vmcb_clean = VMCB_CACHE_DEFAULT & ~vcpustate->dirty;
		vcpustate->dirty = 0;
		VCPU_CTR1(vm, vcpu, "vmcb clean %#x", ctrl->vmcb_clean);

		/* Launch Virtual Machine. */
		VCPU_CTR1(vm, vcpu, "Resume execution at %#lx", state->rip);
		svm_launch(vmcb_pa, gctx, hctx);

		CPU_CLR_ATOMIC(thiscpu, &pmap->pm_active);

		/*
		 * Restore MSR_GSBASE to point to the pcpu data area.
		 *
		 * Note that accesses done via PCPU_GET/PCPU_SET will work
		 * only after MSR_GSBASE is restored.
		 *
		 * Also note that we don't bother restoring MSR_KGSBASE
		 * since it is not used in the kernel and will be restored
		 * when the VMRUN ioctl returns to userspace.
		 */
		wrmsr(MSR_GSBASE, (uint64_t)&__pcpu[thiscpu]);
		KASSERT(curcpu == thiscpu, ("thiscpu/curcpu (%u/%u) mismatch",
		    thiscpu, curcpu));

		/*
		 * The host GDTR and IDTR is saved by VMRUN and restored
		 * automatically on #VMEXIT. However, the host TSS needs
		 * to be restored explicitly.
		 */
		restore_host_tss();

		/* #VMEXIT disables interrupts so re-enable them here. */ 
		enable_gintr();

		/* Handle #VMEXIT and if required return to user space. */
		loop = svm_vmexit(svm_sc, vcpu, vmexit);
	} while (loop);

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
	
	VCPU_CTR0(svm_sc->vm, 0, "SVM:cleanup\n");

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
			ERR("Unknown register requested, reg=%d.\n", reg);
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

 	ERR("SVM_ERR:reg type %x is not saved in VMCB.\n", ident);
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

	/*
	 * XXX deal with CR3 and invalidate TLB entries tagged with the
	 * vcpu's ASID. This needs to be treated differently depending on
	 * whether 'running' is true/false.
	 */

 	ERR("SVM_ERR:reg type %x is not saved in VMCB.\n", ident);
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

	VCPU_CTR1(svm_sc->vm, vcpu, "SVM:set_desc: Type%d\n", type);

	seg = vmcb_seg(vmcb, type);
	if (seg == NULL) {
		ERR("SVM_ERR:Unsupported segment type%d\n", type);
		return (EINVAL);
	}

	/* Map seg_desc access to VMCB attribute format.*/
	attrib = ((desc->access & 0xF000) >> 4) | (desc->access & 0xFF);
	VCPU_CTR3(svm_sc->vm, vcpu, "SVM:[sel %d attribute 0x%x limit:0x%x]\n",
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

	VCPU_CTR1(svm_sc->vm, vcpu, "SVM:get_desc: Type%d\n", type);

	seg = vmcb_seg(svm_get_vmcb(svm_sc, vcpu), type);
	if (!seg) {
		ERR("SVM_ERR:Unsupported segment type%d\n", type);
		return (EINVAL);
	}
	
	/* Map seg_desc access to VMCB attribute format.*/
	desc->access = ((seg->attrib & 0xF00) << 4) | (seg->attrib & 0xFF);
	desc->base = seg->base;
	desc->limit = seg->limit;

	/*
	 * VT-x uses bit 16 (Unusable) to indicate a segment that has been
	 * loaded with a NULL segment selector. The 'desc->access' field is
	 * interpreted in the VT-x format by the processor-independent code.
	 *
	 * SVM uses the 'P' bit to convey the same information so convert it
	 * into the VT-x format. For more details refer to section
	 * "Segment State in the VMCB" in APMv2.
	 */
	if (type == VM_REG_GUEST_CS && type == VM_REG_GUEST_TR)
		desc->access |= 0x80;		/* CS and TS always present */

	if (!(desc->access & 0x80))
		desc->access |= 0x10000;	/* Unusable segment */

	return (0);
}

static int
svm_setcap(void *arg, int vcpu, int type, int val)
{
	struct svm_softc *sc;
	int error;

	sc = arg;
	error = 0;
	switch (type) {
	case VM_CAP_HALT_EXIT:
		svm_set_intercept(sc, vcpu, VMCB_CTRL1_INTCPT,
		    VMCB_INTCPT_HLT, val);
		break;
	case VM_CAP_PAUSE_EXIT:
		svm_set_intercept(sc, vcpu, VMCB_CTRL1_INTCPT,
		    VMCB_INTCPT_PAUSE, val);
		break;
	case VM_CAP_UNRESTRICTED_GUEST:
		/* Unrestricted guest execution cannot be disabled in SVM */
		if (val == 0)
			error = EINVAL;
		break;
	default:
		error = ENOENT;
		break;
	}
	return (error);
}

static int
svm_getcap(void *arg, int vcpu, int type, int *retval)
{
	struct svm_softc *sc;
	int error;

	sc = arg;
	error = 0;

	switch (type) {
	case VM_CAP_HALT_EXIT:
		*retval = svm_get_intercept(sc, vcpu, VMCB_CTRL1_INTCPT,
		    VMCB_INTCPT_HLT);
		break;
	case VM_CAP_PAUSE_EXIT:
		*retval = svm_get_intercept(sc, vcpu, VMCB_CTRL1_INTCPT,
		    VMCB_INTCPT_PAUSE);
		break;
	case VM_CAP_UNRESTRICTED_GUEST:
		*retval = 1;	/* unrestricted guest is always enabled */
		break;
	default:
		error = ENOENT;
		break;
	}
	return (error);
}

static struct vlapic *
svm_vlapic_init(void *arg, int vcpuid)
{
	struct svm_softc *svm_sc;
	struct vlapic *vlapic;

	svm_sc = arg;
	vlapic = malloc(sizeof(struct vlapic), M_SVM_VLAPIC, M_WAITOK | M_ZERO);
	vlapic->vm = svm_sc->vm;
	vlapic->vcpuid = vcpuid;
	vlapic->apic_page = (struct LAPIC *)&svm_sc->apic_page[vcpuid];

	vlapic_init(vlapic);
	
	return (vlapic);
}

static void
svm_vlapic_cleanup(void *arg, struct vlapic *vlapic)
{

        vlapic_cleanup(vlapic);
        free(vlapic, M_SVM_VLAPIC);
}

struct vmm_ops vmm_ops_amd = {
	svm_init,
	svm_cleanup,
	svm_restore,
	svm_vminit,
	svm_vmrun,
	svm_vmcleanup,
	svm_getreg,
	svm_setreg,
	svm_getdesc,
	svm_setdesc,
	svm_getcap,
	svm_setcap,
	svm_npt_alloc,
	svm_npt_free,
	svm_vlapic_init,
	svm_vlapic_cleanup	
};
