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
 *
 * $FreeBSD$
 */

#ifndef _SVM_SOFTC_H_
#define _SVM_SOFTC_H_

#define SVM_IO_BITMAP_SIZE	(3 * PAGE_SIZE)
#define SVM_MSR_BITMAP_SIZE	(2 * PAGE_SIZE)

/*
 * svm_vpcu contains SVM VMCB state and vcpu register state.
 */
struct svm_vcpu {
	struct vmcb	 vmcb;	  /* hardware saved vcpu context */
	struct svm_regctx swctx;  /* software saved vcpu context */
	uint64_t	 vmcb_pa; /* VMCB physical address */
	uint64_t	 loop;	  /* loop count for vcpu */
        int		 lastcpu; /* host cpu that the vcpu last ran on */
} __aligned(PAGE_SIZE);

/*
 * SVM softc, one per virtual machine.
 */
struct svm_softc {
	/*
	 * IO permission map, VMCB.ctrl.iopm_base_pa should point to this.
	 * If a bit is set, access to I/O port is intercepted.
	 */
	uint8_t iopm_bitmap[SVM_IO_BITMAP_SIZE];

	/*
	 * MSR permission bitmap, VMCB.ctrl.msrpm_base_pa should point to this.
	 * Two bits are used for each MSR with the LSB used for read access
	 * and the MSB used for write access. A value of '1' indicates that
	 * the operation is intercepted.
	 */
	uint8_t	msr_bitmap[SVM_MSR_BITMAP_SIZE];

	/* Nested Paging */
	pml4_entry_t	np_pml4[NPML4EPG];

	/* Virtual machine pointer. */
	struct vm	*vm;

	/* Guest VCPU h/w and s/w context. */
	struct svm_vcpu vcpu[VM_MAXCPU];

	uint32_t	svm_feature;	/* SVM features from CPUID.*/

	int		asid;		/* Guest Address Space Identifier */
	int 		vcpu_cnt;	/* number of VCPUs for this guest.*/
} __aligned(PAGE_SIZE);

CTASSERT((offsetof(struct svm_softc, np_pml4) & PAGE_MASK) == 0);

static __inline struct svm_vcpu *
svm_get_vcpu(struct svm_softc *sc, int vcpu)
{

	return (&(sc->vcpu[vcpu]));
}

static __inline struct vmcb *
svm_get_vmcb(struct svm_softc *sc, int vcpu)
{

	return (&(sc->vcpu[vcpu].vmcb));
}

static __inline struct vmcb_state *
svm_get_vmcb_state(struct svm_softc *sc, int vcpu)
{

	return (&(sc->vcpu[vcpu].vmcb.state));
}

static __inline struct vmcb_ctrl *
svm_get_vmcb_ctrl(struct svm_softc *sc, int vcpu)
{

	return (&(sc->vcpu[vcpu].vmcb.ctrl));
}

static __inline struct svm_regctx *
svm_get_guest_regctx(struct svm_softc *sc, int vcpu)
{

	return (&(sc->vcpu[vcpu].swctx));
}

void svm_dump_vmcb(struct svm_softc *svm_sc, int vcpu);
#endif /* _SVM_SOFTC_H_ */
