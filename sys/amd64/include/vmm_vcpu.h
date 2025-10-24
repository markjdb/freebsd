/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 */

#ifndef _VMM_VCPU_H_
#define	_VMM_VCPU_H_

#ifdef _KERNEL

#define	VMM_VCPU_MD_FIELDS						\
	struct vlapic	*vlapic;	/* (i) APIC device model */	\
	enum x2apic_state x2apic_state;	/* (i) APIC mode */		\
	uint64_t	exitintinfo;	/* (i) events pending at VM exit */ \
	int		nmi_pending;	/* (i) NMI pending */		\
	int		extint_pending;	/* (i) INTR pending */		\
	int		exception_pending; /* (i) exception pending */	\
	int		exc_vector;	/* (x) exception collateral */	\
	int		exc_errcode_valid;				\
	uint32_t	exc_errcode;					\
	struct savefpu	*guestfpu;	/* (a,i) guest fpu state */	\
	uint64_t	guest_xcr0;	/* (i) guest %xcr0 register */	\
	struct vm_exit	exitinfo;	/* (x) exit reason and collateral */ \
	cpuset_t	exitinfo_cpuset; /* (x) storage for vmexit handlers */ \
	uint64_t	nextrip;	/* (x) next instruction to execute */ \
	uint64_t	tsc_offset	/* (o) TSC offsetting */

#endif /* _KERNEL */

#endif /* !_VMM_VCPU_H_ */
