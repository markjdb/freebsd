/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 */

#ifndef _VMM_VM_H_
#define	_VMM_VM_H_

#ifdef _KERNEL

#define	VMM_VM_MD_FIELDS						\
	cpuset_t	startup_cpus;	/* (i) [r] waiting for startup */ \
	void		*iommu;		/* (x) iommu-specific data */	\
	struct vioapic	*vioapic;	/* (i) virtual ioapic */	\
	struct vatpic	*vatpic;	/* (i) virtual atpic */		\
	struct vatpit	*vatpit;	/* (i) virtual atpit */		\
	struct vpmtmr	*vpmtmr;	/* (i) virtual ACPI PM timer */	\
	struct vrtc	*vrtc;		/* (o) virtual RTC */		\
	struct vhpet	*vhpet		/* (i) virtual HPET */

#endif /* _KERNEL */

#endif /* !_VMM_VM_H_ */
