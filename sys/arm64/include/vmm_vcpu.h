/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (C) 2015 Mihai Carabas <mihai.carabas@gmail.com>
 * All rights reserved.
 */

#ifndef _VMM_VCPU_H_
#define	_VMM_VCPU_H_

#ifdef _KERNEL

#define	VMM_VCPU_MD_FIELDS						\
	struct vm_exit	exitinfo;					\
	uint64_t	nextpc;		/* (x) next instruction to execute */ \
	struct vfpstate	*guestfpu	/* (a,i) guest fpu state */

#endif /* _KERNEL */

#endif /* !_VMM_VCPU_H_ */
