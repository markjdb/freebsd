/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2015 Mihai Carabas <mihai.carabas@gmail.com>
 * Copyright (c) 2024 Ruslan Bukin <br@bsdpad.com>
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) under Innovate
 * UK project 105694, "Digital Security by Design (DSbD) Technology Platform
 * Prototype".
 */

#ifndef _VMM_VCPU_H_
#define	_VMM_VCPU_H_

#ifdef _KERNEL

#define	VMM_VCPU_MD_FIELDS						\
	struct vm_exit	exitinfo;					\
	uint64_t	nextpc;		/* (x) next instruction to execute */ \
	struct fpreg	*guestfpu	/* (a,i) guest fpu state */

#endif /* _KERNEL */

#endif /* !_VMM_VCPU_H_ */
