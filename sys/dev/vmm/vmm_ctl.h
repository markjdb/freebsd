/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 * Copyright (c) 2024 Mark Johnston, <markj@FreeBSD.org>
 */

#ifndef _VMM_CTL_H_
#define _VMM_CTL_H_

#include <machine/vmm.h>

#ifdef _KERNEL
struct ucred;

int	vmmdev_init(void);
int	vmmdev_cleanup(void);
int	vmm_priv_check(struct ucred *ucred);
#endif /* _KERNEL */

struct vmmctl_vmcreate {
	char		name[VM_MAX_NAMELEN];
	uint64_t	spare[16];
};

struct vmmctl_vmdestroy {
	char		name[VM_MAX_NAMELEN];
	uint64_t	spare[16];
};

#define VMMCTL_VMCREATE		_IOW('V', 1, struct vmmctl_vmcreate)
#define VMMCTL_VMDESTROY	_IOW('V', 2, struct vmmctl_vmdestroy)

#endif /* !_VMM_CTL_H_ */
