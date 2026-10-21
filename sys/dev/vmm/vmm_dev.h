/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * Copyright (C) 2015 Mihai Carabas <mihai.carabas@gmail.com>
 * All rights reserved.
 */

#ifndef	_DEV_VMM_DEV_H_
#define	_DEV_VMM_DEV_H_

#include <sys/types.h>
#include <sys/ioccom.h>

#include <machine/vmm_dev.h>

#include <dev/vmm/vmm_param.h>

#ifdef _KERNEL
struct thread;
struct vm;
struct vcpu;

int	vmm_modinit(void);
int	vmm_modcleanup(void);

int	vmmdev_machdep_ioctl(struct vm *vm, struct vcpu *vcpu, u_long cmd,
	    caddr_t data, int fflag, struct thread *td);

/*
 * Entry in an ioctl handler table.  A number of generic ioctls are defined,
 * plus a table of machine-dependent ioctls.  The flags indicate the
 * required preconditions for a given ioctl.
 *
 * Some ioctls encode a vcpuid as the first member of their ioctl structure.
 * These ioctls must specify one of the following flags:
 * - ALLOC_VCPU: create the vCPU if it does not already exist
 * - LOCK_ONE_VCPU: create the vCPU if it does not already exist
 *   and lock the vCPU for the duration of the ioctl
 * - MAYBE_ALLOC_VCPU: if the vcpuid is -1, do nothing, otherwise
 *   create the vCPU if it does not already exist
 * - REINIT: acquire the per-VM reinit lock, which blocks all other ioctls
 */
struct vmmdev_ioctl {
#define	VMMDEV_IOCTL_SLOCK_MEMSEGS	0x0001
#define	VMMDEV_IOCTL_XLOCK_MEMSEGS	0x0002
#define	VMMDEV_IOCTL_LOCK_ONE_VCPU	0x0004
#define	VMMDEV_IOCTL_LOCK_ALL_VCPUS	0x0008
#define	VMMDEV_IOCTL_ALLOC_VCPU		0x0010
#define	VMMDEV_IOCTL_MAYBE_ALLOC_VCPU	0x0020
#define	VMMDEV_IOCTL_PPT		0x0040
#define	VMMDEV_IOCTL_REINIT		0x0080
#define	VMMDEV_IOCTL_VALID		0x0100
	unsigned short flags;
};

#define	VMMDEV_IOCTL(prefix, f)		\
	[IOCNUM_##prefix] = { .flags = (f) | VMMDEV_IOCTL_VALID }

extern const struct vmmdev_ioctl vmmdev_machdep_ioctls[];
extern const size_t vmmdev_machdep_ioctl_count;

/*
 * Upper limit on vm_maxcpu.  Limited by use of uint16_t types for CPU counts as
 * well as range of vpid values for VT-x on amd64 and by the capacity of
 * cpuset_t masks.  The call to new_unrhdr() in vpid_init() in vmx.c requires
 * 'vm_maxcpu + 1 <= 0xffff', hence the '- 1' below.
 */
#define	VM_MAXCPU	MIN(0xffff - 1, CPU_SETSIZE)

/* Maximum number of vCPUs in a single VM. */
extern u_int vm_maxcpu;

#endif /* _KERNEL */

#define VMMCTL_CREATE_DESTROY_ON_CLOSE 0x1
#define VMMCTL_FLAGS_MASK	       (VMMCTL_CREATE_DESTROY_ON_CLOSE)

struct vmmctl_vm_create {
	char name[VM_MAX_NAMELEN + 1];
	uint32_t flags;
	int reserved[15];
};

struct vmmctl_vm_destroy {
	char name[VM_MAX_NAMELEN + 1];
	int reserved[16];
};

#define	VMMCTL_VM_CREATE	_IOWR('V', 0, struct vmmctl_vm_create)
#define	VMMCTL_VM_DESTROY	_IOWR('V', 1, struct vmmctl_vm_destroy)

#endif /* _DEV_VMM_DEV_H_ */
