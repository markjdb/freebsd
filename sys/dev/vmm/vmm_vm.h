/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 */

#ifndef _DEV_VMM_VM_H_
#define	_DEV_VMM_VM_H_

#ifdef _KERNEL

#include <machine/vmm_vm.h>

struct vcpu;

typedef void (*vm_rendezvous_func_t)(struct vcpu *vcpu, void *arg);

/*
 * Initialization:
 * (o) initialized the first time the VM is created
 * (i) initialized when VM is created and when it is reinitialized
 * (x) initialized before use
 *
 * Locking:
 * [m] mem_segs_lock
 * [r] rendezvous_mtx
 * [v] reads require one frozen vcpu, writes require freezing all vcpus
 */
struct vm {
	void		*cookie;		/* (i) cpu-specific data */
	struct vcpu	**vcpu;			/* (o) guest vcpus */
	struct vm_mem	mem;			/* (i) [m+v] guest memory */

	char		name[VM_MAX_NAMELEN+1];	/* (o) virtual machine name */
	struct sx	vcpus_init_lock;	/* (o) */

	bool		dying;			/* (o) is dying */
	int		suspend;		/* (i) stop VM execution */

	volatile cpuset_t active_cpus;		/* (i) active vcpus */
	volatile cpuset_t debug_cpus;		/* (i) vcpus stopped for debug */
	volatile cpuset_t suspended_cpus; 	/* (i) suspended vcpus */
	volatile cpuset_t halted_cpus;		/* (x) cpus in a hard halt */

	cpuset_t	rendezvous_req_cpus;	/* (x) [r] rendezvous requested */
	cpuset_t	rendezvous_done_cpus;	/* (x) [r] rendezvous finished */
	void		*rendezvous_arg;	/* (x) [r] rendezvous func/arg */
	vm_rendezvous_func_t rendezvous_func;
	struct mtx	rendezvous_mtx;		/* (o) rendezvous lock */

	uint16_t	sockets;		/* (o) num of sockets */
	uint16_t	cores;			/* (o) num of cores/socket */
	uint16_t	threads;		/* (o) num of threads/core */
	uint16_t	maxcpus;		/* (o) max pluggable cpus */

	VMM_VM_MD_FIELDS;
};

#endif /* _KERNEL */

#endif /* !_DEV_VMM_VM_H_ */
