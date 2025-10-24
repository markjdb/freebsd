/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 */

#ifndef _DEV_VMM_VCPU_H_
#define	_DEV_VMM_VCPU_H_

#ifdef _KERNEL

#include <sys/_mutex.h>

#include <machine/vmm_vcpu.h>

enum vcpu_state {
	VCPU_IDLE,
	VCPU_FROZEN,
	VCPU_RUNNING,
	VCPU_SLEEPING,
};

/*
 * Initialization:
 * (a) allocated when vcpu is created
 * (i) initialized when vcpu is created and when it is reinitialized
 * (o) initialized the first time the vcpu is created
 * (x) initialized before use
 */
struct vcpu {
	struct mtx 	mtx;		/* (o) protects 'state' and 'hostcpu' */
	enum vcpu_state	state;		/* (o) vcpu state */
	int		vcpuid;		/* (o) */
	int		hostcpu;	/* (o) vcpu's host cpu */
	int		reqidle;	/* (i) request vcpu to idle */
	struct vm	*vm;		/* (o) */
	void		*cookie;	/* (i) cpu-specific data */
	void		*stats;		/* (a,i) statistics */

	VMM_VCPU_MD_FIELDS;
};

#define	vcpu_lock_init(v)	mtx_init(&((v)->mtx), "vcpu lock", 0, MTX_SPIN)
#define	vcpu_lock_destroy(v)	mtx_destroy(&((v)->mtx))
#define	vcpu_lock(v)		mtx_lock_spin(&((v)->mtx))
#define	vcpu_unlock(v)		mtx_unlock_spin(&((v)->mtx))
#define	vcpu_assert_locked(v)	mtx_assert(&((v)->mtx), MA_OWNED)

int vcpu_set_state(struct vcpu *vcpu, enum vcpu_state state, bool from_idle);
#ifdef __amd64__
int vcpu_set_state_all(struct vm *vm, enum vcpu_state state);
#endif
enum vcpu_state vcpu_get_state(struct vcpu *vcpu, int *hostcpu);

static int __inline
vcpu_is_running(struct vcpu *vcpu, int *hostcpu)
{
	return (vcpu_get_state(vcpu, hostcpu) == VCPU_RUNNING);
}

#ifdef _SYS_PROC_H_
static int __inline
vcpu_should_yield(struct vcpu *vcpu)
{
	struct thread *td;

	td = curthread;
	return (td->td_ast != 0 || td->td_owepreempt != 0);
}
#endif

#endif /* _KERNEL */

#endif /* !_DEV_VMM_VCPU_H_ */
