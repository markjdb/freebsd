/*
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * This software was developed by Mark Johnston under sponsorship from the
 * FreeBSD Foundation.
 */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sysent.h>

#include <security/mac/mac_policy.h>
#include <security/mac_capsicum/mac_capsicum.h>

static MALLOC_DEFINE(M_MAC_CAPSICUM, "mac_capsicum", "MAC/capsicum");

static int mac_capsicum_label_slot;

struct mac_capsicum_policy {
};

struct mac_capsicum_policy_ref {
	struct mac_capsicum_policy *policy;
};

struct mac_capsicium_vnode_policy_head {
	SLIST_HEAD(, mac_capsicum_vnode_policy) head;
};

struct mac_capsicum_vnode_policy {
	struct filecaps fcaps;
	SLIST_ENTRY(mac_capsicum_vnode_policy) link;
};

static void
mac_capsicum_vnode_init_label(struct label *label __unused)
{
	/* We only consume our slot when a policy is loaded. */
}

static void
mac_capsicum_vnode_destroy_label(struct label *label)
{
}

static void
mac_capsicum_proc_init_label(struct label *label __unused)
{
	/* We only consume our slot when a policy is loaded. */
}

static void
mac_capsicum_proc_destroy_label(struct label *label)
{
	struct mac_capsicum_policy_ref *ref;

	ref = (void *)mac_label_get(label, mac_capsicum_label_slot);
	if (ref != NULL) {
		free(ref, M_MAC_CAPSICUM);
		mac_label_set(label, mac_capsicum_label_slot, 0);
	}
}

static int
mac_capsicum_check_syscall(struct syscall_args *sa)
{
	return (ECAPMODE);
}

static int
mac_capsicum_check_sysctl(struct sysctl_oid *oidp, void *arg1, intmax_t arg2,
    struct sysctl_req *req)
{
	return (ECAPMODE);
}

static int
mac_capsicum_vnode_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp)
{
#if 0
	struct mac_capsicum_policy_ref *ref;

	ref = (void *)mac_label_get(curproc->p_label, mac_capsicum_label_slot);
	if (ref == NULL)
		return (0);
#endif
}

static const struct mac_policy_ops mac_capsicum_ops = {
	.mpo_vnode_init_label = mac_capsicum_vnode_init_label,
	.mpo_vnode_destroy_label = mac_capsicum_vnode_destroy_label,

	.mpo_proc_init_label = mac_capsicum_proc_init_label,
	.mpo_proc_destroy_label = mac_capsicum_proc_destroy_label,

	.mpo_cap_check_syscall = mac_capsicum_check_syscall,
	.mpo_cap_check_sysctl = mac_capsicum_check_sysctl,

	.mpo_vnode_check_lookup = mac_capsicum_vnode_check_lookup,
};
MAC_POLICY_SET(&mac_capsicum_ops, mac_capsicum, "MAC/capsicum",
    0, &mac_capsicum_label_slot);

static int
mac_capsicum_devopen(struct cdev *cdev, int flags, int fmt, struct thread *td)
{
	struct mac_capsicum_policy_ref *ref;
	struct proc *p;

	/* XXX-MJ need some locking here */
	p = td->td_proc;
	if (p->p_label == NULL)
		return (ENODEV);
	if (mac_label_get(p->p_label, mac_capsicum_label_slot) != 0)
		return (EBUSY);

	ref = malloc(sizeof(*ref), M_MAC_CAPSICUM, M_WAITOK | M_ZERO);
	mac_label_set(p->p_label, mac_capsicum_label_slot, (intptr_t)ref);
	return (0);
}

static int
mac_capsicum_devioctl_vnode(struct thread *td,
    struct mac_capsicum_vnode_ioc *ioc)
{
	struct filecaps fcaps;
	struct vnode *vp
	int error;

	error = fgetvp_rights(td, ioc->fd, &cap_no_rights, &fcaps, &vp);
	if (error != 0)
		return (error);

	vrele(vp);
	return (0);
}

static int
mac_capsicum_devioctl(struct cdev *cdev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	switch (cmd) {
	case MAC_CAPSICUM_IOC_VNODE:
		return (mac_capsicum_devioctl_vnode(td,
		    (struct mac_capsicum_vnode_ioc *)data));
	default:
		return (ENOTTY);
	}
}

static struct cdev *mac_capsicum_cdev;
static struct cdevsw mac_capsicum_cdevsw = {
	.d_name = "mac_capsicum",
	.d_version = D_VERSION,
	.d_open = mac_capsicum_devopen,
	.d_ioctl = mac_capsicum_devioctl,
};

static void
mac_capsicum_sysinit(void *arg __unused)
{
	mac_capsicum_cdev = make_dev(&mac_capsicum_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "mac_capsicum");
}
SYSINIT(mac_capsicum_sysinit, SI_SUB_DRIVERS, SI_ORDER_ANY,
    mac_capsicum_sysinit, NULL);

static void
mac_capsicum_sysuninit(void *arg __unused)
{
	destroy_dev(mac_capsicum_cdev);
}
SYSUNINIT(mac_capsicum_sysuninit, SI_SUB_DRIVERS, SI_ORDER_ANY,
    mac_capsicum_sysuninit, NULL);

MODULE_VERSION(mac_capsicum, 1);
