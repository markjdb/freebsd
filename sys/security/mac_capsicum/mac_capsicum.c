/*
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * This software was developed by Mark Johnston under sponsorship from the
 * FreeBSD Foundation.
 */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/namei.h>
#include <sys/osd.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/vnode.h>

#include <security/mac/mac_policy.h>
#include <security/mac_capsicum/mac_capsicum.h>

static MALLOC_DEFINE(M_MAC_CAPSICUM, "mac_capsicum", "MAC/capsicum");

static bool mac_capsicum_debug;
SYSCTL_NODE(_security_mac, OID_AUTO, capsicum, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "MAC/capsicum policy controls");
SYSCTL_BOOL(_security_mac_capsicum, OID_AUTO, debug, CTLFLAG_RWTUN,
    &mac_capsicum_debug, 0, "Enable debugging output for MAC/capsicum");

#define	printf(...)	do { if (mac_capsicum_debug) printf(__VA_ARGS__); } while (0)

static int mac_capsicum_label_slot;
static unsigned int mac_capsicum_osd_thread_slot;

struct mac_capsicum_policy {
	bool committed;
};

struct mac_capsicum_vnode_policy_head {
	SLIST_HEAD(, mac_capsicum_vnode_policy) head;
};

struct mac_capsicum_vnode_policy {
	struct mac_capsicum_policy *policy;
	struct filecaps fcaps;
	char name[NAME_MAX + 1];
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
	struct mac_capsicum_policy *policy;

	policy = (void *)mac_label_get(label, mac_capsicum_label_slot);
	if (policy != NULL) {
		free(policy, M_MAC_CAPSICUM);
		mac_label_set(label, mac_capsicum_label_slot, 0);
	}
}

struct mac_capsicum_thread_data {
	struct mac_capsicum_vnode_policy *last;
};

static int
mac_capsicum_cap_check_lookup(struct nameidata *ndp)
{
	struct mac_capsicum_thread_data *data;
	struct thread *td;

	td = curthread;
	if (mac_label_get(td->td_proc->p_label, mac_capsicum_label_slot) == 0)
		return (ECAPMODE);

	data = osd_thread_get(td, mac_capsicum_osd_thread_slot);
	if (data != NULL)
		data->last = NULL;
	else {
		data = malloc(sizeof(*data), M_MAC_CAPSICUM, M_WAITOK);
		data->last = NULL;

		if (osd_thread_set(td, mac_capsicum_osd_thread_slot, data) !=
		    0) {
			void **rsv;

			rsv = osd_reserve(mac_capsicum_osd_thread_slot);
			(void)osd_thread_set_reserved(td,
			    mac_capsicum_osd_thread_slot, rsv, data);
		}
	}

	return (0);
}

static int
mac_capsicum_cap_check_syscall(struct syscall_args *sa)
{
	if (SV_CURPROC_ABI() == SV_ABI_FREEBSD) {
		switch (sa->code) {
		case SYS_open:
		case SYS_fchdir:
			return (0);
		}
	}
	return (ECAPMODE);
}

static int
mac_capsicum_cap_check_sysctl(struct sysctl_oid *oidp, void *arg1,
    intmax_t arg2, struct sysctl_req *req)
{
	return (ECAPMODE);
}

static int
mac_capsicum_vnode_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp)
{
	struct mac_capsicum_vnode_policy_head *head;
	struct mac_capsicum_vnode_policy *vnpol;
	struct mac_capsicum_thread_data *data;
	struct mac_capsicum_policy *policy;
	struct nameidata *ndp;

	ndp = vfs_lookup_nameidata(cnp);
	if (ndp->ni_dirfd != AT_FDCWD)
		return (0);

	policy = (void *)mac_label_get(curproc->p_label,
	    mac_capsicum_label_slot);
	if (policy == NULL || !policy->committed)
		return (0);

	data = osd_thread_get(curthread, mac_capsicum_osd_thread_slot);

	head = (void *)mac_label_get(dvplabel, mac_capsicum_label_slot);
	if (head != NULL) {
		SLIST_FOREACH(vnpol, &head->head, link) {
			if (vnpol->policy != policy)
				continue;
			if (vnpol->name[0] == '\0' ||
			    ((cnp->cn_flags & ISLASTCN) != 0 &&
			    strncmp(vnpol->name, cnp->cn_nameptr,
			    cnp->cn_namelen) == 0)) {
				/* XXX-MJ leaking ioctl buffer? */
				memcpy(&ndp->ni_filecaps, &vnpol->fcaps,
				    sizeof(ndp->ni_filecaps));
				data->last = vnpol;
				break;
			}
		}
	}
	if ((cnp->cn_flags & ISLASTCN) == 0)
		return (0);

	/* XXX-MJ what if last cn is dotdot? */
	if (data->last == NULL)
		return (ECAPMODE);

	return (0);
}

static const struct mac_policy_ops mac_capsicum_ops = {
	.mpo_vnode_init_label = mac_capsicum_vnode_init_label,
	.mpo_vnode_destroy_label = mac_capsicum_vnode_destroy_label,

	.mpo_proc_init_label = mac_capsicum_proc_init_label,
	.mpo_proc_destroy_label = mac_capsicum_proc_destroy_label,

	.mpo_cap_check_lookup = mac_capsicum_cap_check_lookup,
	.mpo_cap_check_syscall = mac_capsicum_cap_check_syscall,
	.mpo_cap_check_sysctl = mac_capsicum_cap_check_sysctl,

	.mpo_vnode_check_lookup = mac_capsicum_vnode_check_lookup,
};
MAC_POLICY_SET(&mac_capsicum_ops, mac_capsicum, "MAC/capsicum",
    MPC_LOADTIME_FLAG_NOTLATE, &mac_capsicum_label_slot);

static int
mac_capsicum_devopen(struct cdev *cdev, int flags, int fmt, struct thread *td)
{
	struct mac_capsicum_policy *policy;
	struct proc *p;

	p = td->td_proc;

	policy = malloc(sizeof(*policy), M_MAC_CAPSICUM, M_WAITOK | M_ZERO);
	policy->committed = false;

	PROC_LOCK(p);
	if (mac_label_get(p->p_label, mac_capsicum_label_slot) != 0) {
		PROC_UNLOCK(p);
		free(policy, M_MAC_CAPSICUM);
		return (EBUSY);
	}
	mac_label_set(p->p_label, mac_capsicum_label_slot, (intptr_t)policy);
	PROC_UNLOCK(p);
	return (0);
}

static int
mac_capsicum_devioctl_vnode(struct thread *td,
    struct mac_capsicum_vnode_ioc *ioc)
{
	struct filecaps fcaps;
	struct mac_capsicum_vnode_policy_head *head;
	struct mac_capsicum_vnode_policy *vnpol;
	struct vnode *vp;
	int error;

	if (strnlen(ioc->name, sizeof(ioc->name)) >= sizeof(ioc->name))
		return (EINVAL);

	error = fgetvp_rights(td, ioc->fd, &cap_no_rights, &fcaps, &vp);
	if (error != 0)
		return (error);
	if (vp->v_type != VDIR) {
		vrele(vp);
		return (ENOTDIR);
	}

	head = (void *)mac_label_get(vp->v_label, mac_capsicum_label_slot);
	if (head == NULL) {
		head = malloc(sizeof(*head), M_MAC_CAPSICUM, M_WAITOK);
		SLIST_INIT(&head->head);
		mac_label_set(vp->v_label, mac_capsicum_label_slot,
		    (intptr_t)head);
	}

	/* XXX-MJ how to handle the vnode ref? do we just want to hold? */
	vnpol = malloc(sizeof(*vnpol), M_MAC_CAPSICUM, M_WAITOK);
	vnpol->fcaps = fcaps;
	strlcpy(vnpol->name, ioc->name, sizeof(vnpol->name));
	vnpol->policy = (void *)mac_label_get(td->td_proc->p_label,
	    mac_capsicum_label_slot);

	(void)vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	SLIST_INSERT_HEAD(&head->head, vnpol, link);
	VOP_UNLOCK(vp);

	return (0);
}

static int
mac_capsicum_devioctl_commit(struct thread *td)
{
	struct mac_capsicum_policy *policy;

	policy = (void *)mac_label_get(td->td_proc->p_label,
	    mac_capsicum_label_slot);
	if (policy == NULL)
		return (EINVAL);
	if (policy->committed)
		return (EINVAL);

	policy->committed = true;
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
	case MAC_CAPSICUM_IOC_COMMIT:
		return (mac_capsicum_devioctl_commit(td));
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
mac_capsicum_dealloc_thread_osd(void *osd)
{
	free(osd, M_MAC_CAPSICUM);
}

static void
mac_capsicum_sysinit(void *arg __unused)
{
	mac_capsicum_cdev = make_dev(&mac_capsicum_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "mac_capsicum");
	mac_capsicum_osd_thread_slot =
	    osd_thread_register(mac_capsicum_dealloc_thread_osd);
}
SYSINIT(mac_capsicum_sysinit, SI_SUB_DRIVERS, SI_ORDER_ANY,
    mac_capsicum_sysinit, NULL);

static void
mac_capsicum_sysuninit(void *arg __unused)
{
	osd_thread_deregister(mac_capsicum_osd_thread_slot);
	destroy_dev(mac_capsicum_cdev);
}
SYSUNINIT(mac_capsicum_sysuninit, SI_SUB_DRIVERS, SI_ORDER_ANY,
    mac_capsicum_sysuninit, NULL);

MODULE_VERSION(mac_capsicum, 1);
