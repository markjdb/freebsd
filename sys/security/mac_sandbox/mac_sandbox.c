/*
 * Copyright (c) 2026 Mark Johnston <markj@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/namei.h>
#include <sys/osd.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/rmlock.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/vnode.h>

#include <security/mac/mac_internal.h>
#include <security/mac/mac_policy.h>
#include <security/mac_sandbox/mac_sandbox.h>

/* XXX-MJ want limits on number of policy objects */

static MALLOC_DEFINE(M_MAC_SANDBOX, "mac_sandbox", "MAC/sandbox");

static bool mac_sandbox_debug = 1;
SYSCTL_NODE(_security_mac, OID_AUTO, sandbox, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "MAC/sandbox policy controls");
SYSCTL_BOOL(_security_mac_sandbox, OID_AUTO, debug, CTLFLAG_RWTUN,
    &mac_sandbox_debug, 0, "Enable debugging output for MAC/sandbox");

#define	printf(...)	do { if (mac_sandbox_debug) printf(__VA_ARGS__); } while (0)

static int mac_sandbox_label_slot;
static unsigned int mac_sandbox_osd_thread_slot;

struct mac_sandbox_vnode_policy_head {
	/* XXX-MJ want some way to deduplicate vnode policies */
	LIST_HEAD(, mac_sandbox_vnode_policy) head;
};

struct mac_sandbox_vnode_policy {
	struct mac_sandbox_policy *policy;
	struct filecaps fcaps;
	char name[NAME_MAX + 1];
	struct vnode *vp;
	SLIST_ENTRY(mac_sandbox_vnode_policy) plink;
	LIST_ENTRY(mac_sandbox_vnode_policy) vnlink;
};

struct mac_sandbox_sysctl_policy {
	int oid[CTL_MAXNAME];
	int oidlen;
	int flags;
	SLIST_ENTRY(mac_sandbox_sysctl_policy) link;
};

struct mac_sandbox_policy {
	struct rmlock lock;
	/* XXX-MJ should be rbtree */
	SLIST_HEAD(, mac_sandbox_sysctl_policy) sysctls;
	SLIST_HEAD(, mac_sandbox_vnode_policy) vnodes;
	bool committed;
};

static void
mac_sandbox_vnode_init_label(struct label *label __unused)
{
	/* We only consume our slot when a policy is loaded. */
}

static void
mac_sandbox_vnode_destroy_label(struct label *label)
{
}

static void
mac_sandbox_proc_init_label(struct label *label __unused)
{
	/* We only consume our slot when a policy is loaded. */
}

static void
mac_sandbox_proc_destroy_label(struct label *label)
{
	struct mac_sandbox_sysctl_policy *sysctlpol;
	struct mac_sandbox_vnode_policy *vnpol;
	struct mac_sandbox_policy *policy;

	policy = (void *)mac_label_get(label, mac_sandbox_label_slot);
	if (policy == NULL)
		return;

	while ((sysctlpol = SLIST_FIRST(&policy->sysctls)) != NULL) {
		SLIST_REMOVE_HEAD(&policy->sysctls, link);
		free(sysctlpol, M_MAC_SANDBOX);
	}

	while ((vnpol = SLIST_FIRST(&policy->vnodes)) != NULL) {
		struct vnode *vp;

		vp = vnpol->vp;
		(void)vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
		LIST_REMOVE(vnpol, vnlink);
		vput(vnpol->vp);

		SLIST_REMOVE_HEAD(&policy->vnodes, plink);
		free(vnpol, M_MAC_SANDBOX);
	}

	free(policy, M_MAC_SANDBOX);
}

struct mac_sandbox_thread_data {
	struct mac_sandbox_vnode_policy *last;
};

static int
mac_sandbox_capsicum_check_bind(struct sockaddr *sa)
{
	return (ECAPMODE);
}

static int
mac_sandbox_capsicum_check_connect(struct sockaddr *sa)
{
	return (ECAPMODE);
}

static struct mac_sandbox_vnode_policy *
mac_sandbox_vnode_find_policy(struct mac_sandbox_policy *policy,
    struct vnode *vp, const char *name)
{
	struct mac_sandbox_vnode_policy *vnpol;
	struct mac_sandbox_vnode_policy_head *head;

	head = (void *)mac_label_get(vp->v_label, mac_sandbox_label_slot);
	if (head == NULL)
		return (NULL);

	/* XXX-MJ locking */
	/* XXX-MJ what if there are multiple policies? */
	LIST_FOREACH(vnpol, &head->head, vnlink) {
		if (vnpol->policy == policy &&
		    (vnpol->name[0] == '\0' ||
		    strcmp(vnpol->name, name) == 0))
			return (vnpol);
	}
	return (NULL);
}

static int
mac_sandbox_vnode_find_origin(struct mac_sandbox_policy *policy,
    struct vnode *vp, struct mac_sandbox_vnode_policy **vnpolp)
{
	struct mac_sandbox_vnode_policy *vnpol;
	char buf[NAME_MAX + 1];
	size_t buflen;

	buflen = sizeof(buf) - 1;
	buf[buflen] = '\0';
	for (;;) {
		int error;

		printf("%s:%d '%s'\n", __func__, __LINE__, &buf[buflen]);

		vnpol = mac_sandbox_vnode_find_policy(policy, vp, &buf[buflen]);
		if (vnpol != NULL) {
			*vnpolp = vnpol;
			return (0);
		}

		printf("%s:%d\n", __func__, __LINE__);

		vrefact(vp);
		error = vn_vptocnp(&vp, buf, &buflen);
		if (error != 0)
			return (error);
	}

	return (0);
}

/*
 * Handle an AT_FDCWD lookup.
 */
static int
mac_sandbox_capsicum_check_lookup(struct nameidata *ndp)
{
	struct mac_sandbox_policy *policy;
	struct mac_sandbox_thread_data *data;
	struct thread *td;
	int error;

	td = curthread;
	policy = (void *)mac_label_get(td->td_proc->p_label,
	    mac_sandbox_label_slot);
	if (policy == NULL || __predict_false(!policy->committed))
		return (ECAPMODE);

	printf("%s:%d %s\n", __func__, __LINE__, ndp->ni_cnd.cn_pnbuf);
	data = osd_thread_get(td, mac_sandbox_osd_thread_slot);
	if (data != NULL)
		data->last = NULL;
	else {
		data = malloc(sizeof(*data), M_MAC_SANDBOX, M_WAITOK);
		data->last = NULL;

		if (osd_thread_set(td, mac_sandbox_osd_thread_slot, data) !=
		    0) {
			void **rsv;

			rsv = osd_reserve(mac_sandbox_osd_thread_slot);
			(void)osd_thread_set_reserved(td,
			    mac_sandbox_osd_thread_slot, rsv, data);
		}
	}

	if ((ndp->ni_cnd.cn_flags & EMPTYPATH) != 0)
		panic("EMPTYPATH is not handled");
	if (ndp->ni_startdir != NULL)
		panic("ni_startdir is not handled");
	if (ndp->ni_cnd.cn_pnbuf[0] != '/') {
		struct mac_sandbox_vnode_policy *vnpol;
		struct vnode *vp;
		struct pwd *pwd;

		pwd = pwd_hold(curthread);
		vp = pwd->pwd_cdir;
		error = mac_sandbox_vnode_find_origin(policy, vp, &vnpol); 
		pwd_drop(pwd);
		if (error != 0)
			return (error);

		if (vnpol != NULL) {
			data->last = vnpol;
			memcpy(&ndp->ni_filecaps, &vnpol->fcaps,
			    sizeof(ndp->ni_filecaps));
		}
		
		/*
		 * XXX-MJ this is hacky, but we want DOTDOT so that the lookup
		 * is serialized with renames
		 */
		ndp->ni_lcf |= NI_LCF_CAP_DOTDOT;
	}

	return (0);
}

static int
mac_sandbox_capsicum_check_sendmsg(struct msghdr *msg)
{
	return (ECAPMODE);
}

static int
mac_sandbox_capsicum_check_syscall(struct syscall_args *sa)
{
	struct proc *p;

	p = curproc;
	if (mac_label_get(p->p_label, mac_sandbox_label_slot) == 0)
		return (ECAPMODE);
	if (SV_PROC_ABI(p) == SV_ABI_FREEBSD) {
		switch (sa->code) {
		case SYS_bind:
		case SYS_connect:
		case SYS_open:
		case SYS_fchdir:
			/* Let AT_FDCWD checks handle it. */
			return (0);
		}
	}
	return (ECAPMODE);
}

/* Note, this is executed under the global sysctl read lock. */
static int
mac_sandbox_capsicum_check_sysctl(struct sysctl_oid *oidp, void *arg1,
    intmax_t arg2, struct sysctl_req *req)
{
	struct mac_sandbox_policy *policy;
	struct mac_sandbox_sysctl_policy *sysctlpol;
	struct proc *p;
	struct rm_priotracker tracker;

	p = curproc;
	policy = (void *)mac_label_get(p->p_label, mac_sandbox_label_slot);
	if (policy == NULL || __predict_false(!policy->committed))
		return (0);

	rm_rlock(&policy->lock, &tracker);
	SLIST_FOREACH(sysctlpol, &policy->sysctls, link) {
		if ((size_t)arg2 < sysctlpol->oidlen)
			continue;
		if (memcmp(arg1, sysctlpol->oid,
		    sysctlpol->oidlen * sizeof(int)) == 0)
			break;

		if (req->oldptr != NULL &&
		    (sysctlpol->flags & MAC_SANDBOX_F_SYSCTL_RD) == 0)
			continue;
		if (req->newptr != NULL &&
		    (sysctlpol->flags & MAC_SANDBOX_F_SYSCTL_WR) == 0)
			continue;
	}
	rm_runlock(&policy->lock, &tracker);
	if (sysctlpol != NULL)
		return (0);
	return (ECAPMODE);
}

static int
mac_sandbox_vnode_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp)
{
	struct mac_sandbox_vnode_policy_head *head;
	struct mac_sandbox_vnode_policy *vnpol;
	struct mac_sandbox_thread_data *data;
	struct mac_sandbox_policy *policy;
	struct nameidata *ndp;
	struct proc *p;

	ASSERT_VOP_LOCKED(dvp, __func__);

	ndp = vfs_lookup_nameidata(cnp);
	if (ndp->ni_dirfd != AT_FDCWD && (ndp->ni_resflags & NIRES_ABS) == 0) {
		/*
		 * Relative lookups are subject to normal Capsicum restrictions.
		 * This might be too strict.
		 */
		return (0);
	}

	p = curproc;
	policy = (void *)mac_label_get(p->p_label, mac_sandbox_label_slot);
	if (policy == NULL || __predict_false(!policy->committed))
		return (0);

	char buf[NAME_MAX + 1];
	memcpy(buf, cnp->cn_nameptr, cnp->cn_namelen);
	buf[cnp->cn_namelen] = '\0';
	printf("%s:%d %s %#lx\n", __func__, __LINE__, buf, cnp->cn_flags);

	data = osd_thread_get(curthread, mac_sandbox_osd_thread_slot);

	if ((cnp->cn_flags & ISDOTDOT) != 0) {
		if (data->last != NULL && data->last->vp == dvp &&
		    !vfs_lookup_isroot(ndp, dvp))
			data->last = NULL;
	} else {
		head = (void *)mac_label_get(dvplabel, mac_sandbox_label_slot);
		if (head != NULL) {
			LIST_FOREACH(vnpol, &head->head, vnlink) {
				if (vnpol->policy != policy)
					continue;
				if (vnpol->name[0] == '\0' ||
				    (strlen(vnpol->name) == cnp->cn_namelen &&
				    strncmp(vnpol->name, cnp->cn_nameptr,
				    cnp->cn_namelen) == 0)) {
					printf("%s:%d\n", __func__, __LINE__);
					/* XXX-MJ leaking ioctl buffer? */
					memcpy(&ndp->ni_filecaps, &vnpol->fcaps,
					    sizeof(ndp->ni_filecaps));
					data->last = vnpol;
					break;
				}
			}
		}
	}

	return (0);
}

static int
mac_sandbox_vnode_check_lookup_final(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	struct mac_sandbox_thread_data *data;
	struct mac_sandbox_vnode_policy *vnpol;
	struct mac_sandbox_vnode_policy_head *head;
	struct mac_sandbox_policy *policy;
	struct nameidata *ndp;
	bool locked;

	ndp = vfs_lookup_nameidata(cnp);
	if (ndp->ni_dirfd != AT_FDCWD && (ndp->ni_resflags & NIRES_ABS) == 0) {
		/*
		 * Relative lookups are subject to normal Capsicum restrictions.
		 * This might be too strict.
		 */
		return (0);
	}

	policy = (void *)mac_label_get(curproc->p_label,
	    mac_sandbox_label_slot);
	if (policy == NULL || __predict_false(!policy->committed))
		return (0);

	data = osd_thread_get(curthread, mac_sandbox_osd_thread_slot);
	if (data->last != NULL)
		return (0);

	locked = VOP_ISLOCKED(vp) == LK_EXCLUSIVE;
	if (!locked)
		(void)vn_lock(vp, LK_SHARED | LK_RETRY);
	head = (void *)mac_label_get(vplabel, mac_sandbox_label_slot);
	if (head != NULL) {
		LIST_FOREACH(vnpol, &head->head, vnlink) {
			if (vnpol->policy == policy && vnpol->name[0] == '\0')
				break;
		}
		if (vnpol != NULL) {
			memcpy(&ndp->ni_filecaps, &vnpol->fcaps,
			    sizeof(ndp->ni_filecaps));
			data->last = vnpol;
		}
	}
	if (!locked)
		VOP_UNLOCK(vp);

	if (data->last == NULL)
		return (ECAPMODE);
	return (0);
}

static const struct mac_policy_ops mac_sandbox_ops = {
	.mpo_vnode_init_label = mac_sandbox_vnode_init_label,
	.mpo_vnode_destroy_label = mac_sandbox_vnode_destroy_label,

	.mpo_proc_init_label = mac_sandbox_proc_init_label,
	.mpo_proc_destroy_label = mac_sandbox_proc_destroy_label,

	.mpo_capsicum_check_bind = mac_sandbox_capsicum_check_bind,
	.mpo_capsicum_check_connect = mac_sandbox_capsicum_check_connect,
	.mpo_capsicum_check_lookup = mac_sandbox_capsicum_check_lookup,
	.mpo_capsicum_check_sendmsg = mac_sandbox_capsicum_check_sendmsg,
	.mpo_capsicum_check_syscall = mac_sandbox_capsicum_check_syscall,
	.mpo_capsicum_check_sysctl = mac_sandbox_capsicum_check_sysctl,

	.mpo_vnode_check_lookup = mac_sandbox_vnode_check_lookup,
	.mpo_vnode_check_lookup_final = mac_sandbox_vnode_check_lookup_final,
};
MAC_POLICY_SET(&mac_sandbox_ops, mac_sandbox, "MAC/sandbox",
    MPC_LOADTIME_FLAG_NOTLATE, &mac_sandbox_label_slot);

static int
mac_sandbox_devopen(struct cdev *cdev, int flags, int fmt, struct thread *td)
{
	struct mac_sandbox_policy *policy;
	struct proc *p;

	p = td->td_proc;

	policy = malloc(sizeof(*policy), M_MAC_SANDBOX, M_WAITOK);
	SLIST_INIT(&policy->sysctls);
	SLIST_INIT(&policy->vnodes);
	policy->committed = false;
	rm_init(&policy->lock, "mac_sandbox_policy");

	/*
	 * XXX-MJ rather than setting policy here, save it in a cdevpriv and
	 * attach it to the label only when committing. Then we don't need the
	 * "committed" flag.
	 */
	PROC_LOCK(p);
	if (mac_label_get(p->p_label, mac_sandbox_label_slot) != 0) {
		PROC_UNLOCK(p);
		free(policy, M_MAC_SANDBOX);
		return (EBUSY);
	}
	mac_label_set(p->p_label, mac_sandbox_label_slot, (intptr_t)policy);
	PROC_UNLOCK(p);
	return (0);
}

static int
mac_sandbox_devioctl_vnode(struct thread *td,
    struct mac_sandbox_vnode_ioc *ioc)
{
	struct filecaps fcaps;
	struct mac_sandbox_vnode_policy_head *head;
	struct mac_sandbox_vnode_policy *vnpol;
	struct mac_sandbox_policy *policy;
	struct vnode *vp;
	int error;

	policy = (void *)mac_label_get(td->td_proc->p_label,
	    mac_sandbox_label_slot);
	if (policy == NULL)
		return (ENOENT);
	if (policy->committed)
		return (ENOTCAPABLE);

	if (strnlen(ioc->name, sizeof(ioc->name)) >= sizeof(ioc->name))
		return (EINVAL);

	error = fgetvp_rights(td, ioc->fd, &cap_no_rights, &fcaps, &vp);
	if (error != 0)
		return (error);
	if (vp->v_type != VDIR) {
		vrele(vp);
		return (ENOTDIR);
	}

	error = vn_lock(vp, LK_EXCLUSIVE);
	if (error != 0) {
		vrele(vp);
		return (error);
	}
	head = (void *)mac_label_get(vp->v_label, mac_sandbox_label_slot);
	if (head == NULL) {
		head = malloc(sizeof(*head), M_MAC_SANDBOX, M_WAITOK);
		LIST_INIT(&head->head);
		mac_label_set(vp->v_label, mac_sandbox_label_slot,
		    (intptr_t)head);
	}

	vnpol = malloc(sizeof(*vnpol), M_MAC_SANDBOX, M_WAITOK);
	vnpol->fcaps = fcaps;
	strlcpy(vnpol->name, ioc->name, sizeof(vnpol->name));
	vnpol->policy = policy;
	vnpol->vp = vp;

	LIST_INSERT_HEAD(&head->head, vnpol, vnlink);
	rm_wlock(&policy->lock);
	/* XXX-MJ what if we already have a policy for this vnode? */
	SLIST_INSERT_HEAD(&policy->vnodes, vnpol, plink);
	VOP_UNLOCK(vp);
	rm_wunlock(&policy->lock);

	return (0);
}

static int
mac_sandbox_devioctl_sysctl(struct thread *td,
    struct mac_sandbox_sysctl_ioc *ioc)
{
	struct mac_sandbox_policy *policy;
	struct mac_sandbox_sysctl_policy *sysctlpol;
	size_t oidlen;
	int error, oid[CTL_MAXNAME];

	if (strnlen(ioc->name, sizeof(ioc->name)) >= sizeof(ioc->name))
		return (EINVAL);
	if ((ioc->flags &
	    ~(MAC_SANDBOX_F_SYSCTL_RD | MAC_SANDBOX_F_SYSCTL_WR)) != 0)
		return (EINVAL);

	error = sysctl_name2oid(td, ioc->name, strlen(ioc->name), oid, &oidlen);
	if (error != 0)
		return (error);

	policy = (void *)mac_label_get(td->td_proc->p_label,
	    mac_sandbox_label_slot);
	if (policy == NULL)
		return (ENOENT);

	sysctlpol = malloc(sizeof(*sysctlpol), M_MAC_SANDBOX,
	    M_WAITOK | M_ZERO);
	memcpy(sysctlpol->oid, oid, oidlen);
	sysctlpol->oidlen = oidlen / sizeof(int);
	sysctlpol->flags = ioc->flags;

	rm_wlock(&policy->lock);
	if (policy->committed)
		error = ENOTCAPABLE;
	else
		SLIST_INSERT_HEAD(&policy->sysctls, sysctlpol, link);
	rm_wunlock(&policy->lock);

	if (error != 0)
		free(sysctlpol, M_MAC_SANDBOX);

	return (error);
}

static int
mac_sandbox_devioctl_commit(struct thread *td)
{
	struct mac_sandbox_policy *policy;
	struct proc *p;
	int error;

	/*
	 * The policy will not be enforced unless the process is in capability
	 * mode, so we ought to check it.
	 */
	if (!IN_CAPABILITY_MODE(td))
		return (ENXIO);

	p = td->td_proc;
	policy = (void *)mac_label_get(p->p_label, mac_sandbox_label_slot);
	if (policy == NULL)
		return (ENOENT);
	rm_wlock(&policy->lock);
	if (policy->committed)
		error = EINVAL;
	else {
		error = 0;
		policy->committed = true;
	}
	rm_wunlock(&policy->lock);
	return (error);
}

static int
mac_sandbox_devioctl(struct cdev *cdev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	switch (cmd) {
	case MAC_SANDBOX_IOC_VNODE:
		return (mac_sandbox_devioctl_vnode(td,
		    (struct mac_sandbox_vnode_ioc *)data));
	case MAC_SANDBOX_IOC_SYSCTL:
		return (mac_sandbox_devioctl_sysctl(td,
		    (struct mac_sandbox_sysctl_ioc *)data));
	case MAC_SANDBOX_IOC_COMMIT:
		return (mac_sandbox_devioctl_commit(td));
	default:
		return (ENOTTY);
	}
}

static struct cdev *mac_sandbox_cdev;
static struct cdevsw mac_sandbox_cdevsw = {
	.d_name = "mac_sandbox",
	.d_version = D_VERSION,
	.d_open = mac_sandbox_devopen,
	.d_ioctl = mac_sandbox_devioctl,
};

static void
mac_sandbox_dealloc_thread_osd(void *osd)
{
	free(osd, M_MAC_SANDBOX);
}

static void
mac_sandbox_sysinit(void *arg __unused)
{
	mac_sandbox_cdev = make_dev(&mac_sandbox_cdevsw, 0,
	    UID_ROOT, GID_WHEEL, 0666, "mac_sandbox");
	mac_sandbox_osd_thread_slot =
	    osd_thread_register(mac_sandbox_dealloc_thread_osd);
}
SYSINIT(mac_sandbox_sysinit, SI_SUB_DRIVERS, SI_ORDER_ANY,
    mac_sandbox_sysinit, NULL);

static void
mac_sandbox_sysuninit(void *arg __unused)
{
	osd_thread_deregister(mac_sandbox_osd_thread_slot);
	destroy_dev(mac_sandbox_cdev);
}
SYSUNINIT(mac_sandbox_sysuninit, SI_SUB_DRIVERS, SI_ORDER_ANY,
    mac_sandbox_sysuninit, NULL);

MODULE_VERSION(mac_sandbox, 1);
