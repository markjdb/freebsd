/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Klara, Inc.
 */

/*
 * XXX-MJ how does this interact with unionfs/nullfs?  Should we generate events
 * for accesses to the underlying file?
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/caprights.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/poll.h>
#include <sys/queue.h>
#include <sys/selinfo.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/syslimits.h>
#include <sys/sysproto.h>
#include <sys/vnode.h>

static SYSCTL_NODE(_vfs, OID_AUTO, inotify, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "inotify configuration");

static int vfs_inotify_max_events = 128;
SYSCTL_INT(_vfs_inotify, OID_AUTO, max_events, CTLFLAG_RWTUN,
    &vfs_inotify_max_events, 0, "Maximum number of events to queue");

static fo_rdwr_t	inotify_read;
static fo_ioctl_t	inotify_ioctl;
static fo_poll_t	inotify_poll;
static fo_kqfilter_t	inotify_kqfilter;
static fo_stat_t	inotify_stat;
static fo_close_t	inotify_close;

static const struct fileops inotifyfdops = {
	.fo_read = inotify_read,
	.fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate,
	.fo_ioctl = inotify_ioctl,
	.fo_poll = inotify_poll,
	.fo_kqfilter = inotify_kqfilter,
	.fo_stat = inotify_stat,
	.fo_close = inotify_close,
	.fo_cmp = file_kcmp_generic,
};

static void	filt_inotifydetach(struct knote *kn);
static int	filt_inotifyevent(struct knote *kn, long hint);

static const struct filterops inotify_rfiltops = {
	.f_isfd = 1,
	.f_detach = filt_inotifydetach,
	.f_event = filt_inotifyevent,
};

static MALLOC_DEFINE(M_INOTIFY, "inotify", "inotify data structures");

struct inotify_record {
	STAILQ_ENTRY(inotify_record) link;
	struct inotify_event	ev;
};

struct inotify_watch {
	struct inotify_softc *sc; /* back-pointer */
	int		wd;	/* unique ID */
	uint32_t	mask;	/* event mask */
	struct vnode	*vp;	/* vnode being watched, refed */
	TAILQ_ENTRY(inotify_watch) ilink;	/* inotify linkage */
	TAILQ_ENTRY(inotify_watch) vlink;	/* vnode linkage */
};

struct inotify_softc {
	STAILQ_HEAD(, inotify_record) pending;	/* events waiting to be read */
	int npending;
	TAILQ_HEAD(, inotify_watch) watches;	/* active watches */
	struct selinfo sel;			/* select/poll/kevent info */
	int nextwatch;				/* next watch ID to try */
	struct mtx lock;
};

static int
inotify_read(struct file *fp, struct uio *uio, struct ucred *cred, int flags,
    struct thread *td)
{
	struct inotify_softc *sc;
	struct inotify_record *rec;
	int error;
	bool first;

	sc = fp->f_data;
	error = 0;

	mtx_lock(&sc->lock);
	while (STAILQ_EMPTY(&sc->pending)) {
		if ((flags & IO_NDELAY) != 0) {
			mtx_unlock(&sc->lock);
			return (EWOULDBLOCK);
		}
		error = msleep(&sc->pending, &sc->lock, PCATCH, "inotify", 0);
		if (error != 0) {
			mtx_unlock(&sc->lock);
			return (error);
		}
	}
	for (first = false; (rec = STAILQ_FIRST(&sc->pending)) != NULL;) {
		if (uio->uio_resid < sizeof(rec->ev) + rec->ev.len) {
			if (first)
				error = EINVAL;
			break;
		}
		STAILQ_REMOVE_HEAD(&sc->pending, link);
		sc->npending--;
		mtx_unlock(&sc->lock);
		error = uiomove(&rec->ev, sizeof(rec->ev) + rec->ev.len, uio);
		free(rec, M_INOTIFY);
		if (error != 0)
			return (error);
		first = false;
		mtx_lock(&sc->lock);
	}
	mtx_unlock(&sc->lock);
	return (error);
}

static int
inotify_ioctl(struct file *fp, u_long com, void *data, struct ucred *cred,
    struct thread *td)
{
	return (0);
}

static int
inotify_poll(struct file *fp, int events, struct ucred *cred, struct thread *td)
{
	struct inotify_softc *sc;
	int revents;

	sc = fp->f_data;
	revents = 0;

	mtx_lock(&sc->lock);
	if ((events & (POLLIN | POLLRDNORM)) != 0 && sc->npending > 0)
		revents |= events & (POLLIN | POLLRDNORM);
	else
		selrecord(td, &sc->sel);
	mtx_unlock(&sc->lock);
	return (revents);
}

static void
filt_inotifydetach(struct knote *kn)
{
	struct inotify_softc *sc;

	sc = kn->kn_hook;
	mtx_lock(&sc->lock);
	knlist_remove(&sc->sel.si_note, kn, 1);
	mtx_unlock(&sc->lock);
}

static int
filt_inotifyevent(struct knote *kn, long hint)
{
	struct inotify_softc *sc;

	sc = kn->kn_hook;
	mtx_lock(&sc->lock);
	kn->kn_data = sc->npending;
	mtx_unlock(&sc->lock);
	return (kn->kn_data > 0);
}

static int
inotify_kqfilter(struct file *fp, struct knote *kn)
{
	struct inotify_softc *sc;

	if (kn->kn_filter != EVFILT_READ)
		return (EINVAL);
	sc = fp->f_data;
	mtx_lock(&sc->lock);
	kn->kn_fop = &inotify_rfiltops;
	kn->kn_hook = sc;
	knlist_add(&sc->sel.si_note, kn, 1);
	mtx_unlock(&sc->lock);
	return (0);
}

static int
inotify_stat(struct file *fp, struct stat *sb, struct ucred *cred)
{
	/* XXX-MJ */
	memset(sb, 0, sizeof(*sb));
	return (0);
}

static void
inotify_free_watch(struct inotify_watch *watch)
{
	VI_LOCK(watch->vp);
	TAILQ_REMOVE(&watch->vp->v_pollinfo->vpi_inotify, watch, vlink);
	if (TAILQ_EMPTY(&watch->vp->v_pollinfo->vpi_inotify))
		watch->vp->v_irflag &= ~VIRF_INOTIFY;
	VI_UNLOCK(watch->vp);

	vrele(watch->vp);
	free(watch, M_INOTIFY);
}

static int
inotify_close(struct file *fp, struct thread *td)
{
	struct inotify_softc *sc;
	struct inotify_record *rec;
	struct inotify_watch *watch;

	sc = fp->f_data;
	while ((rec = STAILQ_FIRST(&sc->pending)) != NULL) {
		STAILQ_REMOVE_HEAD(&sc->pending, link);
		free(rec, M_INOTIFY);
	}
	while ((watch = TAILQ_FIRST(&sc->watches)) != NULL) {
		TAILQ_REMOVE(&sc->watches, watch, ilink);
		inotify_free_watch(watch);
	}
	seldrain(&sc->sel);
	knlist_destroy(&sc->sel.si_note);
	mtx_destroy(&sc->lock);
	free(sc, M_INOTIFY);
	return (0);
}

int
inotify_create_file(struct thread *td, struct file *fp, int flags, int *fflagsp)
{
	struct inotify_softc *sc;
	int fflags;

	/* XXX-MJ audit(9) integration */
	if ((flags & ~(IN_NONBLOCK | IN_CLOEXEC)) != 0)
		return (EINVAL);

	sc = malloc(sizeof(*sc), M_INOTIFY, M_WAITOK | M_ZERO);
	STAILQ_INIT(&sc->pending);
	TAILQ_INIT(&sc->watches);
	mtx_init(&sc->lock, "inotify", NULL, MTX_DEF);
	knlist_init_mtx(&sc->sel.si_note, &sc->lock);

	fflags = FREAD;
	if ((flags & IN_NONBLOCK) != 0)
		fflags |= FNONBLOCK;
	if ((flags & IN_CLOEXEC) != 0)
		*fflagsp |= O_CLOEXEC;
	finit(fp, fflags, DTYPE_INOTIFY, sc, &inotifyfdops);

	return (0);
}

void
inotify_log(struct vnode *vp, struct vnode *dvp, const char *name,
    size_t namelen, int event)
{
	struct inotify_watch *watch;
	struct vnode *tvp;
	int flags;

	flags = 0;
	if (vp->v_type == VDIR)
		flags |= IN_ISDIR;

	tvp = dvp != NULL ? dvp : vp;
	VI_LOCK(tvp);
	TAILQ_FOREACH(watch, &tvp->v_pollinfo->vpi_inotify, vlink) {
		if ((watch->mask & event) != 0) {
			struct inotify_softc *sc;
			struct inotify_event *evp;
			struct inotify_record *rec;

			rec = malloc(
			    sizeof(*rec) + (name != NULL ? namelen + 1 : 0),
			    M_INOTIFY, M_NOWAIT);
			if (rec == NULL) {
				/* XXX-MJ record a drop */
				continue;
			}
			evp = &rec->ev;
			evp->wd = watch->wd;
			evp->mask = event | flags;
			evp->cookie = 0; /* XXX-MJ */
			if (name != NULL) {
				evp->len = namelen + 1;
				memcpy(evp->name, name, evp->len);
			} else {
				evp->len = 0;
			}

			sc = watch->sc;
			mtx_lock(&sc->lock);
			STAILQ_INSERT_TAIL(&sc->pending, rec, link);
			sc->npending++;
			selwakeup(&sc->sel);
			KNOTE_LOCKED(&sc->sel.si_note, 0);
			wakeup(&sc->pending);
			mtx_unlock(&sc->lock);
		}
	}
	VI_UNLOCK(tvp);
}

/* XXX-MJ add a capsicum-friendly variant */
/* XXX-MJ clean up error handling */
/* XXX-MJ handle IN_MASK_CREATE */
int
sys_inotify_add_watch(struct thread *td, struct inotify_add_watch_args *uap)
{
	struct nameidata nd;
	struct file *fp;
	struct inotify_softc *sc;
	struct inotify_watch *watch, *watch1;
	struct vnode *vp;
	uint32_t mask;
	int error;

	mask = uap->mask;
	if ((mask & _IN_ALL_EVENTS) == 0)
		return (EINVAL);
	if ((mask & (IN_MASK_ADD | IN_MASK_CREATE)) ==
	    (IN_MASK_ADD | IN_MASK_CREATE))
		return (EINVAL);
	if ((mask & ~(_IN_ALL_EVENTS | _IN_ALL_FLAGS)) != 0)
		return (EINVAL);

	NDINIT(&nd, LOOKUP, (mask & IN_DONT_FOLLOW) ? NOFOLLOW : FOLLOW,
	    UIO_USERSPACE, uap->path);
	error = namei(&nd);
	if (error != 0)
		return (error);
	NDFREE_PNBUF(&nd);

	if ((mask & IN_ONLYDIR) != 0 && nd.ni_vp->v_type != VDIR) {
		vrele(nd.ni_vp);
		return (ENOTDIR);
	}

	error = fget(td, uap->fd, &cap_read_rights /* XXX-MJ no */, &fp);
	if (error != 0) {
		vrele(nd.ni_vp);
		return (error);
	}
	if (fp->f_type != DTYPE_INOTIFY) {
		vrele(nd.ni_vp);
		fdrop(fp, td);
		return (EINVAL);
	}
	sc = fp->f_data;

	/* XXX-MJ we need to make sure we can access the file */

	watch = malloc(sizeof(*watch), M_INOTIFY, M_WAITOK | M_ZERO);
	watch->sc = sc;
	watch->vp = vp = nd.ni_vp; /* XXX-MJ do we want to downgrade to a hold? */
	watch->mask = mask;

	mtx_lock(&sc->lock);
	do {
		/*
		 * Search for the next available watch descriptor.  This is
		 * implemented so as to avoid reusing watch descriptors for as
		 * long as possible.
		 */
		watch->wd = sc->nextwatch++;
		TAILQ_FOREACH(watch1, &sc->watches, ilink) {
			if (watch->wd == watch1->wd)
				break;
		}
	} while (watch1 != NULL);
	TAILQ_INSERT_TAIL(&sc->watches, watch, ilink);
	mtx_unlock(&sc->lock);

	v_addpollinfo(vp);
	VI_LOCK(vp);
	vp->v_irflag |= VIRF_INOTIFY;
	TAILQ_INSERT_HEAD(&vp->v_pollinfo->vpi_inotify, watch, vlink);
	VI_UNLOCK(vp);

	fdrop(fp, td);
	return (error);
}

int
sys_inotify_rm_watch(struct thread *td, struct inotify_rm_watch_args *uap)
{
	struct file *fp;
	struct inotify_softc *sc;
	struct inotify_watch *watch;
	int error;

	error = fget(td, uap->fd, &cap_read_rights /* XXX-MJ no */, &fp);
	if (error != 0)
		return (error);
	if (fp->f_type != DTYPE_INOTIFY) {
		fdrop(fp, td);
		return (EINVAL);
	}
	sc = fp->f_data;

	mtx_lock(&sc->lock);
	TAILQ_FOREACH(watch, &sc->watches, ilink) {
		if (watch->wd == uap->wd)
			break;
	}
	if (watch == NULL)
		error = ENOENT;
	else
		TAILQ_REMOVE(&sc->watches, watch, ilink);
	mtx_unlock(&sc->lock);
	if (watch != NULL)
		inotify_free_watch(watch);

	fdrop(fp, td);
	return (error);
}
