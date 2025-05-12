/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Klara, Inc.
 */

#ifndef _INOTIFY_H_
#define _INOTIFY_H_

#include <sys/_types.h>

/* Flags for inotify_init1(). */
#define	IN_NONBLOCK	0x00000001
#define	IN_CLOEXEC	0x00000002

struct inotify_event {
	int		wd;
	__uint32_t	mask;
	__uint32_t	cookie;
	__uint32_t	len;
	char		name[0];
};

/* Events, set in the mask field. */
#define	IN_ACCESS		0x00000001
#define	IN_ATTRIB		0x00000002
#define	IN_CLOSE_WRITE		0x00000004
#define	IN_CLOSE_NOWRITE	0x00000008
#define	IN_CLOSE		(IN_CLOSE_WRITE | IN_CLOSE_NOWRITE)
#define	IN_CREATE		0x00000010
#define	IN_DELETE		0x00000020
#define	IN_DELETE_SELF		0x00000040
#define	IN_MODIFY		0x00000080
#define	IN_MOVE_SELF		0x00000100
#define	IN_MOVED_FROM		0x00000200
#define	IN_MOVED_TO		0x00000400
#define	IN_MOVE			(IN_MOVED_FROM | IN_MOVED_TO)
#define	IN_OPEN			0x00000800
#define	IN_ALL_EVENTS		0x00000fff

/* Events report only for entries in a watched dir, not the dir itself. */
#define	_IN_DIR_EVENTS		(IN_CLOSE_WRITE | IN_DELETE | IN_MODIFY | \
				 IN_MOVED_FROM | IN_MOVED_TO)

/* Flags, set in the mask field. */
#define	IN_DONT_FOLLOW		0x00010000
#define	IN_EXCL_UNLINK		0x00020000
#define	IN_MASK_ADD		0x00040000
#define	IN_ONESHOT		0x00080000
#define	IN_ONLYDIR		0x00100000
#define	IN_MASK_CREATE		0x00200000
#define	_IN_ALL_FLAGS		0x003f0000

/* Flags returned by the kernel. */
#define	IN_IGNORED		0x01000000
#define	IN_ISDIR		0x02000000
#define	IN_Q_OVERFLOW		0x04000000
#define	IN_UNMOUNT		0x08000000
#define	_IN_ALL_RETFLAGS	0x0f000000

#define	_IN_ALIGN		_Alignof(struct inotify_event)
#define	_IN_NAMESIZE(namelen)	\
	((namelen) == 0 ? 0 : __align_up((namelen) + 1, _IN_ALIGN))

#ifdef _KERNEL
struct componentname;
struct file;
struct inotify_softc;
struct thread;
struct vnode;

int	inotify_create_file(struct thread *, struct file *, int, int *);
void	inotify_log(struct vnode *, const char *, size_t, int, __uint32_t);

void	vn_inotify(struct vnode *, struct vnode *, struct componentname *, int,
	    uint32_t);
int	vn_inotify_add_watch(struct vnode *, struct inotify_softc *,
	    __uint32_t, __uint32_t *, struct thread *);

/* Log an inotify event. */
#define	INOTIFY(vp, ev) do {						\
	if (__predict_false((vn_irflag_read(vp) & (VIRF_INOTIFY |	\
	    VIRF_INOTIFY_PARENT)) != 0))				\
		VOP_INOTIFY((vp), NULL, NULL, (ev), 0);			\
} while (0)

/* Log an inotify event using a specific name for the vnode. */
#define	INOTIFY_NAME(vp, dvp, cnp, ev) do {				\
	if (__predict_false((vn_irflag_read(vp) & VIRF_INOTIFY) != 0 ||	\
	    (vn_irflag_read(dvp) & VIRF_INOTIFY) != 0)) 		\
		VOP_INOTIFY((vp), (dvp), (cnp), (ev), 0);		\
} while (0)

extern __uint32_t inotify_rename_cookie;

#define	INOTIFY_MOVE(vp, fdvp, fcnp, tdvp, tcnp) do {			\
	if (__predict_false((vn_irflag_read(fdvp) & VIRF_INOTIFY) != 0 || \
	    (vn_irflag_read(tdvp) & VIRF_INOTIFY) != 0 ||		\
	    (vn_irflag_read(vp) & VIRF_INOTIFY) != 0)) {		\
		__uint32_t cookie;					\
									\
		cookie = atomic_fetchadd_32(&inotify_rename_cookie, 1);	\
		VOP_INOTIFY((vp), fdvp, fcnp, IN_MOVED_FROM, cookie);	\
		VOP_INOTIFY((vp), tdvp, tcnp, IN_MOVED_TO, cookie);	\
	}								\
} while (0)

#else
#include <sys/cdefs.h>

__BEGIN_DECLS
int	inotify_init1(int flags);
int	inotify_add_watch(int fd, const char *pathname, __uint32_t mask);
int	inotify_rm_watch(int fd, int wd);
__END_DECLS
#endif /* !_KERNEL */

#endif /* !_INOTIFY_H_ */
