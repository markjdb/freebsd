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
#define	_IN_ALL_EVENTS		0x00000fff

/* Flags, set in the mask field. */
#define	IN_DONT_FOLLOW		0x00010000
#define	IN_EXCL_UNLINK		0x00020000
#define	IN_MASK_ADD		0x00040000
#define	IN_ONESHOT		0x00080000
#define	IN_ONLYDIR		0x00100000
#define	IN_MASK_CREATE		0x00200000
#define	_IN_ALL_FLAGS		0x003f0000

/* Flags returned by the kernel.  XXX-MJ can these overlap? */
#define	IN_IGNORED		0x01000000
#define	IN_ISDIR		0x02000000
#define	IN_Q_OVERFLOW		0x04000000
#define	IN_UNMOUNT		0x08000000

#ifdef _KERNEL
struct file;
struct thread;
struct vnode;

int	inotify_create_file(struct thread *, struct file *, int, int *);
void	inotify_log(struct vnode *, struct vnode *, const char *, size_t, int);
#else
#include <sys/cdefs.h>

__BEGIN_DECLS
int	inotify_init1(int flags);
int	inotify_add_watch(int fd, const char *pathname, __uint32_t mask);
int	inotify_rm_watch(int fd, int wd);
__END_DECLS
#endif /* !_KERNEL */

#endif /* !_INOTIFY_H_ */
