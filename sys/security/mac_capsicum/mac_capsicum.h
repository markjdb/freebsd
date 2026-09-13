/*
 * Copyright (c) 2026 Mark Johnston <markj@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _MAC_CAPSICUM_H_
#define _MAC_CAPSICUM_H_

#include <sys/types.h>
#include <sys/ioccom.h>

struct mac_capsicum_vnode_ioc {
	int	fd;
	char	name[NAME_MAX + 1];
};

struct mac_capsicum_sysctl_ioc {
	char	name[PATH_MAX];
	unsigned int flags;
#define	MAC_CAPSICUM_F_SYSCTL_RD	0x01
#define	MAC_CAPSICUM_F_SYSCTL_WR	0x02
};

#define	MAC_CAPSICUM_IOC_VNODE	_IOWR('M', 1, struct mac_capsicum_vnode_ioc)
#define	MAC_CAPSICUM_IOC_SYSCTL	_IOWR('M', 2, struct mac_capsicum_sysctl_ioc)
#define	MAC_CAPSICUM_IOC_COMMIT	_IO('M', 3)

#define	_PATH_MAC_CAPSICUM	"/dev/mac_capsicum"

#endif /* _MAC_CAPSICUM_H_ */
