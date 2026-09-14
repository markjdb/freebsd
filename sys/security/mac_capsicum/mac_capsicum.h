/*
 * Copyright (c) 2026 Mark Johnston <markj@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _MAC_CAPSICUM_H_
#define _MAC_CAPSICUM_H_

#include <sys/types.h>
#include <sys/caprights.h>
#include <sys/ioccom.h>

struct mac_capsicum_vnode_ioc {
	int	fd;
	cap_rights_t rights;
	char	name[NAME_MAX + 1];
};
#ifdef _KERNEL
_Static_assert(CAP_RIGHTS_VERSION == CAP_RIGHTS_VERSION_00,
    "cap_rights_t version has changed");
#endif

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
