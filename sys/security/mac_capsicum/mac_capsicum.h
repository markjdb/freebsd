/*
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * This software was developed by Mark Johnston under sponsorship from the
 * FreeBSD Foundation.
 */

#ifndef _MAC_CAPSICUM_H_
#define _MAC_CAPSICUM_H_

#include <sys/types.h>
#include <sys/ioccom.h>

struct mac_capsicum_vnode_ioc {
	int	fd;
};

#define	MAC_CAPSICUM_IOC_VNODE	_IOWR('M', 1, struct mac_capsicum_vnode_ioc)

#define	_PATH_MAC_CAPSICUM	"/dev/mac_capsicum"

#endif /* _MAC_CAPSICUM_H_ */
