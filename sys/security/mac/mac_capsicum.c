/*
 * Copyright (c) 2026 Mark Johnston <markj@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "opt_mac.h"

#include <sys/param.h>
#include <sys/module.h>

#include <security/mac/mac_framework.h>
#include <security/mac/mac_internal.h>
#include <security/mac/mac_policy.h>

int
mac_cap_grant_bind(struct sockaddr *sa)
{
	int error = 0;

	MAC_POLICY_GRANT_NOSLEEP(cap_check_bind, sa);
	return (error);
}

int
mac_cap_grant_connect(struct sockaddr *sa)
{
	int error = 0;

	MAC_POLICY_GRANT_NOSLEEP(cap_check_connect, sa);
	return (error);
}

int
mac_cap_grant_lookup(struct nameidata *ndp)
{
	int error = 0;

	MAC_POLICY_GRANT_NOSLEEP(cap_check_lookup, ndp);
	return (error);
}

int
mac_cap_grant_sendmsg(struct msghdr *msg)
{
	int error = 0;

	MAC_POLICY_GRANT_NOSLEEP(cap_check_sendmsg, msg);
	return (error);
}

int
mac_cap_grant_syscall(struct syscall_args *sa)
{
	int error = 0;

	MAC_POLICY_GRANT_NOSLEEP(cap_check_syscall, sa);
	return (error);
}

int
mac_cap_grant_sysctl(struct sysctl_oid *oidp, void *arg1, intmax_t arg2,
    struct sysctl_req *req)
{
	int error = 0;

	MAC_POLICY_GRANT_NOSLEEP(cap_check_sysctl, oidp, arg1, arg2, req);
	return (error);
}
