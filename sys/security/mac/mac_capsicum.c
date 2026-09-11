/*
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * This software was developed by Mark Johnston under sponsorship from the
 * FreeBSD Foundation.
 */

#include "opt_mac.h"

#include <sys/param.h>
#include <sys/module.h>

#include <security/mac/mac_framework.h>
#include <security/mac/mac_internal.h>
#include <security/mac/mac_policy.h>

int
mac_cap_grant_lookup(struct nameidata *ndp)
{
	int error = 0;

	MAC_POLICY_GRANT_NOSLEEP(cap_check_lookup, ndp);
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
