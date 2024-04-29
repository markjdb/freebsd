/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 * Copyright (c) 2024 Mark Johnston, <markj@FreeBSD.org>
 */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/ioccom.h>
#include <sys/jail.h>
#include <sys/proc.h>
#include <sys/ucred.h>

#include <dev/vmm/vmm_ctl.h>

#include <machine/vmm_dev.h>

static struct cdev *vmmctl_dev;
static unsigned int pr_allow_flag;

int
vmm_priv_check(struct ucred *ucred)
{
	if (jailed(ucred) && (ucred->cr_prison->pr_allow & pr_allow_flag) == 0)
		return (EPERM);
	return (0);
}

static int
vmmctl_ioctl(struct cdev *cdev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	int error;

	error = vmm_priv_check(td->td_ucred);
	if (error != 0)
		return (error);

	switch (cmd) {
	case VMMCTL_VMCREATE:
	case VMMCTL_VMDESTROY:
		break;
	default:
		return (ENOTTY);
	}

	return (0);
}

static struct cdevsw vmmctl_cdevsw = {
	.d_name =	"vmmctl",
	.d_version =	D_VERSION,
	.d_ioctl =	vmmctl_ioctl,
};

int
vmmdev_init(void)
{
	int error;

	pr_allow_flag = prison_add_allow(NULL, "vmm", NULL,
	    "Allow use of vmm in a jail.");

	error = make_dev_p(MAKEDEV_CHECKNAME | MAKEDEV_WAITOK,
	    &vmmctl_dev, &vmmctl_cdevsw, NULL, UID_ROOT, GID_WHEEL, 0600,
	    "vmmctl");
	if (error != 0)
		return (error);

	return (0);
}

int
vmmdev_cleanup(void)
{
#if 0
	if (!SLIST_EMPTY(&head))
		return (EBUSY);
#endif

	if (vmmctl_dev != NULL)
		destroy_dev(vmmctl_dev);

	return (0);
}

