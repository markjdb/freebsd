/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Klara, Inc.
 */

#include "namespace.h"
#include <sys/fcntl.h>
#include <sys/inotify.h>
#include <sys/specialfd.h>
#include "un-namespace.h"
#include "libc_private.h"

int
inotify_add_watch(int fd, const char *pathname, uint32_t mask)
{
	return (inotify_add_watch_at(fd, AT_FDCWD, pathname, mask));
}

int
inotify_init1(int flags)
{
	struct specialfd_inotify args;

	args.flags = flags;
	return (__sys___specialfd(SPECIALFD_INOTIFY, &args, sizeof(args)));
}

int
inotify_init(void)
{
	return (inotify_init1(0));
}
