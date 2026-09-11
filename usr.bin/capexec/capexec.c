/*
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * This software was developed by Mark Johnston under sponsorship from the
 * FreeBSD Foundation.
 */

#include <sys/capsicum.h>

#include <security/mac_capsicum/mac_capsicum.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern char **environ;

static void
usage(void)
{
	fprintf(stderr,
	    "usage: capexec [-f policy] command [args ...]\n");
}

int
main(int argc, char **argv)
{
	const char *policy;
	int ch, cmdfd, devfd, policyfd;

	policy = NULL;
	while ((ch = getopt(argc, argv, "f:h")) != -1) {
		switch (ch) {
		case 'f':
			policy = optarg;
			break;
		case 'h':
			usage();
			exit(0);
		default:
			usage();
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	devfd = open(_PATH_MAC_CAPSICUM, O_RDWR | O_CLOEXEC);
	if (devfd < 0)
		err(1, "open(" _PATH_MAC_CAPSICUM ")");

	policyfd = open(policy, O_RDONLY | O_CLOEXEC);
	if (policyfd < 0)
		err(1, "open(%s)", policy);

	cmdfd = open(argv[0], O_EXEC | O_CLOEXEC);
	if (cmdfd < 0)
		err(1, "open(%s)", argv[0]);

	if (cap_enter() < 0)
		err(1, "cap_enter()");

	(void)fexecve(cmdfd, argv, environ);
	err(1, "fexecve(%s)", argv[0]);
}
