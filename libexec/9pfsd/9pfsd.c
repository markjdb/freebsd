/*
 * Copyright (c) 2026 Mark Johnston <markj@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/event.h>

#include <capsicum_helpers.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include <lib9p.h>
#include <backend/fs.h> /* XXX-MJ wtf */
#include <transport/socket.h> /* XXX-MJ wtf */

static void
usage(void)
{
	fprintf(stderr, "usage: 9pfsd [-w] <dir>\n");
	exit(1);
}

static void __printflike(2, 3)
logerr(int errnum, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);
	exit(errnum);
}

int
main(int argc, char **argv)
{
	struct kevent kev;
	struct l9p_backend *backend;
	struct l9p_server *server;
	int c, dfd, kq, sock;
	bool readonly;

	openlog("9pfsd", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	readonly = true;
	while ((c = getopt(argc, argv, "w")) != -1) {
		switch (c) {
		case 'w':
			readonly = false;
			break;
		default:
			usage();
			return (1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	dfd = open(argv[0], O_DIRECTORY);
	if (dfd == -1)
		logerr(1, "open(%s)", argv[0]);

	if (l9p_backend_fs_init(&backend, dfd, readonly) != 0)
		logerr(1, "l9p_backend_fs_init");
	if (l9p_server_init(&server, backend) != 0)
		logerr(1, "l9p_server_init");

	if (caph_enter() == -1)
		logerr(1, "caph_enter");

	sock = STDIN_FILENO;
	l9p_socket_accept(server, sock, NULL, 0);

	/*
	 * Just loop until we observe EOF.  This is stupid, but so is lib9p's
	 * interface design, which in particular gives us no way to block until
	 * it's done with the socket.
	 */
	kq = kqueue();
	if (kq == -1)
		logerr(1, "kqueue");
	EV_SET(&kev, sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		logerr(1, "kevent");
	for (;;) {
		int nev;

		nev = kevent(kq, NULL, 0, &kev, 1, NULL);
		if (nev == -1) {
			if (errno == EINTR)
				continue;
			logerr(1, "kevent");
		}
		if (nev == 0)
			continue;
		if ((kev.flags & EV_EOF) != 0) {
			if (kev.fflags != 0 || kev.data == 0)
				break;
		}
	}

	return (0);
}
