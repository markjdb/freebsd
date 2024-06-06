/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Stormshield
 */

#include <sys/filio.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <string.h>

#include <atf-c.h>

static void
checked_close(int fd)
{
	int error;

	error = close(fd);
	ATF_REQUIRE_MSG(error == 0, "close failed: %s", strerror(errno));
}

static int
fionread(int fd)
{
	int data, error;

	error = ioctl(fd, FIONREAD, &data);
	ATF_REQUIRE_MSG(error == 0, "ioctl failed: %s", strerror(errno));
	return (data);
}

/*
 * Create a pair of connected TCP sockets, returned via the "out" array.
 */
static void
tcp_socketpair(int out[2], int lport)
{
	struct sockaddr_in sin;
	int error, sd[2];

	sd[0] = socket(PF_INET, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(sd[0] >= 0, "socket failed: %s", strerror(errno));
	sd[1] = socket(PF_INET, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(sd[1] >= 0, "socket failed: %s", strerror(errno));

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = lport;

	error = bind(sd[0], (struct sockaddr *)&sin, sizeof(sin));
	ATF_REQUIRE_MSG(error == 0, "bind failed: %s", strerror(errno));
	error = listen(sd[0], 1);
	ATF_REQUIRE_MSG(error == 0, "listen failed: %s", strerror(errno));

	error = connect(sd[1], (struct sockaddr *)&sin, sizeof(sin));
	ATF_REQUIRE_MSG(error == 0, "connect failed: %s", strerror(errno));
	out[0] = accept(sd[0], NULL, NULL);
	ATF_REQUIRE_MSG(out[0] >= 0, "accept failed: %s", strerror(errno));
	checked_close(sd[0]);
	out[1] = sd[1];
}

/*
 * A structure representing a spliced pair of connections.  left[1] is
 * bidirectionally spliced with right[0].
 */
struct splice_conn {
	int left[2];
	int right[2];
};

/*
 * Initialize a splice connection with the given maximum number of bytes to
 * splice and the given idle timeout.  For now we're forced to use TCP socket,
 * but at some point it would be nice (and simpler) to use pairs of PF_LOCAL
 * sockets.
 */
static void
splice_conn_init_limits(struct splice_conn *sc, off_t max, struct timeval *tv)
{
	struct splice sp;
	int error;

	memset(sc, 0, sizeof(*sc));

	/* XXX-MJ it'd be nicer to try random ports in the ephemeral range */
	tcp_socketpair(sc->left, 3456);
	tcp_socketpair(sc->right, 3457);

	sp.sp_fd = sc->right[0];
	sp.sp_max = max;
	if (tv != NULL)
		sp.sp_idle = *tv;
	else
		sp.sp_idle.tv_sec = sp.sp_idle.tv_usec = 0;

	error = setsockopt(sc->left[1], SOL_SOCKET, SO_SPLICE, &sp, sizeof(sp));
	ATF_REQUIRE_MSG(error == 0, "setsockopt failed: %s", strerror(errno));

	sp.sp_fd = sc->left[1];
	error = setsockopt(sc->right[0], SOL_SOCKET, SO_SPLICE, &sp, sizeof(sp));
	ATF_REQUIRE_MSG(error == 0, "setsockopt failed: %s", strerror(errno));
}

static void
splice_conn_init(struct splice_conn *sc)
{
	splice_conn_init_limits(sc, 0, NULL);
}

static void
splice_conn_check_empty(struct splice_conn *sc)
{
	int data;

	data = fionread(sc->left[0]);
	ATF_REQUIRE_MSG(data == 0, "unexpected data on left[0]: %d", data);
	data = fionread(sc->left[1]);
	ATF_REQUIRE_MSG(data == 0, "unexpected data on left[1]: %d", data);
	data = fionread(sc->right[0]);
	ATF_REQUIRE_MSG(data == 0, "unexpected data on right[0]: %d", data);
	data = fionread(sc->right[1]);
	ATF_REQUIRE_MSG(data == 0, "unexpected data on right[1]: %d", data);
}

static void
splice_conn_fini(struct splice_conn *sc)
{
	checked_close(sc->left[0]);
	checked_close(sc->left[1]);
	checked_close(sc->right[0]);
	checked_close(sc->right[1]);
}

/* Pass a byte through a pair of spliced connections. */
ATF_TC_WITHOUT_HEAD(splice_basic);
ATF_TC_BODY(splice_basic, tc)
{
	struct splice_conn sc;
	ssize_t n;
	char c;

	splice_conn_init(&sc);

	/* Left-to-right. */
	c = 'M';
	n = write(sc.left[0], &c, 1);
	ATF_REQUIRE_MSG(n == 1, "write failed: %s", strerror(errno));
	n = read(sc.right[1], &c, 1);
	ATF_REQUIRE_MSG(n == 1, "read failed: %s", strerror(errno));
	ATF_REQUIRE_MSG(c == 'M', "unexpected character: %c", c);

	/* Right-to-left. */
	c = 'J';
	n = write(sc.right[1], &c, 1);
	ATF_REQUIRE_MSG(n == 1, "write failed: %s", strerror(errno));
	n = read(sc.left[0], &c, 1);
	ATF_REQUIRE_MSG(n == 1, "read failed: %s", strerror(errno));
	ATF_REQUIRE_MSG(c == 'J', "unexpected character: %c", c);

	splice_conn_fini(&sc);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, splice_basic);
	return (atf_no_error());
}
