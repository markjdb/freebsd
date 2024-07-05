/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Stormshield
 */

#include <sys/capsicum.h>
#include <sys/filio.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

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
tcp_socketpair(int out[2])
{
	struct sockaddr_in sin;
	int error, sd[2];

	sd[0] = socket(PF_INET, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(sd[0] >= 0, "socket failed: %s", strerror(errno));
	sd[1] = socket(PF_INET, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(sd[1] >= 0, "socket failed: %s", strerror(errno));

	error = setsockopt(sd[0], IPPROTO_TCP, TCP_NODELAY, &(int){ 1 },
	    sizeof(int));
	ATF_REQUIRE_MSG(error == 0, "setsockopt failed: %s", strerror(errno));
	error = setsockopt(sd[1], IPPROTO_TCP, TCP_NODELAY, &(int){ 1 },
	    sizeof(int));
	ATF_REQUIRE_MSG(error == 0, "setsockopt failed: %s", strerror(errno));

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(0);

	error = bind(sd[0], (struct sockaddr *)&sin, sizeof(sin));
	ATF_REQUIRE_MSG(error == 0, "bind failed: %s", strerror(errno));
	error = listen(sd[0], 1);
	ATF_REQUIRE_MSG(error == 0, "listen failed: %s", strerror(errno));

	error = getsockname(sd[0], (struct sockaddr *)&sin,
	    &(socklen_t){ sizeof(sin) });
	ATF_REQUIRE_MSG(error == 0, "getsockname failed: %s", strerror(errno));

	error = connect(sd[1], (struct sockaddr *)&sin, sizeof(sin));
	ATF_REQUIRE_MSG(error == 0, "connect failed: %s", strerror(errno));
	out[0] = accept(sd[0], NULL, NULL);
	ATF_REQUIRE_MSG(out[0] >= 0, "accept failed: %s", strerror(errno));
	checked_close(sd[0]);
	out[1] = sd[1];
}

static off_t
nspliced(int sd)
{
	off_t n;
	socklen_t len;
	int error;

	len = sizeof(n);
	error = getsockopt(sd, SOL_SOCKET, SO_SPLICE, &n, &len);
	ATF_REQUIRE_MSG(error == 0, "getsockopt failed: %s", strerror(errno));
	ATF_REQUIRE_MSG(len == sizeof(n), "unexpected length: %d", len);
	return (n);
}

static void
splice_init(struct splice *sp, int fd, off_t max, struct timeval *tv)
{
	memset(sp, 0, sizeof(*sp));
	sp->sp_fd = fd;
	sp->sp_max = max;
	if (tv != NULL)
		sp->sp_idle = *tv;
	else
		sp->sp_idle.tv_sec = sp->sp_idle.tv_usec = 0;
}

static void
unsplice(int fd)
{
	struct splice sp;
	int error;

	splice_init(&sp, -1, 0, NULL);
	error = setsockopt(fd, SOL_SOCKET, SO_SPLICE, &sp, sizeof(sp));
	ATF_REQUIRE_MSG(error == 0, "setsockopt failed: %s", strerror(errno));
}

static void
unsplice_pair(int fd1, int fd2)
{
	unsplice(fd1);
	unsplice(fd2);
}

static void
splice_pair(int fd1, int fd2, off_t max, struct timeval *tv)
{
	struct splice sp;
	int error;

	splice_init(&sp, fd1, max, tv);
	error = setsockopt(fd2, SOL_SOCKET, SO_SPLICE, &sp, sizeof(sp));
	ATF_REQUIRE_MSG(error == 0, "setsockopt failed: %s", strerror(errno));

	splice_init(&sp, fd2, max, tv);
	error = setsockopt(fd1, SOL_SOCKET, SO_SPLICE, &sp, sizeof(sp));
	ATF_REQUIRE_MSG(error == 0, "setsockopt failed: %s", strerror(errno));
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

	memset(sc, 0, sizeof(*sc));
	tcp_socketpair(sc->left);
	tcp_socketpair(sc->right);
	splice_pair(sc->left[1], sc->right[0], max, tv);
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

	ATF_REQUIRE(nspliced(sc.left[1]) == 0);
	ATF_REQUIRE(nspliced(sc.right[0]) == 0);

	/* Left-to-right. */
	c = 'M';
	n = write(sc.left[0], &c, 1);
	ATF_REQUIRE_MSG(n == 1, "write failed: %s", strerror(errno));
	n = read(sc.right[1], &c, 1);
	ATF_REQUIRE_MSG(n == 1, "read failed: %s", strerror(errno));
	ATF_REQUIRE_MSG(c == 'M', "unexpected character: %c", c);
	ATF_REQUIRE(nspliced(sc.left[1]) == 1);
	ATF_REQUIRE(nspliced(sc.right[0]) == 0);

	/* Right-to-left. */
	c = 'J';
	n = write(sc.right[1], &c, 1);
	ATF_REQUIRE_MSG(n == 1, "write failed: %s", strerror(errno));
	n = read(sc.left[0], &c, 1);
	ATF_REQUIRE_MSG(n == 1, "read failed: %s", strerror(errno));
	ATF_REQUIRE_MSG(c == 'J', "unexpected character: %c", c);
	ATF_REQUIRE(nspliced(sc.left[1]) == 1);
	ATF_REQUIRE(nspliced(sc.right[0]) == 1);

	splice_conn_fini(&sc);
}

static void
remove_rights(int fd, const cap_rights_t *toremove)
{
	cap_rights_t rights;
	int error;

	error = cap_rights_get(fd, &rights);
	ATF_REQUIRE_MSG(error == 0, "cap_rights_get failed: %s",
	    strerror(errno));
	cap_rights_remove(&rights, toremove);
	error = cap_rights_limit(fd, &rights);
	ATF_REQUIRE_MSG(error == 0, "cap_rights_limit failed: %s",
	    strerror(errno));
}

/*
 * Verify that splicing fails when the socket is missing the necessary rights.
 */
ATF_TC_WITHOUT_HEAD(splice_capsicum);
ATF_TC_BODY(splice_capsicum, tc)
{
	struct splice sp;
	cap_rights_t rights;
	off_t n;
	int error, left[2], right[2];

	tcp_socketpair(left);
	tcp_socketpair(right);

	/*
	 * Make sure that we splice a socket that's missing recv rights.
	 */
	remove_rights(left[1], cap_rights_init(&rights, CAP_RECV));
	splice_init(&sp, right[0], 0, NULL);
	error = setsockopt(left[1], SOL_SOCKET, SO_SPLICE, &sp, sizeof(sp));
	ATF_REQUIRE_ERRNO(ENOTCAPABLE, error == -1);

	/* Make sure we can still splice left[1] in the other direction. */
	splice_init(&sp, left[1], 0, NULL);
	error = setsockopt(right[0], SOL_SOCKET, SO_SPLICE, &sp, sizeof(sp));
	ATF_REQUIRE_MSG(error == 0, "setsockopt failed: %s", strerror(errno));
	splice_init(&sp, -1, 0, NULL);
	error = setsockopt(right[0], SOL_SOCKET, SO_SPLICE, &sp, sizeof(sp));
	ATF_REQUIRE_MSG(error == 0, "setsockopt failed: %s", strerror(errno));

	/*
	 * Now remove send rights from left[1] and verify that splicing is no
	 * longer possible.
	 */
	remove_rights(left[1], cap_rights_init(&rights, CAP_SEND));
	splice_init(&sp, left[1], 0, NULL);
	error = setsockopt(right[0], SOL_SOCKET, SO_SPLICE, &sp, sizeof(sp));
	ATF_REQUIRE_ERRNO(ENOTCAPABLE, error == -1);

	/*
	 * It's still ok to query the SO_SPLICE state though.
	 */
	n = -1;
	error = getsockopt(left[1], SOL_SOCKET, SO_SPLICE, &n,
	    &(socklen_t){ sizeof(n) });
	ATF_REQUIRE_MSG(error == 0, "getsockopt failed: %s", strerror(errno));
	ATF_REQUIRE(n == 0);

	/*
	 * Make sure that we can unsplice a spliced pair without any rights
	 * other than CAP_SETSOCKOPT.
	 */
	splice_pair(left[0], right[1], 0, NULL);
	error = cap_rights_limit(left[0],
	    cap_rights_init(&rights, CAP_SETSOCKOPT));
	ATF_REQUIRE_MSG(error == 0, "cap_rights_limit failed: %s",
	    strerror(errno));
	unsplice(left[0]);

	checked_close(left[0]);
	checked_close(left[1]);
	checked_close(right[0]);
	checked_close(right[1]);
}

/*
 * Verify that a splice byte limit is applied.
 */
ATF_TC_WITHOUT_HEAD(splice_limit_bytes);
ATF_TC_BODY(splice_limit_bytes, tc)
{
	struct splice_conn sc;
	off_t sofar;
	ssize_t n;
	uint8_t b, buf[128];

	splice_conn_init_limits(&sc, sizeof(buf) + 1, NULL);

	memset(buf, 'A', sizeof(buf));
	for (size_t total = sizeof(buf); total > 0; total -= n) {
		n = write(sc.left[0], buf, total);
		ATF_REQUIRE_MSG(n > 0, "write failed: %s", strerror(errno));
	}
	for (size_t total = sizeof(buf); total > 0; total -= n) {
		n = read(sc.right[1], buf, sizeof(buf));
		ATF_REQUIRE_MSG(n > 0, "read failed: %s", strerror(errno));
	}

	sofar = nspliced(sc.left[1]);
	ATF_REQUIRE(sofar == sizeof(buf));

	/* Trigger an unsplice by writing the last byte. */
	b = 'B';
	n = write(sc.left[0], &b, 1);
	ATF_REQUIRE_MSG(n == 1, "write failed: %s", strerror(errno));
	n = read(sc.right[1], &b, 1);
	ATF_REQUIRE_MSG(n == 1, "read failed: %s", strerror(errno));
	ATF_REQUIRE(b == 'B');

	/*
	 * The next byte should appear on the other side of the connection
	 * rather than the splice.
	 */
	b = 'C';
	n = write(sc.left[0], &b, 1);
	ATF_REQUIRE_MSG(n == 1, "write failed: %s", strerror(errno));
	n = read(sc.left[1], &b, 1);
	ATF_REQUIRE_MSG(n == 1, "write failed: %s", strerror(errno));
	ATF_REQUIRE(b == 'C');

	splice_conn_check_empty(&sc);

	splice_conn_fini(&sc);
}

/*
 * Make sure that listen() fails on spliced sockets, and that SO_SPLICE can't be
 * used with listening sockets.
 */
ATF_TC_WITHOUT_HEAD(splice_listen);
ATF_TC_BODY(splice_listen, tc)
{
	struct splice sp;
	struct splice_conn sc;
	int error, sd[3];

	/*
	 * These should fail regardless since the sockets are connected, but it
	 * doesn't hurt to check.
	 */
	splice_conn_init(&sc);
	error = listen(sc.left[1], 1);
	ATF_REQUIRE_ERRNO(EINVAL, error == -1);
	error = listen(sc.right[0], 1);
	ATF_REQUIRE_ERRNO(EINVAL, error == -1);
	splice_conn_fini(&sc);

	tcp_socketpair(sd);
	sd[2] = socket(PF_INET, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(sd[2] >= 0, "socket failed: %s", strerror(errno));
	error = listen(sd[2], 1);
	ATF_REQUIRE_MSG(error == 0, "listen failed: %s", strerror(errno));

	/*
	 * Make sure a listening socket can't be spliced in either direction.
	 */
	splice_init(&sp, sd[2], 0, NULL);
	error = setsockopt(sd[1], SOL_SOCKET, SO_SPLICE, &sp, sizeof(sp));
	ATF_REQUIRE_ERRNO(EINVAL, error == -1);
	splice_init(&sp, sd[1], 0, NULL);
	error = setsockopt(sd[2], SOL_SOCKET, SO_SPLICE, &sp, sizeof(sp));
	ATF_REQUIRE_ERRNO(EINVAL, error == -1);

	/*
	 * Make sure we can't try to unsplice a listening socket.
	 */
	splice_init(&sp, -1, 0, NULL);
	error = setsockopt(sd[2], SOL_SOCKET, SO_SPLICE, &sp, sizeof(sp));
	ATF_REQUIRE_ERRNO(EINVAL, error == -1);

	checked_close(sd[0]);
	checked_close(sd[1]);
	checked_close(sd[2]);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, splice_basic);
	ATF_TP_ADD_TC(tp, splice_capsicum);
	ATF_TP_ADD_TC(tp, splice_limit_bytes);
	ATF_TP_ADD_TC(tp, splice_listen);
	return (atf_no_error());
}
