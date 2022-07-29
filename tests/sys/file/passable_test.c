/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2022 The FreeBSD Foundation
 *
 * This software was developed by Mark Johnston under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Tests for the kernel's handling of descriptors without DFLAG_PASSABLE set
 * (i.e., kqueues).
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <atf-c.h>

#define	FMT_ERR(s)		s ": %s", strerror(errno)

#define	CHECKED_CLOSE(fd)	\
	ATF_REQUIRE_MSG(close(fd) == 0, FMT_ERR("close"))

/* Wait for a child process to exit with status 0. */
static void
waitchild(pid_t child, int exstatus)
{
	int error, status;

	error = waitpid(child, &status, 0);
	ATF_REQUIRE_MSG(error != -1, FMT_ERR("waitpid"));
	ATF_REQUIRE_MSG(WIFEXITED(status), "child exited abnormally, status %d",
	    status);
	ATF_REQUIRE_MSG(WEXITSTATUS(status) == exstatus,
	    "child exit status is %d, expected %d",
	    WEXITSTATUS(status), exstatus);
}

static int
fork_check_inherit(int fd)
{
	int error;

	error = fcntl(fd, F_GETFL);
	if (error != -1)
		return (1);
	else
		return (0);
}

/*
 * Verify kqueues are not inherited by the child of a fork().
 */
ATF_TC_WITHOUT_HEAD(fork_inherit);
ATF_TC_BODY(fork_inherit, tc)
{
	pid_t child;
	int pd, kq;

	kq = kqueue();
	ATF_REQUIRE_MSG(kq >= 0, FMT_ERR("kqueue"));

	child = fork();
	ATF_REQUIRE_MSG(child >= 0, FMT_ERR("fork"));
	if (child == 0)
		_exit(fork_check_inherit(kq));
	waitchild(child, 0);

	child = pdfork(&pd, 0);
	ATF_REQUIRE_MSG(child >= 0, FMT_ERR("pdfork"));
	if (child == 0)
		_exit(fork_check_inherit(kq));
	waitchild(child, 0);
	CHECKED_CLOSE(pd);

	CHECKED_CLOSE(kq);
}

/*
 * rfork() can be used to share file descriptor tables among processes.  Make
 * sure that this doesn't work if non-shareable descriptors are present in the
 * table.
 */
ATF_TC_WITHOUT_HEAD(fork_share);
ATF_TC_BODY(fork_share, tc)
{
	pid_t child;
	int p[2], kq;
	char ch;

	ATF_REQUIRE_MSG(pipe(p) == 0, FMT_ERR("pipe"));

	child = rfork(RFPROC);
	ATF_REQUIRE_MSG(child >= 0, FMT_ERR("rfork"));
	if (child == 0) {
		kq = kqueue();
		if (kq >= 0)
			_exit(1);
		if (errno != EOPNOTSUPP)
			_exit(2);

		/*
		 * Block until the parent has had a chance to test kqueue
		 * creation.
		 */
		if (read(p[0], &ch, 1) != 1)
			_exit(3);

		_exit(0);
	}

	kq = kqueue();
	ATF_REQUIRE_ERRNO(EOPNOTSUPP, kq < 0);
	ch = 0;
	ATF_REQUIRE_MSG(write(p[1], &ch, 1) == 1, FMT_ERR("write"));
	waitchild(child, 0);
	CHECKED_CLOSE(p[0]);
	CHECKED_CLOSE(p[1]);

	kq = kqueue();
	ATF_REQUIRE_MSG(kq >= 0, FMT_ERR("kqueue"));

	child = rfork(RFPROC);
	ATF_REQUIRE_ERRNO(EOPNOTSUPP, child == -1);

	CHECKED_CLOSE(kq);
}

/*
 * Verify that it is not possible to transfer non-shareable descriptors over a
 * unix domain socket.
 */
ATF_TC_WITHOUT_HEAD(unix_socket_transfer);
ATF_TC_BODY(unix_socket_transfer, tc)
{
	struct msghdr msg;
	struct cmsghdr *cm;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(int))];
	int kq, sd[2];
	char ch;

	kq = kqueue();
	ATF_REQUIRE_MSG(kq >= 0, FMT_ERR("kqueue"));

	ATF_REQUIRE_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, sd) == 0,
	    FMT_ERR("socketpair"));

	memset(buf, 0, sizeof(buf));
	cm = (struct cmsghdr *)(void *)buf;

	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &kq, sizeof(kq));

	ch = 0;
	iov.iov_base = &ch;
	iov.iov_len = 1;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = CMSG_SPACE(sizeof(int));

	ATF_REQUIRE_ERRNO(EOPNOTSUPP, sendmsg(sd[0], &msg, 0) == -1);

	CHECKED_CLOSE(sd[0]);
	CHECKED_CLOSE(sd[1]);
	CHECKED_CLOSE(kq);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fork_inherit);
	ATF_TP_ADD_TC(tp, fork_share);
	ATF_TP_ADD_TC(tp, unix_socket_transfer);

	return (atf_no_error());
}
