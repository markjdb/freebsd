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

#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include <atf-c.h>

/*
 * Map a region that can be used for "direct" writes in the kernel's pipe
 * implementation, i.e., writes which are opportunistically implemented as
 * direct copies between the participating address spaces.
 */
static void *
map_pipe_direct_buffer(size_t *lenp)
{
	void *addr;
	size_t len, sysctllen;
	int error;

	sysctllen = sizeof(len);
	error = sysctlbyname("kern.ipc.pipe_mindirect", &len, &sysctllen,
	    NULL, 0);
	ATF_REQUIRE(error == 0);
	ATF_REQUIRE(len > 0);

	addr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
	ATF_REQUIRE(addr != MAP_FAILED);

	*lenp = len;
	return (addr);
}

struct pipe_direct_write_unmap_thread_arg {
	void *addr;
	size_t len;
	int fd1, fd2;
	char exc;
};

static void *
pipe_direct_write_unmap_thread(void *_arg)
{
	struct pollfd pollfd;
	struct pipe_direct_write_unmap_thread_arg *arg;
	char *buf;
	ssize_t n;
	char c;

	arg = _arg;

	/* Wait for the other thread to block in the direct write path. */
	pollfd.fd = arg->fd1;
	pollfd.events = POLLIN | POLLPRI;
	pollfd.revents = 0;
	if (poll(&pollfd, 1, -1) != 1)
		_exit(10);

	/* Now the writer holds the pages backing the shared mapping. */
	if (munmap(arg->addr, arg->len) != 0)
		_exit(11);

	/* Signal the parent process to have it write to the shared mapping. */
	c = 1;
	if (write(arg->fd2, &c, 1) != 1)
		_exit(12);
	if (read(arg->fd2, &c, 1) != 1)
		_exit(13);
	if (c != 2)
		_exit(14);

	/*
	 * Read out a copy of the mapped data, make sure the parent's
	 * modification is not visible.
	 */
	buf = malloc(arg->len);
	if (buf == NULL)
		_exit(15);
	n = read(arg->fd1, buf, arg->len);
	if (n < 0 || (size_t)n != arg->len)
		_exit(16);
	for (size_t i = 0; i < arg->len; i++)
		if (buf[i] != arg->exc)
			_exit(17);
	free(buf);

	return (NULL);
}

static void
pipe_direct_write_child(int sigfd, void *addr, size_t len, char exc)
{
	struct pipe_direct_write_unmap_thread_arg arg;
	pthread_t tid;
	ssize_t n;
	int fd[2];

	if (pipe(fd) == -1)
		_exit(1);

	arg.addr = addr;
	arg.len = len;
	arg.fd1 = fd[1];
	arg.fd2 = sigfd;
	arg.exc = exc;
	if (pthread_create(&tid, NULL, pipe_direct_write_unmap_thread, &arg) !=
	    0)
		_exit(2);

	n = write(fd[0], addr, len);
	if (n < 0 || (size_t)n != len)
		_exit(3);

	if (pthread_join(tid, NULL) != 0)
		_exit(4);

	if (close(fd[0]) != 0)
		_exit(5);
	if (close(fd[1]) != 0)
		_exit(6);
}

/*
 * Verify that the pipe code's "direct write" optimization does not violate COW
 * semantics.  The basic idea is to map a region of memory, fork, and modify the
 * memory in the parent after having unmapped the region in the child.  The
 * child uses the direct write mechanism to obtain a reference on the pages
 * backing the region, and the kernel's COW logic must ensure that the parent's
 * modifications are not made visible via the pipe.
 *
 * Based on a test case by David Hildenbrand <david@redhat.com>.
 */
ATF_TC_WITHOUT_HEAD(cow__pipe_direct_write);
ATF_TC_BODY(cow__pipe_direct_write, tc)
{
	char *addr;
	ssize_t n;
	size_t len;
	int fd[2], status;
	pid_t pid;
	char c, oc;

	addr = map_pipe_direct_buffer(&len);

	oc = 'a';
	memset(addr, oc, len);

	ATF_REQUIRE(pipe(fd) == 0);

	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		pipe_direct_write_child(fd[0], addr, len, oc);
		_exit(0);
	}

	/* Wait for the child to unmap the COW region. */
	n = read(fd[1], &c, 1);
	ATF_REQUIRE(n == 1);
	ATF_REQUIRE(c == 1);

	/* This modification to the shared mapping must be private. */
	memset(addr, 'b', len);

	c = 2;
	n = write(fd[1], &c, 1);
	ATF_REQUIRE(n == 1);

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_MSG(WEXITSTATUS(status) == 0,
	    "child exited with status %d", WEXITSTATUS(status));

	ATF_REQUIRE(close(fd[0]) == 0);
	ATF_REQUIRE(close(fd[1]) == 0);
	ATF_REQUIRE(munmap(addr, len) == 0);
}

static void *
write_thread(void *_arg)
{
	struct pipe_direct_write_unmap_thread_arg *arg;
	ssize_t n;

	arg = _arg;

	n = write(arg->fd1, arg->addr, arg->len);
	ATF_REQUIRE(n >= 0);
	ATF_REQUIRE((size_t)n == arg->len);

	return (NULL);
}

static void
pipe_direct_write_child2(int sigfd, char *addr, size_t len, char exc)
{
	ssize_t n;
	char c;

	n = read(sigfd, &c, 1);
	if (n < 0)
		_exit(1);
	if (n != 1)
		_exit(2);

	memset(addr, exc + 1, len);
}

/*
 * A variant of pipe_direct_write where the parent uses the same bug to read a
 * child process' memory.
 */
ATF_TC_WITHOUT_HEAD(cow__pipe_direct_write2);
ATF_TC_BODY(cow__pipe_direct_write2, tc)
{
	struct pipe_direct_write_unmap_thread_arg arg;
	struct pollfd pollfd;
	char *addr, *buf;
	pthread_t tid;
	size_t len;
	ssize_t n;
	int fd[2], fd2[2], status;
	pid_t pid;
	char oc;

	addr = map_pipe_direct_buffer(&len);

	oc = 'a';
	memset(addr, oc, len);

	ATF_REQUIRE(pipe(fd) == 0);

	arg.addr = addr;
	arg.len = len;
	arg.fd1 = fd[1];
	arg.fd2 = -1;
	arg.exc = oc;
	ATF_REQUIRE(pthread_create(&tid, NULL, write_thread, &arg) == 0);

	/* Wait for the writing thread to block. */
	pollfd.fd = fd[0];
	pollfd.events = POLLIN;
	pollfd.revents = 0;
	ATF_REQUIRE(poll(&pollfd, 1, -1) == 1);

	ATF_REQUIRE(pipe(fd2) == 0);

	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		pipe_direct_write_child2(fd2[0], addr, len, oc);
		_exit(0);
	}

	ATF_REQUIRE(munmap(addr, len) == 0);

	/* Signal our child process and wait for it to exit. */
	ATF_REQUIRE(write(fd2[1], &oc, 1) == 1);

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_MSG(WEXITSTATUS(status) == 0,
	    "child exited with status %d", WEXITSTATUS(status));

	buf = malloc(len);
	ATF_REQUIRE(buf != NULL);
	n = read(fd[0], buf, len);
	ATF_REQUIRE(n >= 0);
	ATF_REQUIRE((size_t)n == len);
	for (size_t i = 0; i < len; i++)
		ATF_REQUIRE(buf[i] == oc);

	ATF_REQUIRE(pthread_join(tid, NULL) == 0);

	ATF_REQUIRE(close(fd[0]) == 0);
	ATF_REQUIRE(close(fd[1]) == 0);
	ATF_REQUIRE(close(fd2[0]) == 0);
	ATF_REQUIRE(close(fd2[1]) == 0);
}

ATF_TP_ADD_TCS(tp)
{
	/* XXX-MJ this can go the other way, i.e., parent reads child */
	/* XXX-MJ does proc_rwmem() have a similar problem? */
	/* XXX-MJ how can we ensure that vm_fault_soft_fast() is exercised */
	ATF_TP_ADD_TC(tp, cow__pipe_direct_write);
	ATF_TP_ADD_TC(tp, cow__pipe_direct_write2);
	return (atf_no_error());
}
