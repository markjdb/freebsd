/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2019 The FreeBSD Foundation
 *
 * This software was developed by BFF Storage Systems, LLC under sponsorship
 * from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

extern "C" {
#include <sys/param.h>

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/user.h>

#include <fcntl.h>
#include <libutil.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "mntopts.h"	// for build_iovec
}

#include <gtest/gtest.h>

#include "mockfs.hh"

using namespace testing;

int verbosity = 0;

const char* opcode2opname(uint32_t opcode)
{
	const int NUM_OPS = 39;
	const char* table[NUM_OPS] = {
		"Unknown (opcode 0)",
		"LOOKUP",
		"FORGET",
		"GETATTR",
		"SETATTR",
		"READLINK",
		"SYMLINK",
		"Unknown (opcode 7)",
		"MKNOD",
		"MKDIR",
		"UNLINK",
		"RMDIR",
		"RENAME",
		"LINK",
		"OPEN",
		"READ",
		"WRITE",
		"STATFS",
		"RELEASE",
		"Unknown (opcode 19)",
		"FSYNC",
		"SETXATTR",
		"GETXATTR",
		"LISTXATTR",
		"REMOVEXATTR",
		"FLUSH",
		"INIT",
		"OPENDIR",
		"READDIR",
		"RELEASEDIR",
		"FSYNCDIR",
		"GETLK",
		"SETLK",
		"SETLKW",
		"ACCESS",
		"CREATE",
		"INTERRUPT",
		"BMAP",
		"DESTROY"
	};
	if (opcode >= NUM_OPS)
		return ("Unknown (opcode > max)");
	else
		return (table[opcode]);
}

ProcessMockerT
ReturnErrno(int error)
{
	return([=](auto in, auto &out) {
		auto out0 = new mockfs_buf_out;
		out0->header.unique = in->header.unique;
		out0->header.error = -error;
		out0->header.len = sizeof(out0->header);
		out.push_back(out0);
	});
}

/* Helper function used for returning negative cache entries for LOOKUP */
ProcessMockerT
ReturnNegativeCache(const struct timespec *entry_valid)
{
	return([=](auto in, auto &out) {
		/* nodeid means ENOENT and cache it */
		auto out0 = new mockfs_buf_out;
		out0->body.entry.nodeid = 0;
		out0->header.unique = in->header.unique;
		out0->header.error = 0;
		out0->body.entry.entry_valid = entry_valid->tv_sec;
		out0->body.entry.entry_valid_nsec = entry_valid->tv_nsec;
		SET_OUT_HEADER_LEN(out0, entry);
		out.push_back(out0);
	});
}

ProcessMockerT
ReturnImmediate(std::function<void(const struct mockfs_buf_in *in,
				   struct mockfs_buf_out *out)> f)
{
	return([=](auto in, auto &out) {
		auto out0 = new mockfs_buf_out;
		out0->header.unique = in->header.unique;
		f(in, out0);
		out.push_back(out0);
	});
}

void sigint_handler(int __unused sig) {
	// Don't do anything except interrupt the daemon's read(2) call
}

void debug_fuseop(const mockfs_buf_in *in)
{
	printf("%-11s ino=%2lu", opcode2opname(in->header.opcode),
		in->header.nodeid);
	if (verbosity > 1) {
		printf(" uid=%5u gid=%5u pid=%5u unique=%lu len=%u",
			in->header.uid, in->header.gid, in->header.pid,
			in->header.unique, in->header.len);
	}
	switch (in->header.opcode) {
		const char *name, *value;

		case FUSE_ACCESS:
			printf(" mask=%#x", in->body.access.mask);
			break;
		case FUSE_CREATE:
			name = (const char*)in->body.bytes +
				sizeof(fuse_open_in);
			printf(" flags=%#x name=%s",
				in->body.open.flags, name);
			break;
		case FUSE_FLUSH:
			printf(" fh=%#lx lock_owner=%lu", in->body.flush.fh,
				in->body.flush.lock_owner);
			break;
		case FUSE_FORGET:
			printf(" nlookup=%lu", in->body.forget.nlookup);
			break;
		case FUSE_FSYNC:
			printf(" flags=%#x", in->body.fsync.fsync_flags);
			break;
		case FUSE_FSYNCDIR:
			printf(" flags=%#x", in->body.fsyncdir.fsync_flags);
			break;
		case FUSE_INTERRUPT:
			printf(" unique=%lu", in->body.interrupt.unique);
			break;
		case FUSE_LINK:
			printf(" oldnodeid=%lu", in->body.link.oldnodeid);
			break;
		case FUSE_LOOKUP:
			printf(" %s", in->body.lookup);
			break;
		case FUSE_MKNOD:
			printf(" mode=%#o rdev=%x", in->body.mknod.mode,
				in->body.mknod.rdev);
			break;
		case FUSE_OPEN:
			printf(" flags=%#x mode=%#o",
				in->body.open.flags, in->body.open.mode);
			break;
		case FUSE_OPENDIR:
			printf(" flags=%#x mode=%#o",
				in->body.opendir.flags, in->body.opendir.mode);
			break;
		case FUSE_READ:
			printf(" offset=%lu size=%u", in->body.read.offset,
				in->body.read.size);
			break;
		case FUSE_READDIR:
			printf(" fh=%#lx offset=%lu size=%u",
				in->body.readdir.fh, in->body.readdir.offset,
				in->body.readdir.size);
			break;
		case FUSE_RELEASE:
			printf(" fh=%#lx flags=%#x lock_owner=%lu",
				in->body.release.fh,
				in->body.release.flags,
				in->body.release.lock_owner);
			break;
		case FUSE_SETATTR:
			if (verbosity <= 1) {
				printf(" valid=%#x", in->body.setattr.valid);
				break;
			}
			if (in->body.setattr.valid & FATTR_MODE)
				printf(" mode=%#o", in->body.setattr.mode);
			if (in->body.setattr.valid & FATTR_UID)
				printf(" uid=%u", in->body.setattr.uid);
			if (in->body.setattr.valid & FATTR_GID)
				printf(" gid=%u", in->body.setattr.gid);
			if (in->body.setattr.valid & FATTR_SIZE)
				printf(" size=%zu", in->body.setattr.size);
			if (in->body.setattr.valid & FATTR_ATIME)
				printf(" atime=%zu.%u",
					in->body.setattr.atime,
					in->body.setattr.atimensec);
			if (in->body.setattr.valid & FATTR_MTIME)
				printf(" mtime=%zu.%u",
					in->body.setattr.mtime,
					in->body.setattr.mtimensec);
			if (in->body.setattr.valid & FATTR_FH)
				printf(" fh=%zu", in->body.setattr.fh);
			break;
		case FUSE_SETLK:
			printf(" fh=%#lx owner=%lu type=%u pid=%u",
				in->body.setlk.fh, in->body.setlk.owner,
				in->body.setlk.lk.type,
				in->body.setlk.lk.pid);
			if (verbosity >= 2) {
				printf(" range=[%lu-%lu]",
					in->body.setlk.lk.start,
					in->body.setlk.lk.end);
			}
			break;
		case FUSE_SETXATTR:
			/* 
			 * In theory neither the xattr name and value need be
			 * ASCII, but in this test suite they always are.
			 */
			name = (const char*)in->body.bytes +
				sizeof(fuse_setxattr_in);
			value = name + strlen(name) + 1;
			printf(" %s=%s", name, value);
			break;
		case FUSE_WRITE:
			printf(" fh=%#lx offset=%lu size=%u flags=%u",
				in->body.write.fh,
				in->body.write.offset, in->body.write.size,
				in->body.write.write_flags);
			break;
		default:
			break;
	}
	printf("\n");
}

MockFS::MockFS(int max_readahead, bool allow_other, bool default_permissions,
	bool push_symlinks_in, bool ro, uint32_t flags)
{
	struct sigaction sa;
	struct iovec *iov = NULL;
	int iovlen = 0;
	char fdstr[15];
	const bool trueval = true;

	m_daemon_id = NULL;
	m_maxreadahead = max_readahead;
	m_quit = false;

	/*
	 * Kyua sets pwd to a testcase-unique tempdir; no need to use
	 * mkdtemp
	 */
	/*
	 * googletest doesn't allow ASSERT_ in constructors, so we must throw
	 * instead.
	 */
	if (mkdir("mountpoint" , 0755) && errno != EEXIST)
		throw(std::system_error(errno, std::system_category(),
			"Couldn't make mountpoint directory"));

	m_fuse_fd = open("/dev/fuse", O_CLOEXEC | O_RDWR);
	if (m_fuse_fd < 0)
		throw(std::system_error(errno, std::system_category(),
			"Couldn't open /dev/fuse"));
	sprintf(fdstr, "%d", m_fuse_fd);

	m_pid = getpid();
	m_child_pid = -1;

	build_iovec(&iov, &iovlen, "fstype", __DECONST(void *, "fusefs"), -1);
	build_iovec(&iov, &iovlen, "fspath",
		    __DECONST(void *, "mountpoint"), -1);
	build_iovec(&iov, &iovlen, "from", __DECONST(void *, "/dev/fuse"), -1);
	build_iovec(&iov, &iovlen, "fd", fdstr, -1);
	if (allow_other) {
		build_iovec(&iov, &iovlen, "allow_other",
			__DECONST(void*, &trueval), sizeof(bool));
	}
	if (default_permissions) {
		build_iovec(&iov, &iovlen, "default_permissions",
			__DECONST(void*, &trueval), sizeof(bool));
	}
	if (push_symlinks_in) {
		build_iovec(&iov, &iovlen, "push_symlinks_in",
			__DECONST(void*, &trueval), sizeof(bool));
	}
	if (ro) {
		build_iovec(&iov, &iovlen, "ro",
			__DECONST(void*, &trueval), sizeof(bool));
	}
	if (nmount(iov, iovlen, 0))
		throw(std::system_error(errno, std::system_category(),
			"Couldn't mount filesystem"));

	// Setup default handler
	ON_CALL(*this, process(_, _))
		.WillByDefault(Invoke(this, &MockFS::process_default));

	init(flags);
	bzero(&sa, sizeof(sa));
	sa.sa_handler = sigint_handler;
	sa.sa_flags = 0;	/* Don't set SA_RESTART! */
	if (0 != sigaction(SIGUSR1, &sa, NULL))
		throw(std::system_error(errno, std::system_category(),
			"Couldn't handle SIGUSR1"));
	if (pthread_create(&m_daemon_id, NULL, service, (void*)this))
		throw(std::system_error(errno, std::system_category(),
			"Couldn't Couldn't start fuse thread"));
}

MockFS::~MockFS() {
	kill_daemon();
	if (m_daemon_id != NULL) {
		pthread_join(m_daemon_id, NULL);
		m_daemon_id = NULL;
	}
	::unmount("mountpoint", MNT_FORCE);
	rmdir("mountpoint");
}

void MockFS::init(uint32_t flags) {
	mockfs_buf_in *in;
	mockfs_buf_out *out;

	in = (mockfs_buf_in*) malloc(sizeof(*in));
	ASSERT_TRUE(in != NULL);
	out = (mockfs_buf_out*) malloc(sizeof(*out));
	ASSERT_TRUE(out != NULL);

	read_request(in);
	ASSERT_EQ(FUSE_INIT, in->header.opcode);

	memset(out, 0, sizeof(*out));
	out->header.unique = in->header.unique;
	out->header.error = 0;
	out->body.init.major = FUSE_KERNEL_VERSION;
	out->body.init.minor = FUSE_KERNEL_MINOR_VERSION;
	out->body.init.flags = in->body.init.flags & flags;

	/*
	 * The default max_write is set to this formula in libfuse, though
	 * individual filesystems can lower it.  The "- 4096" was added in
	 * commit 154ffe2, with the commit message "fix".
	 */
	uint32_t default_max_write = 32 * getpagesize() + 0x1000 - 4096;
	/* For testing purposes, it should be distinct from MAXPHYS */
	m_max_write = MIN(default_max_write, MAXPHYS / 2);
	out->body.init.max_write = m_max_write;

	out->body.init.max_readahead = m_maxreadahead;
	SET_OUT_HEADER_LEN(out, init);
	write(m_fuse_fd, out, out->header.len);

	free(in);
}

void MockFS::kill_daemon() {
	m_quit = true;
	if (m_daemon_id != NULL)
		pthread_kill(m_daemon_id, SIGUSR1);
	// Closing the /dev/fuse file descriptor first allows unmount to
	// succeed even if the daemon doesn't correctly respond to commands
	// during the unmount sequence.
	close(m_fuse_fd);
	m_fuse_fd = -1;
}

void MockFS::loop() {
	mockfs_buf_in *in;
	std::vector<mockfs_buf_out*> out;

	in = (mockfs_buf_in*) malloc(sizeof(*in));
	ASSERT_TRUE(in != NULL);
	while (!m_quit) {
		bzero(in, sizeof(*in));
		read_request(in);
		if (m_quit)
			break;
		if (verbosity > 0)
			debug_fuseop(in);
		if (pid_ok((pid_t)in->header.pid)) {
			process(in, out);
		} else {
			/* 
			 * Reject any requests from unknown processes.  Because
			 * we actually do mount a filesystem, plenty of
			 * unrelated system daemons may try to access it.
			 */
			process_default(in, out);
		}
		for (auto &it: out) {
			ASSERT_TRUE(write(m_fuse_fd, it, it->header.len) > 0 ||
				    errno == EAGAIN)
				<< strerror(errno);
			delete it;
		}
		out.clear();
	}
	free(in);
}

bool MockFS::pid_ok(pid_t pid) {
	if (pid == m_pid) {
		return (true);
	} else if (pid == m_child_pid) {
		return (true);
	} else {
		struct kinfo_proc *ki;
		bool ok = false;

		ki = kinfo_getproc(pid);
		if (ki == NULL)
			return (false);
		/* 
		 * Allow access by the aio daemon processes so that our tests
		 * can use aio functions
		 */
		if (0 == strncmp("aiod", ki->ki_comm, 4))
			ok = true;
		free(ki);
		return (ok);
	}
}

void MockFS::process_default(const mockfs_buf_in *in,
		std::vector<mockfs_buf_out*> &out)
{
	if (verbosity > 1)
		printf("%-11s REJECTED (wrong pid %d)\n",
			opcode2opname(in->header.opcode), in->header.pid);
	auto out0 = new mockfs_buf_out;
	out0->header.unique = in->header.unique;
	out0->header.error = -EOPNOTSUPP;
	out0->header.len = sizeof(out0->header);
	out.push_back(out0);
}

void MockFS::read_request(mockfs_buf_in *in) {
	ssize_t res;

	res = read(m_fuse_fd, in, sizeof(*in));
	if (res < 0 && !m_quit)
		perror("read");
	ASSERT_TRUE(res >= (ssize_t)sizeof(in->header) || m_quit);
}

void* MockFS::service(void *pthr_data) {
	MockFS *mock_fs = (MockFS*)pthr_data;

	mock_fs->loop();

	return (NULL);
}

void MockFS::unmount() {
	::unmount("mountpoint", 0);
}
