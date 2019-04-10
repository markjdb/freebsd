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
#include <sys/mman.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <pwd.h>
#include <semaphore.h>
#include <unistd.h>
}

#include <gtest/gtest.h>

#include "mockfs.hh"
#include "utils.hh"

using namespace testing;

/* Check that fusefs(4) is accessible and the current user can mount(2) */
void check_environment()
{
	const char *devnode = "/dev/fuse";
	const char *usermount_node = "vfs.usermount";
	int usermount_val = 0;
	size_t usermount_size = sizeof(usermount_val);
	if (eaccess(devnode, R_OK | W_OK)) {
		if (errno == ENOENT) {
			GTEST_SKIP() << devnode << " does not exist";
		} else if (errno == EACCES) {
			GTEST_SKIP() << devnode <<
			    " is not accessible by the current user";
		} else {
			GTEST_SKIP() << strerror(errno);
		}
	}
	sysctlbyname(usermount_node, &usermount_val, &usermount_size,
		     NULL, 0);
	if (geteuid() != 0 && !usermount_val)
		GTEST_SKIP() << "current user is not allowed to mount";
}

class FuseEnv: public Environment {
	virtual void SetUp() {
	}
};

void FuseTest::SetUp() {
	const char *node = "vfs.maxbcachebuf";
	int val = 0;
	size_t size = sizeof(val);

	/*
	 * XXX check_environment should be called from FuseEnv::SetUp, but
	 * can't due to https://github.com/google/googletest/issues/2189
	 */
	check_environment();
	if (IsSkipped())
		return;

	ASSERT_EQ(0, sysctlbyname(node, &val, &size, NULL, 0))
		<< strerror(errno);
	m_maxbcachebuf = val;

	try {
		m_mock = new MockFS(m_maxreadahead, m_allow_other,
			m_default_permissions, m_push_symlinks_in, m_ro,
			m_init_flags);
		/* 
		 * FUSE_ACCESS is called almost universally.  Expecting it in
		 * each test case would be super-annoying.  Instead, set a
		 * default expectation for FUSE_ACCESS and return ENOSYS.
		 *
		 * Individual test cases can override this expectation since
		 * googlemock evaluates expectations in LIFO order.
		 */
		EXPECT_CALL(*m_mock, process(
			ResultOf([=](auto in) {
				return (in->header.opcode == FUSE_ACCESS);
			}, Eq(true)),
			_)
		).Times(AnyNumber())
		.WillRepeatedly(Invoke(ReturnErrno(ENOSYS)));
	} catch (std::system_error err) {
		FAIL() << err.what();
	}
}

void
FuseTest::expect_access(uint64_t ino, mode_t access_mode, int error)
{
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in->header.opcode == FUSE_ACCESS &&
				in->header.nodeid == ino &&
				in->body.access.mask == access_mode);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnErrno(error)));
}

void
FuseTest::expect_flush(uint64_t ino, int times, ProcessMockerT r)
{
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in->header.opcode == FUSE_FLUSH &&
				in->header.nodeid == ino);
		}, Eq(true)),
		_)
	).Times(times)
	.WillRepeatedly(Invoke(r));
}

void
FuseTest::expect_forget(uint64_t ino, uint64_t nlookup)
{
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in->header.opcode == FUSE_FORGET &&
				in->header.nodeid == ino &&
				in->body.forget.nlookup == nlookup);
		}, Eq(true)),
		_)
	).WillOnce(Invoke([](auto in __unused, auto &out __unused) {
		/* FUSE_FORGET has no response! */
	}));
}

void FuseTest::expect_getattr(uint64_t ino, uint64_t size)
{
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in->header.opcode == FUSE_GETATTR &&
				in->header.nodeid == ino);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnImmediate([=](auto i __unused, auto out) {
		SET_OUT_HEADER_LEN(out, attr);
		out->body.attr.attr.ino = ino;	// Must match nodeid
		out->body.attr.attr.mode = S_IFREG | 0644;
		out->body.attr.attr.size = size;
		out->body.attr.attr_valid = UINT64_MAX;
	})));
}

void FuseTest::expect_lookup(const char *relpath, uint64_t ino, mode_t mode,
	uint64_t size, int times, uint64_t attr_valid, uid_t uid)
{
	EXPECT_LOOKUP(1, relpath)
	.Times(times)
	.WillRepeatedly(Invoke(ReturnImmediate([=](auto in __unused, auto out) {
		SET_OUT_HEADER_LEN(out, entry);
		out->body.entry.attr.mode = mode;
		out->body.entry.nodeid = ino;
		out->body.entry.attr.nlink = 1;
		out->body.entry.attr_valid = attr_valid;
		out->body.entry.attr.size = size;
		out->body.entry.attr.uid = uid;
	})));
}

void FuseTest::expect_open(uint64_t ino, uint32_t flags, int times)
{
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in->header.opcode == FUSE_OPEN &&
				in->header.nodeid == ino);
		}, Eq(true)),
		_)
	).Times(times)
	.WillRepeatedly(Invoke(ReturnImmediate([=](auto in __unused, auto out) {
		out->header.len = sizeof(out->header);
		SET_OUT_HEADER_LEN(out, open);
		out->body.open.fh = FH;
		out->body.open.open_flags = flags;
	})));
}

void FuseTest::expect_opendir(uint64_t ino)
{
	/* opendir(3) calls fstatfs */
	EXPECT_CALL(*m_mock, process(
		ResultOf([](auto in) {
			return (in->header.opcode == FUSE_STATFS);
		}, Eq(true)),
		_)
	).WillRepeatedly(Invoke(ReturnImmediate([=](auto i __unused, auto out) {
		SET_OUT_HEADER_LEN(out, statfs);
	})));

	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in->header.opcode == FUSE_OPENDIR &&
				in->header.nodeid == ino);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnImmediate([=](auto in __unused, auto out) {
		out->header.len = sizeof(out->header);
		SET_OUT_HEADER_LEN(out, open);
		out->body.open.fh = FH;
	})));
}

void FuseTest::expect_read(uint64_t ino, uint64_t offset, uint64_t isize,
	uint64_t osize, const void *contents)
{
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in->header.opcode == FUSE_READ &&
				in->header.nodeid == ino &&
				in->body.read.fh == FH &&
				in->body.read.offset == offset &&
				in->body.read.size == isize);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnImmediate([=](auto in __unused, auto out) {
		out->header.len = sizeof(struct fuse_out_header) + osize;
		memmove(out->body.bytes, contents, osize);
	}))).RetiresOnSaturation();
}

void FuseTest::expect_release(uint64_t ino, uint64_t fh)
{
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in->header.opcode == FUSE_RELEASE &&
				in->header.nodeid == ino &&
				in->body.release.fh == fh);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnErrno(0)));
}

void FuseTest::expect_releasedir(uint64_t ino, ProcessMockerT r)
{
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in->header.opcode == FUSE_RELEASEDIR &&
				in->header.nodeid == ino &&
				in->body.release.fh == FH);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(r));
}

void FuseTest::expect_unlink(uint64_t parent, const char *path, int error)
{
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in->header.opcode == FUSE_UNLINK &&
				0 == strcmp(path, in->body.unlink) &&
				in->header.nodeid == parent);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnErrno(error)));
}

void FuseTest::expect_write(uint64_t ino, uint64_t offset, uint64_t isize,
	uint64_t osize, uint32_t flags, const void *contents)
{
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			const char *buf = (const char*)in->body.bytes +
				sizeof(struct fuse_write_in);
			bool pid_ok;

			if (in->body.write.write_flags & FUSE_WRITE_CACHE)
				pid_ok = true;
			else
				pid_ok = (pid_t)in->header.pid == getpid();

			return (in->header.opcode == FUSE_WRITE &&
				in->header.nodeid == ino &&
				in->body.write.fh == FH &&
				in->body.write.offset == offset  &&
				in->body.write.size == isize &&
				pid_ok &&
				in->body.write.write_flags == flags &&
				0 == bcmp(buf, contents, isize));
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnImmediate([=](auto in __unused, auto out) {
		SET_OUT_HEADER_LEN(out, write);
		out->body.write.size = osize;
	})));
}

static void
get_unprivileged_uid(uid_t *uid)
{
	struct passwd *pw;

	/* 
	 * First try "tests", Kyua's default unprivileged user.  XXX after
	 * GoogleTest gains a proper Kyua wrapper, get this with the Kyua API
	 */
	pw = getpwnam("tests");
	if (pw == NULL) {
		/* Fall back to "nobody" */
		pw = getpwnam("nobody");
	}
	if (pw == NULL)
		GTEST_SKIP() << "Test requires an unprivileged user";
	*uid = pw->pw_uid;
}

void
FuseTest::fork(bool drop_privs, std::function<void()> parent_func,
	std::function<int()> child_func)
{
	sem_t *sem;
	int mprot = PROT_READ | PROT_WRITE;
	int mflags = MAP_ANON | MAP_SHARED;
	pid_t child;
	uid_t uid;
	
	if (drop_privs) {
		get_unprivileged_uid(&uid);
		if (IsSkipped())
			return;
	}

	sem = (sem_t*)mmap(NULL, sizeof(*sem), mprot, mflags, -1, 0);
	ASSERT_NE(MAP_FAILED, sem) << strerror(errno);
	ASSERT_EQ(0, sem_init(sem, 1, 0)) << strerror(errno);

	if ((child = ::fork()) == 0) {
		/* In child */
		int err = 0;

		if (sem_wait(sem)) {
			perror("sem_wait");
			err = 1;
			goto out;
		}

		if (drop_privs && 0 != setreuid(-1, uid)) {
			perror("setreuid");
			err = 1;
			goto out;
		}
		err = child_func();

out:
		sem_destroy(sem);
		_exit(err);
	} else if (child > 0) {
		int child_status;

		/* 
		 * In parent.  Cleanup must happen here, because it's still
		 * privileged.
		 */
		m_mock->m_child_pid = child;
		ASSERT_NO_FATAL_FAILURE(parent_func());

		/* Signal the child process to go */
		ASSERT_EQ(0, sem_post(sem)) << strerror(errno);

		ASSERT_LE(0, wait(&child_status)) << strerror(errno);
		ASSERT_EQ(0, WEXITSTATUS(child_status));
	} else {
		FAIL() << strerror(errno);
	}
	munmap(sem, sizeof(*sem));
}

static void usage(char* progname) {
	fprintf(stderr, "Usage: %s [-v]\n\t-v increase verbosity\n", progname);
	exit(2);
}

int main(int argc, char **argv) {
	int ch;
	FuseEnv *fuse_env = new FuseEnv;

	InitGoogleTest(&argc, argv);
	AddGlobalTestEnvironment(fuse_env);

	while ((ch = getopt(argc, argv, "v")) != -1) {
		switch (ch) {
			case 'v':
				verbosity++;
				break;
			default:
				usage(argv[0]);
				break;
		}
	}

	return (RUN_ALL_TESTS());
}
