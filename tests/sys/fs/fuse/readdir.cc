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
#include <dirent.h>
#include <fcntl.h>
}

#include "mockfs.hh"
#include "utils.hh"

using namespace testing;
using namespace std;

class Readdir: public FuseTest {
public:
void expect_lookup(const char *relpath, uint64_t ino)
{
	FuseTest::expect_lookup(relpath, ino, S_IFDIR | 0755, 1);
}

void expect_readdir(uint64_t ino, uint64_t off, vector<struct dirent> &ents)
{
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in->header.opcode == FUSE_READDIR &&
				in->header.nodeid == ino &&
				in->body.readdir.offset == off);
		}, Eq(true)),
		_)
	).WillRepeatedly(Invoke(ReturnImmediate([=](auto in, auto out) {
		struct fuse_dirent *fde = (struct fuse_dirent*)out->body.bytes;
		int i = 0;

		out->header.unique = in->header.unique;
		out->header.error = 0;
		out->header.len = 0;

		for (const auto& it: ents) {
			size_t entlen, entsize;

			fde->ino = it.d_fileno;
			fde->off = it.d_off;
			fde->type = it.d_type;
			fde->namelen = it.d_namlen;
			strncpy(fde->name, it.d_name, it.d_namlen);
			entlen = FUSE_NAME_OFFSET + fde->namelen;
			entsize = FUSE_DIRENT_SIZE(fde);
			/* 
			 * The FUSE protocol does not require zeroing out the
			 * unused portion of the name.  But it's a good
			 * practice to prevent information disclosure to the
			 * FUSE client, even though the client is usually the
			 * kernel
			 */
			memset(fde->name + fde->namelen, 0, entsize - entlen);
			if (out->header.len + entsize > in->body.read.size) {
				printf("Overflow in readdir expectation: i=%d\n"
					, i);
				break;
			}
			out->header.len += entsize;
			fde = (struct fuse_dirent*)
				((long*)fde + entsize / sizeof(long));
			i++;
		}
		out->header.len += sizeof(out->header);
	})));

}
};

/* FUSE_READDIR returns nothing but "." and ".." */
TEST_F(Readdir, dots)
{
	const char FULLPATH[] = "mountpoint/some_dir";
	const char RELPATH[] = "some_dir";
	uint64_t ino = 42;
	DIR *dir;
	struct dirent *de;
	vector<struct dirent> ents(2);
	vector<struct dirent> empty_ents(0);
	const char *dot = ".";
	const char *dotdot = "..";

	expect_lookup(RELPATH, ino);
	expect_opendir(ino);
	ents[0].d_fileno = 2;
	ents[0].d_off = 2000;
	ents[0].d_namlen = strlen(dotdot);
	ents[0].d_type = DT_DIR;
	strncpy(ents[0].d_name, dotdot, ents[0].d_namlen);
	ents[1].d_fileno = 3;
	ents[1].d_off = 3000;
	ents[1].d_namlen = strlen(dot);
	ents[1].d_type = DT_DIR;
	strncpy(ents[1].d_name, dot, ents[1].d_namlen);
	expect_readdir(ino, 0, ents);
	expect_readdir(ino, 3000, empty_ents);

	errno = 0;
	dir = opendir(FULLPATH);
	ASSERT_NE(NULL, dir) << strerror(errno);

	errno = 0;
	de = readdir(dir);
	ASSERT_NE(NULL, de) << strerror(errno);
	EXPECT_EQ(2ul, de->d_fileno);
	/*
	 * fuse(4) doesn't actually set d_off, which is ok for now because
	 * nothing uses it.
	 */
	//EXPECT_EQ(2000, de->d_off);
	EXPECT_EQ(DT_DIR, de->d_type);
	EXPECT_EQ(2, de->d_namlen);
	EXPECT_EQ(0, strcmp("..", de->d_name));

	errno = 0;
	de = readdir(dir);
	ASSERT_NE(NULL, de) << strerror(errno);
	EXPECT_EQ(3ul, de->d_fileno);
	//EXPECT_EQ(3000, de->d_off);
	EXPECT_EQ(DT_DIR, de->d_type);
	EXPECT_EQ(1, de->d_namlen);
	EXPECT_EQ(0, strcmp(".", de->d_name));

	ASSERT_EQ(NULL, readdir(dir));
	ASSERT_EQ(0, errno);

	/* Deliberately leak dir.  RELEASEDIR will be tested separately */
}

TEST_F(Readdir, eio)
{
	const char FULLPATH[] = "mountpoint/some_dir";
	const char RELPATH[] = "some_dir";
	uint64_t ino = 42;
	DIR *dir;
	struct dirent *de;

	expect_lookup(RELPATH, ino);
	expect_opendir(ino);
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in->header.opcode == FUSE_READDIR &&
				in->header.nodeid == ino &&
				in->body.readdir.offset == 0);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnErrno(EIO)));

	errno = 0;
	dir = opendir(FULLPATH);
	ASSERT_NE(NULL, dir) << strerror(errno);

	errno = 0;
	de = readdir(dir);
	ASSERT_EQ(NULL, de);
	ASSERT_EQ(EIO, errno);

	/* Deliberately leak dir.  RELEASEDIR will be tested separately */
}

/*
 * FUSE_READDIR returns nothing, not even "." and "..".  This is legal, though
 * the filesystem obviously won't be fully functional.
 */
TEST_F(Readdir, nodots)
{
	const char FULLPATH[] = "mountpoint/some_dir";
	const char RELPATH[] = "some_dir";
	uint64_t ino = 42;
	DIR *dir;

	expect_lookup(RELPATH, ino);
	expect_opendir(ino);

	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in->header.opcode == FUSE_READDIR &&
				in->header.nodeid == ino);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnImmediate([=](auto in, auto out) {
		out->header.unique = in->header.unique;
		out->header.error = 0;
		out->header.len = sizeof(out->header);
	})));

	errno = 0;
	dir = opendir(FULLPATH);
	ASSERT_NE(NULL, dir) << strerror(errno);
	errno = 0;
	ASSERT_EQ(NULL, readdir(dir));
	ASSERT_EQ(0, errno);

	/* Deliberately leak dir.  RELEASEDIR will be tested separately */
}

/* telldir(3) and seekdir(3) should work with fuse */
TEST_F(Readdir, seekdir)
{
	const char FULLPATH[] = "mountpoint/some_dir";
	const char RELPATH[] = "some_dir";
	uint64_t ino = 42;
	DIR *dir;
	struct dirent *de;
	/*
	 * use enough entries to be > 4096 bytes, so getdirentries must be
	 * called
	 * multiple times.
	 */
	vector<struct dirent> ents0(122), ents1(102), ents2(30);
	long bookmark;
	int i = 0;

	for (auto& it: ents0) {
		snprintf(it.d_name, MAXNAMLEN, "file.%d", i);
		it.d_fileno = 2 + i;
		it.d_off = (2 + i) * 1000;
		it.d_namlen = strlen(it.d_name);
		it.d_type = DT_REG;
		i++;
	}
	for (auto& it: ents1) {
		snprintf(it.d_name, MAXNAMLEN, "file.%d", i);
		it.d_fileno = 2 + i;
		it.d_off = (2 + i) * 1000;
		it.d_namlen = strlen(it.d_name);
		it.d_type = DT_REG;
		i++;
	}
	for (auto& it: ents2) {
		snprintf(it.d_name, MAXNAMLEN, "file.%d", i);
		it.d_fileno = 2 + i;
		it.d_off = (2 + i) * 1000;
		it.d_namlen = strlen(it.d_name);
		it.d_type = DT_REG;
		i++;
	}

	expect_lookup(RELPATH, ino);
	expect_opendir(ino);

	expect_readdir(ino, 0, ents0);
	expect_readdir(ino, 123000, ents1);
	expect_readdir(ino, 225000, ents2);

	errno = 0;
	dir = opendir(FULLPATH);
	ASSERT_NE(NULL, dir) << strerror(errno);

	for (i=0; i < 128; i++) {
		errno = 0;
		de = readdir(dir);
		ASSERT_NE(NULL, de) << strerror(errno);
		EXPECT_EQ(2 + (ino_t)i, de->d_fileno);
	}
	bookmark = telldir(dir);

	for (; i < 232; i++) {
		errno = 0;
		de = readdir(dir);
		ASSERT_NE(NULL, de) << strerror(errno);
		EXPECT_EQ(2 + (ino_t)i, de->d_fileno);
	}

	seekdir(dir, bookmark);
	de = readdir(dir);
	ASSERT_NE(NULL, de) << strerror(errno);
	EXPECT_EQ(130ul, de->d_fileno);

	/* Deliberately leak dir.  RELEASEDIR will be tested separately */
}
