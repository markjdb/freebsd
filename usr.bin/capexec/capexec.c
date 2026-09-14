/*
 * Copyright (c) 2026 Mark Johnston <markj@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/capsicum.h>
#include <sys/stat.h>

#include <security/mac_capsicum/mac_capsicum.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

extern char **environ;

static void
usage(void)
{
	fprintf(stderr,
	    "usage: capexec [-f policy] command [args ...]\n");
}

static const struct {
	const char *name;
	uint64_t right;
} rightstab[] = {
	{ "read", CAP_READ },
	{ "write", CAP_WRITE },
	{ "seek_tell", CAP_SEEK_TELL },
	{ "seek", CAP_SEEK },
	{ "pread", CAP_PREAD },
	{ "pwrite", CAP_PWRITE },
	{ "mmap", CAP_MMAP },
	{ "mmap_r", CAP_MMAP_R },
	{ "mmap_w", CAP_MMAP_W },
	{ "mmap_x", CAP_MMAP_X },
	{ "mmap_rw", CAP_MMAP_RW },
	{ "mmap_rx", CAP_MMAP_RX },
	{ "mmap_wx", CAP_MMAP_WX },
};

static void
add_path(const char *path, int macfd)
{
	struct mac_capsicum_vnode_ioc ioc;
	struct stat sb;
	int fd;

	assert(path[0] == '/');

	fd = open(path, O_PATH);
	if (fd < 0) {
		if (errno != ENOENT)
			err(1, "open(%s)", path);

		/*
		 * Some paths might legitimately not exist, such as
		 * /etc/malloc.conf.
		 */
		return;
	}
	if (fstat(fd, &sb) < 0)
		err(1, "fstat(%s)", path);

	memset(&ioc, 0, sizeof(ioc));
	if (!S_ISDIR(sb.st_mode)) {
		char *copy, *lastcn;

		copy = strdup(path);
		if (copy == NULL)
			err(1, "strdup(%s)", path);

		lastcn = strrchr(copy, '/');
		strlcpy(ioc.name, lastcn + 1, sizeof(ioc.name));

		*lastcn = '\0';
		(void)close(fd);
		fd = open(copy, O_PATH);
		if (fd < 0)
			err(1, "open(%s)", copy);

		free(copy);
	}
	ioc.fd = fd;
	if (ioctl(macfd, MAC_CAPSICUM_IOC_VNODE, &ioc) < 0)
		err(1, "failed to load '%s' into policy", path);

	(void)close(fd);
}

static void
add_paths(lua_State *L, int macfd)
{
	size_t n;

	lua_getglobal(L, "paths");
	if (lua_isnil(L, -1))
		return;
	if (!lua_istable(L, -1))
		errx(1, "'paths' must be a table");
	n = lua_rawlen(L, -1);
	for (size_t i = 1; i <= n; i++) {
		const char *path;
		cap_rights_t rights;

		lua_rawgeti(L, -1, i);
		if (lua_isstring(L, -1)) {
			path = lua_tostring(L, -1);
			if (path[0] != '/')
				errx(1, "path '%s' is not absolute", path);
			add_path(path, macfd);
			lua_pop(L, 1);
		} else if (lua_istable(L, -1)) {
		} else {
			errx(1,
	    "paths[%zu] must be a string or a <path, rights...> tuple", i);
		}
	}
}

static void
add_sysctl(const char *sysctl, int flags, int macfd)
{
	struct mac_capsicum_sysctl_ioc ioc;

	memset(&ioc, 0, sizeof(ioc));
	strlcpy(ioc.name, sysctl, sizeof(ioc.name));
	ioc.flags = flags;
	if (ioctl(macfd, MAC_CAPSICUM_IOC_SYSCTL, &ioc) != 0)
		err(1, "ioctl(MAC_CAPSICUM_IOC_SYSCTL)");
}

static void
add_sysctls(lua_State *L, int macfd)
{
	size_t n;

	lua_getglobal(L, "sysctls");
	if (lua_isnil(L, -1))
		return;
	if (!lua_istable(L, -1))
		errx(1, "'sysctls' must be a table");
	n = lua_rawlen(L, -1);
	for (size_t i = 1; i <= n; i++) {
		const char *sysctl;
		int flags;

		lua_rawgeti(L, -1, i);
		if (lua_istable(L, -1)) {
			const char *flagstr;
			int j;

			if (lua_rawlen(L, -1) != 2)
				errx(1, "sysctl tuple must have length 2");

			lua_rawgeti(L, -1, 1);
			if (!lua_isstring(L, -1))
				errx(1, "sysctl tuple[1] must be a string");
			sysctl = lua_tostring(L, -1);
			lua_pop(L, 1);

			lua_rawgeti(L, -1, 2);
			if (!lua_isstring(L, -1))
				errx(1, "sysctl tuple[2] must be a string");
			flagstr = lua_tostring(L, -1);
			lua_pop(L, 1);

			flags = j = 0;
			if (flagstr[j] == 'r') {
				flags |= MAC_CAPSICUM_F_SYSCTL_RD;
				j++;
			}
			if (flagstr[j] == 'w') {
				flags |= MAC_CAPSICUM_F_SYSCTL_WR;
				j++;
			}
			if (flagstr[j] != '\0')
				errx(1,
				    "invalid sysctl flag string '%s'", flagstr);
		} else if (lua_isstring(L, -1)) {
			sysctl = lua_tostring(L, -1);
			flags = MAC_CAPSICUM_F_SYSCTL_RD |
			    MAC_CAPSICUM_F_SYSCTL_WR;
		} else {
			errx(1,
		    "sysctls[%zu] must be strings or <string,flag> tuples", i);
		}

		add_sysctl(sysctl, flags, macfd);

		lua_pop(L, 1);
	}
}

static int
l_cwd(lua_State *L)
{
	char cwd[PATH_MAX];

	if (getcwd(cwd, sizeof(cwd)) == NULL)
		return (luaL_error(L, "getcwd: %s", strerror(errno)));

	lua_pushstring(L, cwd);
	return (1);
}

static void
load_policy(const char *policy, int macfd)
{
	lua_State *L;

	L = luaL_newstate();

	lua_pushcfunction(L, l_cwd);
	lua_setglobal(L, "cwd");

	if (luaL_dofile(L, policy) != LUA_OK)
		errx(1, "luaL_dofile(%s): %s", policy, lua_tostring(L, -1));

	add_paths(L, macfd);
	add_sysctls(L, macfd);

	lua_close(L);
}

int
main(int argc, char **argv)
{
	const char *policy;
	int ch, cmdfd, macfd;

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

	macfd = open(_PATH_MAC_CAPSICUM, O_RDWR | O_CLOEXEC);
	if (macfd < 0)
		err(1, "open(" _PATH_MAC_CAPSICUM ")");

	load_policy(policy, macfd);

	cmdfd = open(argv[0], O_EXEC | O_CLOEXEC);
	if (cmdfd < 0)
		err(1, "open(%s)", argv[0]);

	if (cap_enter() < 0)
		err(1, "cap_enter()");

	if (ioctl(macfd, MAC_CAPSICUM_IOC_COMMIT) < 0)
		err(1, "failed to commit policy");

	(void)fexecve(cmdfd, argv, environ);
	err(1, "fexecve(%s)", argv[0]);
}
