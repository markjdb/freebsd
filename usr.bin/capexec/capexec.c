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
	{ "create", CAP_CREATE },
	{ "fexecve", CAP_FEXECVE },
	{ "fsync", CAP_FSYNC },
	{ "ftruncate", CAP_FTRUNCATE },
	{ "lookup", CAP_LOOKUP },
	{ "fchdir", CAP_FCHDIR },
	{ "fchflags", CAP_FCHFLAGS },
	{ "chflagsat", CAP_CHFLAGSAT },
	{ "fchmod", CAP_FCHMOD },
	{ "fchmodat", CAP_FCHMODAT },
	{ "fchown", CAP_FCHOWN },
	{ "fchownat", CAP_FCHOWNAT },
	{ "fcntl", CAP_FCNTL },
	{ "flock", CAP_FLOCK },
	{ "fpathconf", CAP_FPATHCONF },
	{ "fstat", CAP_FSTAT },
	{ "fstatat", CAP_FSTATAT },
	{ "fstatfs", CAP_FSTATFS },
	{ "futimes", CAP_FUTIMES },
	{ "futimesat", CAP_FUTIMESAT },
	{ "linkat_target", CAP_LINKAT_TARGET },
	{ "mkdirat", CAP_MKDIRAT },
	{ "mkfifoat", CAP_MKFIFOAT },
	{ "mknodat", CAP_MKNODAT },
	{ "renameat_source", CAP_RENAMEAT_SOURCE },
	{ "symlinkat", CAP_SYMLINKAT },
	{ "unlinkat", CAP_UNLINKAT },
	{ "accept", CAP_ACCEPT },
	{ "bind", CAP_BIND },
	{ "connect", CAP_CONNECT },
	{ "getpeername", CAP_GETPEERNAME },
	{ "getsockname", CAP_GETSOCKNAME },
	{ "getsockopt", CAP_GETSOCKOPT },
	{ "listen", CAP_LISTEN },
	{ "peeloff", CAP_PEELOFF },
	{ "recv", CAP_RECV },
	{ "send", CAP_SEND },
	{ "setsockopt", CAP_SETSOCKOPT },
	{ "shutdown", CAP_SHUTDOWN },
	{ "bindat", CAP_BINDAT },
	{ "connectat", CAP_CONNECTAT },
	{ "linkat_source", CAP_LINKAT_SOURCE },
	{ "renameat_target", CAP_RENAMEAT_TARGET },
	{ "fchroot", CAP_FCHROOT },
	{ "mac_get", CAP_MAC_GET },
	{ "mac_set", CAP_MAC_SET },
	{ "sem_getvalue", CAP_SEM_GETVALUE },
	{ "sem_post", CAP_SEM_POST },
	{ "sem_wait", CAP_SEM_WAIT },
	{ "event", CAP_EVENT },
	{ "kqueue_event", CAP_KQUEUE_EVENT },
	{ "ioctl", CAP_IOCTL },
	{ "ttyhook", CAP_TTYHOOK },
	{ "pdgetpid", CAP_PDGETPID },
	{ "pdwait", CAP_PDWAIT },
	{ "pdkill", CAP_PDKILL },
	{ "extattr_delete", CAP_EXTATTR_DELETE },
	{ "extattr_get", CAP_EXTATTR_GET },
	{ "extattr_set", CAP_EXTATTR_SET },
	{ "extattr_list", CAP_EXTATTR_LIST },
	{ NULL, 0 },
};

static uint64_t
right2mask(const char *rightstr)
{
	for (size_t i = 0; rightstab[i].name != NULL; i++) {
		if (strcmp(rightstr, rightstab[i].name) == 0)
			return (rightstab[i].right);
	}
	return (0);
}

static void
add_path(const char *path, cap_rights_t *rightsp, int macfd)
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
		if (fstat(fd, &sb) < 0)
			err(1, "fstat(%s)", path);
		if (!S_ISDIR(sb.st_mode))
			errx(1, "parent of '%s' is not a directory", path);

		free(copy);
	}
	if (cap_rights_limit(fd, rightsp) != 0)
		err(1, "cap_rights_limit(%s)", path);
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

			CAP_ALL(&rights);
			add_path(path, &rights, macfd);
			lua_pop(L, 1);
		} else if (lua_istable(L, -1)) {
			size_t m;

			m = lua_rawlen(L, -1);
			if (m < 1)
				errx(1, "paths[%zu] must contain a path", i);
			lua_rawgeti(L, -1, 1);
			if (!lua_isstring(L, -1))
				errx(1, "paths[%zu][1] must be a string", i);
			path = lua_tostring(L, -1);

			cap_rights_init(&rights);
			for (size_t j = 2; j <= m; j++) {
				const char *rightstr;
				uint64_t mask;

				lua_rawgeti(L, -1, j);
				if (!lua_isstring(L, -1)) {
					errx(1,
					    "paths[%zu][%zu] must be a string",
					    i, j);
				}
				rightstr = lua_tostring(L, -1);
				mask = right2mask(rightstr);
				if (mask == 0) {
					errx(1,
					    "paths[%zu] unknown right '%s'",
					    i, rightstr);
				}

				cap_rights_set(&rights, mask);
				lua_pop(L, 1);
			}
			add_path(path, &rights, macfd);
			lua_pop(L, 1);
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
