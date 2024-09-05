/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Mark Johnston <markj@FreeBSD.org>
 */

#include <sys/capsicum.h>

#include <assert.h>
#include <errno.h>
#include <string.h>

#include <lua.h>
#include "lauxlib.h"
#include "lfreebsd.h"

/* XXX-MJ duplicated with lposix.c */
#define	FREEBSD_SYS_FD_KEY		"freebsd_sys_fd"
#define	FREEBSD_SYS_CAPSICUM_RIGHTS	"freebsd_sys_capsicum_rights"

#define	PUSH_ERROR(L, error) do {		\
	lua_pushnil(L);				\
	lua_pushstring(L, strerror(error));	\
	lua_pushinteger(L, error);		\
} while (0)

#define	PUSH_ERRNO(L) do {			\
	int saved_error = errno;		\
	PUSH_ERROR(L, saved_error);		\
} while (0)

static int
lua_cap_enter(lua_State *L)
{
	int error;

	error = cap_enter();
	if (error != 0) {
		PUSH_ERRNO(L);
		return (3);
	}

	lua_pushboolean(L, 1);
	return (1);
}

static int
lua_cap_getmode(lua_State *L)
{
	unsigned int mode;
	int error;

	error = cap_getmode(&mode);
	if (error != 0) {
		PUSH_ERRNO(L);
		return (3);
	}

	lua_pushinteger(L, mode);
	return (1);
}

static const struct luaL_Reg sys_capsicumlib[] = {
	{ "cap_enter", lua_cap_enter },
	{ "cap_getmode", lua_cap_getmode },

#ifdef notyet
	{ "cap_rights_get", lua_cap_rights_get },
	{ "cap_rights_limit", lua_cap_rights_limit },

	{ "cap_rights_init", lua_cap_rights_init },
	{ "cap_rights_set", lua_cap_rights_set },
	{ "cap_rights_clear", lua_cap_rights_clear },
	{ "cap_rights_is_set", lua_cap_rights_is_set },
	{ "cap_rights_is_empty", lua_cap_rights_is_empty },
	{ "cap_rights_is_valid", lua_cap_rights_is_valid },
	{ "cap_rights_merge", lua_cap_rights_merge },
	{ "cap_rights_remove", lua_cap_rights_remove },
	{ "cap_rights_contains", lua_cap_rights_contains },

	{ "cap_fcntls_limit", lua_cap_fcntls_limit },
	{ "cap_fcntls_get", lua_cap_fcntls_get },
	{ "cap_ioctls_limit", lua_cap_ioctls_limit },
	{ "cap_ioctls_get", lua_cap_ioctls_get },
#endif
	{ NULL, NULL }
};

static int
luaopen_freebsd_sys_capsicum(lua_State *L)
{
	int ret;

	ret = luaL_newmetatable(L, FREEBSD_SYS_CAPSICUM_RIGHTS);
	assert(ret == 1);

	luaL_newlib(L, sys_capsicumlib);
#define	ADDRIGHT(r) do {				\
	lua_pushinteger(L, r);				\
	lua_setfield(L, -2, #r);			\
} while (0)
	/*
	 * awk '/#define[[:space:]]+CAP_[A-Z0-9_]+[[:space:]]/
	 *      {print "\tADDRIGHT("$2");"}' /usr/include/sys/capsicum.h
	 */
	ADDRIGHT(CAP_READ);
	ADDRIGHT(CAP_WRITE);
	ADDRIGHT(CAP_SEEK_TELL);
	ADDRIGHT(CAP_SEEK);
	ADDRIGHT(CAP_PREAD);
	ADDRIGHT(CAP_PWRITE);
	ADDRIGHT(CAP_MMAP);
	ADDRIGHT(CAP_MMAP_R);
	ADDRIGHT(CAP_MMAP_W);
	ADDRIGHT(CAP_MMAP_X);
	ADDRIGHT(CAP_MMAP_RW);
	ADDRIGHT(CAP_MMAP_RX);
	ADDRIGHT(CAP_MMAP_WX);
	ADDRIGHT(CAP_MMAP_RWX);
	ADDRIGHT(CAP_CREATE);
	ADDRIGHT(CAP_FEXECVE);
	ADDRIGHT(CAP_FSYNC);
	ADDRIGHT(CAP_FTRUNCATE);
	ADDRIGHT(CAP_LOOKUP);
	ADDRIGHT(CAP_FCHDIR);
	ADDRIGHT(CAP_FCHFLAGS);
	ADDRIGHT(CAP_CHFLAGSAT);
	ADDRIGHT(CAP_FCHMOD);
	ADDRIGHT(CAP_FCHMODAT);
	ADDRIGHT(CAP_FCHOWN);
	ADDRIGHT(CAP_FCHOWNAT);
	ADDRIGHT(CAP_FCNTL);
	ADDRIGHT(CAP_FLOCK);
	ADDRIGHT(CAP_FPATHCONF);
	ADDRIGHT(CAP_FSCK);
	ADDRIGHT(CAP_FSTAT);
	ADDRIGHT(CAP_FSTATAT);
	ADDRIGHT(CAP_FSTATFS);
	ADDRIGHT(CAP_FUTIMES);
	ADDRIGHT(CAP_FUTIMESAT);
	ADDRIGHT(CAP_LINKAT_TARGET);
	ADDRIGHT(CAP_MKDIRAT);
	ADDRIGHT(CAP_MKFIFOAT);
	ADDRIGHT(CAP_MKNODAT);
	ADDRIGHT(CAP_RENAMEAT_SOURCE);
	ADDRIGHT(CAP_SYMLINKAT);
	ADDRIGHT(CAP_UNLINKAT);
	ADDRIGHT(CAP_ACCEPT);
	ADDRIGHT(CAP_BIND);
	ADDRIGHT(CAP_CONNECT);
	ADDRIGHT(CAP_GETPEERNAME);
	ADDRIGHT(CAP_GETSOCKNAME);
	ADDRIGHT(CAP_GETSOCKOPT);
	ADDRIGHT(CAP_LISTEN);
	ADDRIGHT(CAP_PEELOFF);
	ADDRIGHT(CAP_RECV);
	ADDRIGHT(CAP_SEND);
	ADDRIGHT(CAP_SETSOCKOPT);
	ADDRIGHT(CAP_SHUTDOWN);
	ADDRIGHT(CAP_BINDAT);
	ADDRIGHT(CAP_CONNECTAT);
	ADDRIGHT(CAP_LINKAT_SOURCE);
	ADDRIGHT(CAP_RENAMEAT_TARGET);
	ADDRIGHT(CAP_SOCK_CLIENT);
	ADDRIGHT(CAP_SOCK_SERVER);
	ADDRIGHT(CAP_MAC_GET);
	ADDRIGHT(CAP_MAC_SET);
	ADDRIGHT(CAP_SEM_GETVALUE);
	ADDRIGHT(CAP_SEM_POST);
	ADDRIGHT(CAP_SEM_WAIT);
	ADDRIGHT(CAP_EVENT);
	ADDRIGHT(CAP_KQUEUE_EVENT);
	ADDRIGHT(CAP_IOCTL);
	ADDRIGHT(CAP_TTYHOOK);
	ADDRIGHT(CAP_PDGETPID);
	ADDRIGHT(CAP_PDWAIT);
	ADDRIGHT(CAP_PDKILL);
	ADDRIGHT(CAP_EXTATTR_DELETE);
	ADDRIGHT(CAP_EXTATTR_GET);
	ADDRIGHT(CAP_EXTATTR_LIST);
	ADDRIGHT(CAP_EXTATTR_SET);
	ADDRIGHT(CAP_ACL_CHECK);
	ADDRIGHT(CAP_ACL_DELETE);
	ADDRIGHT(CAP_ACL_GET);
	ADDRIGHT(CAP_ACL_SET);
	ADDRIGHT(CAP_KQUEUE_CHANGE);
	ADDRIGHT(CAP_KQUEUE);
	ADDRIGHT(CAP_POLL_EVENT);
	ADDRIGHT(CAP_FCNTL_GETFL);
	ADDRIGHT(CAP_FCNTL_SETFL);
	ADDRIGHT(CAP_FCNTL_GETOWN);
	ADDRIGHT(CAP_FCNTL_SETOWN);
	ADDRIGHT(CAP_FCNTL_ALL);
	ADDRIGHT(CAP_IOCTLS_ALL);
#undef ADDRIGHT
	return (1);
}

int
luaopen_freebsd(lua_State *L)
{
	lua_newtable(L);	/* freebsd */
	lua_newtable(L);	/* freebsd.sys */
	luaL_requiref(L,
	    "freebsd.sys.capsicum", luaopen_freebsd_sys_capsicum, 1);
	lua_setfield(L, -2, "capsicum");
	lua_setfield(L, -2, "sys");
	return (1);
}
