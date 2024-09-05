/*-
 * Copyright (c) 2019 Kyle Evans <kevans@FreeBSD.org>
 * Copyright (c) 2024 Mark Johnston <markj@FreeBSD.org>
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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include <assert.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lua.h>
#include "lauxlib.h"
#include "lposix.h"

/* udata keys */
#define	FREEBSD_SYS_FD_KEY		"freebsd_sys_fd"
#define	POSIX_SPAWN_FILE_ACTIONS_KEY	"freebsd_posix_spawn_file_actions"
#define	POSIX_SPAWNATTR_KEY		"freebsd_posix_spawnattr"

#define	PUSH_ERROR(L, error) do {		\
	lua_pushnil(L);				\
	lua_pushstring(L, strerror(error));	\
	lua_pushinteger(L, error);		\
} while (0)

#define	PUSH_ERRNO(L) do {			\
	int saved_error = errno;		\
	PUSH_ERROR(L, saved_error);		\
} while (0)

/*
 * Minimal implementation of luaposix needed for internal FreeBSD bits.
 */

static int
lua_chmod(lua_State *L)
{
	int n;
	const char *path;
	mode_t mode;

	n = lua_gettop(L);
	luaL_argcheck(L, n == 2, n > 2 ? 3 : n,
	    "chmod takes exactly two arguments");
	path = luaL_checkstring(L, 1);
	mode = (mode_t)luaL_checkinteger(L, 2);
	if (chmod(path, mode) == -1) {
		lua_pushnil(L);
		lua_pushstring(L, strerror(errno));
		lua_pushinteger(L, errno);
		return 3;
	}
	lua_pushinteger(L, 0);
	return 1;
}

static int
lua_chown(lua_State *L)
{
	int n;
	const char *path;
	uid_t owner = (uid_t) -1;
	gid_t group = (gid_t) -1;

	n = lua_gettop(L);
	luaL_argcheck(L, n > 1, n,
	   "chown takes at least two arguments");
	path = luaL_checkstring(L, 1);
	if (lua_isinteger(L, 2))
		owner = (uid_t) lua_tointeger(L, 2);
	else if (lua_isstring(L, 2)) {
		struct passwd *p = getpwnam(lua_tostring(L, 2));
		if (p != NULL)
			owner = p->pw_uid;
		else
			return (luaL_argerror(L, 2,
			    lua_pushfstring(L, "unknown user %s",
			    lua_tostring(L, 2))));
	} else if (!lua_isnoneornil(L, 2)) {
		const char *type = luaL_typename(L, 2);
		return (luaL_argerror(L, 2,
		    lua_pushfstring(L, "integer or string expected, got %s",
		    type)));
	}

	if (lua_isinteger(L, 3))
		group = (gid_t) lua_tointeger(L, 3);
	else if (lua_isstring(L, 3)) {
		struct group *g = getgrnam(lua_tostring(L, 3));
		if (g != NULL)
			group = g->gr_gid;
		else
			return (luaL_argerror(L, 3,
			    lua_pushfstring(L, "unknown group %s",
			    lua_tostring(L, 3))));
	} else if (!lua_isnoneornil(L, 3)) {
		const char *type = luaL_typename(L, 3);
		return (luaL_argerror(L, 3,
		    lua_pushfstring(L, "integer or string expected, got %s",
		    type)));
	}

	if (chown(path, owner, group) == -1) {
		lua_pushnil(L);
		lua_pushstring(L, strerror(errno));
		lua_pushinteger(L, errno);
		return (3);
	}
	lua_pushinteger(L, 0);
	return (1);
}

static int
lua_close_(lua_State *L)
{
	int error, *fdp;

	fdp = luaL_checkudata(L, 1, FREEBSD_SYS_FD_KEY);
	error = close(*fdp);
	if (error != 0) {
		PUSH_ERRNO(L);
		return (3);
	}
	/* Prevent __gc from touching this fd. */
	*fdp = -1;
	lua_pushboolean(L, 1);
	return (1);
}

static int
lua_pipe(lua_State *L)
{
	int error, fds[2];
	int *fdp;

	error = pipe(fds);
	if (error == -1) {
		PUSH_ERRNO(L);
		return (3);
	}

	fdp = lua_newuserdata(L, sizeof(int));
	*fdp = fds[0];
	luaL_getmetatable(L, FREEBSD_SYS_FD_KEY);
	lua_setmetatable(L, -2);
	fdp = lua_newuserdata(L, sizeof(int));
	*fdp = fds[1];
	luaL_getmetatable(L, FREEBSD_SYS_FD_KEY);
	lua_setmetatable(L, -2);

	return (2);
}

static int
lua_posix_spawn_impl(lua_State *L, bool path)
{
	extern char **environ;
	posix_spawn_file_actions_t file_actions, *file_actionsp;
	posix_spawnattr_t attr, *attrp;
	const char *file;
	const char **argv;
	const char **envp;
	char *const *_argv;
	char *const *_envp;
	int argi, argc, envc, ret, ret1;
	pid_t pid;

	argi = 1;
	file = luaL_checkstring(L, argi++);

	/*
	 * File actions and spawn attributes are optional.  They must be
	 * followed by a table.
	 */
	attrp = NULL;
	file_actionsp = NULL;
	if (lua_isuserdata(L, argi)) {
		lua_getmetatable(L, argi);
		luaL_getmetatable(L, POSIX_SPAWN_FILE_ACTIONS_KEY);
		if (lua_rawequal(L, -1, -2)) {
			file_actionsp = luaL_checkudata(L, argi,
			    POSIX_SPAWN_FILE_ACTIONS_KEY);
			argi++;
		}
		lua_pop(L, 2);
	}
	if (lua_isuserdata(L, argi)) {
		void *val;

		val = luaL_checkudata(L, argi, POSIX_SPAWNATTR_KEY);
		if (val != NULL) {
			attrp = val;
			argi++;
		}
	}
	luaL_checktype(L, argi, LUA_TTABLE);

	/*
	 * If the caller didn't provide a file actions or spawn attributes, set
	 * up a no-op default.
	 */
	if (file_actionsp == NULL) {
		ret = posix_spawn_file_actions_init(&file_actions);
		if (ret != 0) {
			PUSH_ERROR(L, ret);
			return (3);
		}
		file_actionsp = &file_actions;
	}
	if (attrp == NULL) {
		ret = posix_spawnattr_init(&attr);
		if (ret != 0) {
			PUSH_ERROR(L, ret);
			return (3);
		}
		attrp = &attr;
	}

	argc = lua_rawlen(L, argi);
	argv = calloc(argc + 1, sizeof(char *));
	if (argv == NULL) {
		PUSH_ERROR(L, ret);
		return (3);
	}
	for (int i = 0; i < argc; i++) {
		lua_rawgeti(L, argi, i + 1);
		argv[i] = lua_tostring(L, -1);
		lua_pop(L, 1);
	}
	argi++;

	/*
	 * POSIX doesn't appear to specify what happens if the envp is NULL.
	 * FreeBSD treats it as meaning that the environment is to be inherited,
	 * which seems sensible.  Follow that behaviour if the caller didn't
	 * specify a final parameter.
	 */
	if (lua_gettop(L) >= argi && lua_type(L, argi) != LUA_TNIL) {
		luaL_checktype(L, argi, LUA_TTABLE);
		envc = lua_rawlen(L, argi);
		envp = calloc(envc + 1, sizeof(char *));
		if (envp == NULL) {
			PUSH_ERRNO(L);
			return (3);
		}
		for (int i = 0; i < envc; i++) {
			lua_rawgeti(L, argi, i + 1);
			envp[i] = lua_tostring(L, -1);
			lua_pop(L, 1);
		}
		argi++;
	} else {
		envp = __DECONST(const char **, environ);
	}

	_argv = __DECONST(char * const *, argv);
	_envp = __DECONST(char * const *, envp);
	ret = path ?
	    posix_spawnp(&pid, file, file_actionsp, attrp, _argv, _envp) :
	    posix_spawn(&pid, file, file_actionsp, attrp, _argv, _envp);

	if (file_actionsp == &file_actions) {
		ret1 = posix_spawn_file_actions_destroy(file_actionsp);
		assert(ret1 == 0);
	}
	if (attrp == &attr) {
		ret1 = posix_spawnattr_destroy(attrp);
		assert(ret1 == 0);
	}

	free(argv);
	if (envp != __DECONST(const char **, environ))
		free(envp);

	if (ret != 0) {
		PUSH_ERROR(L, ret);
		return (3);
	}

	lua_pushinteger(L, pid);
	return (1);
}

static int
lua_posix_spawn(lua_State *L)
{
	return (lua_posix_spawn_impl(L, false));
}

static int
lua_posix_spawnp(lua_State *L)
{
	return (lua_posix_spawn_impl(L, true));
}

static int
lua_posix_spawn_file_actions_init(lua_State *L)
{
	posix_spawn_file_actions_t *file_actions;
	int error;

	file_actions = lua_newuserdata(L, sizeof(posix_spawn_file_actions_t));
	error = posix_spawn_file_actions_init(file_actions);
	if (error != 0) {
		PUSH_ERROR(L, error);
		return (3);
	}

	luaL_getmetatable(L, POSIX_SPAWN_FILE_ACTIONS_KEY);
	lua_setmetatable(L, -2);

	return (1);
}

static int
lua_posix_spawn_file_actions_addopen(lua_State *L)
{
	posix_spawn_file_actions_t *file_actions;
	const char *path;
	int error, *fdp, oflags;
	mode_t mode;

	file_actions = luaL_checkudata(L, 1, POSIX_SPAWN_FILE_ACTIONS_KEY);
	fdp = luaL_checkudata(L, 2, FREEBSD_SYS_FD_KEY);
	path = luaL_checkstring(L, 3);
	oflags = luaL_checkinteger(L, 4);
	mode = luaL_optinteger(L, 5, 0);

	error = posix_spawn_file_actions_addopen(file_actions, *fdp, path,
	    oflags, mode);
	if (error != 0) {
		PUSH_ERROR(L, error);
		return (3);
	}

	lua_pushboolean(L, 1);
	return (1);
}

static int
lua_posix_spawn_file_actions_adddup2(lua_State *L)
{
	posix_spawn_file_actions_t *file_actions;
	int error, *oldfdp, newfd;

	file_actions = luaL_checkudata(L, 1, POSIX_SPAWN_FILE_ACTIONS_KEY);
	oldfdp = luaL_checkudata(L, 2, FREEBSD_SYS_FD_KEY);
	newfd = luaL_checkinteger(L, 3);

	error = posix_spawn_file_actions_adddup2(file_actions, *oldfdp, newfd);
	if (error != 0) {
		PUSH_ERROR(L, error);
		return (3);
	}

	lua_pushboolean(L, 1);
	return (1);
}

static int
lua_posix_spawn_file_actions_addclose(lua_State *L)
{
	posix_spawn_file_actions_t *file_actions;
	int error, *fdp;

	file_actions = luaL_checkudata(L, 1, POSIX_SPAWN_FILE_ACTIONS_KEY);
	fdp = luaL_checkudata(L, 2, FREEBSD_SYS_FD_KEY);

	error = posix_spawn_file_actions_addclose(file_actions, *fdp);
	if (error != 0) {
		PUSH_ERROR(L, error);
		return (3);
	}

	lua_pushboolean(L, 1);
	return (1);
}

static int
lua_posix_spawn_file_actions_addclosefrom_np(lua_State *L)
{
	posix_spawn_file_actions_t *file_actions;
	int error, from;

	file_actions = luaL_checkudata(L, 1, POSIX_SPAWN_FILE_ACTIONS_KEY);
	from = luaL_checkinteger(L, 2);

	error = posix_spawn_file_actions_addclosefrom_np(file_actions, from);
	if (error != 0) {
		PUSH_ERROR(L, error);
		return (3);
	}

	lua_pushboolean(L, 1);
	return (1);
}

static int
lua_posix_spawn_file_actions_addchdir_np(lua_State *L)
{
	posix_spawn_file_actions_t *file_actions;
	const char *path;
	int error;

	file_actions = luaL_checkudata(L, 1, POSIX_SPAWN_FILE_ACTIONS_KEY);
	path = luaL_checkstring(L, 2);

	error = posix_spawn_file_actions_addchdir_np(file_actions, path);
	if (error != 0) {
		PUSH_ERROR(L, error);
		return (3);
	}

	lua_pushboolean(L, 1);
	return (1);
}

static int
lua_posix_spawn_file_actions_addfchdir_np(lua_State *L)
{
	posix_spawn_file_actions_t *file_actions;
	int error, *fdp;

	file_actions = luaL_checkudata(L, 1, POSIX_SPAWN_FILE_ACTIONS_KEY);
	fdp = luaL_checkudata(L, 2, FREEBSD_SYS_FD_KEY);

	error = posix_spawn_file_actions_addfchdir_np(file_actions, *fdp);
	if (error != 0) {
		PUSH_ERROR(L, error);
		return (3);
	}

	lua_pushboolean(L, 1);
	return (1);
}

static int
lua_posix_spawnattr_init(lua_State *L)
{
	posix_spawnattr_t *attr;
	int error;

	attr = lua_newuserdata(L, sizeof(posix_spawnattr_t));

	error = posix_spawnattr_init(attr);
	if (error != 0) {
		PUSH_ERROR(L, error);
		return (3);
	}

	luaL_getmetatable(L, POSIX_SPAWNATTR_KEY);
	lua_setmetatable(L, -2);
	return (1);
}

static int
lua_posix_spawnattr_getflags(lua_State *L)
{
	posix_spawnattr_t *attr;
	short flags;
	int error;

	attr = luaL_checkudata(L, 1, POSIX_SPAWNATTR_KEY);

	error = posix_spawnattr_getflags(attr, &flags);
	if (error != 0) {
		PUSH_ERROR(L, error);
		return (3);
	}

	lua_pushinteger(L, flags);
	return (1);
}

static int
lua_posix_spawnattr_setflags(lua_State *L)
{
	posix_spawnattr_t *attr;
	lua_Integer lflags;
	short flags;
	int error;

	attr = luaL_checkudata(L, 1, POSIX_SPAWNATTR_KEY);
	lflags = luaL_checkinteger(L, 2);
	if (lflags > SHRT_MAX || lflags < SHRT_MIN) {
		return (luaL_error(L, "flags too large: %jx",
		    (uintmax_t)lflags));
	}
	flags = (short)lflags;

	error = posix_spawnattr_setflags(attr, flags);
	assert(error == 0);
	lua_pushboolean(L, 1);
	return (1);
}

static int
lua_posix_spawnattr_getpgroup(lua_State *L)
{
	posix_spawnattr_t *attr;
	pid_t pgroup;
	int error;

	attr = luaL_checkudata(L, 1, POSIX_SPAWNATTR_KEY);

	error = posix_spawnattr_getpgroup(attr, &pgroup);
	assert(error == 0);
	lua_pushinteger(L, pgroup);
	return (1);
}

static int
lua_posix_spawnattr_setpgroup(lua_State *L)
{
	posix_spawnattr_t *attr;
	lua_Integer lpgrp;
	pid_t pgrp;
	int error;

	attr = luaL_checkudata(L, 1, POSIX_SPAWNATTR_KEY);
	lpgrp = luaL_checkinteger(L, 2);
	if (lpgrp > INT_MAX || lpgrp < INT_MIN)
		return (luaL_error(L, "pgrp too large: %jd", (intmax_t)lpgrp));
	pgrp = (pid_t)lpgrp;

	error = posix_spawnattr_setpgroup(attr, pgrp);
	assert(error == 0);
	lua_pushboolean(L, 1);
	return (1);
}

static int
lua_getpid(lua_State *L)
{
	int n;

	n = lua_gettop(L);
	luaL_argcheck(L, n == 0, 1, "too many arguments");
	lua_pushinteger(L, getpid());
	return 1;
}

static int
lua_uname(lua_State *L)
{
	struct utsname name;
	int error, n;

	n = lua_gettop(L);
	luaL_argcheck(L, n == 0, 1, "too many arguments");

	error = uname(&name);
	if (error != 0) {
		error = errno;
		lua_pushnil(L);
		lua_pushstring(L, strerror(error));
		lua_pushinteger(L, error);
		return (3);
	}

	lua_newtable(L);
#define	setkv(f) do {			\
	lua_pushstring(L, name.f);	\
	lua_setfield(L, -2, #f);	\
} while (0)
	setkv(sysname);
	setkv(nodename);
	setkv(release);
	setkv(version);
	setkv(machine);
#undef setkv

	return (1);
}

#define REG_SIMPLE(n)	{ #n, lua_ ## n }
static const struct luaL_Reg spawnlib[] = {
	REG_SIMPLE(posix_spawn),
	REG_SIMPLE(posix_spawnp),
	REG_SIMPLE(posix_spawn_file_actions_init),
	REG_SIMPLE(posix_spawn_file_actions_addopen),
	REG_SIMPLE(posix_spawn_file_actions_adddup2),
	REG_SIMPLE(posix_spawn_file_actions_addclose),

	/*
	 * XXX-MJ should these be excluded from the posix module and instead
	 * included in a hypothetical freebsd.c.spawn module?  Does the _np
	 * suffix have any formal significance in posix?
	 */
	REG_SIMPLE(posix_spawn_file_actions_addclosefrom_np),
	REG_SIMPLE(posix_spawn_file_actions_addchdir_np),
	REG_SIMPLE(posix_spawn_file_actions_addfchdir_np),

	REG_SIMPLE(posix_spawnattr_init),
	REG_SIMPLE(posix_spawnattr_getflags),
	REG_SIMPLE(posix_spawnattr_setflags),
	REG_SIMPLE(posix_spawnattr_getpgroup),
	REG_SIMPLE(posix_spawnattr_setpgroup),
#ifdef notyet
	REG_SIMPLE(posix_spawnattr_getsigdefault),
	REG_SIMPLE(posix_spawnattr_setsigdefault),
	REG_SIMPLE(posix_spawnattr_getsigmask),
	REG_SIMPLE(posix_spawnattr_setsigmask),
	REG_SIMPLE(posix_spawnattr_getschedparam),
	REG_SIMPLE(posix_spawnattr_setschedparam),
	REG_SIMPLE(posix_spawnattr_getschedpolicy),
	REG_SIMPLE(posix_spawnattr_setschedpolicy),
#endif
	{ NULL, NULL },
};

static int
lua_posix_spawn_file_actions_destroy(lua_State *L)
{
	posix_spawn_file_actions_t *file_actions;

	file_actions = luaL_checkudata(L, 1, POSIX_SPAWN_FILE_ACTIONS_KEY);
	posix_spawn_file_actions_destroy(file_actions);
	return (0);
}

static const struct luaL_Reg posix_spawn_file_actions_mt[] = {
	{ "__gc", lua_posix_spawn_file_actions_destroy },
	{ NULL, NULL }
};

static int
lua_freebsd_sys_fd_gc(lua_State *L)
{
	int error, *fdp;

	fdp = luaL_checkudata(L, 1, FREEBSD_SYS_FD_KEY);
	if (*fdp != -1) {
		error = close(*fdp);
		assert(error == 0);
		*fdp = -1;
	}
	return (0);
}

static const struct luaL_Reg lua_freebsd_sys_fd[] = {
	{ "__gc", lua_freebsd_sys_fd_gc },
	{ NULL, NULL },
};

static int
lua_posix_spawnattr_destroy(lua_State *L)
{
	posix_spawnattr_t *attr;

	attr = luaL_checkudata(L, 1, POSIX_SPAWNATTR_KEY);
	posix_spawnattr_destroy(attr);
	return (0);
}

static const struct luaL_Reg posix_spawnattr_mt[] = {
	{ "__gc", lua_posix_spawnattr_destroy },
	{ NULL, NULL }
};

static const struct luaL_Reg sys_statlib[] = {
	REG_SIMPLE(chmod),
	{ NULL, NULL },
};

static const struct luaL_Reg sys_utsnamelib[] = {
	REG_SIMPLE(uname),
	{ NULL, NULL },
};

static const struct luaL_Reg unistdlib[] = {
	REG_SIMPLE(chown),
	{ "close", lua_close_ }, /* XXX-MJ name collision */
	REG_SIMPLE(getpid),
	REG_SIMPLE(pipe),
	{ NULL, NULL },
};
#undef REG_SIMPLE

int
luaopen_posix_spawn(lua_State *L)
{
	int ret;

	ret = luaL_newmetatable(L, POSIX_SPAWN_FILE_ACTIONS_KEY);
	assert(ret == 1);
	luaL_setfuncs(L, posix_spawn_file_actions_mt, 0);
	ret = luaL_newmetatable(L, POSIX_SPAWNATTR_KEY);
	assert(ret == 1);
	luaL_setfuncs(L, posix_spawnattr_mt, 0);

	/* XXX-MJ this is generic and doesn't belong here */
	ret = luaL_newmetatable(L, FREEBSD_SYS_FD_KEY);
	assert(ret == 1);
	luaL_setfuncs(L, lua_freebsd_sys_fd, 0);

	luaL_newlib(L, spawnlib);
#define	ADDFLAG(c)		\
	lua_pushinteger(L, c);	\
	lua_setfield(L, -2, #c)
	ADDFLAG(POSIX_SPAWN_RESETIDS);
	ADDFLAG(POSIX_SPAWN_SETPGROUP);
	ADDFLAG(POSIX_SPAWN_SETSIGDEF);
	ADDFLAG(POSIX_SPAWN_SETSIGMASK);
	ADDFLAG(POSIX_SPAWN_SETSCHEDPARAM);
	ADDFLAG(POSIX_SPAWN_SETSCHEDULER);
#ifdef POSIX_SPAWN_DISABLE_ASLR_NP
	ADDFLAG(POSIX_SPAWN_DISABLE_ASLR_NP);
#endif
#undef ADDFLAG
	return (1);
}

int
luaopen_posix_sys_stat(lua_State *L)
{
	luaL_newlib(L, sys_statlib);
	return (1);
}

int
luaopen_posix_sys_utsname(lua_State *L)
{
	luaL_newlib(L, sys_utsnamelib);
	return (1);
}

int
luaopen_posix_unistd(lua_State *L)
{
	luaL_newlib(L, unistdlib);
	return (1);
}

/*
 * The base 'posix' module is a stopgap to implement a table compatible with
 * the real lposix implementation.  Ideally we'd just implement this as an
 * init.lua that require()s the other modules in, but defer that work until we
 * move all of this out into modules as it should be.  That particular work is
 * blocked on the bootstrap flua gaining module support (and bootstrap modules).
 */
int
luaopen_posix(lua_State *L)
{
	/* Somewhat duplicated from linit_flua.c */
	static const luaL_Reg posixlibs[] = {
	    { "posix.spawn", luaopen_posix_spawn },
	    { "posix.sys.stat", luaopen_posix_sys_stat },
	    { "posix.sys.utsname", luaopen_posix_sys_utsname },
	    { "posix.unistd", luaopen_posix_unistd },
	};

	lua_newtable(L);	/* posix */
	lua_newtable(L);	/* sys */

	for (size_t i = 0; i < nitems(posixlibs); i++) {
		const luaL_Reg *modinfo = &posixlibs[i];
		const char *name;
		int tblidx = -3;	/* posix */

		name = modinfo->name;
		assert(strncmp(name, "posix.", strlen("posix.")) == 0);
		luaL_requiref(L, name, modinfo->func, 1);

		/* Chop off the leading bit. */
		name += strlen("posix.");

		if (strncmp(name, "sys.", strlen("sys.")) == 0) {
			/* Add to the sys table instead. */
			tblidx = -2;

			name += strlen("sys.");
		}

		lua_setfield(L, tblidx, name);
	}

	/* Finally, push the sys table in. */
	lua_setfield(L, -2, "sys");
	return (1);
}
