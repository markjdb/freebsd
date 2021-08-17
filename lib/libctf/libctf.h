/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2019 Mark Johnston <markj@FreeBSD.org>
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

#ifndef _LIBCTF_H_
#define	_LIBCTF_H_

#include <sys/types.h>
#include <sys/ctf.h>

typedef long ctf_id_t;

typedef struct _Ctf Ctf;

enum Ctf_Error {
	CTF_E_NONE,
	CTF_E_ARGUMENT,
	CTF_E_FULL,
	CTF_E_IO,
	CTF_E_RESOURCE,
	CTF_E_VERSION,
};

#define	CTF_MODEL_ILP32	1
#define	CTF_MODEL_LP64	2

#ifdef __LP64__
#define	CTF_MODEL_NATIVE	CTF_MODEL_LP64
#else
#define	CTF_MODEL_NATIVE	CTF_MODEL_ILP32
#endif

#ifdef __cplusplus
extern "C" {
#endif

ctf_id_t	ctf_add_array(Ctf *_ctf, unsigned int _flags /*, XXX */);
ctf_id_t	ctf_add_const(Ctf *_ctf, unsigned int _flags, ctf_id_t _id);
ctf_id_t	ctf_add_enum(Ctf *_ctf, unsigned int _flags, const char *_name);
int		ctf_add_enumerator(Ctf *_ctf, ctf_id_t _id, const char *_name,
		    int value);
ctf_id_t	ctf_add_float(Ctf *_ctf, unsigned int _flags, const char *_name,
		    unsigned int _encoding);
ctf_id_t	ctf_add_function(Ctf *_ctf, unsigned int _flags /*, XXX */);
ctf_id_t	ctf_add_integer(Ctf *_ctf, unsigned int _flags,
		    unsigned int _encoding);
int		ctf_add_member(Ctf *_ctf, ctf_id_t _id, const char *_name,
		    ctf_id_t _type);
ctf_id_t	ctf_add_pointer(Ctf *_ctf, unsigned int _flags, ctf_id_t _ref);
ctf_id_t	ctf_add_restrict(Ctf *_ctf, unsigned int _flags, ctf_id_t _ref);
ctf_id_t	ctf_add_typedef(Ctf *_ctf, unsigned int _flags,
		    const char *_name, ctf_id_t _ref);
ctf_id_t	ctf_add_volatile(Ctf *_ctf, unsigned int _flags, ctf_id_t _ref);
void		ctf_close(Ctf *_ctf);
const char	*ctf_enum_name(Ctf *_ctf, ctf_id_t _id, int _value);
int		ctf_enum_value(Ctf *_ctf, ctf_id_t _id, const char *_name,
		    int *_valp);
const char	*ctf_errmsg(int _error);
int		ctf_errno(Ctf *_ctf);
Ctf		*ctf_fdopen(int _fd, int *_errp);
int		ctf_getmodel(Ctf *_ctf);
void		*ctf_getspecific(Ctf *_ctf);
ctf_id_t	ctf_lookup_by_name(Ctf *_ctf, const char *_name);
Ctf		*ctf_open(const char *_path, int *_errp);
int		ctf_setmodel(Ctf *_ctf, int _model);
void		ctf_setspecific(Ctf *_ctf, void *_value);
ctf_id_t	ctf_type_resolve(Ctf *_ctf, ctf_id_t _id);
int		ctf_update(Ctf *_ctf);
int		ctf_version(int _version);
int		ctf_write(Ctf *_ctf, int _fd);

Ctf		*ctf_convert_dwarf(int, void (*)(const char *));

#ifdef __cplusplus
}
#endif

#endif /* _LIBCTF_H_ */
