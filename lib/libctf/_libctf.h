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

#ifndef __LIBCTF_H_
#define	__LIBCTF_H_

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/tree.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libelftc.h>

#include "libctf.h"

struct ctf_imtype;

struct _Ctf {
	STAILQ_HEAD(, ctf_imtype) ctf_dtypes;
	size_t		ctf_dtype_bsz;

	Elftc_String_Table *ctf_strtab;

	int		ctf_error;

	char		*ctf_buf;
	size_t		ctf_bufsz;

	ctf_id_t	ctf_nextid;

	int		ctf_model;
	void		*ctf_specific;
};

struct ctf_imtelem {
	size_t		e_name;
	uint64_t	e_type; /* func, struct, union */
	union {
		int	e_val;	/* enum */
		uint64_t e_off;	/* struct, union */
	};
};

struct ctf_imtelem_list {
	struct ctf_imtelem	*el_list;
	int			el_count;	/* entries */
	int			el_size;	/* total space */
};

/*
 * In-memory representation of a C type.
 */
struct ctf_imtype {
	size_t		t_name;
	int		t_kind;

	union {
		struct {
			struct ctf_imtelem_list vals;
		} t_enum;

		struct {
			struct ctf_imtelem_list params;
			bool		variadic;
		} t_func;

		struct {
			uint32_t	enc;
		} t_num;

		struct {
			struct ctf_imtelem_list members;
			size_t bsz;
		} t_sou;

		struct {
			uint64_t	id;
			uint64_t	tindex;	/* array */
			int		count;	/* array */
		} t_ref;
	};

	/* Fields filled in when adding a dynamic type to a container: */

	uint64_t	t_id;		/* CTF type index */
	size_t		t_ctfsz;	/* byte size of CTF representation */
	STAILQ_ENTRY(ctf_imtype) t_next; /* dynamic type list linkage */
};

#define	LIBCTF_SET_ERROR(errp, e) do {			\
	if ((errp) != NULL)				\
		*(errp) = (e);				\
} while (0)

static inline struct ctf_imtelem_list *
ctf_imtelem_list_init(struct ctf_imtelem_list *l, int n)
{

	l->el_list = malloc(n * sizeof(*l->el_list));
	assert(l != NULL);
	l->el_count = 0;
	l->el_size = n;
	return (l);
}

static inline void
ctf_imtelem_list_add(struct ctf_imtelem_list *l, struct ctf_imtelem *e)
{

	if (l->el_count == l->el_size) {
		l->el_size *= 2;
		l->el_list = realloc(l->el_list,
		    l->el_size * sizeof(*l->el_list));
	}
	l->el_list[l->el_count++] = *e;
}

ctf_id_t	libctf_add_type(Ctf *, struct ctf_imtype *);
Ctf		*libctf_create(size_t, int *);

#endif /* __LIBCTF_H_ */
