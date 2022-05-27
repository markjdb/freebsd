/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Portions Copyright	2022 Christos Margiolis <christos@freebsd.org>
 *			2022 Mark Johnston <markj@freebsd.org>
 *
 * $FreeBSD$
 *
 */

#ifndef _KINST_H_
#define _KINST_H_

#define	KINST_PROBETAB_SIZE	0x8000		/* 32k entries -- 128K total */

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_KINST);
#endif /* MALLOC_DECLARE */

struct kinst_probe {
	char		kp_name[16];
	dtrace_id_t	kp_id;
	int		kp_flags;
	uint32_t	*kp_trampoline;
};

struct linker_file;
struct linker_symval;

extern dtrace_provider_id_t	kinst_id;
extern struct kinst_probe	**kinst_probetab;

//int	kinst_invop(uintptr_t, struct trapframe *, uintptr_t);
int	kinst_provide_module_function(struct linker_file *, int,
	    struct linker_symval *, void *);

#endif /* _KINST_H_ */
