/*
 * SPDX-License-Identifier: CDDL 1.0
 *
 * Copyright 2023 Christos Margiolis <christos@FreeBSD.org>
 */

#ifndef _KINST_ISA_H_
#define _KINST_ISA_H_

#include <machine/riscvreg.h>
#include <machine/encoding.h>

#define KINST_PATCHVAL		MATCH_EBREAK
#define KINST_C_PATCHVAL	MATCH_C_EBREAK

#define KINST_TRAMP_SIZE	32
#define KINST_TRAMPCHUNK_SIZE	PAGE_SIZE

#define KINST_TRAMP_INIT(t, s)	memset((t), KINST_PATCHVAL, (s))

typedef uint32_t kinst_patchval_t;

struct kinst_probe_md {
	int			instlen;	/* original instr len */
	int			tinstlen;	/* trampoline instr len */
	uint8_t			template[16];	/* copied into thread tramps */
};

#endif /* _KINST_ISA_H_ */
