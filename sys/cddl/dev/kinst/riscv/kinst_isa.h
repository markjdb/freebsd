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

/*
 * Each trampoline is 8 bytes long and contains [instruction, [nop], ebreak]. 8
 * bytes is enough to cover both compressed (instruction = 2 bytes, nop padding
 * = 2 bytes, ebreak = 4 bytes) and non-compressed instructions (instruction 4
 * bytes, ebreak = 4 bytes).
 */
#define KINST_TRAMP_SIZE	8
#define KINST_TRAMPCHUNK_SIZE	PAGE_SIZE
/*
 * TODO: explain
 */
#define KINST_TRAMP_FILL	KINST_PATCHVAL
#define KINST_TRAMP_FILL_SIZE	sizeof(uint32_t)

typedef uint32_t kinst_patchval_t;

struct kinst_probe_md {
	int		emulate;	/* emulate in sw */
	int		instlen;	/* original instr len */
	uint8_t		template[4];	/* copied into thread tramps */
};

#endif /* _KINST_ISA_H_ */
