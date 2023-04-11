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
 * Each trampoline is 8 bytes long and contains [instruction, ebreak]. Since we
 * have 2 instructions stored in the trampoline, and each of them can take up
 * to 4 bytes, 8 bytes is enough to cover even the worst case scenario.
 */
#define KINST_TRAMP_SIZE	8
#define KINST_TRAMPCHUNK_SIZE	PAGE_SIZE

typedef uint32_t kinst_patchval_t;

struct kinst_probe_md {
	int		emulate;			/* emulate in sw */
	int		instlen;			/* original instr len */
	uint8_t		template[KINST_TRAMP_SIZE / 2];	/* copied into thread tramps */
};

#endif /* _KINST_ISA_H_ */
