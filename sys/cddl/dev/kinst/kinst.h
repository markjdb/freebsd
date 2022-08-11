/*
 * SPDX-License-Identifier: CDDL 1.0
 */
#ifndef _KINST_H_
#define _KINST_H_

#include <sys/queue.h>

#include "kinst_isa.h"

struct linker_file;
struct linker_symval;

struct kinst_probe {
	char			kp_name[16];
	dtrace_id_t		kp_id;
	int			kp_rval;
	uint8_t			kp_len;
	kinst_patchval_t	kp_patchval;
	kinst_patchval_t	kp_savedval;
	kinst_patchval_t	*kp_patchpoint;
#ifdef __amd64__
	int			kp_frame_off;
	int			kp_immediate_off;
	union {
		uint8_t		*kp_trampoline;
		register_t	kp_calladdr;
	};
#endif /* __amd64__ */
};

extern dtrace_provider_id_t	kinst_id;
extern struct kinst_probe	**kinst_probetab;

#define KINST_PROBETAB_MAX	0x8000	/* 32k */
#define KINST_ADDR2NDX(addr)	(((uintptr_t)(addr)) & (KINST_PROBETAB_MAX - 1))

int	kinst_invop(uintptr_t, struct trapframe *, uintptr_t);
void	kinst_patch_tracepoint(struct kinst_probe *, kinst_patchval_t);
int	kinst_make_probe(struct linker_file *, int, struct linker_symval *,
	    void *);

#endif /* _KINST_H_ */
