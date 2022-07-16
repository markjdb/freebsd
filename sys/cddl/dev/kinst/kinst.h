/*
 * SPDX-License-Identifier: CDDL 1.0
 */
#ifndef _KINST_H_
#define _KINST_H_

#include <sys/queue.h>

#include "kinst_isa.h"

#define KINST_PROBE_MAX	0x8000	/* 32k */

struct linker_file;
struct linker_symval;

struct kinst_probe {
	TAILQ_ENTRY(kinst_probe) kp_next;
	char		kp_name[16];
	dtrace_id_t	kp_id;
	uint8_t		*kp_trampoline;
	kinst_patchval_t *kp_patchpoint;
	kinst_patchval_t kp_patchval;
	kinst_patchval_t kp_savedval;
};

extern dtrace_provider_id_t			kinst_id;
/* TODO: convert to hashtable */
extern TAILQ_HEAD(kinsthead, kinst_probe)	kinst_probes;

int	kinst_invop(uintptr_t, struct trapframe *, uintptr_t);
void	kinst_patch_tracepoint(struct kinst_probe *, kinst_patchval_t);
int	kinst_make_probe(struct linker_file *, int, struct linker_symval *,
	    void *);

#endif /* _KINST_H_ */
