/*
 * SPDX-License-Identifier: CDDL 1.0
 */
#ifndef _KINST_H_
#define _KINST_H_

typedef struct {
	char	func[DTRACE_FUNCNAMELEN];
	int	off;
} dtrace_kinst_probedesc_t;
#define KINSTIOC_MAKEPROBE	_IOW('k', 1, dtrace_kinst_probedesc_t)

#ifdef _KERNEL

#include <sys/queue.h>

#include "kinst_isa.h"

struct linker_file;
struct linker_symval;

struct kinst_probe {
	LIST_ENTRY(kinst_probe)	kp_hashnext;
	const char		*kp_func;
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
		register_t	kp_calladdr;
		uint8_t		*kp_trampoline;
	};
#endif /* __amd64__ */
};

LIST_HEAD(kinst_probe_list, kinst_probe);

extern dtrace_provider_id_t	kinst_id;
extern struct kinst_probe_list	*kinst_probetab;

#define KINST_PROBETAB_MAX	0x8000	/* 32k */
#define KINST_ADDR2NDX(addr)	(((uintptr_t)(addr)) & (KINST_PROBETAB_MAX - 1))
#define KINST_GETPROBE(i) 	(kinst_probetab[KINST_ADDR2NDX(i)])

int	kinst_invop(uintptr_t, struct trapframe *, uintptr_t);
void	kinst_patch_tracepoint(struct kinst_probe *, kinst_patchval_t);
int	kinst_make_probe(struct linker_file *, int, struct linker_symval *,
	    void *);

#endif /*_KERNEL */

#endif /* _KINST_H_ */
