/*
 * SPDX-License-Identifier: CDDL 1.0
 *
 * Copyright 2023 Christos Margiolis <christos@FreeBSD.org>
 */

#include <sys/param.h>

#include <sys/dtrace.h>
#include <cddl/dev/dtrace/dtrace_cddl.h>

#include "kinst.h"

#define KINST_RVC_MASK	0x03

/*
 * Per-CPU trampolines used when the interrupted thread is executing with
 * interrupts disabled.  If an interrupt is raised while executing a trampoline,
 * the interrupt thread cannot safely overwrite its trampoline if it hits a
 * kinst probe while executing the interrupt handler.
 */
DPCPU_DEFINE_STATIC(uint8_t *, intr_tramp);

int
kinst_invop(uintptr_t addr, struct trapframe *frame, uintptr_t scratch)
{
	return (0);
}

void
kinst_patch_tracepoint(struct kinst_probe *kp, kinst_patchval_t val)
{
	/*switch (kp->kp_patchval) {*/
	/*case KINST_C_PATCHVAL:*/
		/**(uint16_t *)kp->kp_patchpoint = (uint16_t)val;*/
		/*fence_i();*/
		/*break;*/
	/*case KINST_PATCHVAL:*/
		/**kp->kp_patchpoint = val;*/
		/*fence_i();*/
		/*break;*/
	/*}*/

	printf("%p\t", kp->kp_patchpoint);
	for (int i = 0; i < kp->kp_md.instlen; i++)
		printf("%02x ", *((uint8_t *)(kp->kp_patchpoint + i)));
	printf("\n");
}

static int
kinst_instr_dissect(struct kinst_probe *kp, uint8_t **instr, int instrsize)
{
	struct kinst_probe_md *kpmd;

	kpmd = &kp->kp_md;
	kpmd->instlen = kpmd->tinstlen = instrsize;

	memcpy(kpmd->template, *instr, kpmd->instlen);

	return (0);
}

int
kinst_make_probe(linker_file_t lf, int symindx, linker_symval_t *symval,
    void *opaque)
{
	struct kinst_probe *kp;
	dtrace_kinst_probedesc_t *pd;
	const char *func;
	uint8_t *instr, *limit;
	int error, instrsize, n, off;

	pd = opaque;
	func = symval->name;

	if (kinst_excluded(func))
		return (0);
	if (strcmp(func, pd->kpd_func) != 0)
		return (0);

	instr = (uint8_t *)symval->value;
	limit = (uint8_t *)symval->value + symval->size;
	if (instr >= limit)
		return (0);

	n = 0;
	/*
	 * Parse instructions byte-by-byte to be able to determine their size.
	 */
	while (instr < limit) {
		/* Detect compressed instructions. */
		if ((~(*instr) & KINST_RVC_MASK) == 0)
			instrsize = 4;
		else
			instrsize = 2;
		off = (int)(instr - (uint8_t *)symval->value);
		if (pd->kpd_off != -1 && off != pd->kpd_off)
			goto cont;
		
		/* TODO: handle sti and popf equivalents */

		/*
		 * Prevent separate dtrace(1) instances from creating copies of
		 * the same probe.
		 */
		LIST_FOREACH(kp, KINST_GETPROBE(instr), kp_hashnext) {
			if (strcmp(kp->kp_func, func) == 0 &&
			    strtol(kp->kp_name, NULL, 10) == off)
				return (0);
		}
		if (++n > KINST_PROBETAB_MAX) {
			KINST_LOG("probe list full: %d entries", n);
			return (ENOMEM);
		}
		kp = malloc(sizeof(struct kinst_probe), M_KINST,
		    M_WAITOK | M_ZERO);
		kp->kp_func = func;
		snprintf(kp->kp_name, sizeof(kp->kp_name), "%d", off);
		kp->kp_savedval = *instr;
		if (instrsize == 2)
			kp->kp_patchval = KINST_C_PATCHVAL;
		else
			kp->kp_patchval = KINST_PATCHVAL;
		kp->kp_patchpoint = (kinst_patchval_t *)instr;

		error = kinst_instr_dissect(kp, &instr, instrsize);
		if (error != 0)
			return (error);

		kinst_probe_create(kp, lf);
cont:
		instr += instrsize;
	}

	return (0);
}

int
kinst_md_init(void)
{
	uint8_t *tramp;
	int cpu;

	CPU_FOREACH(cpu) {
		tramp = kinst_trampoline_alloc(M_WAITOK);
		if (tramp == NULL)
			return (ENOMEM);
		DPCPU_ID_SET(cpu, intr_tramp, tramp);
	}

	return (0);
}

void
kinst_md_deinit(void)
{
	uint8_t *tramp;
	int cpu;

	CPU_FOREACH(cpu) {
		tramp = DPCPU_ID_GET(cpu, intr_tramp);
		if (tramp != NULL) {
			kinst_trampoline_dealloc(DPCPU_ID_GET(cpu, intr_tramp));
			DPCPU_ID_SET(cpu, intr_tramp, NULL);
		}
	}
}
