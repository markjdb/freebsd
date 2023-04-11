/*
 * SPDX-License-Identifier: CDDL 1.0
 *
 * Copyright 2023 Christos Margiolis <christos@FreeBSD.org>
 */

#include <sys/param.h>

#include <sys/dtrace.h>
#include <cddl/dev/dtrace/dtrace_cddl.h>

#include "kinst.h"

/*
 * Per-CPU trampolines used when the interrupted thread is executing with
 * interrupts disabled.  If an interrupt is raised while executing a trampoline,
 * the interrupt thread cannot safely overwrite its trampoline if it hits a
 * kinst probe while executing the interrupt handler.
 */
DPCPU_DEFINE_STATIC(uint8_t *, intr_tramp);

static void
kinst_trampoline_populate(struct kinst_probe *kp, uint8_t *tramp)
{
	int ilen;

	ilen = kp->kp_md.instlen;
	memcpy(tramp, kp->kp_md.template, ilen);
	/*
	 * TODO explain
	 */
	memcpy(&tramp[ilen], &kp->kp_patchval, ilen);
}

int
kinst_invop(uintptr_t addr, struct trapframe *frame, uintptr_t scratch)
{
	solaris_cpu_t *cpu;
	struct kinst_probe *kp;
	uint8_t *tramp;

	if ((frame->tf_sstatus & SSTATUS_SPIE) == 0)
		tramp = DPCPU_GET(intr_tramp);
	else
		tramp = curthread->t_kinst;

	/*
	 * Detect if kinst_invop() was triggered by the trampoline breakpoint,
	 * and set PC manually to jump to the next instruction.
	 */
	if (tramp != NULL &&
	    addr == (uintptr_t)(tramp + dtrace_instr_size(tramp))) {
		kp = curthread->t_kinst_curprobe;
		curthread->t_kinst_curprobe = NULL;
		frame->tf_sepc =
		    (register_t)((uint8_t *)kp->kp_patchpoint +
		    kp->kp_md.instlen);
		return (MATCH_C_NOP);
	}

	LIST_FOREACH(kp, KINST_GETPROBE(addr), kp_hashnext) {
		if ((uintptr_t)kp->kp_patchpoint == addr)
			break;
	}
	if (kp == NULL)
		return (0);

	cpu = &solaris_cpu[curcpu];
	cpu->cpu_dtrace_caller = frame->tf_ra - INSN_SIZE;
	dtrace_probe(kp->kp_id, 0, 0, 0, 0, 0);
	cpu->cpu_dtrace_caller = 0;

	if (tramp == NULL) {
		/*
		 * A trampoline allocation failed, so this probe is
		 * effectively disabled.  Restore the original
		 * instruction.
		 *
		 * We can't safely print anything here, but the
		 * trampoline allocator should have left a breadcrumb in
		 * the dmesg.
		 */
		kinst_patch_tracepoint(kp, kp->kp_savedval);
		frame->tf_sepc = (register_t)kp->kp_patchpoint;
	} else {
		kinst_trampoline_populate(kp, tramp);
		frame->tf_sepc = (register_t)tramp;
		curthread->t_kinst_curprobe = kp;
	}
	return (MATCH_C_NOP);
}

void
kinst_patch_tracepoint(struct kinst_probe *kp, kinst_patchval_t val)
{
	switch (kp->kp_patchval) {
	case KINST_C_PATCHVAL:
		*(uint16_t *)kp->kp_patchpoint = (uint16_t)val;
		fence_i();
		break;
	case KINST_PATCHVAL:
		*kp->kp_patchpoint = val;
		fence_i();
		break;
	}
}

static int
kinst_instr_dissect(struct kinst_probe *kp, uint8_t *instr, int instrsize)
{
	struct kinst_probe_md *kpmd;

	kpmd = &kp->kp_md;
	kpmd->instlen = instrsize;
	kpmd->emulate = 0;

	if (kpmd->instlen == INSN_SIZE) {
		switch (*instr & 0x7f) {
		case 0b0000011:	/* load */
		case 0b0100011:	/* store */
		case 0b1101111: /* jal */
		case 0b1100111:	/* jalr */
		case 0b1100011:	/* branch */
		case 0b0110111:	/* lui */
		case 0b0010111:	/* auipc */
			kpmd->emulate = 1;
			break;
		}
	} else {
		/* TODO */
	}
	if (!kpmd->emulate)
		memcpy(kpmd->template, instr, kpmd->instlen);

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
		instrsize = dtrace_instr_size(instr);
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
		kp->kp_patchpoint = (kinst_patchval_t *)instr;
		kp->kp_savedval = *(kinst_patchval_t *)instr;
		if (instrsize == INSN_SIZE)
			kp->kp_patchval = KINST_PATCHVAL;
		else
			kp->kp_patchval = KINST_C_PATCHVAL;

		error = kinst_instr_dissect(kp, instr, instrsize);
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
