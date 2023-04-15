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

static int
kinst_regoff(struct trapframe *frame, int n)
{
#define _MATCH_REG(reg)	\
	(offsetof(struct trapframe, tf_ ## reg) / sizeof(register_t))

	switch (n) {
	case 0:
		/* There is no zero register in the trapframe structure. */
		return (-1);
	case 1:
		return (_MATCH_REG(ra));
	case 2:
		return (_MATCH_REG(sp));
	case 3:
		return (_MATCH_REG(gp));
	case 4:
		return (_MATCH_REG(tp));
	case 5 ... 7:
		return (_MATCH_REG(t[n - 5]));
	case 8 ... 9:
		return (_MATCH_REG(s[n - 8]));
	case 10 ... 17:
		return (_MATCH_REG(a[n - 10]));
	case 18 ... 27:
		return (_MATCH_REG(s[n - 18 + 2]));
	case 28 ... 31:
		return (_MATCH_REG(t[n - 28 + 3]));
#undef _MATCH_REG
	default:
		panic("%s: unhandled register index %d", __func__, n);
	}
}

/*
 * Emulate instructions that cannot be copied to the trampoline without
 * modification.
 */
static int
kinst_emulate(struct trapframe *frame, struct kinst_probe *kp)
{
	kinst_patchval_t instr = kp->kp_savedval;
	register_t prevpc;
	int32_t imm;
	uint8_t width, funct;

	if (kp->kp_md.instlen == INSN_SIZE) {
#define rs1_index	((instr & RS1_MASK) >> RS1_SHIFT)
#define rs2_index	((instr & RS2_MASK) >> RS2_SHIFT)
#define rd_index	((instr & RD_MASK) >> RD_SHIFT)
#define rs1		((register_t *)frame)[kinst_regoff(frame, rs1_index)]
#define rs2		((register_t *)frame)[kinst_regoff(frame, rs2_index)]
#define rd		((register_t *)frame)[kinst_regoff(frame, rd_index)]
#define rs1_lval	(rs1_index != 0 ? rs1 : 0)
#define rs2_lval	(rs2_index != 0 ? rs2 : 0)
		switch (instr & 0x7f) {
		case 0b0000011:	/* load */
			if (rd_index == 0)	/* XXX raise exception? */
				break;
			imm = (instr & IMM_MASK) >> IMM_SHIFT;
			if (imm & 0x00000800)
				imm |= 0xfffff000;
			width = (instr >> 12) & 0x07;
			switch (width) {
			case 0b000:	/* lb */
				rd = *(int8_t *)(rs1_lval + imm);
				break;
			case 0b001:	/* lh */
				rd = *(int16_t *)(rs1_lval + imm);
				break;
			case 0b010:	/* lw */
				rd = *(int32_t *)(rs1_lval + imm);
				break;
			case 0b100:	/* lbu */
				rd = *(uint8_t *)(rs1_lval + imm);
				break;
			case 0b101:	/* lhu */
				rd = *(uint16_t *)(rs1_lval + imm);
				break;
			case 0b110:	/* lwu */
				rd = *(uint32_t *)(rs1_lval + imm);
				break;
			case 0b011:	/* ld */
				rd = *(int64_t *)(rs1_lval + imm);
				break;
			}
			frame->tf_sepc += INSN_SIZE;
			break;
		case 0b0100011:	/* store */
			imm = (instr >> 7) & 0x1f;
			imm |= ((instr >> 25) & 0x7f) << 5;
			if (imm & 0x00000800)
				imm |= 0xfffff000;
			width = (instr >> 12) & 0x07;
			switch (width) {
			case 0b000:	/* sb */
				*(int8_t *)(rs1_lval + imm) = (int8_t)rs2_lval;
				break;
			case 0b001:	/* sh */
				*(int16_t *)(rs1_lval + imm) = (int16_t)rs2_lval;
				break;
			case 0b010:	/* sw */
				*(int32_t *)(rs1_lval + imm) = (int32_t)rs2_lval;
				break;
			case 0b011:	/* sd */
				*(int64_t *)(rs1_lval + imm) = (int64_t)rs2_lval;
				break;
			}
			frame->tf_sepc += INSN_SIZE;
			break;
		case 0b1101111: /* jal */
			imm = (instr >> 12) & 0x00ff;
			imm |= ((instr >> 20) & 0x0001) << 8;
			imm |= ((instr >> 21) & 0x03ff) << 9;
			imm |= ((instr >> 31) & 0x0001) << 19;
			if (imm & 0x00080000)
				imm |= 0xfff00000;
			if (rd_index != 0)
				rd = frame->tf_sepc + 4;
			frame->tf_sepc += imm;
			break;
		case 0b1100111:	/* jalr */
			prevpc = frame->tf_sepc;
			imm = (instr & IMM_MASK) >> IMM_SHIFT;
			if (imm & 0x00000800)
				imm |= 0xfffff000;
			frame->tf_sepc = (rs1_lval + imm) & ~1;
			if (rd_index != 0)
				rd = prevpc + 4;
			break;
		case 0b1100011:	/* branch */
			imm = (instr >> 7) & 0x0001;
			imm |= ((instr >> 8) & 0x000f) << 1;
			imm |= ((instr >> 25) & 0x003f) << 5;
			imm |= ((instr >> 31) & 0x0001) << 11;
			if (imm & 0x00000800)
				imm |= 0xfffff000;
			funct = (instr >> 12) & 0x07;
			switch (funct) {
			case 0b000:	/* beq */
				if (rs1_lval == rs2_lval)
					frame->tf_sepc += imm;
				else
					frame->tf_sepc += INSN_SIZE;
				break;
			case 0b001:	/* bne */
				if (rs1_lval != rs2_lval)
					frame->tf_sepc += imm;
				else
					frame->tf_sepc += INSN_SIZE;
				break;
			case 0b100:	/* blt */
				if ((int64_t)rs1_lval < (int64_t)rs2_lval)
					frame->tf_sepc += imm;
				else
					frame->tf_sepc += INSN_SIZE;
				break;
			case 0b110:	/* bltu */
				if ((uint64_t)rs1_lval < (uint64_t)rs2_lval)
					frame->tf_sepc += imm;
				else
					frame->tf_sepc += INSN_SIZE;
				break;
			case 0b101:	/* bge */
				if ((int64_t)rs1_lval >= (int64_t)rs2_lval)
					frame->tf_sepc += imm;
				else
					frame->tf_sepc += INSN_SIZE;
				break;
			case 0b111:	/* bgeu */
				if ((uint64_t)rs1_lval >= (uint64_t)rs2_lval)
					frame->tf_sepc += imm;
				else
					frame->tf_sepc += INSN_SIZE;
				break;
			}
			break;
		case 0b0110111:	/* lui */
			imm = instr & 0xfffff000;
			/* XXX: rd = zero */
			rd = imm;
			frame->tf_sepc += INSN_SIZE;
			break;
		case 0b0010111:	/* auipc */
			imm = instr & 0xfffff000;
			/* XXX: rd = zero */
			rd = frame->tf_sepc + imm;
			frame->tf_sepc += INSN_SIZE;
			break;
		}
#undef rs1_lval
#undef rs2_lval
#undef rs1
#undef rs2
#undef rd
#undef rs1_index
#undef rs2_index
#undef rd_index
	} else {
		/* TODO */
	}

	return (MATCH_C_NOP);
}

static void
kinst_trampoline_populate(struct kinst_probe *kp, uint8_t *tramp)
{
	int ilen;

	ilen = kp->kp_md.instlen;
	memcpy(tramp, kp->kp_md.template, ilen);
	/*
	 * Since we cannot encode large displacements in a single instruction
	 * in order to encode a far-jump back to the next instruction, and we
	 * also cannot clobber a register inside the trampoline, we instead add
	 * a breakpoint after the copied instruction. kinst_invop() is
	 * responsible for detecting this special case and perform the "jump"
	 * manually.
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
	 * and set PC manually to to the next instruction.
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

	if (kp->kp_md.emulate)
		return (kinst_emulate(frame, kp));

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
