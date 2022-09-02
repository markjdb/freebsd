/*
 * SPDX-License-Identifier: CDDL 1.0
 */
#include <sys/param.h>

#include <machine/cpufunc.h>
#include <machine/md_var.h>

#include <sys/dtrace.h>
#include <cddl/dev/dtrace/dtrace_cddl.h>
#include <dis_tables.h>

#include "extern.h"
#include "kinst.h"
#include "trampoline.h"

#define KINST_PUSHL_RBP		0x55
#define KINST_STI		0xfb
#define KINST_POPF		0x9d

#define KINST_MOD_DEPENDENT	0xff

#define KINST_CALL_DIRECT	0xe8

#define KINST_JMP		0xe9
#define KINST_JMP_LEN		5

#define KINST_NEARJMP_PREFIX	0x0f
#define KINST_NEARJMP_FIRST	0x80
#define KINST_NEARJMP_LAST	0x8f
#define KINST_NEARJMP_LEN	6

#define KINST_UNCOND_SHORTJMP	0xeb
#define KINST_SHORTJMP_FIRST	0x70
#define KINST_SHORTJMP_LAST	0x7f
#define KINST_SHORTJMP_LEN	2

#define KINST_MOD(b)		(((b) & 0xc0) >> 6)
#define KINST_REG(b)		(((b) & 0x38) >> 3)
#define KINST_RM(b)		((b) & 0x07)
#define KINST_MODRM(b)		((KINST_MOD(b) << 3) | KINST_RM(b))

#define KINST_MODRM_RIPREL(b)	(KINST_MODRM(b) == 5)

#define KINST_F_CALL		0x0001
#define KINST_F_DIRECT_CALL	0x0002
#define KINST_F_RIPREL_CALL	0x0004
#define KINST_F_REG_CALL	0x0008

static int	kinst_dis_get_byte(void *);
static int32_t	kinst_displ(uint8_t *, uint8_t *, int);
static int	kinst_is_uncond_jmp(uint8_t *);
static int	kinst_is_short_jmp(uint8_t *);
static int	kinst_is_near_jmp(uint8_t *);
static int	kinst_is_jmp(uint8_t *);
static int	kinst_match_regoff(int);

int
kinst_invop(uintptr_t addr, struct trapframe *frame, uintptr_t scratch)
{
	solaris_cpu_t *cpu;
	uintptr_t *stack, *retaddr;
	struct kinst_probe *kp;

	stack = (uintptr_t *)frame->tf_rsp;
	cpu = &solaris_cpu[curcpu];

	LIST_FOREACH(kp, &KINST_GETPROBE(addr), kp_hashnext) {
		if ((uintptr_t)kp->kp_patchpoint != addr)
			return (0);
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		cpu->cpu_dtrace_caller = stack[0];
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT | CPU_DTRACE_BADADDR);
		dtrace_probe(kp->kp_id, 0, 0, 0, 0, 0);
		cpu->cpu_dtrace_caller = 0;

		if (kp->kp_flags & KINST_F_CALL) {
			retaddr = (uintptr_t *)(kp->kp_patchpoint + kp->kp_len);
			/*
			 * dtrace_invop_start() reserves 16 bytes on the stack
			 * as a scratch buffer to store the return address of
			 * the call instruction.
			 */
			*(void **)scratch = retaddr;
			/*
			 * The call address can only be computed here because
			 * we don't know and cannot access the register
			 * contents anywhere else.
			 */
			if (kp->kp_flags & KINST_F_RIPREL_CALL) {
				frame->tf_rip =
				    *(uintptr_t *)(kp->kp_patchpoint +
				    kp->kp_immediate_off);
			} else if (kp->kp_flags & KINST_F_REG_CALL) {
				frame->tf_rip =
				    *(uintptr_t *)
				    (((register_t *)frame)[kp->kp_frame_off] +
				    kp->kp_immediate_off);
			} else
				frame->tf_rip = kp->kp_calladdr;
		} else
			frame->tf_rip = (register_t)kp->kp_trampoline;

		return (kp->kp_rval);
	}

	return (0);
}

void
kinst_patch_tracepoint(struct kinst_probe *kp, kinst_patchval_t val)
{
	register_t reg;
	int oldwp;

	reg = intr_disable();
	oldwp = disable_wp();
	*kp->kp_patchpoint = val;
	restore_wp(oldwp);
	intr_restore(reg);
}

int
kinst_make_probe(linker_file_t lf, int symindx, linker_symval_t *symval,
    void *opaque)
{
	struct kinst_probe *kp;
	dis86_t d86;
	dtrace_kinst_probedesc_t *pd;
	const char *func;
	int n, off, mode, opclen, trlen, rmidx;
	int32_t displ, origdispl;
	uint8_t *curinstr, *instr, *limit, *bytes, *modrm;

	pd = opaque;
	func = symval->name;
	if (strcmp(func, pd->func) != 0 ||
	    strcmp(func, "trap_check") == 0)
		return (0);

	instr = (uint8_t *)symval->value;
	limit = (uint8_t *)symval->value + symval->size;
	mode = (DATAMODEL_LP64 == DATAMODEL_NATIVE) ? SIZE64 : SIZE32;

	if (instr >= limit)
		return (0);

	/*
	 * Ignore functions not beginning with the usual function prologue.
	 * These might correspond to assembly routines with which we should not
	 * meddle.
	 */
	if (*instr != KINST_PUSHL_RBP)
		return (0);

	n = 0;
	while (instr < limit) {
		off = (int)(instr - (uint8_t *)symval->value);
		/*
		 * In libdtrace we set pd->off to -1 in case the probe name is
		 * a wildcard. To reduce overhead, we want to create probes for
		 * all instructions at once, instead of going through the ioctl
		 * for each new probe.
		 *
		 * We also want to ignore the sti and popf instructions,
		 * otherwise we cannot use dtrace_sync() to create barriers.
		 * Those instructions can break the atomicity of the trampoline
		 * mechanism in case a thread is interrupted while it's
		 * executing the trampoline.
		 */
		if ((pd->off != off && pd->off != -1) ||
		    *instr == KINST_STI || *instr == KINST_POPF) {
			instr += dtrace_instr_size(instr);
			continue;
		}
		/*
		 * Prevent separate dtrace(1) instances from creating copies of
		 * the same probe.
		 */
		LIST_FOREACH(kp, &KINST_GETPROBE(instr), kp_hashnext) {
			if (strcmp(kp->kp_func, func) == 0 &&
			    strtol(kp->kp_name, NULL, 10) == off)
				return (0);
		}
		if (++n > KINST_PROBETAB_MAX) {
			KINST_LOG("probe list full: %d entries", n);
			return (ENOMEM);
		}
		kp = malloc(sizeof(struct kinst_probe), M_KINST, M_WAITOK | M_ZERO);
		kp->kp_func = func;
		snprintf(kp->kp_name, sizeof(kp->kp_name), "%d", off);
		kp->kp_savedval = *instr;
		kp->kp_patchval = KINST_PATCHVAL;
		kp->kp_patchpoint = instr;
		kp->kp_flags = 0;

		curinstr = instr;
		d86.d86_data = (void **)&instr;
		d86.d86_get_byte = kinst_dis_get_byte;
		d86.d86_check_func = NULL;
		if (dtrace_disx86(&d86, mode) != 0) {
			KINST_LOG("failed to disassemble instruction at: %p", instr);
			return (EINVAL);
		}
		bytes = d86.d86_bytes;
		kp->kp_len = d86.d86_len;
		if (d86.d86_got_modrm) {
			rmidx = d86.d86_rmindex;
			modrm = &bytes[rmidx];
		}

		if (*bytes != KINST_MOD_DEPENDENT)
			goto skip;
		switch (KINST_REG(*modrm)) {
		case 0:
			/* TODO: inc */
			break;
		case 1:
			/* TODO: das */
			break;
		case 2:	/* FALLTHROUGH */
		case 3:
			if (KINST_MODRM_RIPREL(*modrm)) {
				memcpy(&origdispl, modrm + 1, sizeof(origdispl));
				kp->kp_immediate_off = origdispl + kp->kp_len;
				kp->kp_flags |= KINST_F_RIPREL_CALL;
			} else {
				int reg;

				/*
				 * Takes into account both the opcode and the
				 * MODRM byte.
				 */
				opclen = 2;
				reg = KINST_RM(*modrm);
				kp->kp_frame_off = kinst_match_regoff(reg);
				/*
				 * If the instruction is longer than 2 bytes,
				 * it means that there's an offset after MODRM.
				 */
				if (kp->kp_len > opclen) {
					memcpy(&kp->kp_immediate_off, modrm + 1,
					    kp->kp_len - opclen);
				} else
					kp->kp_immediate_off = 0;
				kp->kp_flags |= KINST_F_REG_CALL;
			}
			kp->kp_flags |= KINST_F_CALL;
			kp->kp_rval = DTRACE_INVOP_CALL;
			goto done;
		case 4:	/* FALLTHROUGH */
		case 5:
			/* TODO: jmp */
			break;
		case 6:
			/* TODO: push */
			break;
		}
skip:
		if (*bytes == KINST_CALL_DIRECT) {
			/*
			 * call instructions cannot be straightforwardly copied
			 * to a trampoline since they would store the wrong
			 * return address.  Instead, they are emulated in
			 * software with some help from kinst_invop().
			 */
			memcpy(&origdispl, &bytes[1], sizeof(origdispl));
			kp->kp_calladdr =
			    (register_t)(curinstr + origdispl + kp->kp_len);
			kp->kp_flags |= KINST_F_CALL | KINST_F_DIRECT_CALL;
			kp->kp_rval = DTRACE_INVOP_CALL;
			goto done;
		}

		if ((kp->kp_trampoline = kinst_trampoline_alloc()) == NULL) {
			KINST_LOG("cannot allocate trampoline for: %p", instr);
			return (ENOMEM);
		}

		if (kinst_is_jmp(bytes)) {
			/*
			 * For jump instructions, we need to recalculate the
			 * jump offsets to be relative to the trampoline.
			 */
			opclen = kinst_is_near_jmp(bytes) ? 2 : 1;
			memcpy(&origdispl, &bytes[opclen], sizeof(origdispl));
			if (kinst_is_short_jmp(bytes)) {
				if (*bytes == KINST_UNCOND_SHORTJMP) {
					/*
					 * Convert unconditional short JMP to a
					 * regular JMP.
					 */
					kp->kp_trampoline[0] = KINST_JMP;
					trlen = KINST_JMP_LEN;
				} else {
					/*
					 * "Recalculate" the opcode length
					 * since we are converting from a short
					 * to near jump. That's a hack.
					 */
					opclen = 0;
					kp->kp_trampoline[opclen++] =
					    KINST_NEARJMP_PREFIX;
					/*
					 * Convert short-jump to its near-jmp
					 * equivalent.
					 */
					kp->kp_trampoline[opclen++] =
					    *bytes + 0x10;
					trlen = KINST_NEARJMP_LEN;
				}
				displ = kinst_displ(curinstr +
				    (origdispl & 0xff) + KINST_SHORTJMP_LEN,
				    kp->kp_trampoline, trlen);
			} else {
				if (kinst_is_uncond_jmp(bytes))
					trlen = KINST_JMP_LEN;
				else
					trlen = KINST_NEARJMP_LEN;
				memcpy(kp->kp_trampoline, bytes, opclen);
				displ = kinst_displ(curinstr + origdispl + trlen,
				    kp->kp_trampoline, trlen);
			}
			memcpy(&kp->kp_trampoline[opclen], &displ, sizeof(displ));
		} else if (d86.d86_got_modrm && KINST_MODRM_RIPREL(*modrm)) {
			/*
			 * Handle %rip-relative MOVs.
			 */
			opclen = rmidx + 1;
			trlen = kp->kp_len;
			memcpy(&origdispl, modrm + 1, sizeof(origdispl));
			memcpy(kp->kp_trampoline, bytes, rmidx + 1);
			/*
			 * Create a new %rip-relative instruction with a
			 * recalculated offset to %rip.
			 */
			displ = kinst_displ(curinstr + origdispl + trlen,
			    kp->kp_trampoline, trlen);
			memcpy(&kp->kp_trampoline[opclen], &displ, sizeof(displ));
		} else {
			/*
			 * Regular instructions need no modification, just copy
			 * them to the trampoline as-is.
			 */
			memcpy(kp->kp_trampoline, bytes, kp->kp_len);
			trlen = kp->kp_len;
		}

		/*
		 * The following jmp takes us back to the original code.  It is
		 * encoded as "jmp *0(%rip)" (six bytes), followed by the
		 * absolute address of the instruction following the one that
		 * was traced (eight bytes).
		 */
		kp->kp_trampoline[trlen + 0] = 0xff;
		kp->kp_trampoline[trlen + 1] = 0x25;
		kp->kp_trampoline[trlen + 2] = 0x00;
		kp->kp_trampoline[trlen + 3] = 0x00;
		kp->kp_trampoline[trlen + 4] = 0x00;
		kp->kp_trampoline[trlen + 5] = 0x00;
		memcpy(&kp->kp_trampoline[trlen + 6], &instr, sizeof(uint64_t));

		kp->kp_rval = DTRACE_INVOP_NOP;
done:
		kp->kp_id = dtrace_probe_create(kinst_id, lf->filename,
		    kp->kp_func, kp->kp_name, 3, kp);

		if (&KINST_GETPROBE(curinstr) == NULL)
			LIST_INIT(&KINST_GETPROBE(curinstr));
		LIST_INSERT_HEAD(&KINST_GETPROBE(curinstr), kp, kp_hashnext);
	}

	return (0);
}

static int
kinst_dis_get_byte(void *p)
{
	int ret;
	uint8_t **instr = p;

	ret = **instr;
	(*instr)++;

	return (ret);
}

static int32_t
kinst_displ(uint8_t *dst, uint8_t *src, int len)
{
	return (dst - (src + len));
}

static int
kinst_is_uncond_jmp(uint8_t *bytes)
{
	return (bytes[0] == KINST_JMP);
}

static int
kinst_is_short_jmp(uint8_t *bytes)
{
	/*
	 * KINST_UNCOND_SHORTJMP could be kinst_is_uncond_jmp() but I
	 * think it's easier to work with if we have it here.
	 */
	return ((bytes[0] >= KINST_SHORTJMP_FIRST &&
	    bytes[0] <= KINST_SHORTJMP_LAST) ||
	    bytes[0] == KINST_UNCOND_SHORTJMP);
}

static int
kinst_is_near_jmp(uint8_t *bytes)
{
	return (bytes[0] == KINST_NEARJMP_PREFIX &&
	    bytes[1] >= KINST_NEARJMP_FIRST &&
	    bytes[1] <= KINST_NEARJMP_LAST);
}

static int
kinst_is_jmp(uint8_t *bytes)
{
	return (kinst_is_uncond_jmp(bytes) ||
	    kinst_is_short_jmp(bytes) ||
	    kinst_is_near_jmp(bytes));
}

enum {
	KINST_REG_RAX,
	KINST_REG_RCX,
	KINST_REG_RDX,
	KINST_REG_RBX,
	KINST_REG_RSP,
	KINST_REG_RBP,
	KINST_REG_RSI,
	KINST_REG_RDI,
};

static int
kinst_match_regoff(int reg)
{
	int off;

	switch (reg) {
	case KINST_REG_RAX:
		off = offsetof(struct trapframe, tf_rax);
		break;
	case KINST_REG_RCX:
		off = offsetof(struct trapframe, tf_rcx);
		break;
	case KINST_REG_RDX:
		off = offsetof(struct trapframe, tf_rdx);
		break;
	case KINST_REG_RBX:
		off = offsetof(struct trapframe, tf_rbx);
		break;
	case KINST_REG_RSP:
		off = offsetof(struct trapframe, tf_rsp);
		break;
	case KINST_REG_RBP:
		off = offsetof(struct trapframe, tf_rbp);
		break;
	case KINST_REG_RSI:
		off = offsetof(struct trapframe, tf_rsi);
		break;
	case KINST_REG_RDI:
		off = offsetof(struct trapframe, tf_rdi);
		break;
	}

	return (off / sizeof(register_t));
}
