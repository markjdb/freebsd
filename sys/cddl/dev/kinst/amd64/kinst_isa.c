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

#define KINST_PUSHL_EBP		0x55
#define KINST_STI		0xfb
#define KINST_POPF		0x9d

#define KINST_CALL		0xe8
#define KINST_CALL_REG		0xff

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

#define KINST_MODRM_RIPREL	0x05
#define KINST_MOD(b)		(((b) & 0xc0) >> 6)
#define KINST_RM(b)		((b) & 0x07)

static int	kinst_dis_get_byte(void *);
static int32_t	kinst_displ(uint8_t *, uint8_t *, int);
static int	kinst_is_call(uint8_t *);
static int	kinst_is_uncond_jmp(uint8_t *);
static int	kinst_is_short_jmp(uint8_t *);
static int	kinst_is_near_jmp(uint8_t *);
static int	kinst_is_jmp(uint8_t *);

int
kinst_invop(uintptr_t addr, struct trapframe *frame, uintptr_t rval)
{
	solaris_cpu_t *cpu;
	uintptr_t *stack;
	struct kinst_probe *kp;

	stack = (uintptr_t *)frame->tf_rsp;
	cpu = &solaris_cpu[curcpu];
	kp = kinst_probetab[KINST_ADDR2NDX(addr)];

	if ((uintptr_t)kp->kp_patchpoint != addr)
		return (0);
	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	cpu->cpu_dtrace_caller = stack[0];
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT | CPU_DTRACE_BADADDR);
	dtrace_probe(kp->kp_id, 0, 0, 0, 0, 0);
	cpu->cpu_dtrace_caller = 0;
	/* Redirect execution to the trampoline after iret. */
	frame->tf_rip = (register_t)kp->kp_trampoline;
	/*
	 * dtrace_invop_start() reserves 16 bytes to store the call address.
	 * Save the return address of the call 8 bytes below the trapframe.
	 * TODO explain further
	 *
	 * Magic.
	 */
	if (kinst_is_call(&kp->kp_savedval)) {
		*(uintptr_t *)((uintptr_t)frame - 8) =
		    (uintptr_t)(kp->kp_patchpoint + kp->kp_len);
	}

	return (kp->kp_rval);
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
	int n, off, mode, opclen, trlen;
	int32_t displ, origdispl;
	uint8_t *curinstr, *instr, *limit, *bytes;

	pd = opaque;
	if (strcmp(symval->name, pd->func) != 0 ||
	    strcmp(symval->name, "trap_check") == 0)
		return (0);

	instr = (uint8_t *)symval->value;
	limit = (uint8_t *)symval->value + symval->size;
	mode = (DATAMODEL_LP64 == DATAMODEL_NATIVE) ? SIZE64 : SIZE32;

	if (instr >= limit)
		return (0);
	/*
	 * TODO: explain
	 */
	if (*instr != KINST_PUSHL_EBP)
		return (0);

	n = 0;
	/*
	 * TODO: explain
	 */
	while (instr < limit) {
		off = (int)(instr - (uint8_t *)symval->value);
		/*
		 * In libdtrace we set pd->off to -1 in case the probe name is
		 * a wildcard. To reduce overhead, we want to create probes for
		 * all instructions at once, instead of going through the ioctl
		 * for each new probe.
		 *
		 * We also want to ignore the sti and popf instructions.
		 * TODO: explain why
		 */
		if ((pd->off != off && pd->off != -1) ||
		    *instr == KINST_STI || *instr == KINST_POPF) {
			instr += dtrace_instr_size(instr);
			continue;
		}
		if (++n > KINST_PROBETAB_MAX) {
			KINST_LOG("probe list full: %d entries", n);
			return (ENOMEM);
		}
		kp = malloc(sizeof(struct kinst_probe), M_KINST, M_WAITOK | M_ZERO);
		snprintf(kp->kp_name, sizeof(kp->kp_name), "%d", off);
		/*
		 * Save the first byte of the instruction so that we can
		 * recover it when the probe is disabled.
		 */
		kp->kp_savedval = *instr;
		kp->kp_patchval = KINST_PATCHVAL;
		kp->kp_patchpoint = instr;

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

		/*
		 * TODO: explain why call needs special handling
		 */
		if (kinst_is_call(bytes)) {
			memcpy(&origdispl, &bytes[1], sizeof(origdispl));
			/*
			 * The trampoline is pointing at the call target.
			 * Although the trampoline has a different function for
			 * all non-call instructons, we're reusing it here to
			 * avoid having machine-dependent fields in the probe
			 * structure.
			 */
			kp->kp_trampoline = curinstr + origdispl + kp->kp_len;
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
		} else if (d86.d86_got_modrm &&
		    KINST_MOD(bytes[d86.d86_rmindex]) == 0 &&
		    KINST_RM(bytes[d86.d86_rmindex]) == 5) {
			/*
			 * Handle %rip-relative MOVs.
			 */
			opclen = d86.d86_rmindex + 1;
			trlen = kp->kp_len;
			memcpy(&origdispl, &bytes[d86.d86_rmindex + 1],
			    sizeof(origdispl));
			memcpy(kp->kp_trampoline, bytes, d86.d86_rmindex + 1);
			/*
			 * Create a new %rip-relative instruction with a
			 * recalculated offset to %rip.
			 */
			displ = kinst_displ(curinstr + origdispl + trlen,
			    kp->kp_trampoline, trlen);
			memcpy(&kp->kp_trampoline[opclen], &displ, sizeof(displ));
		} else {
			/*
			 * Regular instructions need no modification, so we
			 * just copy them to the trampoline as-is.
			 */
			memcpy(kp->kp_trampoline, bytes, kp->kp_len);
			trlen = kp->kp_len;
		}
		/*
		 * Encode a jmp back to the next instruction so that the thread
		 * can continue execution normally.
		 */
		kp->kp_trampoline[trlen] = KINST_JMP;
		displ = kinst_displ(instr, &kp->kp_trampoline[trlen],
		    KINST_JMP_LEN);
		memcpy(&kp->kp_trampoline[trlen + 1], &displ, sizeof(displ));
		kp->kp_rval = DTRACE_INVOP_NOP;
done:
		kp->kp_id = dtrace_probe_create(kinst_id, lf->filename,
		    symval->name, kp->kp_name, 3, kp);
		kinst_probetab[KINST_ADDR2NDX(curinstr)] = kp;
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
kinst_is_call(uint8_t *bytes)
{
	return (bytes[0] == KINST_CALL || bytes[0] == KINST_CALL_REG);
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
