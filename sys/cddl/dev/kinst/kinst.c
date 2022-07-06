/*
 * SPDX-License-Identifier: CDDL 1.0
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/module.h>

#include <sys/dtrace.h>
#include <cddl/dev/dtrace/dtrace_cddl.h>
#include <dis_tables.h>

#include <machine/cpufunc.h>
#include <machine/md_var.h>
#include <machine/stdarg.h>

#include "kinst.h"
#include "trampoline.h"

#define KINST_CALL		0xe8
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

MALLOC_DEFINE(M_KINST, "kinst", "Kernel Instruction Tracing");

static int	kinst_dis_get_byte(void *);
static int32_t	kinst_displ(uint8_t *, uint8_t *, int);
static int	kinst_is_call_or_uncond_jmp(uint8_t *);
static int	kinst_is_short_jmp(uint8_t *);
static int	kinst_is_near_jmp(uint8_t *);
static int	kinst_is_jmp(uint8_t *);

static void	kinst_provide_module(void *, modctl_t *);
static void	kinst_getargdesc(void *, dtrace_id_t, void *,
		    dtrace_argdesc_t *);
static void	kinst_destroy(void *, dtrace_id_t, void *);
static void	kinst_enable(void *, dtrace_id_t, void *);
static void	kinst_disable(void *, dtrace_id_t, void *);
static int	kinst_linker_file_cb(linker_file_t, void *);
static void	kinst_load(void *);
static int	kinst_unload(void);
static int	kinst_modevent(module_t, int, void *);

static dtrace_pattr_t kinst_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static const dtrace_pops_t kinst_pops = {
	.dtps_provide =		NULL,
	.dtps_provide_module =	kinst_provide_module,
	.dtps_enable =		kinst_enable,
	.dtps_disable =		kinst_disable,
	.dtps_suspend =		NULL,
	.dtps_resume =		NULL,
	.dtps_getargdesc =	kinst_getargdesc,
	.dtps_getargval =	NULL,
	.dtps_usermode =	NULL,
	.dtps_destroy =		kinst_destroy
};

static dtrace_provider_id_t	kinst_id;
TAILQ_HEAD(, kinst_probe)	kinst_probes;

int
kinst_invop(uintptr_t addr, struct trapframe *frame, uintptr_t rval)
{
	solaris_cpu_t *cpu;
	uintptr_t *stack;
	struct kinst_probe *kp;

#ifdef __amd64__
	stack = (uintptr_t *)frame->tf_rsp;
#else
	/* Skip hardware-saved registers. */
	stack = (uintptr_t *)frame->tf_isp + 3;
#endif
	cpu = &solaris_cpu[curcpu];

	TAILQ_FOREACH(kp, &kinst_probes, kp_next) {
		if ((uintptr_t)kp->kp_patchpoint != addr)
			continue;
		/*KINST_LOG("FIRING: %s", kp->kp_name);*/
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		cpu->cpu_dtrace_caller = stack[0];
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT | CPU_DTRACE_BADADDR);
		dtrace_probe(kp->kp_id, 0, 0, 0, 0, 0);
		cpu->cpu_dtrace_caller = 0;
		/* Redirect execution to the trampoline after iret. */
		frame->tf_rip = (register_t)kp->kp_trampoline;

		return (DTRACE_INVOP_NOP);
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
kinst_provide_module_function(linker_file_t lf, int symindx,
    linker_symval_t *symval, void *opaque)
{
	struct kinst_probe *kp;
	dis86_t d86;
	int n = 0, mode, opclen, trlen;
	int32_t displ, origdispl;
	uint8_t *instr, *limit, *bytes;

	if (strcmp(symval->name, "trap_check") == 0 ||
	    strcmp(symval->name, "vm_fault") != 0)
		return (0);

	instr = (uint8_t *)symval->value;
	limit = (uint8_t *)symval->value + symval->size;
	mode = (DATAMODEL_LP64 == DATAMODEL_NATIVE) ? SIZE64 : SIZE32;

	if (instr >= limit)
		return (0);

	while (instr < limit) {
		if (++n > KINST_PROBE_MAX) {
			KINST_LOG("probe list full: %d entries", n);
			return (1);
		}
		kp = malloc(sizeof(struct kinst_probe), M_KINST, M_WAITOK | M_ZERO);
		snprintf(kp->kp_name, sizeof(kp->kp_name), "%d",
		    (int)(instr - (uint8_t *)symval->value));
		/*
		 * Save the first byte of the instruction so that we can
		 * recover it when the probe is disabled.
		 */
		kp->kp_savedval = *instr;
		kp->kp_patchval = KINST_PATCHVAL;
		kp->kp_patchpoint = instr;
		if ((kp->kp_trampoline = kinst_trampoline_alloc()) == NULL) {
			KINST_LOG("cannot allocate trampoline for: %p", instr);
			return (1);
		}
		d86.d86_data = (void **)&instr;
		d86.d86_get_byte = kinst_dis_get_byte;
		d86.d86_check_func = NULL;
		if (dtrace_disx86(&d86, mode) != 0) {
			KINST_LOG("failed to disassemble instruction at: %p", instr);
			return (1);
		}
		bytes = d86.d86_bytes;
		/*
		 * Copy current instruction to the trampoline to be executed
		 * when the probe fires. In case the instruction takes %rip as
		 * an implicit operand, we have to modify it first in order for
		 * the offset encodings to be correct.
		 */
		if (kinst_is_jmp(bytes)) {
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
				displ = kinst_displ(instr - d86.d86_len +
				    (origdispl & 0xff) + KINST_SHORTJMP_LEN,
				    kp->kp_trampoline, trlen);
			} else {
				if (kinst_is_call_or_uncond_jmp(bytes))
					trlen = KINST_JMP_LEN;
				else
					trlen = KINST_NEARJMP_LEN;
				memcpy(kp->kp_trampoline, bytes, opclen);
				displ = kinst_displ(instr - d86.d86_len +
				    origdispl + trlen, kp->kp_trampoline, trlen);
			}
			memcpy(&kp->kp_trampoline[opclen], &displ, sizeof(displ));
		} else if (d86.d86_got_modrm &&
		    KINST_MOD(bytes[d86.d86_rmindex]) == 0 &&
		    KINST_RM(bytes[d86.d86_rmindex]) == 5) {
			opclen = d86.d86_rmindex + 1;
			trlen = d86.d86_len;
			memcpy(&origdispl, &bytes[d86.d86_rmindex + 1],
			    sizeof(origdispl));
			memcpy(kp->kp_trampoline, bytes, d86.d86_rmindex + 1);
			/*
			 * Create a new %rip-relative instruction with a
			 * recalculated offset to %rip.
			 */
			displ = kinst_displ(instr - d86.d86_len +
			    origdispl + trlen, kp->kp_trampoline, trlen);
			memcpy(&kp->kp_trampoline[opclen], &displ, sizeof(displ));
		} else {
			memcpy(kp->kp_trampoline, d86.d86_bytes, d86.d86_len);
			trlen = d86.d86_len;
		}
		/*
		 * Encode a jmp back to the next instruction so that the thread
		 * can continue execution normally.
		 */
		kp->kp_trampoline[trlen] = KINST_JMP;
		displ = kinst_displ(instr, &kp->kp_trampoline[trlen],
		    KINST_JMP_LEN);
		memcpy(&kp->kp_trampoline[trlen + 1], &displ, sizeof(displ));

		kp->kp_id = dtrace_probe_create(kinst_id, lf->filename,
		    symval->name, kp->kp_name, 3, kp);
		TAILQ_INSERT_TAIL(&kinst_probes, kp, kp_next);
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
kinst_is_call_or_uncond_jmp(uint8_t *bytes)
{
	return (*bytes == KINST_CALL || *bytes == KINST_JMP);
}

static int
kinst_is_short_jmp(uint8_t *bytes)
{
	/*
	 * KINST_UNCOND_SHORTJMP could be kinst_is_call_or_uncond_jmp() but I
	 * think it's easier to work with if we have it here.
	 */
	return ((*bytes >= KINST_SHORTJMP_FIRST &&
	    *bytes <= KINST_SHORTJMP_LAST) ||
	    *bytes == KINST_UNCOND_SHORTJMP);
}

static int
kinst_is_near_jmp(uint8_t *bytes)
{
	return (*bytes == KINST_NEARJMP_PREFIX &&
	    bytes[1] >= KINST_NEARJMP_FIRST && bytes[1] <= KINST_NEARJMP_LAST);
}

static int
kinst_is_jmp(uint8_t *bytes)
{
	return (kinst_is_call_or_uncond_jmp(bytes) ||
	    kinst_is_short_jmp(bytes) ||
	    kinst_is_near_jmp(bytes));
}

static void
kinst_provide_module(void *arg, modctl_t *lf)
{
	/*
	 * Invoke kinst_provide_module_function() once for each function symbol
	 * in the module "lf".
	 */
	linker_file_function_listall(lf, kinst_provide_module_function, NULL);
}

static void
kinst_getargdesc(void *arg, dtrace_id_t id, void *parg, dtrace_argdesc_t *desc)
{
}

static void
kinst_destroy(void *arg, dtrace_id_t id, void *parg)
{
}

static void
kinst_enable(void *arg, dtrace_id_t id, void *parg)
{
	struct kinst_probe *kp = parg;

	kinst_patch_tracepoint(kp, kp->kp_patchval);
	KINST_LOG("probe %u (%s) is enabled", id, kp->kp_name);
}

static void
kinst_disable(void *arg, dtrace_id_t id, void *parg)
{
	struct kinst_probe *kp = parg;

	kinst_patch_tracepoint(kp, kp->kp_savedval);
	KINST_LOG("probe %u (%s) is disabled", id, kp->kp_name);
}

static int
kinst_linker_file_cb(linker_file_t lf, void *arg)
{
	kinst_provide_module(arg, lf);

	return (0);
}

static void
kinst_load(void *dummy)
{
	TAILQ_INIT(&kinst_probes);
	kinst_trampoline_init();

	if (dtrace_register("kinst", &kinst_attr, DTRACE_PRIV_USER,
	    NULL, &kinst_pops, NULL, &kinst_id) != 0)
		return;
	dtrace_invop_add(kinst_invop);

	/* Loop over all functions in the kernel and loaded modules. */
	linker_file_foreach(kinst_linker_file_cb, NULL);
}

static int
kinst_unload(void)
{
	struct kinst_probe *kp;

	dtrace_invop_remove(kinst_invop);

	while (!TAILQ_EMPTY(&kinst_probes)) {
		kp = TAILQ_FIRST(&kinst_probes);
		kinst_trampoline_dealloc(kp->kp_trampoline);
		TAILQ_REMOVE(&kinst_probes, kp, kp_next);
		if (kp != NULL)
			free(kp, M_KINST);
	}
	kinst_trampoline_deinit();

	return (dtrace_unregister(kinst_id));
}

static int
kinst_modevent(module_t mod __unused, int type, void *data __unused)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		break;
	case MOD_UNLOAD:
		break;
	case MOD_SHUTDOWN:
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

SYSINIT(kinst_load, SI_SUB_DTRACE_PROVIDER, SI_ORDER_ANY, kinst_load, NULL);
SYSUNINIT(kinst_unload, SI_SUB_DTRACE_PROVIDER, SI_ORDER_ANY, kinst_unload, NULL);

DEV_MODULE(kinst, kinst_modevent, NULL);
MODULE_VERSION(kinst, 1);
MODULE_DEPEND(kinst, dtrace, 1, 1, 1);
MODULE_DEPEND(kinst, opensolaris, 1, 1, 1);
