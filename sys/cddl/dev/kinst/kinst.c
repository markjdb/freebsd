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

#include <machine/stdarg.h>

#include "extern.h"
#include "kinst.h"
#include "trampoline.h"

#define KINST_JMP_LEN		5
#define KINST_OPCODE_JMP	0xe9
/*
 * Special cases where an instruction has to be modified before it is copied to
 * the trampoline.
 */
#define KINST_OPCODE_CALL	0xe8
#define KINST_MODRM_RIPREL	0x05

#define KINST_F_BRANCH		0x01
#define KINST_F_RIPREL		0x02

MALLOC_DEFINE(M_KINST, "kinst", "Kernel Instruction Tracing");

static int	kinst_dis_get_byte(void *);

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
kinst_provide_module_function(linker_file_t lf, int symindx,
    linker_symval_t *symval, void *opaque)
{
	struct kinst_probe *kp;
	dis86_t d86;
	int n = 0, mode;
	int32_t displ;
	uint8_t *instr, *limit;

	if (strcmp(symval->name, "trap_check") == 0 ||
	    strcmp(symval->name, "vm_fault") != 0)
		return (0);

	instr = (uint8_t *)symval->value;
	limit = (uint8_t *)symval->value + symval->size;
	mode = (DATAMODEL_LP64 == DATAMODEL_NATIVE) ? SIZE64 : SIZE32;

	if (instr >= limit)
		return (0);

	while (instr < limit) {
		if (n >= KINST_PROBE_MAX) {
			KINST_LOG("probe list full: %d entries", n);
			return (1);
		}
		kp = malloc(sizeof(struct kinst_probe), M_KINST, M_WAITOK | M_ZERO);
		snprintf(kp->kp_name, sizeof(kp->kp_name), "%d", n++);
		/*
		 * Save the first byte of the instruction so that we can
		 * recover it after we restore the breakpoint.
		 */
		kp->kp_recover_byte = *instr;
		if ((kp->kp_trampoline = kinst_trampoline_alloc()) == NULL) {
			/* FIXME: prevent semory leak/cleanup resources? */
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
		kp->kp_flags = 0;
		/*
		 * Determine whether the instruction has to be modified before
		 * we copy it to the trampoline.
		 */
		if ((uint8_t)d86.d86_bytes[0] == KINST_OPCODE_CALL)
			kp->kp_flags |= KINST_F_BRANCH;
		if (d86.d86_rmindex != -1 &&
		    d86.d86_bytes[d86.d86_rmindex] == KINST_MODRM_RIPREL)
			kp->kp_flags |= KINST_F_RIPREL;
		/* TODO: more cases */

		/*
		 * Copy instruction to trampoline.
		 * TODO: make modifications
		 */
		memcpy(kp->kp_trampoline, d86.d86_bytes, d86.d86_len);
		kp->kp_trampoline[d86.d86_len] = KINST_OPCODE_JMP;
		/* dst - (src + len) */
		displ = instr - ((kp->kp_trampoline + d86.d86_len) + KINST_JMP_LEN);
		memcpy(&kp->kp_trampoline[d86.d86_len + 1], &displ, sizeof(displ));

		kp->kp_id = dtrace_probe_create(kinst_id, lf->filename,
		    symval->name, kp->kp_name, 3, NULL);
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
	/*
	 * TODO: move instruction parsing from provide_module_function() here
	 * so that we allocate things lazily.
	 */
	KINST_LOG("probe %u is enabled", id);
}

static void
kinst_disable(void *arg, dtrace_id_t id, void *parg)
{
	/* TODO: dealloc trampolines here */
	KINST_LOG("probe %u is disabled", id);
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

	/* Loop over all functions in the kernel and loaded modules. */
	linker_file_foreach(kinst_linker_file_cb, NULL);
}

static int
kinst_unload(void)
{
	struct kinst_probe *kp;

	while (!TAILQ_EMPTY(&kinst_probes)) {
		kp = TAILQ_FIRST(&kinst_probes);
		/* XXX: move to kinst_disable */
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
