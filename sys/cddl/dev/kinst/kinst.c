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

#include "kinst.h"

MALLOC_DEFINE(M_KINST, "kinst", "Kernel Instruction Tracing");

static int	kinst_unload(void);
static void	kinst_getargdesc(void *, dtrace_id_t, void *,
		    dtrace_argdesc_t *);
static void	kinst_provide_module(void *, modctl_t *);
static void	kinst_destroy(void *, dtrace_id_t, void *);
static void	kinst_enable(void *, dtrace_id_t, void *);
static void	kinst_disable(void *, dtrace_id_t, void *);
static void	kinst_load(void *);

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

dtrace_provider_id_t	kinst_id;
struct kinst_probe	**kinst_probetab;

int
kinst_provide_module_function(linker_file_t lf, int symindx,
    linker_symval_t *symval, void *opaque)
{
	struct kinst_probe *kp;
	int size, n = 0;
	uint8_t *instr, *limit;

	/*
	 * Taken from fbt_isa.c
	 */
	if (strcmp(symval->name, "trap_check") == 0 ||
	    strcmp(symval->name, "vm_fault") != 0)
		return (0);

	instr = (uint8_t *)symval->value;
	limit = (uint8_t *)symval->value + symval->size;

	if (instr >= limit)
		return (0);
	
	while (instr < limit) {
		if ((size = dtrace_instr_size(instr)) <= 0) {
			printf("%s:%d failed to decode instruction at %p\n",
			    __func__, __LINE__, instr);
			return (1);
		}
		/* XXX: is this right? */
		if (n >= KINST_PROBETAB_SIZE) {
			printf("%s:%d probetab full\n", __func__, __LINE__);
			return (1);
		}
		kp = malloc(sizeof(struct kinst_probe), M_KINST, M_WAITOK | M_ZERO);
		snprintf(kp->kp_name, sizeof(kp->kp_name), "%d", n);
		kp->kp_id = dtrace_probe_create(kinst_id, lf->filename,
		    symval->name, kp->kp_name, 3, NULL);
		kinst_probetab[n++] = kp;
		printf("%s:%d created probe with id %u\n", __func__, __LINE__,
		    kp->kp_id);
		instr += size;
	}

	return (0);
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
	printf("%s:%d probe %u is enabled\n", __func__, __LINE__, id);
}

static void
kinst_disable(void *arg, dtrace_id_t id, void *parg)
{
	printf("%s:%d probe %u is disabled\n", __func__, __LINE__, id);
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
	/* XXX /dev/dtrace/kinst? */

	kinst_probetab = malloc(KINST_PROBETAB_SIZE *
	    sizeof(struct kinst_probe *), M_KINST, M_WAITOK | M_ZERO);

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
	int i = 0;

	/* FIXME: bad/slow? */
	for (; i < KINST_PROBETAB_SIZE; i++) {
		kp = kinst_probetab[i];
		if (kp != NULL) {
			free(kp, M_KINST);
			kp = NULL;
		}
	}
	free(kinst_probetab, M_KINST);
	kinst_probetab = NULL;

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

SYSINIT(kinst_load, SI_SUB_DTRACE_PROVIDER, SI_ORDER_ANY, kinst_load,
    NULL);
SYSUNINIT(kinst_unload, SI_SUB_DTRACE_PROVIDER, SI_ORDER_ANY, kinst_unload,
    NULL);

DEV_MODULE(kinst, kinst_modevent, NULL);
MODULE_VERSION(kinst, 1);
MODULE_DEPEND(kinst, dtrace, 1, 1, 1);
MODULE_DEPEND(kinst, opensolaris, 1, 1, 1);
