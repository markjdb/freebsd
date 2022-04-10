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

static dtrace_provider_id_t	kinst_id;

static void
kinst_getargdesc(void *arg, dtrace_id_t id, void *parg, dtrace_argdesc_t *desc)
{
}

static int
kinst_provide_module_function(linker_file_t lf, int symindx,
    linker_symval_t *symval, void *opaque)
{
	dtrace_id_t probeid;
	char probename[16];
	uint8_t *firstinstr;

	/* Only create probes for vm_fault() for now. */
	if (strcmp(symval->name, "vm_fault") != 0)
		return (0);

	firstinstr = symval->value;
	if (dtrace_instr_size(firstinstr) <= 0) {
		printf("%s:%d failed to decode instruction at %p\n",
		    __func__, __LINE__, firstinstr);
		return (1);
	}

	snprintf(probename, sizeof(probename), "%d", 0);
	probeid = dtrace_probe_create(kinst_id, lf->filename, symval->name,
	    probename, 3, NULL);
	/* XXX this probe ID needs to be saved somewhere */
	printf("%s:%d created probe with id %u\n", __func__, __LINE__,
	    probeid);
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
	if (dtrace_register("kinst", &kinst_attr, DTRACE_PRIV_USER,
	    NULL, &kinst_pops, NULL, &kinst_id) != 0)
		return;

	/* Loop over all functions in the kernel and loaded modules. */
	linker_file_foreach(kinst_linker_file_cb, NULL);
}

static int
kinst_unload(void)
{
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
