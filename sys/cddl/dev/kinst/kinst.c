/*
 * SPDX-License-Identifier: CDDL 1.0
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/bitset.h>

#include <sys/dtrace.h>
#include <dis_tables.h>

#include <machine/stdarg.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

#include "kinst.h"

#define KINST_LOG_HELPER(fmt, ...) \
	printf("%s:%d: " fmt "%s\n", __func__, __LINE__, __VA_ARGS__)
#define KINST_LOG(...) \
	KINST_LOG_HELPER(__VA_ARGS__, "")

#define KINST_TRAMP_SIZE	32
#define KINST_TRAMPCHUNK_SIZE	PAGE_SIZE
/*
 * We can have 4KB/32B = 128 trampolines per chunk.
 */
#define KINST_TRAMPS_PER_CHUNK	(KINST_TRAMPCHUNK_SIZE / KINST_TRAMP_SIZE)
/*
 * Set the object size to 2GB, since we know that the object will only ever be
 * used to allocate pages in the range [KERNBASE, 0xfffffffffffff000].
 */
#define KINST_VMOBJ_SIZE	(VM_MAX_ADDRESS - KERNBASE)

MALLOC_DEFINE(M_KINST, "kinst", "Kernel Instruction Tracing");

struct trampchunk {
	uint8_t *addr;
	/* 0 -> allocated, 1 -> free */
	BITSET_DEFINE(, KINST_TRAMPS_PER_CHUNK) free;
};

static struct trampchunk *kinst_alloc_trampchunk(void);
/* TODO: dealloc_trampchunk */
static uint8_t	*kinst_alloc_trampoline(struct trampchunk *);
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
static vm_object_t		kinst_vmobj;
static struct trampchunk	*kinst_trampchunk;

int
kinst_provide_module_function(linker_file_t lf, int symindx,
    linker_symval_t *symval, void *opaque)
{
	struct kinst_probe *kp;
	dis86_t d86;
	int n = 0;
	uint8_t *instr, *limit;

	if (strcmp(symval->name, "trap_check") == 0 ||
	    strcmp(symval->name, "vm_fault") != 0)
		return (0);

	instr = (uint8_t *)symval->value;
	limit = (uint8_t *)symval->value + symval->size;

	if (instr >= limit)
		return (0);

	/* XXX: not sure if this should be here */
	if ((kinst_trampchunk = kinst_alloc_trampchunk()) == NULL) {
		KINST_LOG("cannot allocate trampoline chunk");
		return (1);
	}

	while (instr < limit) {
		if (n >= KINST_PROBE_MAX) {
			KINST_LOG("probe list full");
			return (1);
		}
		kp = malloc(sizeof(struct kinst_probe), M_KINST, M_WAITOK | M_ZERO);
		snprintf(kp->kp_name, sizeof(kp->kp_name), "%d", n++);
		/*
		 * Save the first byte of the instruction so that we can recover it after
		 * we restore the breakpoint.
		 */
		kp->kp_recover_byte = *instr;
		/*
		 * Determine whether the instruction has to be modified before
		 * we allocate the trampoline.
		 */
		d86.d86_data = (void **)&instr;
		d86.d86_get_byte = kinst_dis_get_byte;
		d86.d86_check_func = NULL;
		if (dtrace_disx86(&d86, SIZE64) != 0) {
			KINST_LOG("failed to disassemble instruction at: %p", instr);
			return (1);
		}
		kp->kp_flags = 0;
		if (d86.d86_rmindex != -1) {
			/* TODO */
		}
		kp->kp_id = dtrace_probe_create(kinst_id, lf->filename,
		    symval->name, kp->kp_name, 3, NULL);
		TAILQ_INSERT_TAIL(&kinst_probes, kp, kp_next);
	}

	return (0);
}

static struct trampchunk *
kinst_alloc_trampchunk(void)
{
	struct trampchunk *chunk;
	vm_offset_t trampaddr;
	int error;

	/*
	 * Allocate virtual memory for the trampoline chunk. The returned
	 * address is saved in "trampaddr".
	 *
	 * VM_PROT_ALL expands to VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXEC,
	 * i.e., the mapping will be writeable and executable.
	 *
	 * Setting "trampaddr" to KERNBASE causes vm_map_find() to return an
	 * address above KERNBASE, so this satisfies both requirements.
	 */
	trampaddr = KERNBASE;
	error = vm_map_find(kernel_map, kinst_vmobj, 0, &trampaddr, PAGE_SIZE,
	    0, VMFS_ANY_SPACE, VM_PROT_ALL, VM_PROT_ALL, 0);
	if (error != KERN_SUCCESS) {
		vm_object_deallocate(kinst_vmobj);
		kinst_vmobj = NULL;
		KINST_LOG("trampoline chunk allocation failed: %d", error);
		return (NULL);
	}
	/*
	 * We allocated a page of virtual memory, but that needs to be
	 * backed by physical memory, or else any access will result in
	 * a page fault.
	 */
	error = vm_map_wire(kernel_map, trampaddr, trampaddr + PAGE_SIZE,
	    VM_MAP_WIRE_SYSTEM | VM_MAP_WIRE_NOHOLES);
	if (error != KERN_SUCCESS) {
		KINST_LOG("trampoline chunk wiring failed: %d", error);
		return (NULL);
	}

	/*
	 * Fill the trampolines with breakpoint instructions so that the kernel
	 * will crash cleanly if things somehow go wrong.
	 */
	memset((void *)trampaddr, 0xcc, KINST_TRAMPCHUNK_SIZE);

	/* Allocate a tracker for this chunk. */
	chunk = malloc(sizeof(*chunk), M_KINST, M_WAITOK);
	chunk->addr = (void *)trampaddr;
	BIT_FILL(KINST_TRAMPS_PER_CHUNK, &chunk->free);

	return (chunk);
}

static uint8_t *
kinst_alloc_trampoline(struct trampchunk *chunk)
{
	uint8_t *tramp;
	int off;

	/* Find a the first free trampoline. */
	if ((off = BIT_FFS(KINST_TRAMPS_PER_CHUNK, &chunk->free)) == 0) {
		/*
		 * All trampolines from this chunk are already allocated. We
		 * need to allocate a new chunk.
		 * TODO
		 */
		return (NULL);
	}
	/* BIT_FFS() returns indices starting at 1 instead of 0. */
	off--;

	/* Mark trampoline as allocated. */
	BIT_CLR(KINST_TRAMPS_PER_CHUNK, off, &chunk->free);
	tramp = chunk->addr + off * KINST_TRAMPCHUNK_SIZE;

	return (tramp);
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

	kinst_vmobj = vm_pager_allocate(OBJT_PHYS, NULL, KINST_VMOBJ_SIZE,
	    VM_PROT_ALL, 0, curthread->td_ucred);
	if (kinst_vmobj == NULL) {
		KINST_LOG("cannot allocate vm_object");
		return;
	}

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
		TAILQ_REMOVE(&kinst_probes, kp, kp_next);
		if (kp != NULL)
			free(kp, M_KINST);
	}
	/*vm_pager_deallocate(kinst_vmobj);*/
	(void)vm_map_remove(kernel_map, (vm_offset_t)kinst_trampchunk->addr,
	    (vm_offset_t)(kinst_trampchunk->addr + KINST_TRAMPCHUNK_SIZE));
	free(kinst_trampchunk, M_KINST);

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
