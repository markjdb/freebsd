/*
 * SPDX-License-Identifier: CDDL 1.0
 */
#include <sys/param.h>
#include <sys/bitset.h>
#include <sys/queue.h>

#include <sys/dtrace.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

#include "extern.h"
#include "trampoline.h"

/*
 * Each trampoline is 32 bytes long and contains [instruction, jmp]. Since we
 * have 2 instructions stored in the trampoline, and each of them can take up
 * to 16 bytes, 32 bytes is enough to cover even the worst case scenario.
 */
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

struct trampchunk {
	TAILQ_ENTRY(trampchunk) next;
	uint8_t *addr;
	/* 0 -> allocated, 1 -> free */
	BITSET_DEFINE(, KINST_TRAMPS_PER_CHUNK) free;
};

static struct trampchunk *kinst_trampchunk_alloc(void);

static vm_object_t		kinst_vmobj;
TAILQ_HEAD(, trampchunk)	kinst_trampchunks;

static struct trampchunk *
kinst_trampchunk_alloc(void)
{
	struct trampchunk *chunk;
	vm_offset_t trampaddr;
	int error;

	vm_object_reference(kinst_vmobj);
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

int
kinst_trampoline_init(void)
{
	struct trampchunk *chunk;

	kinst_vmobj = vm_pager_allocate(OBJT_PHYS, NULL, KINST_VMOBJ_SIZE,
	    VM_PROT_ALL, 0, curthread->td_ucred);
	if (kinst_vmobj == NULL) {
		KINST_LOG("cannot allocate vm_object");
		return (1);
	}
	if ((chunk = kinst_trampchunk_alloc()) == NULL) {
		KINST_LOG("cannot allocate trampoline chunk");
		return (1);
	}
	TAILQ_INIT(&kinst_trampchunks);
	TAILQ_INSERT_TAIL(&kinst_trampchunks, chunk, next);

	return (0);
}

int
kinst_trampoline_deinit(void)
{
	struct trampchunk *chunk;

	while (!TAILQ_EMPTY(&kinst_trampchunks)) {
		chunk = TAILQ_FIRST(&kinst_trampchunks);
		TAILQ_REMOVE(&kinst_trampchunks, chunk, next);
		(void)vm_map_remove(kernel_map, (vm_offset_t)chunk->addr,
		    (vm_offset_t)(chunk->addr + KINST_TRAMPCHUNK_SIZE));
		if (chunk != NULL)
			free(chunk, M_KINST);
	}
	vm_object_deallocate(kinst_vmobj);

	return (0);
}

uint8_t *
kinst_trampoline_alloc(void)
{
	struct trampchunk *chunk;
	uint8_t *tramp;
	int off;

	/* Find a the first free trampoline. */
	TAILQ_FOREACH(chunk, &kinst_trampchunks, next) {
		/* All trampolines from this chunk are already allocated. */
		if ((off = BIT_FFS(KINST_TRAMPS_PER_CHUNK, &chunk->free)) == 0)
			continue;
		/* BIT_FFS() returns indices starting at 1 instead of 0. */
		off--;
		/* Mark trampoline as allocated. */
		goto found;
	}
	if ((chunk = kinst_trampchunk_alloc()) == NULL) {
		KINST_LOG("cannot allocate new trampchunk");
		return (NULL);
	}
	TAILQ_INSERT_TAIL(&kinst_trampchunks, chunk, next);
	off = 0;
found:
	BIT_CLR(KINST_TRAMPS_PER_CHUNK, off, &chunk->free);
	tramp = chunk->addr + off * KINST_TRAMP_SIZE;

	return (tramp);
}

void
kinst_trampoline_dealloc(uint8_t *tramp)
{
	/*
	 * TODO: find which chunk it belongs to
	 */
	memset((void *)tramp, 0xcc, KINST_TRAMP_SIZE);
}
