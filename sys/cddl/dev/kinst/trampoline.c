/*
 * SPDX-License-Identifier: CDDL 1.0
 *
 * Copyright 2022 Christos Margiolis <christos@FreeBSD.org>
 * Copyright 2022 Mark Johnston <markj@FreeBSD.org>
 */

#include <sys/param.h>
#include <sys/bitset.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/sx.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

#include "kinst.h"
#include "kinst_isa.h"

/*
 * Each trampoline is 32 bytes long and contains [instruction, jmp]. Since we
 * have 2 instructions stored in the trampoline, and each of them can take up
 * to 16 bytes, 32 bytes is enough to cover even the worst case scenario.
 *
 * XXX-MJ this is amd64-specific
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

static vm_object_t		kinst_vmobj;
static TAILQ_HEAD(, trampchunk)	kinst_trampchunks =
    TAILQ_HEAD_INITIALIZER(kinst_trampchunks);
static struct sx		kinst_tramp_sx;
SX_SYSINIT(kinst_tramp_sx, &kinst_tramp_sx, "kinst tramp");

static struct trampchunk *
kinst_trampchunk_alloc(void)
{
	static int objoff = 0;
	struct trampchunk *chunk;
	vm_offset_t trampaddr;
	int error, off;

	sx_assert(&kinst_tramp_sx, SX_XLOCKED);

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
	off = objoff;
	objoff += KINST_TRAMPCHUNK_SIZE;
	error = vm_map_find(kernel_map, kinst_vmobj, off, &trampaddr,
	    KINST_TRAMPCHUNK_SIZE, 0, VMFS_ANY_SPACE, VM_PROT_ALL, VM_PROT_ALL,
	    0);
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
	error = vm_map_wire(kernel_map, trampaddr,
	    trampaddr + KINST_TRAMPCHUNK_SIZE,
	    VM_MAP_WIRE_SYSTEM | VM_MAP_WIRE_NOHOLES);
	if (error != KERN_SUCCESS) {
		KINST_LOG("trampoline chunk wiring failed: %d", error);
		(void)vm_map_remove(kernel_map, trampaddr,
		    trampaddr + KINST_TRAMPCHUNK_SIZE);
		return (NULL);
	}

	/*
	 * Fill the trampolines with breakpoint instructions so that the kernel
	 * will crash cleanly if things somehow go wrong.
	 *
	 * XXX-MJ assumes patchval is one byte, not true on !amd64
	 */
	memset((void *)trampaddr, KINST_PATCHVAL, KINST_TRAMPCHUNK_SIZE);

	/* Allocate a tracker for this chunk. */
	chunk = malloc(sizeof(*chunk), M_KINST, M_WAITOK);
	chunk->addr = (void *)trampaddr;
	BIT_FILL(KINST_TRAMPS_PER_CHUNK, &chunk->free);

	TAILQ_INSERT_HEAD(&kinst_trampchunks, chunk, next);

	return (chunk);
}

static void
kinst_trampchunk_free(struct trampchunk *chunk)
{
	sx_assert(&kinst_tramp_sx, SX_XLOCKED);

	TAILQ_REMOVE(&kinst_trampchunks, chunk, next);
	(void)vm_map_remove(kernel_map, (vm_offset_t)chunk->addr,
	    (vm_offset_t)(chunk->addr + KINST_TRAMPCHUNK_SIZE));
	free(chunk, M_KINST);
}

int
kinst_trampoline_init(void)
{
	kinst_vmobj = vm_pager_allocate(OBJT_PHYS, NULL, KINST_VMOBJ_SIZE,
	    VM_PROT_ALL, 0, NULL);
	if (kinst_vmobj == NULL) {
		KINST_LOG("cannot allocate vm_object");
		return (1);
	}
	return (0);
}

int
kinst_trampoline_deinit(void)
{
	KASSERT(TAILQ_EMPTY(&kinst_trampchunks),
	    ("%s: leaked trampoline chunks", __func__));
	vm_object_deallocate(kinst_vmobj);
	return (0);
}

uint8_t *
kinst_trampoline_alloc(void)
{
	struct trampchunk *chunk;
	uint8_t *tramp;
	int off;

	sx_xlock(&kinst_tramp_sx);
	TAILQ_FOREACH(chunk, &kinst_trampchunks, next) {
		/* All trampolines from this chunk are already allocated. */
		if ((off = BIT_FFS(KINST_TRAMPS_PER_CHUNK, &chunk->free)) == 0)
			continue;
		/* BIT_FFS() returns indices starting at 1 instead of 0. */
		off--;
		break;
	}
	if (chunk == NULL) {
		/*
		 * We didn't find any free trampoline in the current list,
		 * allocate a new one.
		 */
		if ((chunk = kinst_trampchunk_alloc()) == NULL) {
			KINST_LOG("cannot allocate new trampchunk");
			return (NULL);
		}
		off = 0;
	}
	BIT_CLR(KINST_TRAMPS_PER_CHUNK, off, &chunk->free);
	tramp = chunk->addr + off * KINST_TRAMP_SIZE;
	sx_xunlock(&kinst_tramp_sx);

	return (tramp);
}

void
kinst_trampoline_dealloc(uint8_t *tramp)
{
	struct trampchunk *chunk;
	int off;

	if (tramp == NULL)
		return;

	sx_xlock(&kinst_tramp_sx);
	TAILQ_FOREACH(chunk, &kinst_trampchunks, next) {
		for (off = 0; off < KINST_TRAMPS_PER_CHUNK; off++) {
			if (chunk->addr + off * KINST_TRAMP_SIZE == tramp) {
				memset((void *)tramp, KINST_PATCHVAL,
				    KINST_TRAMP_SIZE);
				BIT_SET(KINST_TRAMPS_PER_CHUNK, off,
				    &chunk->free);
				if (BIT_ISFULLSET(KINST_TRAMPS_PER_CHUNK,
				    &chunk->free))
					kinst_trampchunk_free(chunk);
				sx_xunlock(&kinst_tramp_sx);
				return;
			}
		}
	}
	panic("%s: did not find trampoline chunk for %p", __func__, tramp);
}
