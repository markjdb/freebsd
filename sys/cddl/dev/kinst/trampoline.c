/*
 * SPDX-License-Identifier: CDDL 1.0
 */
#include <sys/param.h>
#include <sys/bitset.h>
#include <sys/malloc.h>
#include <sys/queue.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>

#include "extern.h"
#include "kinst_isa.h"
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

static TAILQ_HEAD(, trampchunk) kinst_trampchunks =
    TAILQ_HEAD_INITIALIZER(kinst_trampchunks);

static struct trampchunk *
kinst_trampchunk_alloc(void)
{
	struct trampchunk *chunk;
	vm_offset_t trampaddr;

	trampaddr = kmem_malloc(KINST_TRAMPCHUNK_SIZE, M_WAITOK | M_EXEC);

	/*
	 * Fill the trampolines with breakpoint instructions so that the kernel
	 * will crash cleanly if things somehow go wrong.
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
	TAILQ_REMOVE(&kinst_trampchunks, chunk, next);
	kmem_free((vm_offset_t)chunk->addr, KINST_TRAMPCHUNK_SIZE);
	free(chunk, M_KINST);
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
		goto found;
	}
	/*
	 * We didn't find any free trampoline in the current list, we need to
	 * allocate a new one.
	 */
	if ((chunk = kinst_trampchunk_alloc()) == NULL) {
		KINST_LOG("cannot allocate new trampchunk");
		return (NULL);
	}
	off = 0;
found:
	/* Mark trampoline as allocated. */
	BIT_CLR(KINST_TRAMPS_PER_CHUNK, off, &chunk->free);
	tramp = chunk->addr + off * KINST_TRAMP_SIZE;

	return (tramp);
}

void
kinst_trampoline_dealloc(uint8_t *tramp)
{
	struct trampchunk *chunk;

	TAILQ_FOREACH(chunk, &kinst_trampchunks, next) {
		uintptr_t trampaddr;

		trampaddr = (uintptr_t)tramp;
		if (trampaddr >= (uintptr_t)chunk->addr &&
		    trampaddr < (uintptr_t)chunk->addr +
		    KINST_TRAMPCHUNK_SIZE) {
			int off;

			off = (trampaddr % KINST_TRAMPCHUNK_SIZE) /
			    KINST_TRAMP_SIZE;
			BIT_SET(KINST_TRAMPS_PER_CHUNK, off, &chunk->free);
			memset(tramp, KINST_PATCHVAL, KINST_TRAMP_SIZE);

			/* Release the chunk if it is unused. */
			if (BIT_ISFULLSET(KINST_TRAMPS_PER_CHUNK, &chunk->free))
				kinst_trampchunk_free(chunk);
			return;
		}
	}
	panic("could not find trampoline chunk for %p", tramp);
}
