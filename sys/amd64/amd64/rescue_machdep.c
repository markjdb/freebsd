/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Juniper Networks, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/disk.h>
#include <sys/efi.h>
#include <sys/interrupt.h>
#include <sys/kenv.h>
#include <sys/kernel.h>
#include <sys/kerneldump.h>
#include <sys/linker.h>
#include <sys/malloc.h>
#include <sys/msgbuf.h>
#include <sys/smp.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/vm_dumpset.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <machine/atomic.h>
#include <machine/cpu.h>
#include <machine/metadata.h>
#include <machine/pc/bios.h>
#include <machine/rescue.h>

bool do_rescue_minidump = false;

/*
 * Parameters for memory reserved for the rescue kernel.  The boundary and
 * alignment are fixed by the requirements of locore.  The size is configurable
 * but of course must be satisfiable by an allocation with the defined alignment
 * and boundary requirements.
 *
 * rescue_kernel_exec() also assumes that the reserved region can be mapped
 * using a single PDP entry.
 */
#define	RESCUE_RESERV_ALIGN	(2 * 1024 * 1024u)	/* 2MB */
#define	RESCUE_RESERV_BOUNDARY	(1024 * 1024 * 1024u)	/* 1GB */
#define	RESCUE_RESERV_DEFAULT_SIZE (128 * 1024 * 1024u)	/* 128MB */

/*
 * Environment variables beginning with this prefix are copied into the rescue
 * kernel's environment with the prefix stripped.
 */
#define	RESCUE_KENV_PREFIX	"debug.rescue."
#define	RESCUE_KENV_ENABLED	"debug.rescue_minidump"
#define	RESCUE_KENV_MEMSIZE	"debug.rescue_memsize"

static void *rescue_va;
static vm_paddr_t rescue_pa;
static vm_size_t rescue_memsize;

/*
 * Called from the host kernel at panic time to populate rescue dumper
 * parameters.  The returned structure is passed to the rescue kernel.
 */
static void
rescue_dump_params_init(struct rescue_dump_params *rdp)
{
	/* XXX-MJ currently does not handle 5-level page tables */
	rdp->dp_msgbufpa = vtophys(msgbufp->msg_ptr);
	rdp->dp_msgbufsz = msgbufp->msg_size;
	rdp->dp_vmdumppa = vtophys(vm_page_dump);
	rdp->dp_vmdumpsz = BITSET_SIZE(vm_page_dump_pages);
	rdp->dp_dumpavailpa = vtophys(dump_avail);
	rdp->dp_kernpml4pa = vtophys(kernel_pmap->pm_pmltop);
	rdp->dp_kernstart = VM_MIN_KERNEL_ADDRESS;
	rdp->dp_kernend = MAX(KERNBASE + nkpt * NBPDR, kernel_vm_end);
	rdp->dp_kernmax = VM_MAX_KERNEL_ADDRESS;
	rdp->dp_dmapmin = DMAP_MIN_ADDRESS;
	rdp->dp_dmapmax = DMAP_MAX_ADDRESS;
}

static void
rescue_kernel_cpu_switch(void)
{
	struct pcpu *pcpu;

	pcpu = cpuid_to_pcpu[0];
	if (get_pcpu() != pcpu) {
		cpustop_restartfunc = rescue_kernel_exec;
		atomic_thread_fence_seq_cst();
		CPU_SET_ATOMIC(0, &started_cpus);
		for (;;)
			cpu_spinwait();
	}
}

#define	NRESCUEPTP	(16)
static uint64_t *rescue_ptps = NULL;
static size_t rescue_ptps_offset = 0;

/*
 * A bump allocator for bootstrap page table pages.  This uses the rescue
 * reservation since locore/hammer_time() might interrogate the PTPs to
 * determine where the kernel is loaded.  In particular, the PTPs must be
 * mapped by rescue_kernel_exec().
 */
static uint64_t *
rescue_kernel_alloc_ptp(void)
{
	uint64_t *ptp;

	if (rescue_ptps_offset * sizeof(uint64_t) >= NRESCUEPTP * PAGE_SIZE) {
		/* Should only happen due to a programming error. */
		panic("rescue: ran out of bootstrap PTPs");
	}
	ptp = rescue_ptps + rescue_ptps_offset;
	rescue_ptps_offset += NPTEPG;
	return (ptp);
}

extern void rescue_tramp(uint64_t ncr3, uintptr_t start, uintptr_t itramp);
extern uintptr_t rescue_itramp;

/*
 * Set up initial page tables for the rescue kernel.  These need to satisfy both
 * amd64 locore and the remainder of rescue_kernel_exec().  So, we map:
 * - the rescue reservation using an identity map,
 * - the current thread's stack,
 * - everything that's currently mapped above KERNBASE.
 *
 * The physical address of the new root PTP is returned.
 */
static int
rescue_kernel_exec_cr3(uint64_t *cr3p)
{
	pml4_entry_t *pml4;
	pdp_entry_t *pdp;
	pd_entry_t *pd;
	pt_entry_t *pt;
	vm_offset_t kstack;
	vm_paddr_t tramppa;
	size_t kstacksz;

	pml4 = rescue_kernel_alloc_ptp();

	/*
	 * First build the identity map for the reservation using 2MB pages.
	 */
	pdp = rescue_kernel_alloc_ptp();
	pml4[pmap_pml4e_index(rescue_pa)] = X86_PG_RW | X86_PG_V | vtophys(pdp);
	pd = rescue_kernel_alloc_ptp();
	pdp[pmap_pdpe_index(rescue_pa)] = X86_PG_RW | X86_PG_V | vtophys(pd);
	for (vm_paddr_t pa = rescue_pa; pa < rescue_pa + rescue_memsize;
	    pa += NBPDR)
		pd[pmap_pde_index(pa)] = X86_PG_PS | X86_PG_RW | X86_PG_V | pa;

	/*
	 * Extend the identity map to include the host kernel's rescue_tramp().
	 * rescue_tramp() is aligned such that it will not cross a page
	 * boundary.
	 */
	tramppa = trunc_2mpage(vtophys(&rescue_tramp));
	if (pml4[pmap_pml4e_index(tramppa)] == 0) {
		printf("rescue: rescue_tramp() is not mapped by PML4 page\n");
		return (EDOOFUS);
	}
	if (pdp[pmap_pdpe_index(tramppa)] == 0) {
		pd = rescue_kernel_alloc_ptp();
		pdp[pmap_pdpe_index(tramppa)] = X86_PG_A | X86_PG_V |
		    vtophys(pd);
	}
	if (pd[pmap_pde_index(tramppa)] == 0) {
		pd[pmap_pde_index(tramppa)] = X86_PG_PS | X86_PG_A | X86_PG_V |
		    tramppa;
	}

	/*
	 * Identity-map the low 4KB of RAM for the benefit of the BIOS.
	 */
	if (pml4[pmap_pml4e_index(0)] == 0) {
		pdp = rescue_kernel_alloc_ptp();
		pml4[pmap_pml4e_index(0)] = X86_PG_RW | X86_PG_V |
		    vtophys(pdp);
	} else {
		pdp = (pdp_entry_t *)PHYS_TO_DMAP(pml4[pmap_pml4e_index(0)] &
		    PG_FRAME);
	}
	if (pdp[pmap_pdpe_index(0)] == 0) {
		pd = rescue_kernel_alloc_ptp();
		pdp[pmap_pdpe_index(0)] = X86_PG_RW | X86_PG_V | vtophys(pd);
	} else {
		pd = (pd_entry_t *)PHYS_TO_DMAP(pdp[pmap_pdpe_index(0)] &
		    PG_FRAME);
	}
	if (pd[pmap_pde_index(0)] != 0) {
		printf("rescue: low 2MB already occupied by reservation\n");
		return (EDOOFUS);
	}
	pt = rescue_kernel_alloc_ptp();
	pd[pmap_pde_index(0)] = X86_PG_RW | X86_PG_V | vtophys(pt);
	pt[pmap_pte_index(0)] = X86_PG_RW | X86_PG_V;

	/*
	 * Map the rescue kernel at KERNSTART.
	 */
	if (pml4[pmap_pml4e_index(KERNBASE)] != 0) {
		printf("rescue: kernel already mapped by identity map\n");
		return (EDOOFUS);
	}
	pdp = rescue_kernel_alloc_ptp();
	pml4[pmap_pml4e_index(KERNBASE)] = X86_PG_RW | X86_PG_V | vtophys(pdp);
	pd = rescue_kernel_alloc_ptp();
	pdp[pmap_pdpe_index(KERNBASE)] = X86_PG_RW | X86_PG_V | vtophys(pd);
	for (vm_offset_t va = KERNBASE; va < KERNBASE + rescue_memsize;
	    va += NBPDR) {
		pd[pmap_pde_index(va)] = X86_PG_PS | X86_PG_RW | X86_PG_V |
		    (rescue_pa + (va - KERNBASE));
	}

	/*
	 * Finally, map the current stack.  For now we assume that the stack
	 * doesn't span multiple PDEs.  This is generally true, but a more
	 * complete implementation could handle that possibility.
	 */
	kstack = curthread->td_kstack;
	kstacksz = curthread->td_kstack_pages * PAGE_SIZE;
	if (pml4[pmap_pml4e_index(kstack)] != 0) {
		printf("rescue: kernel stack already mapped by identity map\n");
		return (ENXIO);
	}
	if (pmap_pdpe_index(kstack) != pmap_pdpe_index(kstack + kstacksz - 1)) {
		printf("rescue: kernel stack spans multiple PDP pages\n");
		return (ENXIO);
	}
	if (pmap_pde_index(kstack) != pmap_pde_index(kstack + kstacksz - 1)) {
		printf("rescue: kernel stack spans multiple PD pages\n");
		return (ENXIO);
	}
	pdp = rescue_kernel_alloc_ptp();
	pml4[pmap_pml4e_index(kstack)] = X86_PG_RW | X86_PG_V | vtophys(pdp) |
	    pg_nx;
	pd = rescue_kernel_alloc_ptp();
	pdp[pmap_pdpe_index(kstack)] = X86_PG_RW | X86_PG_V | vtophys(pd) |
	    pg_nx;
	pt = rescue_kernel_alloc_ptp();
	pd[pmap_pde_index(kstack)] = X86_PG_RW | X86_PG_V | vtophys(pt) |
	    pg_nx;
	for (vm_offset_t va = kstack; va < kstack + kstacksz; va += PAGE_SIZE) {
		pt[pmap_pte_index(va)] = X86_PG_RW | X86_PG_V | pg_nx |
		    X86_PG_A | X86_PG_M | vtophys(va);
	}

	*cr3p = vtophys(pml4);
	return (0);
}

void
rescue_kernel_exec(void)
{
	pml4_entry_t *opml4, *pml4;
	pdp_entry_t *pdp;
	pd_entry_t *pd;
	pt_entry_t *pt;
	struct rescue_kernel_params *params;
	uintptr_t entry, itramp, tramp;
	Elf64_Ehdr *ehdr;
	uint64_t cr3, ocr3;

	KASSERT((read_rflags() & PSL_I) == 0,
	    ("%s: interrupts enabled", __func__));

	/*
	 * Switch to the boot CPU if we are not already on it.
	 */
	rescue_kernel_cpu_switch();

	printf("rescue: preparing to exec rescue kernel\n");

	intr_rescue_exec();

	/*
	 * Prepare the dump parameters structure for the rescue kernel.  The
	 * rest of the parameters must already have been initialized.  These
	 * will be accessed via an aliasing mapping, so make sure the cache is
	 * written back.
	 */
	params = rescue_va;
	rescue_dump_params_init(&params->kp_dumpparams);

	ehdr = (Elf64_Ehdr *)((char *)rescue_va + RESCUE_RESERV_KERNEL_OFFSET);
	if (ehdr->e_ident[0] != ELFMAG0 || ehdr->e_ident[1] != ELFMAG1 ||
	    ehdr->e_ident[2] != ELFMAG2 || ehdr->e_ident[3] != ELFMAG3) {
		printf("rescue: rescue kernel is not an ELF file\n");
		return;
	}
	entry = ehdr->e_entry;

	if (rescue_kernel_exec_cr3(&cr3) != 0) {
		printf("rescue: failed to initialize bootstrap page tables\n");
		return;
	}

	tramp = trunc_page(vtophys(&rescue_tramp));
	itramp = vtophys(&rescue_itramp);

	/*
	 * amd64 locore expects to be executed via a mapping at KERNSTART.
	 * However, the current (panicked) kernel is already mapped there.  So,
	 * we use a trampoline which can be executed via an identity map; the
	 * trampoline installs the rescue kernel's bootstrap root PML4 page
	 * before jumping to its entry point.
	 *
	 * For this to work, the trampoline must be identity-mapped in both the
	 * old and new kernels.  rescue_kernel_exec_cr3() takes care of this for
	 * the rescue kernel.  For the old kernel, we make a copy of the
	 * current PML4P (to avoid modifying host memory which might be relevant
	 * to a debugging session), then install it as the root PTP until the
	 * trampoline swaps in its own root PTP.
	 */
	ocr3 = rcr3() & ~(CR3_PCID_MASK | CR3_PCID_SAVE);
	opml4 = (pml4_entry_t *)PHYS_TO_DMAP(ocr3);
	pml4 = rescue_kernel_alloc_ptp();
	/* Just copy everything in the top half of the address space. */
	for (vm_pindex_t i = PML4PML4I; i < NPML4EPG; i++)
		pml4[i] = opml4[i];
	pdp = rescue_kernel_alloc_ptp();
	pml4[pmap_pml4e_index(tramp)] = X86_PG_A | X86_PG_V | vtophys(pdp);
	pd = rescue_kernel_alloc_ptp();
	pdp[pmap_pdpe_index(tramp)] = X86_PG_A | X86_PG_V | vtophys(pd);
	pt = rescue_kernel_alloc_ptp();
	pd[pmap_pde_index(tramp)] = X86_PG_A | X86_PG_V | vtophys(pt);
	pt[pmap_pte_index(tramp)] = X86_PG_A | X86_PG_V | tramp;
	load_cr4(rcr4() & ~(CR4_PCIDE | CR4_PGE));
	load_cr3(vtophys(pml4));

	rescue_tramp(cr3, entry, itramp);
}

/*
 * Dummy function to satisfy the dumper interface.  This should never be
 * called.
 */
static int
rescue_dumper_dummy(void *priv, void *virtual, off_t offset, size_t length)
{
	printf("%s: unexpected call\n", __func__);
	return (EOPNOTSUPP);
}

/*
 * Copy a buffer into the rescue kernel's memory reservation at the specified
 * offset.  Returns an error if the copy would overflow the reservation buffer.
 */
static int
rescue_memcpy(vm_offset_t off, const void *src, size_t size, vm_offset_t *offp)
{
	if (off >= rescue_memsize || off + size > rescue_memsize)
		return (1);

	memcpy((char *)rescue_va + off, src, size);
	if (offp != NULL)
		*offp = off + size;
	return (0);
}

/*
 * Memset a region of the rescue kernel's memory reservation, with overflow
 * checking.
 */
static int
rescue_memset(vm_offset_t off, char c, size_t size)
{
	if (off >= rescue_memsize || off + size > rescue_memsize)
		return (1);

	memset((char *)rescue_va + off, c, size);
	return (0);
}

static size_t
rescue_kernel_init_efimap(const struct efi_map_header *srchdr, vm_offset_t off,
    unsigned long memsize)
{
	struct efi_map_header hdr;
	const struct efi_md *srcmd;
	vm_offset_t start, end;
	const size_t hdrsz = roundup2(sizeof(struct efi_map_header), 16);
	int ndesc;

	start = end = off;

	memcpy(&hdr, srchdr, sizeof(hdr));
	end += hdrsz;

	/*
	 * Copy the memory map, excluding RAM entries that do not overlap with
	 * the rescue reservation.
	 */
	srcmd = (const struct efi_md *)((const uint8_t *)srchdr + hdrsz);
	ndesc = srchdr->memory_size / srchdr->descriptor_size;
	for (int i = 0; i < ndesc; i++) {
		if (efi_physmem_type(srcmd->md_type)) {
			if (srcmd->md_phys == 0) {
				if (rescue_memcpy(end, srcmd,
				    srchdr->descriptor_size, &end))
					return (0);
			} else if (srcmd->md_phys <= rescue_pa &&
			    srcmd->md_phys + ptoa(srcmd->md_pages) >=
			    rescue_pa) {
				struct efi_md *dstmd;

				dstmd = malloc(srchdr->descriptor_size, M_TEMP,
				    M_WAITOK);
				memcpy(dstmd, srcmd, srchdr->descriptor_size);
				dstmd->md_phys = rescue_pa;
				dstmd->md_pages = atop(memsize);
				bool err = rescue_memcpy(end, dstmd,
				    srchdr->descriptor_size, &end);
				free(dstmd, M_TEMP);
				if (err)
					return (0);
			}
		} else if (rescue_memcpy(end, srcmd, srchdr->descriptor_size,
		    &end)) {
			return (0);
		}
		srcmd = efi_next_descriptor(__DECONST(void *, srcmd),
		    srchdr->descriptor_size);
	}
	hdr.memory_size = end - start - sizeof(hdr);
	if (rescue_memcpy(start, &hdr, sizeof(hdr), NULL))
		return (0);

	return (end - start);
}

/*
 * Initialize the rescue kernel's staging area:
 * 1. Allocate the staging area.
 * 2. Stash kernel metadata (the memory map, loader tunables) at the beginning
 *    of the staging area.
 * 3. Copy the rescue kernel into the staging area.
 * 4. Optionally free pages backing the original copy of the kernel, since they
 *    are no longer needed.
 */
static void
rescue_kernel_init(void *arg __unused)
{
	extern u_long rescue_start, rescue_end;
	struct dumperinfo di;
	struct diocskerneldump_arg kda;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	const struct efi_map_header *srchdr;
	struct rescue_kernel_params *params;
	const char *p;
	caddr_t kmdp;
	size_t kernlen, varlen;
	vm_offset_t envstart, off;
	unsigned long memsize;
	int enabled, error, freeorig;

	enabled = 0;
	TUNABLE_INT_FETCH(RESCUE_KENV_ENABLED, &enabled);
	if (!enabled)
		return;
	if (!do_minidump) {
		printf("rescue: minidumps are not enabled\n");
		return;
	}

	kernlen = (u_long)&rescue_end - (u_long)&rescue_start;

	/*
	 * Figure how much memory we need to allocate.  We allocate free memory
	 * for the rescue kernel, memory to hold the rescue kernel image, and
	 * 2MB for the environment and metadata, and for bootstrap page table
	 * pages.
	 */
	memsize = RESCUE_RESERV_DEFAULT_SIZE;
	TUNABLE_ULONG_FETCH(RESCUE_KENV_MEMSIZE, &memsize);
	memsize += round_page(kernlen);
	memsize += NBPDR;

	/*
	 * Require memory below the 4GB boundary both for the benefit of devices
	 * with limited DMA addressing capabilities, and because the amd64
	 * kernel assumes that it is loaded below 4GB.  See amd64_loadaddr(),
	 * for example.
	 */
	rescue_va = kmem_alloc_contig(memsize, M_NOWAIT | M_ZERO | M_NODUMP,
	    0, (vm_paddr_t)1 << 32, RESCUE_RESERV_ALIGN, RESCUE_RESERV_BOUNDARY,
	    VM_MEMATTR_DEFAULT);
	if (rescue_va == NULL) {
		printf("rescue: failed to reserve contiguous memory\n");
		goto out;
	}
	rescue_pa = pmap_kextract((vm_offset_t)rescue_va);
	rescue_memsize = memsize;

	params = rescue_va;
	off = roundup2(sizeof(*params), sizeof(void *));
	params->kp_boothowto = boothowto;

	kmdp = preload_search_by_type("elf kernel");
	if (kmdp == NULL)
		kmdp = preload_search_by_type("elf64 kernel");
	srchdr = (const struct efi_map_header *)preload_search_info(kmdp,
	    MODINFO_METADATA | MODINFOMD_EFI_MAP);
	if (srchdr != NULL) {
		const struct efi_fb *efifb;
		size_t efimaplen;

		efimaplen = rescue_kernel_init_efimap(srchdr, off, memsize);
		if (efimaplen == 0) {
			printf("rescue: failed to copy EFI memory map\n");
			goto out;
		}
		params->kp_efimapstart = rescue_pa + off;
		params->kp_efimaplen = efimaplen;
		off += efimaplen;

		efifb = (const struct efi_fb *)preload_search_info(kmdp,
		    MODINFO_METADATA | MODINFOMD_EFI_FB);
		if (efifb != NULL) {
			params->kp_efifbaddr = rescue_pa + off;
			if (rescue_memcpy(off, efifb, sizeof(*efifb), &off)) {
				printf(
				    "rescue: failed to copy EFI framebuffer\n");
				goto out;
			}
		}
	} else {
		struct bios_smap smap;
		size_t smaplen;

		smaplen = sizeof(struct bios_smap) + sizeof(uint32_t);
		smap.base = rescue_pa;
		smap.length = memsize;
		smap.type = SMAP_TYPE_MEMORY;

		params->kp_smapstart = rescue_pa + off;
		params->kp_smaplen = smaplen;
		if (rescue_memcpy(off, &smap, sizeof(smap), &off)) {
			printf("rescue: failed to copy BIOS memory map\n");
			goto out;
		}
	}

	/*
	 * Copy the host kernel's environment, with three differences:
	 * 1. SMP is disabled.
	 * 2. debug.rescue_minidump=1 from the host is omitted.
	 * 3. Any tunables prefixed by debug.rescue are copied without the
	 *    prefix.  This provides a mechanism to override host tunables
	 *    if needed.  Prefixed tunables are copied first since tunable
	 *    lookups are first-match.
	 */
	envstart = off;
	p = "kern.smp.disabled=1";
	varlen = strlen(p) + 1;
	if (rescue_memcpy(off, p, varlen, &off)) {
		printf("rescue: failed to copy tunable\n");
		goto out;
	}
	for (int i = 0; kenvp[i] != NULL; i++) {
		p = kenvp[i];
		if (strncmp(p, RESCUE_KENV_PREFIX,
		    sizeof(RESCUE_KENV_PREFIX) - 1) != 0)
			continue;
		p += sizeof(RESCUE_KENV_PREFIX) - 1;
		varlen = strlen(p) + 1;
		if (rescue_memcpy(off, p, varlen, &off)) {
			printf("rescue: failed to copy tunable\n");
			goto out;
		}
	}
	for (int i = 0; kenvp[i] != NULL; i++) {
		p = kenvp[i];
		if (strncmp(p, RESCUE_KENV_PREFIX,
		    sizeof(RESCUE_KENV_PREFIX) - 1) == 0)
			continue;
		varlen = strlen(p) + 1;
		if (rescue_memcpy(off, p, varlen, &off)) {
			printf("rescue: failed to copy tunable\n");
			goto out;
		}
	}
	p = "\0";
	if (rescue_memcpy(off, p, 1, &off)) {
		printf("rescue: failed to copy tunable\n");
		goto out;
	}
	params->kp_kenvstart = rescue_pa + envstart;
	params->kp_kenvlen = off - envstart;

	/*
	 * Finally, reserve some space for the bootstrap page table pages.
	 */
	off = round_page(off);
	rescue_ptps = (uint64_t *)((uintptr_t)rescue_va + off);
	off += NRESCUEPTP * PAGE_SIZE;

	/*
	 * The kernel must be loaded at a 2MB-aligned address.  To simplify
	 * location of the parameter structure, we require that the parameters,
	 * EFI map, bootstrap page table pages, and rescue kernel environment
	 * all fit in the first 2MB of the reservation.
	 */
	off = round_2mpage(off);
	if (off != RESCUE_RESERV_KERNEL_OFFSET) {
		printf("rescue: kernel metadata is too large\n");
		goto out;
	}
	params->kp_kernstart = rescue_pa + off;

	/*
	 * Copy the kernel image.  This must come last since the length might
	 * not include that of allocated sections (i.e., .bss) depending on how
	 * the kernel was linked.
	 */
	if (rescue_memcpy(off, &rescue_start, kernlen, NULL)) {
		printf("rescue: failed to copy kernel image\n");
		goto out;
	}
	ehdr = (Elf64_Ehdr *)((vm_offset_t)rescue_va + off);
	if (!IS_ELF(*ehdr)) {
		printf("rescue: kernel image is not an ELF file\n");
		goto out;
	}
	phdr = (Elf64_Phdr *)((vm_offset_t)ehdr + ehdr->e_phoff);
	for (int i = 0; i < ehdr->e_phnum; i++) {
		vm_offset_t foff;

		/*
		 * Zero out any segments that need it, i.e., the BSS.
		 */
		if (phdr[i].p_type != PT_LOAD ||
		    phdr[i].p_filesz >= phdr[i].p_memsz)
			continue;
		foff = phdr[i].p_offset + phdr[i].p_filesz;
		if (rescue_memset(off + foff, 0,
		    phdr[i].p_memsz - phdr[i].p_filesz)) {
			printf("rescue: failed to zero BSS\n");
			goto out;
		}
	}

	/*
	 * Free the original copy of the rescue kernel: we don't need it
	 * anymore, and this releases a significant amount of memory, especially
	 * if the rescue kernel contains an embedded root filesystem.
	 */
	freeorig = 1;
	TUNABLE_INT_FETCH("debug.rescue_free_kernel", &freeorig);
	if (freeorig)
		kmem_bootstrap_free((vm_offset_t)&rescue_start, kernlen);

	/*
	 * Finally tell the generic kernel dump layer that a dump device
	 * exists, so that it calls into rescue_kernel_exec().
	 */
	memset(&di, 0, sizeof(di));
	di.dumper = rescue_dumper_dummy;
	memset(&kda, 0, sizeof(kda));
	kda.kda_index = 0; /* highest priority */
	error = dumper_insert(&di, "rescue", &kda);
	if (error != 0) {
		printf("rescue: failed to set dump device: %d\n", error);
		goto out;
	}

	do_rescue_minidump = true;
	printf("rescue: initialized\n");
	return;

out:
	if (rescue_va != NULL) {
		kmem_free(rescue_va, memsize);
		rescue_va = NULL;
		rescue_pa = 0;
		rescue_memsize = 0;
	}
	rescue_ptps = NULL;
}
SYSINIT(rescue_kernel, SI_SUB_VM_CONF, SI_ORDER_ANY, rescue_kernel_init, NULL);
