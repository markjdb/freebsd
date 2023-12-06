/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020, 2023 Juniper Networks, Inc.
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

#include "opt_platform.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/cpuset.h>
#include <sys/disk.h>
#include <sys/efi.h>
#include <sys/elf_common.h>
#include <sys/intr.h>
#include <sys/kenv.h>
#include <sys/kernel.h>
#include <sys/kerneldump.h>
#include <sys/linker.h>
#include <sys/msgbuf.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/smp.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/vm_dumpset.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <machine/machdep.h>
#include <machine/md_var.h>
#include <machine/metadata.h>
#include <machine/pmap.h>
#include <machine/rescue.h>
#include <machine/vmparam.h>

#ifdef FDT
#include <dev/ofw/openfirm.h>
#include <contrib/libfdt/libfdt.h>
#endif

bool do_rescue_minidump = false;

/*
 * Parameters for memory reserved for the rescue kernel.  The boundary and
 * alignment are fixed by the requirements of locore.  The size is configurable
 * but of course must be satisfiable by an allocation with the defined alignment
 * and boundary requirements.
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
 * Called from the host kernel to populate rescue dumper parameters.
 * The returned structure is passed to the rescue kernel.
 */
static void
rescue_dump_params_init(struct rescue_dump_params *rdp)
{
	rdp->dp_msgbufpa = vtophys(msgbufp->msg_ptr);
	rdp->dp_msgbufsz = msgbufp->msg_size;
	rdp->dp_vmdumppa = vtophys(vm_page_dump);
	rdp->dp_vmdumpsz = round_page(BITSET_SIZE(vm_page_dump_pages));
	rdp->dp_dumpavailpa = vtophys(dump_avail);
	rdp->dp_kernl0pa = vtophys(kernel_pmap->pm_l0);
	rdp->dp_kernstart = VM_MIN_KERNEL_ADDRESS;
	rdp->dp_kernend = kernel_vm_end;
	rdp->dp_kernmax = VM_MAX_KERNEL_ADDRESS;
	rdp->dp_dmapbasepa = DMAP_MIN_PHYSADDR;
	rdp->dp_dmapmin = DMAP_MIN_ADDRESS;
	rdp->dp_dmapmax = DMAP_MAX_ADDRESS;
}

static void
rescue_kernel_cpu_switch(void)
{
	struct pcpu *pcpu;

	pcpu = cpuid_to_pcpu[0];
	if (get_pcpu() != pcpu) {
		CPU_SET_ATOMIC(pcpu->pc_cpuid, &started_cpus);
		for (;;)
			cpu_spinwait();
	}
}

/*
 * Make the final preparations to jump into the rescue kernel, and then do it.
 */
void
rescue_kernel_exec(void)
{
	static pd_entry_t pt_l0[Ln_ENTRIES] __aligned(PAGE_SIZE);
	static pd_entry_t pt_l1[Ln_ENTRIES] __aligned(PAGE_SIZE);
	static pd_entry_t pt_l2[Ln_ENTRIES] __aligned(PAGE_SIZE);
	struct rescue_kernel_params *params;
	void (*rescue)(u_long modulep);
	Elf64_Ehdr *ehdr;
	vm_paddr_t pa;
	off_t entryoff;

	/*
	 * Switch to the boot CPU if we are not already on it.
	 */
	rescue_kernel_cpu_switch();

	printf("rescue: preparing to exec rescue kernel\n");

	/*
	 * Acknowledge any active interrupts to avoid leaving the PIC in an
	 * indeterminate state.  Mute system errors: the rescue kernel will
	 * re-enable them once it's prepared to handle them.
	 */
	intr_isrc_reset();
	serror_disable();

	/*
	 * Prepare the dump parameters structure for the rescue kernel.  The
	 * rest of the parameters must already have been initialized.  These
	 * will be accessed via an aliasing mapping, so make sure the cache is
	 * written back.
	 */
	params = rescue_va;
	rescue_dump_params_init(&params->kp_dumpparams);
	cpu_dcache_wb_range((vm_offset_t)params, sizeof(*params));

	/*
	 * Construct an identity map for the rescue kernel's locore.  This
	 * covers the entire reservation.  Because it does not span a 1GB
	 * boundary, only three pages are needed.  This will be replaced by
	 * locore.
	 */
	pt_l0[pmap_l0_index(rescue_pa)] = L0_TABLE | vtophys(pt_l1);
	pt_l1[pmap_l1_index(rescue_pa)] = L1_TABLE | vtophys(pt_l2);
	for (pa = rescue_pa; pa < rescue_pa + rescue_memsize; pa += L2_SIZE)
		pt_l2[pmap_l2_index(pa)] = L2_BLOCK | ATTR_DEFAULT |
		    ATTR_S1_IDX(VM_MEMATTR_UNCACHEABLE) | ATTR_S1_nG | pa;
	dsb(ishst);

	set_ttbr0(pmap_kextract((vm_offset_t)pt_l0));
	cpu_tlb_flushID();

	ehdr = (Elf64_Ehdr *)((char *)rescue_pa + RESCUE_RESERV_KERNEL_OFFSET);
	if (IS_ELF(*ehdr))
		entryoff = ehdr->e_entry - KERNBASE;
	else
		entryoff = 0;

	/*
	 * Jump to the entry point.  Currently we pass a dummy module pointer to
	 * ensure that locore maps some memory following the rescue kernel, but
	 * this is really a hack to avoid modifying locore.
	 */
	rescue = (void *)(rescue_pa + RESCUE_RESERV_KERNEL_OFFSET + entryoff);
	(rescue)(KERNBASE + rescue_memsize);
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

#ifdef FDT
/*
 * Copy the DTB into the reserved region and update its memory map to restrict
 * the rescue kernel's address space to the reservation.
 */
static size_t
rescue_kernel_init_fdt(vm_paddr_t pa, vm_offset_t off, unsigned long memsize)
{
	void *dtbp, *fdtp;
	const uint32_t *addr_cellsp, *size_cellsp;
	uint8_t *buf, *sb;
	caddr_t kmdp;
	size_t dtblen;
	uint32_t addr_cells, size_cells;
	int error, len, memoff, rootoff;

	/*
	 * Copy the DTB into the reserved area.  It would be simpler to copy the
	 * kernel to the base of the reservation and copy the DTB to the space
	 * following the kernel, but we do not know the kernel's full size.
	 * Thus the DTB is copied first and the kernel is copied to the next
	 * 2MB-aligned address.
	 */
	kmdp = preload_search_by_type("elf kernel");
	if (kmdp == NULL)
		kmdp = preload_search_by_type("elf64 kernel");
	dtbp = MD_FETCH(kmdp, MODINFOMD_DTBP, void *);
	dtblen = fdt_totalsize(dtbp);

	fdtp = malloc(dtblen, M_TEMP, M_WAITOK | M_ZERO);
	memcpy(fdtp, dtbp, dtblen);

	/*
	 * Fix up the DTB used by the rescue kernel: update the memory node to
	 * point at reserved memory, and delete the rescue and memreserve nodes.
	 */
	rootoff = fdt_path_offset(fdtp, "/");
	if (rootoff < 0) {
		printf("rescue: failed to look up FDT root offset\n");
		return (0);
	}
	memoff = fdt_path_offset(fdtp, "/memory");
	if (memoff < 0) {
		printf("rescue: failed to look up FDT memory offset\n");
		return (0);
	}
	addr_cellsp = fdt_getprop(fdtp, rootoff, "#address-cells", NULL);
	if (addr_cellsp == NULL) {
		printf("rescue: failed to look up address-cells property\n");
		return (0);
	}
	size_cellsp = fdt_getprop(fdtp, rootoff, "#size-cells", NULL);
	if (addr_cellsp == NULL || size_cellsp == NULL) {
		printf("rescue: failed to look up address-cells property\n");
		return (0);
	}
	addr_cells = fdt32_to_cpu(*addr_cellsp);
	size_cells = fdt32_to_cpu(*size_cellsp);

	len = (addr_cells + size_cells) * sizeof(uint32_t);
	sb = buf = malloc(len, M_TEMP, M_WAITOK | M_ZERO);
	if (addr_cells == 2)
		*(uint64_t *)buf = cpu_to_fdt64(pa);
	else
		*(uint32_t *)buf = cpu_to_fdt32(pa);
	buf += addr_cells * sizeof(uint32_t);
	if (size_cells == 2)
		*(uint64_t *)buf = cpu_to_fdt64(memsize);
	else
		*(uint32_t *)buf = cpu_to_fdt32(memsize);
	error = fdt_setprop_inplace(fdtp, memoff, "reg", sb, len);
	free(sb, M_TEMP);
	if (error != 0) {
		printf("rescue: failed to update reg property: %d\n", error);
		return (0);
	}

	if (rescue_memcpy(off, fdtp, dtblen, NULL) != 0) {
		printf("rescue: failed to copy FDT\n");
		return (0);
	}

	return (dtblen);
}
#endif

static size_t
rescue_kernel_init_efimap(const struct efi_map_header *srchdr, vm_offset_t off,
    unsigned long memsize)
{
	struct efi_map_header hdr;
	const struct efi_md *srcmd;
	struct efi_md *dstmd;
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
			if (srcmd->md_phys <= rescue_pa &&
			    srcmd->md_phys + ptoa(srcmd->md_pages) >=
			    rescue_pa) {
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

static void
rescue_kernel_init(void *arg __unused)
{
	extern u_long rescue_start, rescue_end;
	struct dumperinfo di;
	struct diocskerneldump_arg kda;
	struct rescue_kernel_params *params;
	char *p;
	size_t kernlen, varlen;
	vm_offset_t envstart, off;
	unsigned long memsize;
	int enabled, error;

	enabled = 0;
	TUNABLE_INT_FETCH("debug.rescue_minidump", &enabled);
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
	memsize += L2_SIZE;

	/*
	 * First try to obtain memory below the 4GB boundary for the benefit of
	 * devices with limited DMA addressing capabilities.  This might not be
	 * possible depending on the layout of the physical address space.
	 */
	rescue_va = kmem_alloc_contig(memsize, M_WAITOK | M_ZERO | M_NODUMP,
	    0, (vm_paddr_t)1 << 32, RESCUE_RESERV_ALIGN, RESCUE_RESERV_BOUNDARY,
	    VM_MEMATTR_DEFAULT);
	if (rescue_va == NULL) {
		rescue_va = kmem_alloc_contig(memsize,
		    M_WAITOK | M_ZERO | M_NODUMP,
		    0, ~(vm_paddr_t)0, RESCUE_RESERV_ALIGN,
		    RESCUE_RESERV_BOUNDARY, VM_MEMATTR_DEFAULT);
		if (rescue_va == NULL) {
			printf("rescue: failed to reserve contiguous memory\n");
			goto out;
		}
	}
	rescue_pa = pmap_kextract((vm_offset_t)rescue_va);
	if (rescue_pa >= VM_MAX_USER_ADDRESS) {
		/* We might need to handle this case at some point. */
		printf("rescue: reserved memory cannot be mapped by TTBR0\n");
		goto out;
	}
	rescue_memsize = memsize;

	params = rescue_va;
	off = roundup2(sizeof(*params), sizeof(void *));
	params->kp_boothowto = boothowto;

	switch (arm64_bus_method) {
#ifdef FDT
	case ARM64_BUS_FDT: {
		size_t dtblen;

		dtblen = rescue_kernel_init_fdt(rescue_pa, off, memsize);
		if (dtblen == 0)
			goto out;
		params->kp_dtbstart = rescue_pa + off;
		params->kp_dtblen = dtblen;
		off += dtblen;
		break;
	}
#endif
	case ARM64_BUS_ACPI: {
		const struct efi_map_header *srchdr;
		const struct efi_fb *efifb;
		caddr_t kmdp;
		size_t efimaplen;

		kmdp = preload_search_by_type("elf kernel");
		if (kmdp == NULL)
			kmdp = preload_search_by_type("elf64 kernel");
		srchdr = (const struct efi_map_header *)preload_search_info(
		    kmdp, MODINFO_METADATA | MODINFOMD_EFI_MAP);
		if (srchdr == NULL) {
			printf("rescue: failed to find EFI map\n");
			goto out;
		}

		efimaplen = rescue_kernel_init_efimap(srchdr, off, memsize);
		if (efimaplen == 0)
			goto out;
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
		break;
	}
	default:
		printf("rescue: unsupported bus method %d\n", arm64_bus_method);
		goto out;
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
	 * The kernel must be loaded at a 2MB-aligned address.  To simplify
	 * location of the parameter structure, we require that the parameters,
	 * DTB and rescue kernel environment all fit in the first 2MB of the
	 * reservation.
	 */
	off = roundup2(off, L2_SIZE);
	if (off != RESCUE_RESERV_KERNEL_OFFSET) {
		printf("rescue: kernel metadata is too large\n");
		goto out;
	}
	params->kp_kernstart = rescue_pa + off;

	/*
	 * Copy the kernel image.  This must come last since the file size may
	 * not include that of allocated segments.
	 */
	if (rescue_memcpy(off, &rescue_start, kernlen, NULL)) {
		printf("rescue: failed to copy kernel image\n");
		goto out;
	}
	cpu_dcache_wbinv_range((vm_offset_t)rescue_va, memsize);
	arm64_aliasing_icache_sync_range((vm_offset_t)rescue_va,
	    memsize);

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
}
SYSINIT(rescue_kernel, SI_SUB_VM_CONF, SI_ORDER_ANY, rescue_kernel_init, NULL);
