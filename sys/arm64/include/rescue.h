/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020, 2023 Juniper Networks Inc.
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

#ifndef _RESCUE_H_
#define	_RESCUE_H_

/*
 * Dump parameters passed from the panicked kernel to the rescue kernel.  Some
 * of these are known at compile-time, but pass them anyway to avoid surprises.
 */
struct rescue_dump_params {
	vm_paddr_t	dp_msgbufpa;	/* message buffer physaddr */
	vm_size_t	dp_msgbufsz;	/* message buffer size */
	vm_paddr_t	dp_vmdumppa;	/* vm_page_dump physaddr */
	vm_size_t	dp_vmdumpsz;	/* vm_page_dump size (bytes) */
	vm_paddr_t	dp_dumpavailpa;	/* dump_avail[] physaddr */
	vm_paddr_t	dp_kernl0pa;	/* L0 page table page physaddr */
	vm_offset_t	dp_kernstart;	/* beginning of KVA */
	vm_offset_t	dp_kernend;	/* end of mapped KVA */
	vm_offset_t	dp_kernmax;	/* maximum KVA */
	vm_paddr_t	dp_dmapbasepa;	/* lowest addr mapped by direct map */
	vm_offset_t	dp_dmapmin;	/* beginning of direct map range */
	vm_offset_t	dp_dmapmax;	/* end of direct map range */
};

/*
 * Memory layout parameters passed to the rescue kernel.  These are used to
 * bootstrap the kernel and to initialize the dumper.
 */
struct rescue_kernel_params {
	struct rescue_dump_params kp_dumpparams;
	vm_paddr_t	kp_dtbstart;
	vm_size_t	kp_dtblen;
	vm_paddr_t	kp_efimapstart;
	vm_size_t	kp_efimaplen;
	vm_paddr_t	kp_efifbaddr;
	vm_paddr_t	kp_kenvstart;
	vm_size_t	kp_kenvlen;
	vm_paddr_t	kp_kernstart;
	int		kp_boothowto;
};

/*
 * The rescue kernel is copied at this offset into the rescue reservation.  The
 * offset must be a multiple of 2MB.
 */
#define	RESCUE_RESERV_KERNEL_OFFSET	L2_SIZE

extern bool do_rescue_minidump;

extern void rescue_dumper_init(struct rescue_dump_params *);
extern void rescue_kernel_exec(void);

#endif /* !_RESCUE_H_ */
