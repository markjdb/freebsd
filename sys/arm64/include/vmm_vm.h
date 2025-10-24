/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (C) 2015 Mihai Carabas <mihai.carabas@gmail.com>
 * All rights reserved.
 */

#ifndef _VMM_VM_H_
#define	_VMM_VM_H_

#ifdef _KERNEL

#include <sys/types.h>

#include <machine/vmm_instruction_emul.h>

struct vmm_mmio_region {
	uint64_t start;
	uint64_t end;
	mem_region_read_t read;
	mem_region_write_t write;
};
#define	VM_MAX_MMIO_REGIONS	4

struct vmm_special_reg {
	uint32_t	esr_iss;
	uint32_t	esr_mask;
	reg_read_t	reg_read;
	reg_write_t	reg_write;
	void		*arg;
};
#define	VM_MAX_SPECIAL_REGS	16

#define	VMM_VM_MD_FIELDS						\
	struct vmm_mmio_region mmio_region[VM_MAX_MMIO_REGIONS];	\
	struct vmm_special_reg special_reg[VM_MAX_SPECIAL_REGS]

#endif /* _KERNEL */

#endif /* !_VMM_VM_H_ */
