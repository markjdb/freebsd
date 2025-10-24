/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2015 Mihai Carabas <mihai.carabas@gmail.com>
 * Copyright (c) 2024 Ruslan Bukin <br@bsdpad.com>
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) under Innovate
 * UK project 105694, "Digital Security by Design (DSbD) Technology Platform
 * Prototype".
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

#define	VMM_VM_MD_FIELDS						\
	struct vmm_mmio_region mmio_region[VM_MAX_MMIO_REGIONS]

#endif /* _KERNEL */

#endif /* !_VMM_VM_H_ */
