/*-
 * Copyright (C) 2012 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 *
 * $FreeBSD$
 */

#ifndef __NVME_PRIVATE_H__
#define __NVME_PRIVATE_H__

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/rman.h>
#include <sys/systm.h>
#include <sys/taskqueue.h>

#include <machine/bus.h>

#include "nvme.h"

#define DEVICE2SOFTC(dev) ((struct nvme_controller *) device_get_softc(dev))

MALLOC_DECLARE(M_NVME);

#define CHATHAM2

#ifdef CHATHAM2
#define CHATHAM_PCI_ID		0x20118086
#define CHATHAM_CONTROL_BAR	0
#endif

#define IDT_PCI_ID		0x80d0111d

#define NVME_MAX_PRP_LIST_ENTRIES	(128)

/*
 * For commands requiring more than 2 PRP entries, one PRP will be
 *  embedded in the command (prp1), and the rest of the PRP entries
 *  will be in a list pointed to by the command (prp2).  This means
 *  that real max number of PRP entries we support is 128+1, which
 *  results in a max xfer size of 128*PAGE_SIZE.
 */
#define NVME_MAX_XFER_SIZE	NVME_MAX_PRP_LIST_ENTRIES * PAGE_SIZE

#define NVME_ADMIN_ENTRIES	(128)
/* min and max are defined in admin queue attributes section of spec */
#define NVME_MIN_ADMIN_ENTRIES	(2)
#define NVME_MAX_ADMIN_ENTRIES	(4096)

#define NVME_IO_ENTRIES		(1024)
/* min is a reasonable value picked for the nvme(4) driver */
#define NVME_MIN_IO_ENTRIES	(128)
/*
 * NVME_MAX_IO_ENTRIES is not defined, since it is specified in CC.MQES
 *  for each controller.
 */

#define NVME_INT_COAL_TIME	(0)	/* disabled */
#define NVME_INT_COAL_THRESHOLD (0)	/* 0-based */

#define NVME_MAX_NAMESPACES	(16)
#define NVME_MAX_CONSUMERS	(2)
#define NVME_MAX_ASYNC_EVENTS	(4)

#define NVME_TIMEOUT_IN_SEC	(30)

#ifndef CACHE_LINE_SIZE
#define CACHE_LINE_SIZE		(64)
#endif

struct nvme_prp_list {
	uint64_t			prp[NVME_MAX_PRP_LIST_ENTRIES];
	SLIST_ENTRY(nvme_prp_list)	slist;
	bus_addr_t			bus_addr;
	bus_dmamap_t			dma_map;
};

struct nvme_tracker {

	SLIST_ENTRY(nvme_tracker)	slist;
	struct nvme_qpair		*qpair;
	struct nvme_command		cmd;
	struct callout			timer;
	bus_dmamap_t			dma_map;
	nvme_cb_fn_t			cb_fn;
	void				*cb_arg;
	uint32_t			payload_size;
	struct nvme_prp_list		*prp_list;
	uint16_t			cid;
};

struct nvme_qpair {

	struct nvme_controller	*ctrlr;
	uint32_t		id;
	uint32_t		phase;

	uint16_t		vector;
	int			rid;
	struct resource		*res;
	void 			*tag;

	uint32_t		max_xfer_size;
	uint32_t		num_entries;
	uint32_t		sq_tdbl_off;
	uint32_t		cq_hdbl_off;

	uint32_t		sq_head;
	uint32_t		sq_tail;
	uint32_t		cq_head;

	int64_t			num_cmds;
	int64_t			num_intr_handler_calls;

	struct nvme_command	*cmd;
	struct nvme_completion	*cpl;

	bus_dma_tag_t		dma_tag;

	bus_dmamap_t		cmd_dma_map;
	uint64_t		cmd_bus_addr;

	bus_dmamap_t		cpl_dma_map;
	uint64_t		cpl_bus_addr;

	uint32_t		num_tr;
	uint32_t		num_prp_list;

	SLIST_HEAD(, nvme_tracker)	free_tr;

	struct nvme_tracker	**act_tr;

	SLIST_HEAD(, nvme_prp_list)	free_prp_list;

	struct mtx		lock __aligned(CACHE_LINE_SIZE);

} __aligned(CACHE_LINE_SIZE);

struct nvme_namespace {

	struct nvme_controller		*ctrlr;
	struct nvme_namespace_data	data;
	uint16_t			id;
	uint16_t			flags;
	struct cdev			*cdev;
};

/*
 * One of these per allocated PCI device.
 */
struct nvme_controller {

	device_t		dev;

	uint32_t		ready_timeout_in_ms;

	bus_space_tag_t		bus_tag;
	bus_space_handle_t	bus_handle;
	int			resource_id;
	struct resource		*resource;

#ifdef CHATHAM2
	bus_space_tag_t		chatham_bus_tag;
	bus_space_handle_t	chatham_bus_handle;
	int			chatham_resource_id;
	struct resource		*chatham_resource;
#endif

	uint32_t		msix_enabled;
	uint32_t		force_intx;

	uint32_t		num_io_queues;
	boolean_t		per_cpu_io_queues;

	/* Fields for tracking progress during controller initialization. */
	struct intr_config_hook	config_hook;
	uint32_t		ns_identified;
	uint32_t		queues_created;

	/* For shared legacy interrupt. */
	int			rid;
	struct resource		*res;
	void			*tag;
	struct task		task;
	struct taskqueue	*taskqueue;

	bus_dma_tag_t		hw_desc_tag;
	bus_dmamap_t		hw_desc_map;

	/** maximum i/o size in bytes */
	uint32_t		max_xfer_size;

	/** interrupt coalescing time period (in microseconds) */
	uint32_t		int_coal_time;

	/** interrupt coalescing threshold */
	uint32_t		int_coal_threshold;

	struct nvme_qpair	adminq;
	struct nvme_qpair	*ioq;

	struct nvme_registers		*regs;

	struct nvme_controller_data	cdata;
	struct nvme_namespace		ns[NVME_MAX_NAMESPACES];

	struct cdev			*cdev;

	boolean_t			is_started;

#ifdef CHATHAM2
	uint64_t		chatham_size;
	uint64_t		chatham_lbas;
#endif
};

#define nvme_mmio_offsetof(reg)						       \
	offsetof(struct nvme_registers, reg)

#define nvme_mmio_read_4(sc, reg)					       \
	bus_space_read_4((sc)->bus_tag, (sc)->bus_handle,		       \
	    nvme_mmio_offsetof(reg))

#define nvme_mmio_write_4(sc, reg, val)					       \
	bus_space_write_4((sc)->bus_tag, (sc)->bus_handle,		       \
	    nvme_mmio_offsetof(reg), val)

#define nvme_mmio_write_8(sc, reg, val) \
	do {								       \
		bus_space_write_4((sc)->bus_tag, (sc)->bus_handle,	       \
		    nvme_mmio_offsetof(reg), val & 0xFFFFFFFF); 	       \
		bus_space_write_4((sc)->bus_tag, (sc)->bus_handle,	       \
		    nvme_mmio_offsetof(reg)+4,				       \
		    (val & 0xFFFFFFFF00000000UL) >> 32);		       \
	} while (0);

#ifdef CHATHAM2
#define chatham_read_4(softc, reg) \
	bus_space_read_4((softc)->chatham_bus_tag,			       \
	    (softc)->chatham_bus_handle, reg)

#define chatham_write_8(sc, reg, val)					       \
	do {								       \
		bus_space_write_4((sc)->chatham_bus_tag,		       \
		    (sc)->chatham_bus_handle, reg, val & 0xffffffff);	       \
		bus_space_write_4((sc)->chatham_bus_tag,		       \
		    (sc)->chatham_bus_handle, reg+4,			       \
		    (val & 0xFFFFFFFF00000000UL) >> 32);		       \
	} while (0);

#endif /* CHATHAM2 */

#if __FreeBSD_version < 800054
#define wmb()	__asm volatile("sfence" ::: "memory")
#define mb()	__asm volatile("mfence" ::: "memory")
#endif

void	nvme_ns_test(struct nvme_namespace *ns, u_long cmd, caddr_t arg);

void	nvme_ctrlr_cmd_set_feature(struct nvme_controller *ctrlr,
				   uint8_t feature, uint32_t cdw11,
				   void *payload, uint32_t payload_size,
				   nvme_cb_fn_t cb_fn, void *cb_arg);
void	nvme_ctrlr_cmd_get_feature(struct nvme_controller *ctrlr,
				   uint8_t feature, uint32_t cdw11,
				   void *payload, uint32_t payload_size,
				   nvme_cb_fn_t cb_fn, void *cb_arg);
void	nvme_ctrlr_cmd_identify_controller(struct nvme_controller *ctrlr,
					   void *payload,
					   nvme_cb_fn_t cb_fn, void *cb_arg);
void	nvme_ctrlr_cmd_identify_namespace(struct nvme_controller *ctrlr,
					  uint16_t nsid, void *payload,
					  nvme_cb_fn_t cb_fn, void *cb_arg);
void	nvme_ctrlr_cmd_set_interrupt_coalescing(struct nvme_controller *ctrlr,
						uint32_t microseconds,
						uint32_t threshold,
						nvme_cb_fn_t cb_fn,
						void *cb_arg);
void	nvme_ctrlr_cmd_get_health_information_page(struct nvme_controller *ctrlr,
						   uint32_t nsid,
						   struct nvme_health_information_page *payload,
						   nvme_cb_fn_t cb_fn,
						   void *cb_arg);
void	nvme_ctrlr_cmd_create_io_cq(struct nvme_controller *ctrlr,
				    struct nvme_qpair *io_que, uint16_t vector,
				    nvme_cb_fn_t cb_fn, void *cb_arg);
void	nvme_ctrlr_cmd_create_io_sq(struct nvme_controller *ctrlr,
				    struct nvme_qpair *io_que,
				    nvme_cb_fn_t cb_fn, void *cb_arg);
void	nvme_ctrlr_cmd_delete_io_cq(struct nvme_controller *ctrlr,
				    struct nvme_qpair *io_que,
				    nvme_cb_fn_t cb_fn, void *cb_arg);
void	nvme_ctrlr_cmd_delete_io_sq(struct nvme_controller *ctrlr,
				    struct nvme_qpair *io_que,
				    nvme_cb_fn_t cb_fn, void *cb_arg);
void	nvme_ctrlr_cmd_set_num_queues(struct nvme_controller *ctrlr,
				      uint32_t num_queues, nvme_cb_fn_t cb_fn,
				      void *cb_arg);
void	nvme_ctrlr_cmd_set_asynchronous_event_config(struct nvme_controller *ctrlr,
					   union nvme_critical_warning_state state,
					   nvme_cb_fn_t cb_fn, void *cb_arg);
void	nvme_ctrlr_cmd_asynchronous_event_request(struct nvme_controller *ctrlr,
						  nvme_cb_fn_t cb_fn,
						  void *cb_arg);

struct nvme_tracker *	nvme_allocate_tracker(struct nvme_controller *ctrlr,
					      boolean_t is_admin,
					      nvme_cb_fn_t cb_fn, void *cb_arg,
					      uint32_t payload_size,
					      void *payload);
void	nvme_payload_map(void *arg, bus_dma_segment_t *seg, int nseg,
			 int error);

int	nvme_ctrlr_construct(struct nvme_controller *ctrlr, device_t dev);
int	nvme_ctrlr_reset(struct nvme_controller *ctrlr);
/* ctrlr defined as void * to allow use with config_intrhook. */
void	nvme_ctrlr_start(void *ctrlr_arg);

void	nvme_qpair_construct(struct nvme_qpair *qpair, uint32_t id,
			     uint16_t vector, uint32_t num_entries,
			     uint32_t max_xfer_size,
			     struct nvme_controller *ctrlr);
void	nvme_qpair_submit_cmd(struct nvme_qpair *qpair,
			      struct nvme_tracker *tr);
void	nvme_qpair_process_completions(struct nvme_qpair *qpair);
struct nvme_tracker *	nvme_qpair_allocate_tracker(struct nvme_qpair *qpair,
						    boolean_t alloc_prp_list);

void	nvme_admin_qpair_destroy(struct nvme_qpair *qpair);

void	nvme_io_qpair_destroy(struct nvme_qpair *qpair);

int	nvme_ns_construct(struct nvme_namespace *ns, uint16_t id,
			  struct nvme_controller *ctrlr);

int	nvme_ns_physio(struct cdev *dev, struct uio *uio, int ioflag);

void	nvme_sysctl_initialize_ctrlr(struct nvme_controller *ctrlr);

void	nvme_dump_command(struct nvme_command *cmd);
void	nvme_dump_completion(struct nvme_completion *cpl);

static __inline void
nvme_single_map(void *arg, bus_dma_segment_t *seg, int nseg, int error)
{
	uint64_t *bus_addr = (uint64_t *)arg;

	*bus_addr = seg[0].ds_addr;
}

#endif /* __NVME_PRIVATE_H__ */
