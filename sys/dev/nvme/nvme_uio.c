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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/uio.h>

#include "nvme_private.h"

static void
nvme_uio_done(void *arg, const struct nvme_completion *status)
{
	struct mtx *mtx;

	/* TODO: update uio flags based on status */

	mtx = mtx_pool_find(mtxpool_sleep, arg);
	mtx_lock(mtx);
	wakeup(arg);
	mtx_unlock(mtx);
}

static struct nvme_tracker *
nvme_allocate_tracker_uio(struct nvme_controller *ctrlr, struct uio *uio)
{
	struct nvme_tracker 	*tr;
	struct nvme_qpair	*qpair;

	if (ctrlr->per_cpu_io_queues)
		qpair = &ctrlr->ioq[curcpu];
	else
		qpair = &ctrlr->ioq[0];

	/*
	 * For uio, always allocate a PRP list, rather than walking
	 *  the iovecs.
	 */
	tr = nvme_qpair_allocate_tracker(qpair, TRUE /* alloc_prp_list */);

	memset(&tr->cmd, 0, sizeof(tr->cmd));

	tr->qpair = qpair;
	tr->cb_fn = nvme_uio_done;
	tr->cb_arg = uio;

	return (tr);
}

static void
nvme_payload_map_uio(void *arg, bus_dma_segment_t *seg, int nseg,
    bus_size_t mapsize, int error)
{
	nvme_payload_map(arg, seg, nseg, error);
}

static void
nvme_read_uio(struct nvme_namespace *ns, struct uio *uio)
{
	struct nvme_tracker	*tr;
	struct nvme_command	*cmd;
	int			err, i;
	uint64_t		lba, iosize = 0;

	tr = nvme_allocate_tracker_uio(ns->ctrlr, uio);

	cmd = &tr->cmd;
	cmd->opc = NVME_OPC_READ;
	cmd->nsid = ns->id;
	lba = uio->uio_offset / nvme_ns_get_sector_size(ns);

	*(uint64_t *)&cmd->cdw10 = lba;

	for (i = 0; i < uio->uio_iovcnt; i++) {
		iosize += uio->uio_iov[i].iov_len;
	}

	cmd->cdw12 = (iosize / nvme_ns_get_sector_size(ns))-1;

	err = bus_dmamap_load_uio(tr->qpair->dma_tag, tr->dma_map, uio,
	    nvme_payload_map_uio, tr, 0);

	KASSERT(err == 0, ("bus_dmamap_load_uio returned non-zero!\n"));
}

static void
nvme_write_uio(struct nvme_namespace *ns, struct uio *uio)
{
	struct nvme_tracker	*tr;
	struct nvme_command	*cmd;
	int			err, i;
	uint64_t		lba, iosize = 0;

	tr = nvme_allocate_tracker_uio(ns->ctrlr, uio);

	cmd = &tr->cmd;
	cmd->opc = NVME_OPC_WRITE;
	cmd->nsid = ns->id;
	lba = uio->uio_offset / nvme_ns_get_sector_size(ns);

	*(uint64_t *)&cmd->cdw10 = lba;

	for (i = 0; i < uio->uio_iovcnt; i++) {
		iosize += uio->uio_iov[i].iov_len;
	}

	cmd->cdw12 = (iosize / nvme_ns_get_sector_size(ns))-1;

	err = bus_dmamap_load_uio(tr->qpair->dma_tag, tr->dma_map, uio,
	    nvme_payload_map_uio, tr, 0);

	KASSERT(err == 0, ("bus_dmamap_load_uio returned non-zero!\n"));
}

int
nvme_ns_physio(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct nvme_namespace	*ns;
	struct mtx		*mtx;
#if __FreeBSD_version > 900017
	int			ref;
#endif

	PHOLD(curproc);

	ns = dev->si_drv1;
	mtx = mtx_pool_find(mtxpool_sleep, uio);

#if __FreeBSD_version > 900017
	dev_refthread(dev, &ref);
#else
	dev_refthread(dev);
#endif

	mtx_lock(mtx);
	if (uio->uio_rw == UIO_READ)
		nvme_read_uio(ns, uio);
	else
		nvme_write_uio(ns, uio);

	msleep(uio, mtx, PRIBIO, "nvme_physio", 0);
	mtx_unlock(mtx);

#if __FreeBSD_version > 900017
	dev_relthread(dev, ref);
#else
	dev_relthread(dev);
#endif

	uio->uio_resid = 0;

	PRELE(curproc);
	return (0);
}
