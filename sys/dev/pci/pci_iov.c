/*-
 * Copyright (c) 2013-2015 Sandvine Inc.  All rights reserved.
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

#include "opt_bus.h"

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/fcntl.h>
#include <sys/ioccom.h>
#include <sys/iov.h>
#include <sys/linker.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/pciio.h>
#include <sys/queue.h>
#include <sys/rman.h>
#include <sys/sysctl.h>

#include <machine/bus.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pci_private.h>
#include <dev/pci/pci_iov_private.h>

#include "pci_if.h"
#include "pcib_if.h"

static MALLOC_DEFINE(M_SRIOV, "sr_iov", "PCI SR-IOV allocations");

static d_ioctl_t pci_iov_ioctl;

static struct cdevsw iov_cdevsw = {
	.d_version = D_VERSION,
	.d_name = "iov",
	.d_ioctl = pci_iov_ioctl
};

#define IOV_READ(d, r, w) \
	pci_read_config((d)->cfg.dev, (d)->cfg.iov->iov_pos + r, w)

#define IOV_WRITE(d, r, v, w) \
	pci_write_config((d)->cfg.dev, (d)->cfg.iov->iov_pos + r, v, w)

int
pci_iov_attach_method(device_t bus, device_t dev)
{
	device_t pcib;
	struct pci_devinfo *dinfo;
	struct pcicfg_iov *iov;
	uint32_t version;
	int error;
	int iov_pos;

	dinfo = device_get_ivars(dev);
	pcib = device_get_parent(bus);
	
	error = pci_find_extcap(dev, PCIZ_SRIOV, &iov_pos);

	if (error != 0)
		return (error);

	version = pci_read_config(dev, iov_pos, 4); 
	if (PCI_EXTCAP_VER(version) != 1) {
		if (bootverbose)
			device_printf(dev, 
			    "Unsupported version of SR-IOV (%d) detected\n",
			    PCI_EXTCAP_VER(version));

		return (ENXIO);
	}

	iov = malloc(sizeof(*dinfo->cfg.iov), M_SRIOV, M_WAITOK | M_ZERO);

	mtx_lock(&Giant);
	if (dinfo->cfg.iov != NULL) {
		error = EBUSY;
		goto cleanup;
	}
	iov->iov_pos = iov_pos;

	iov->iov_cdev = make_dev(&iov_cdevsw, device_get_unit(dev),
	    UID_ROOT, GID_WHEEL, 0600, "iov/%s", device_get_nameunit(dev));

	if (iov->iov_cdev == NULL) {
		error = ENOMEM;
		goto cleanup;
	}
	
	dinfo->cfg.iov = iov;
	iov->iov_cdev->si_drv1 = dinfo;
	mtx_unlock(&Giant);

	return (0);

cleanup:
	free(iov, M_SRIOV);
	mtx_unlock(&Giant);
	return (error);
}

int
pci_iov_detach_method(device_t bus, device_t dev)
{
	struct pci_devinfo *dinfo;
	struct pcicfg_iov *iov;

	mtx_lock(&Giant);
	dinfo = device_get_ivars(dev);
	iov = dinfo->cfg.iov;

	if (iov == NULL) {
		mtx_unlock(&Giant);
		return (0);
	}

	if (iov->iov_num_vfs != 0) {
		mtx_unlock(&Giant);
		return (EBUSY);
	}

	dinfo->cfg.iov = NULL;

	if (iov->iov_cdev) {
		destroy_dev(iov->iov_cdev);
		iov->iov_cdev = NULL;
	}

	free(iov, M_SRIOV);
	mtx_unlock(&Giant);

	return (0);
}

static int
pci_iov_alloc_bar(struct pci_devinfo *dinfo, int bar, pci_addr_t bar_shift)
{
	struct resource *res;
	struct pcicfg_iov *iov;
	device_t dev, bus;
	u_long start, end;
	pci_addr_t bar_size;
	int rid;

	iov = dinfo->cfg.iov;
	dev = dinfo->cfg.dev;
	bus = device_get_parent(dev);
	rid = iov->iov_pos + PCIR_SRIOV_BAR(bar);
	bar_size = 1 << bar_shift;

	res = pci_alloc_multi_resource(bus, dev, SYS_RES_MEMORY, &rid, 0ul,
	    ~0ul, 1, iov->iov_num_vfs, RF_ACTIVE);

	if (res == NULL)
		return (ENXIO);

	iov->iov_bar[bar].res = res;
	iov->iov_bar[bar].bar_size = bar_size;
	iov->iov_bar[bar].bar_shift = bar_shift;

	start = rman_get_start(res);
	end = rman_get_end(res);
	return (rman_manage_region(&iov->rman, start, end));
}

static void
pci_iov_add_bars(struct pcicfg_iov *iov, struct pci_devinfo *dinfo)
{
	struct pci_iov_bar *bar;
	uint64_t bar_start;
	int i;

	for (i = 0; i <= PCIR_MAX_BAR_0; i++) {
		bar = &iov->iov_bar[i];
		if (bar->res != NULL) {
			bar_start = rman_get_start(bar->res) +
			    dinfo->cfg.vf.index * bar->bar_size;

			pci_add_bar(dinfo->cfg.dev, PCIR_BAR(i), bar_start,
			    bar->bar_shift);
		}
	}
}

/*
 * Set the ARI_EN bit in the lowest-numbered PCI function with the SR-IOV
 * capability.  This bit is only writeable on the lowest-numbered PF but
 * affects all PFs on the device.
 */
static int
pci_iov_set_ari(device_t bus)
{
	device_t lowest;
	device_t *devlist;
	int i, error, devcount, lowest_func, lowest_pos, iov_pos, dev_func;
	uint16_t iov_ctl;

	/* If ARI is disabled on the downstream port there is nothing to do. */
	if (!PCIB_ARI_ENABLED(device_get_parent(bus)))
		return (0);

	error = device_get_children(bus, &devlist, &devcount);

	if (error != 0)
		return (error);

	lowest = NULL;
	for (i = 0; i < devcount; i++) {
		if (pci_find_extcap(devlist[i], PCIZ_SRIOV, &iov_pos) == 0) {
			dev_func = pci_get_function(devlist[i]);
			if (lowest == NULL || dev_func < lowest_func) {
				lowest = devlist[i];
				lowest_func = dev_func;
				lowest_pos = iov_pos;
			}
		}
	}

	/*
	 * If we called this function some device must have the SR-IOV
	 * capability.
	 */
	KASSERT(lowest != NULL,
	    ("Could not find child of %s with SR-IOV capability",
	    device_get_nameunit(bus)));

	iov_ctl = pci_read_config(lowest, iov_pos + PCIR_SRIOV_CTL, 2);
	iov_ctl |= PCIM_SRIOV_ARI_EN;
	pci_write_config(lowest, iov_pos + PCIR_SRIOV_CTL, iov_ctl, 2);
	free(devlist, M_TEMP);
	return (0);
}

static int
pci_iov_config_page_size(struct pci_devinfo *dinfo)
{
	uint32_t page_cap, page_size;

	page_cap = IOV_READ(dinfo, PCIR_SRIOV_PAGE_CAP, 4);

	/*
	 * If the system page size is less than the smallest SR-IOV page size
	 * then round up to the smallest SR-IOV page size.
	 */
	if (PAGE_SHIFT < PCI_SRIOV_BASE_PAGE_SHIFT)
		page_size = (1 << 0);
	else
		page_size = (1 << (PAGE_SHIFT - PCI_SRIOV_BASE_PAGE_SHIFT));

	/* Check that the device supports the system page size. */
	if (!(page_size & page_cap))
		return (ENXIO);

	IOV_WRITE(dinfo, PCIR_SRIOV_PAGE_SIZE, page_size, 4);
	return (0);
}

static int
pci_iov_init_rman(device_t pf, struct pcicfg_iov *iov)
{
	int error;

	iov->rman.rm_start = 0;
	iov->rman.rm_end = ~0ul;
	iov->rman.rm_type = RMAN_ARRAY;
	snprintf(iov->rman_name, sizeof(iov->rman_name), "%s VF I/O memory",
	    device_get_nameunit(pf));
	iov->rman.rm_descr = iov->rman_name;

	error = rman_init(&iov->rman);
	if (error != 0)
		return (error);

	iov->iov_flags |= IOV_RMAN_INITED;
	return (0);
}

static int
pci_iov_setup_bars(struct pci_devinfo *dinfo)
{
	device_t dev;
	struct pcicfg_iov *iov;
	pci_addr_t bar_value, testval;
	int i, last_64, error;

	iov = dinfo->cfg.iov;
	dev = dinfo->cfg.dev;
	last_64 = 0;

	for (i = 0; i <= PCIR_MAX_BAR_0; i++) {
		/*
		 * If a PCI BAR is a 64-bit wide BAR, then it spans two
		 * consecutive registers.  Therefore if the last BAR that
		 * we looked at was a 64-bit BAR, we need to skip this
		 * register as it's the second half of the last BAR.
		 */
		if (!last_64) {
			pci_read_bar(dev,
			    iov->iov_pos + PCIR_SRIOV_BAR(i),
			    &bar_value, &testval, &last_64);

			if (testval != 0) {
				error = pci_iov_alloc_bar(dinfo, i,
				   pci_mapsize(testval));
				if (error != 0)
					return (error);
			}
		} else
			last_64 = 0;
	}

	return (0);
}

static void
pci_iov_enumerate_vfs(struct pci_devinfo *dinfo, const char *driver,
    uint16_t first_rid, uint16_t rid_stride)
{
	device_t bus, dev, vf;
	struct pcicfg_iov *iov;
	struct pci_devinfo *vfinfo;
	size_t size;
	int i, error;
	uint16_t vid, did, next_rid;

	iov = dinfo->cfg.iov;
	dev = dinfo->cfg.dev;
	bus = device_get_parent(dev);
	size = dinfo->cfg.devinfo_size;
	next_rid = first_rid;
	vid = pci_get_vendor(dev);
	did = IOV_READ(dinfo, PCIR_SRIOV_VF_DID, 2);

	for (i = 0; i < iov->iov_num_vfs; i++, next_rid += rid_stride) {


		vf = PCI_CREATE_IOV_CHILD(bus, dev, next_rid, vid, did);
		if (vf == NULL)
			break;

		vfinfo = device_get_ivars(vf);

		vfinfo->cfg.iov = iov;
		vfinfo->cfg.vf.index = i;

		pci_iov_add_bars(iov, vfinfo);

		error = PCI_ADD_VF(dev, i);
		if (error != 0) {
			device_printf(dev, "Failed to add VF %d\n", i);
			pci_delete_child(bus, vf);
		}
	}

	bus_generic_attach(bus);
}

static int
pci_iov_config(struct cdev *cdev, struct pci_iov_arg *arg)
{
	device_t bus, dev;
	const char *driver;
	struct pci_devinfo *dinfo;
	struct pcicfg_iov *iov;
	int i, error;
	uint16_t rid_off, rid_stride;
	uint16_t first_rid, last_rid;
	uint16_t iov_ctl;
	uint16_t total_vfs;
	int iov_inited;

	mtx_lock(&Giant);
	dinfo = cdev->si_drv1;
	iov = dinfo->cfg.iov;
	dev = dinfo->cfg.dev;
	bus = device_get_parent(dev);
	iov_inited = 0;

	if (iov->iov_num_vfs != 0) {
		mtx_unlock(&Giant);
		return (EBUSY);
	}

	total_vfs = IOV_READ(dinfo, PCIR_SRIOV_TOTAL_VFS, 2);

	if (arg->num_vfs > total_vfs) {
		error = EINVAL;
		goto out;
	}

	/*
	 * If we are creating passthrough devices then force the ppt driver to
	 * attach to prevent a VF driver from claming the VFs.
	 */
	if (arg->passthrough)
		driver = "ppt";
	else
		driver = NULL;

	error = pci_iov_config_page_size(dinfo);
	if (error != 0)
		goto out;

	error = pci_iov_set_ari(bus);
	if (error != 0)
		goto out;

	error = PCI_INIT_IOV(dev, arg->num_vfs);

	if (error != 0)
		goto out;

	iov_inited = 1;
	IOV_WRITE(dinfo, PCIR_SRIOV_NUM_VFS, arg->num_vfs, 2);

	rid_off = IOV_READ(dinfo, PCIR_SRIOV_VF_OFF, 2);
	rid_stride = IOV_READ(dinfo, PCIR_SRIOV_VF_STRIDE, 2);

	first_rid = pci_get_rid(dev) + rid_off;
	last_rid = first_rid + (arg->num_vfs - 1) * rid_stride;

	/* We don't yet support allocating extra bus numbers for VFs. */
	if (pci_get_bus(dev) != PCI_RID2BUS(last_rid)) {
		error = ENOSPC;
		goto out;
	}

	iov_ctl = IOV_READ(dinfo, PCIR_SRIOV_CTL, 2);
	iov_ctl &= ~(PCIM_SRIOV_VF_EN | PCIM_SRIOV_VF_MSE);
	IOV_WRITE(dinfo, PCIR_SRIOV_CTL, iov_ctl, 2);

	error = pci_iov_init_rman(dev, iov);
	if (error != 0)
		goto out;

	iov->iov_num_vfs = arg->num_vfs;

	error = pci_iov_setup_bars(dinfo);
	if (error != 0)
		goto out;

	iov_ctl = IOV_READ(dinfo, PCIR_SRIOV_CTL, 2);
	iov_ctl |= PCIM_SRIOV_VF_EN | PCIM_SRIOV_VF_MSE;
	IOV_WRITE(dinfo, PCIR_SRIOV_CTL, iov_ctl, 2);

	/* Per specification, we must wait 100ms before accessing VFs. */
	pause("iov", roundup(hz, 10));
	pci_iov_enumerate_vfs(dinfo, driver, first_rid, rid_stride);
	mtx_unlock(&Giant);

	return (0);
out:
	if (iov_inited)
		PCI_UNINIT_IOV(dev);

	for (i = 0; i <= PCIR_MAX_BAR_0; i++) {
		if (iov->iov_bar[i].res != NULL) {
			pci_release_resource(bus, dev, SYS_RES_MEMORY,
			    iov->iov_pos + PCIR_SRIOV_BAR(i),
			    iov->iov_bar[i].res);
			pci_delete_resource(bus, dev, SYS_RES_MEMORY,
			    iov->iov_pos + PCIR_SRIOV_BAR(i));
			iov->iov_bar[i].res = NULL;
		}
	}

	if (iov->iov_flags & IOV_RMAN_INITED) {
		rman_fini(&iov->rman);
		iov->iov_flags &= ~IOV_RMAN_INITED;
	}
	iov->iov_num_vfs = 0;
	mtx_unlock(&Giant);
	return (error);
}

static int
pci_iov_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{

	switch (cmd) {
	case IOV_CONFIG:
		return (pci_iov_config(dev, (struct pci_iov_arg *)data));
	default:
		return (EINVAL);
	}
}

struct resource *
pci_vf_alloc_mem_resource(device_t dev, device_t child, int *rid, u_long start,
    u_long end, u_long count, u_int flags)
{
	struct pci_devinfo *dinfo;
	struct pcicfg_iov *iov;
	struct pci_map *map;
	struct resource *res;
	struct resource_list_entry *rle;
	u_long bar_start, bar_end;
	pci_addr_t bar_length;
	int error;

	dinfo = device_get_ivars(child);
	iov = dinfo->cfg.iov;

	map = pci_find_bar(child, *rid);
	if (map == NULL)
		return (NULL);

	bar_length = 1 << map->pm_size;
	bar_start = map->pm_value;
	bar_end = bar_start + bar_length - 1;

	/* Make sure that the resource fits the constraints. */
	if (bar_start >= end || bar_end <= bar_start || count != 1)
		return (NULL);

	/* Clamp the resource to the constraints if necessary. */
	if (bar_start < start)
		bar_start = start;
	if (bar_end > end)
		bar_end = end;
	bar_length = bar_end - bar_start + 1;

	res = rman_reserve_resource(&iov->rman, bar_start, bar_end,
	    bar_length, flags, child);
	if (res == NULL)
		return (NULL);

	rle = resource_list_add(&dinfo->resources, SYS_RES_MEMORY, *rid,
	    bar_start, bar_end, 1);
	if (rle == NULL) {
		rman_release_resource(res);
		return (NULL);
	}

	rman_set_rid(res, *rid);

	if (flags & RF_ACTIVE) {
		error = bus_activate_resource(child, SYS_RES_MEMORY, *rid, res);
		if (error != 0) {
			resource_list_delete(&dinfo->resources, SYS_RES_MEMORY,
			    *rid);
			rman_release_resource(res);
			return (NULL);
		}
	}
	rle->res = res;

	return (res);
}

int
pci_vf_release_mem_resource(device_t dev, device_t child, int rid,
    struct resource *r)
{
	struct pci_devinfo *dinfo;
	struct resource_list_entry *rle;
	int error;

	dinfo = device_get_ivars(child);

	if (rman_get_flags(r) & RF_ACTIVE) {
		error = bus_deactivate_resource(child, SYS_RES_MEMORY, rid, r);
		if (error != 0)
			return (error);
	}

	rle = resource_list_find(&dinfo->resources, SYS_RES_MEMORY, rid);
	if (rle != NULL) {
		rle->res = NULL;
		resource_list_delete(&dinfo->resources, SYS_RES_MEMORY,
		    rid);
	}

	return (rman_release_resource(r));
}

