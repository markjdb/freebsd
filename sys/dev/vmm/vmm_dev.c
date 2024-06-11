/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * Copyright (C) 2015 Mihai Carabas <mihai.carabas@gmail.com>
 * All rights reserved.
 */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/uio.h>

#include <machine/vmm.h>
#include <machine/vmm_dev.h>

#include <vm/vm.h>
#include <vm/vm_object.h>

struct devmem_softc {
	int	segid;
	char	*name;
	struct cdev *cdev;
	struct vmmdev_softc *sc;
	SLIST_ENTRY(devmem_softc) link;
};

struct vmmdev_softc {
	struct vm	*vm;		/* vm instance cookie */
	struct cdev	*cdev;
	struct ucred	*ucred;
	SLIST_ENTRY(vmmdev_softc) link;
	SLIST_HEAD(, devmem_softc) devmem;
	int		flags;
};
#define	VSC_LINKED		0x01

static SLIST_HEAD(, vmmdev_softc) head;

static unsigned pr_allow_flag;
static struct mtx vmmdev_mtx;
MTX_SYSINIT(vmmdev_mtx, &vmmdev_mtx, "vmm device mutex", MTX_DEF);

static MALLOC_DEFINE(M_VMMDEV, "vmmdev", "vmmdev");

SYSCTL_DECL(_hw_vmm);

static void devmem_destroy(void *arg);

static int
vmm_priv_check(struct ucred *ucred)
{
	if (jailed(ucred) &&
	    !(ucred->cr_prison->pr_allow & pr_allow_flag))
		return (EPERM);

	return (0);
}

static int
vcpu_lock_one(struct vcpu *vcpu)
{
	return (vcpu_set_state(vcpu, VCPU_FROZEN, true));
}

static void
vcpu_unlock_one(struct vcpu *vcpu)
{
	enum vcpu_state state;

	state = vcpu_get_state(vcpu, NULL);
	if (state != VCPU_FROZEN) {
		panic("vcpu %s(%d) has invalid state %d",
		    vm_name(vcpu_vm(vcpu)), vcpu_vcpuid(vcpu), state);
	}

	vcpu_set_state(vcpu, VCPU_IDLE, false);
}

static int
vcpu_lock_all(struct vmmdev_softc *sc)
{
	struct vcpu *vcpu;
	int error;
	uint16_t i, j, maxcpus;

	error = 0;
	vm_slock_vcpus(sc->vm);
	maxcpus = vm_get_maxcpus(sc->vm);
	for (i = 0; i < maxcpus; i++) {
		vcpu = vm_vcpu(sc->vm, i);
		if (vcpu == NULL)
			continue;
		error = vcpu_lock_one(vcpu);
		if (error)
			break;
	}

	if (error) {
		for (j = 0; j < i; j++) {
			vcpu = vm_vcpu(sc->vm, j);
			if (vcpu == NULL)
				continue;
			vcpu_unlock_one(vcpu);
		}
		vm_unlock_vcpus(sc->vm);
	}

	return (error);
}

static void
vcpu_unlock_all(struct vmmdev_softc *sc)
{
	struct vcpu *vcpu;
	uint16_t i, maxcpus;

	maxcpus = vm_get_maxcpus(sc->vm);
	for (i = 0; i < maxcpus; i++) {
		vcpu = vm_vcpu(sc->vm, i);
		if (vcpu == NULL)
			continue;
		vcpu_unlock_one(vcpu);
	}
	vm_unlock_vcpus(sc->vm);
}

static struct vmmdev_softc *
vmmdev_lookup(const char *name)
{
	struct vmmdev_softc *sc;

#ifdef notyet	/* XXX kernel is not compiled with invariants */
	mtx_assert(&vmmdev_mtx, MA_OWNED);
#endif

	SLIST_FOREACH(sc, &head, link) {
		if (strcmp(name, vm_name(sc->vm)) == 0)
			break;
	}

	if (sc == NULL)
		return (NULL);

	if (cr_cansee(curthread->td_ucred, sc->ucred))
		return (NULL);

	return (sc);
}

static struct vmmdev_softc *
vmmdev_lookup2(struct cdev *cdev)
{
	return (cdev->si_drv1);
}

static int
vmmdev_rw(struct cdev *cdev, struct uio *uio, int flags)
{
	int error, off, c, prot;
	vm_paddr_t gpa, maxaddr;
	void *hpa, *cookie;
	struct vmmdev_softc *sc;

	error = vmm_priv_check(curthread->td_ucred);
	if (error)
		return (error);

	sc = vmmdev_lookup2(cdev);
	if (sc == NULL)
		return (ENXIO);

	/*
	 * Get a read lock on the guest memory map.
	 */
	vm_slock_memsegs(sc->vm);

	prot = (uio->uio_rw == UIO_WRITE ? VM_PROT_WRITE : VM_PROT_READ);
	maxaddr = vmm_sysmem_maxaddr(sc->vm);
	while (uio->uio_resid > 0 && error == 0) {
		gpa = uio->uio_offset;
		off = gpa & PAGE_MASK;
		c = min(uio->uio_resid, PAGE_SIZE - off);

		/*
		 * The VM has a hole in its physical memory map. If we want to
		 * use 'dd' to inspect memory beyond the hole we need to
		 * provide bogus data for memory that lies in the hole.
		 *
		 * Since this device does not support lseek(2), dd(1) will
		 * read(2) blocks of data to simulate the lseek(2).
		 */
		hpa = vm_gpa_hold_global(sc->vm, gpa, c, prot, &cookie);
		if (hpa == NULL) {
			if (uio->uio_rw == UIO_READ && gpa < maxaddr)
				error = uiomove(__DECONST(void *, zero_region),
				    c, uio);
			else
				error = EFAULT;
		} else {
			error = uiomove(hpa, c, uio);
			vm_gpa_release(cookie);
		}
	}
	vm_unlock_memsegs(sc->vm);
	return (error);
}

static int
vmmdev_ioctl(struct cdev *cdev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	return (0);
}

static int
vmmdev_mmap_single(struct cdev *cdev, vm_ooffset_t *offset, vm_size_t mapsize,
    struct vm_object **objp, int nprot)
{
	struct vmmdev_softc *sc;
	vm_paddr_t gpa;
	size_t len;
	vm_ooffset_t segoff, first, last;
	int error, found, segid;
	bool sysmem;

	error = vmm_priv_check(curthread->td_ucred);
	if (error)
		return (error);

	first = *offset;
	last = first + mapsize;
	if ((nprot & PROT_EXEC) || first < 0 || first >= last)
		return (EINVAL);

	sc = vmmdev_lookup2(cdev);
	if (sc == NULL) {
		/* virtual machine is in the process of being created */
		return (EINVAL);
	}

	/*
	 * Get a read lock on the guest memory map.
	 */
	vm_slock_memsegs(sc->vm);

	gpa = 0;
	found = 0;
	while (!found) {
		error = vm_mmap_getnext(sc->vm, &gpa, &segid, &segoff, &len,
		    NULL, NULL);
		if (error)
			break;

		if (first >= gpa && last <= gpa + len)
			found = 1;
		else
			gpa += len;
	}

	if (found) {
		error = vm_get_memseg(sc->vm, segid, &len, &sysmem, objp);
		KASSERT(error == 0 && *objp != NULL,
		    ("%s: invalid memory segment %d", __func__, segid));
		if (sysmem) {
			vm_object_reference(*objp);
			*offset = segoff + (first - gpa);
		} else {
			error = EINVAL;
		}
	}
	vm_unlock_memsegs(sc->vm);
	return (error);
}

static void
vmmdev_destroy(void *arg)
{
	struct vmmdev_softc *sc = arg;
	struct devmem_softc *dsc;
	int error __diagused;

	vm_disable_vcpu_creation(sc->vm);
	error = vcpu_lock_all(sc);
	KASSERT(error == 0, ("%s: error %d freezing vcpus", __func__, error));
	vm_unlock_vcpus(sc->vm);

	while ((dsc = SLIST_FIRST(&sc->devmem)) != NULL) {
		KASSERT(dsc->cdev == NULL, ("%s: devmem not free", __func__));
		SLIST_REMOVE_HEAD(&sc->devmem, link);
		free(dsc->name, M_VMMDEV);
		free(dsc, M_VMMDEV);
	}

	if (sc->cdev != NULL)
		destroy_dev(sc->cdev);

	if (sc->vm != NULL)
		vm_destroy(sc->vm);

	if (sc->ucred != NULL)
		crfree(sc->ucred);

	if ((sc->flags & VSC_LINKED) != 0) {
		mtx_lock(&vmmdev_mtx);
		SLIST_REMOVE(&head, sc, vmmdev_softc, link);
		mtx_unlock(&vmmdev_mtx);
	}

	free(sc, M_VMMDEV);
}


static int
sysctl_vmm_destroy(SYSCTL_HANDLER_ARGS)
{
	struct devmem_softc *dsc;
	struct vmmdev_softc *sc;
	struct cdev *cdev;
	char *buf;
	int error, buflen;

	error = vmm_priv_check(req->td->td_ucred);
	if (error)
		return (error);

	buflen = VM_MAX_NAMELEN + 1;
	buf = malloc(buflen, M_VMMDEV, M_WAITOK | M_ZERO);
	strlcpy(buf, "beavis", buflen);
	error = sysctl_handle_string(oidp, buf, buflen, req);
	if (error != 0 || req->newptr == NULL)
		goto out;

	mtx_lock(&vmmdev_mtx);
	sc = vmmdev_lookup(buf);
	if (sc == NULL || sc->cdev == NULL) {
		mtx_unlock(&vmmdev_mtx);
		error = EINVAL;
		goto out;
	}

	/*
	 * Setting 'sc->cdev' to NULL is used to indicate that the VM
	 * is scheduled for destruction.
	 */
	cdev = sc->cdev;
	sc->cdev = NULL;
	mtx_unlock(&vmmdev_mtx);

	/*
	 * Destroy all cdevs:
	 *
	 * - any new operations on the 'cdev' will return an error (ENXIO).
	 *
	 * - the 'devmem' cdevs are destroyed before the virtual machine 'cdev'
	 */
	SLIST_FOREACH(dsc, &sc->devmem, link) {
		KASSERT(dsc->cdev != NULL, ("devmem cdev already destroyed"));
		destroy_dev(dsc->cdev);
		devmem_destroy(dsc);
	}
	destroy_dev(cdev);
	vmmdev_destroy(sc);
	error = 0;

out:
	free(buf, M_VMMDEV);
	return (error);
}
SYSCTL_PROC(_hw_vmm, OID_AUTO, destroy,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_PRISON | CTLFLAG_MPSAFE,
    NULL, 0, sysctl_vmm_destroy, "A",
    NULL);

static struct cdevsw vmmdevsw = {
	.d_name		= "vmmdev",
	.d_version	= D_VERSION,
	.d_ioctl	= vmmdev_ioctl,
	.d_mmap_single	= vmmdev_mmap_single,
	.d_read		= vmmdev_rw,
	.d_write	= vmmdev_rw,
};

static int
sysctl_vmm_create(SYSCTL_HANDLER_ARGS)
{
	struct vm *vm;
	struct cdev *cdev;
	struct vmmdev_softc *sc, *sc2;
	char *buf;
	int error, buflen;

	error = vmm_priv_check(req->td->td_ucred);
	if (error)
		return (error);

	buflen = VM_MAX_NAMELEN + 1;
	buf = malloc(buflen, M_VMMDEV, M_WAITOK | M_ZERO);
	strlcpy(buf, "beavis", buflen);
	error = sysctl_handle_string(oidp, buf, buflen, req);
	if (error != 0 || req->newptr == NULL)
		goto out;

	mtx_lock(&vmmdev_mtx);
	sc = vmmdev_lookup(buf);
	mtx_unlock(&vmmdev_mtx);
	if (sc != NULL) {
		error = EEXIST;
		goto out;
	}

	error = vm_create(buf, &vm);
	if (error != 0)
		goto out;

	sc = malloc(sizeof(struct vmmdev_softc), M_VMMDEV, M_WAITOK | M_ZERO);
	sc->ucred = crhold(curthread->td_ucred);
	sc->vm = vm;
	SLIST_INIT(&sc->devmem);

	/*
	 * Lookup the name again just in case somebody sneaked in when we
	 * dropped the lock.
	 */
	mtx_lock(&vmmdev_mtx);
	sc2 = vmmdev_lookup(buf);
	if (sc2 == NULL) {
		SLIST_INSERT_HEAD(&head, sc, link);
		sc->flags |= VSC_LINKED;
	}
	mtx_unlock(&vmmdev_mtx);

	if (sc2 != NULL) {
		vmmdev_destroy(sc);
		error = EEXIST;
		goto out;
	}

	error = make_dev_p(MAKEDEV_CHECKNAME, &cdev, &vmmdevsw, sc->ucred,
	    UID_ROOT, GID_WHEEL, 0600, "vmm/%s", buf);
	if (error != 0) {
		vmmdev_destroy(sc);
		goto out;
	}

	mtx_lock(&vmmdev_mtx);
	sc->cdev = cdev;
	sc->cdev->si_drv1 = sc;
	mtx_unlock(&vmmdev_mtx);

out:
	free(buf, M_VMMDEV);
	return (error);
}
SYSCTL_PROC(_hw_vmm, OID_AUTO, create,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_PRISON | CTLFLAG_MPSAFE,
    NULL, 0, sysctl_vmm_create, "A",
    NULL);

void
vmmdev_init(void)
{
	pr_allow_flag = prison_add_allow(NULL, "vmm", NULL,
	    "Allow use of vmm in a jail.");
}

int
vmmdev_cleanup(void)
{
	int error;

	if (SLIST_EMPTY(&head))
		error = 0;
	else
		error = EBUSY;

	return (error);
}

static int
devmem_mmap_single(struct cdev *cdev, vm_ooffset_t *offset, vm_size_t len,
    struct vm_object **objp, int nprot)
{
	struct devmem_softc *dsc;
	vm_ooffset_t first, last;
	size_t seglen;
	int error;
	bool sysmem;

	dsc = cdev->si_drv1;
	if (dsc == NULL) {
		/* 'cdev' has been created but is not ready for use */
		return (ENXIO);
	}

	first = *offset;
	last = *offset + len;
	if ((nprot & PROT_EXEC) || first < 0 || first >= last)
		return (EINVAL);

	vm_slock_memsegs(dsc->sc->vm);

	error = vm_get_memseg(dsc->sc->vm, dsc->segid, &seglen, &sysmem, objp);
	KASSERT(error == 0 && !sysmem && *objp != NULL,
	    ("%s: invalid devmem segment %d", __func__, dsc->segid));

	if (seglen >= last)
		vm_object_reference(*objp);
	else
		error = EINVAL;

	vm_unlock_memsegs(dsc->sc->vm);
	return (error);
}

static struct cdevsw devmemsw = {
	.d_name		= "devmem",
	.d_version	= D_VERSION,
	.d_mmap_single	= devmem_mmap_single,
};

static int
devmem_create_cdev(const char *vmname, int segid, char *devname)
{
	struct devmem_softc *dsc;
	struct vmmdev_softc *sc;
	struct cdev *cdev;
	int error;

	error = make_dev_p(MAKEDEV_CHECKNAME, &cdev, &devmemsw, NULL,
	    UID_ROOT, GID_WHEEL, 0600, "vmm.io/%s.%s", vmname, devname);
	if (error)
		return (error);

	dsc = malloc(sizeof(struct devmem_softc), M_VMMDEV, M_WAITOK | M_ZERO);

	mtx_lock(&vmmdev_mtx);
	sc = vmmdev_lookup(vmname);
	KASSERT(sc != NULL, ("%s: vm %s softc not found", __func__, vmname));
	if (sc->cdev == NULL) {
		/* virtual machine is being created or destroyed */
		mtx_unlock(&vmmdev_mtx);
		free(dsc, M_VMMDEV);
		destroy_dev_sched_cb(cdev, NULL, 0);
		return (ENODEV);
	}

	dsc->segid = segid;
	dsc->name = devname;
	dsc->cdev = cdev;
	dsc->sc = sc;
	SLIST_INSERT_HEAD(&sc->devmem, dsc, link);
	mtx_unlock(&vmmdev_mtx);

	/* The 'cdev' is ready for use after 'si_drv1' is initialized */
	cdev->si_drv1 = dsc;
	return (0);
}

static void
devmem_destroy(void *arg)
{
	struct devmem_softc *dsc = arg;

	KASSERT(dsc->cdev, ("%s: devmem cdev already destroyed", __func__));
	dsc->cdev = NULL;
	dsc->sc = NULL;
}
