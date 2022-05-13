/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2022 The FreeBSD Foundation
 *
 * This software was developed by Mark Johnston under sponsorship from
 * the FreeBSD Foundation.
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
#include <sys/dirent.h>
#include <sys/endian.h>
#include <sys/queue.h>

#include <assert.h>
#include <bitstring.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <util.h>

#include "makefs.h"
#include "zfs/nvlist.h"
#include "zfs/zfsimpl.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#include "fletcher.c"
#include "sha256.c"
#pragma clang diagnostic pop

/*
 * XXX-MJ
 * - support for multiple filesystems
 * - documentation
 * - review checksum algorithm selection (most should likely be "inherit"?)
 * - review vdev_space_alloc()
 * - review type usage (off_t vs. size_t vs. uint64_t)
 * - inconsistency in variable/field naming (how to name a dnode vs dnode id)
 */

#define	MAXBLOCKSIZE		((off_t)SPA_OLDMAXBLOCKSIZE)	/* 128KB */
#define	MAXBLOCKSHIFT		17
#define	MINBLOCKSHIFT		9
/*
 * XXX-MJ this might wrong but I don't understand where DN_MAX_LEVELS' definition
 * comes from.  Be sure to test with large files...
 */
#define	INDIR_LEVELS		6
#define	BLKPTR_PER_INDIR	(MAXBLOCKSIZE / sizeof(blkptr_t))

#define	VDEV_LABEL_SPACE	\
	((off_t)(VDEV_LABEL_START_SIZE + VDEV_LABEL_END_SIZE))

typedef struct {
	const char	*name;
	unsigned int	id;
	uint16_t	size;
	sa_bswap_type_t	bs;
} zfs_sattr_t;

typedef struct zfs_objset {
	objset_phys_t	*osphys;
	off_t		osloc;
	off_t		osblksz;
	blkptr_t	osbp;		/* set in objset_write() */

	off_t		space;		/* bytes allocated to this objset */

	dnode_phys_t	*dnodes;	/* dnode array */
	uint64_t	dnodenextfree;	/* dnode ID bump allocator */
	uint64_t	dnodecount;	/* total number of dnodes */
	off_t		dnodeloc;	/* preallocated vdev space */

	STAILQ_HEAD(, zfs_objset) children;	/* child datasets */
} zfs_objset_t;

typedef struct zfs_zap_entry {
	char		*name;
	union {
		uint8_t	 *valp;
		uint16_t *val16p;
		uint32_t *val32p;
		uint64_t *val64p;
	};
	uint64_t	val64;		/* embedded value for a common case */
	uint64_t	hash;
	size_t		intsz;
	size_t		intcnt;
	STAILQ_ENTRY(zfs_zap_entry) next;
} zfs_zap_entry_t;

typedef struct zfs_zap {
	STAILQ_HEAD(, zfs_zap_entry) kvps;
	uint64_t	hashsalt;
	unsigned long	kvpcnt;	/* number of key-value pairs */
	unsigned long	chunks;	/* count of chunks needed for fat ZAP */
	bool		micro;	/* can this be a micro ZAP? */

	dnode_phys_t	*dnode;
	zfs_objset_t	*os;
} zfs_zap_t;

typedef struct zfs_dsl_dir {
	zfs_objset_t	*heados;
	STAILQ_HEAD(, zfs_dsl_dir) children;
} zfs_dsl_dir_t;

typedef struct {
	zfs_objset_t	os;

	/* Offset table for system attributes, indexed by a zpl_attr_t. */
	const zfs_sattr_t *satab;
	size_t		sacnt;
	uint16_t	*saoffs;
} zfs_fs_t;

typedef struct {
	/* I/O buffer, just for convenience. */
	char		filebuf[MAXBLOCKSIZE];

	/* Pool parameters. */
	const char	*poolname;
	const char	*mountpoint;	/* root mountpoint */
	int		ashift;		/* vdev block size */

	/* Pool state. */
	uint64_t	guid;		/* pool and vdev GUID */

	/* MOS state. */
	zfs_objset_t	mos;		/* meta object set */
	uint64_t	objarrid;	/* space map object array */

	/* DSL state. */
	uint64_t	rootdsldirid;	/* root DSL directory object */
	zfs_fs_t	rootfs;		/* root dataset */

	/* vdev state. */
	int		fd;		/* vdev disk fd */
	off_t		vdevsize;	/* vdev size, including labels */
	off_t		asize;		/* vdev size, excluding labels */
	bitstr_t	*spacemap;	/* space allocator */
	int		spacemapbits;	/* one bit per ashift-sized block */
	uint64_t	msshift;	/* metaslab size */
	uint64_t	mscount;	/* number of metaslabs for this vdev */
} zfs_opt_t;

static void zap_init(zfs_zap_t *, zfs_objset_t *, dnode_phys_t *);
static void zap_add_uint64(zfs_zap_t *, const char *, uint64_t);
static void zap_add_string(zfs_zap_t *, const char *, const char *);
static void zap_write(zfs_opt_t *, zfs_zap_t *);

static dnode_phys_t *objset_dnode_lookup(zfs_objset_t *, uint64_t);
static dnode_phys_t *objset_dnode_alloc(zfs_objset_t *, uint8_t, uint64_t *);
static dnode_phys_t *objset_dnode_bonus_alloc(zfs_objset_t *, uint8_t, uint8_t,
    uint16_t, uint64_t *);
static off_t objset_space_alloc(zfs_opt_t *, zfs_objset_t *, off_t *);

static void spacemap_init(zfs_opt_t *);

struct dnode_cursor {
	char		inddir[INDIR_LEVELS][MAXBLOCKSIZE];
	off_t		indloc;
	off_t		indspace;
	dnode_phys_t	*dnode;
	off_t		dataoff;
	off_t		datablksz;
};

static struct dnode_cursor *dnode_cursor_init(zfs_opt_t *, zfs_objset_t *,
    dnode_phys_t *, off_t, off_t);
static blkptr_t *dnode_cursor_next(zfs_opt_t *, struct dnode_cursor *,
    off_t);
static void dnode_cursor_finish(zfs_opt_t *, struct dnode_cursor *);

static off_t vdev_space_alloc(zfs_opt_t *, off_t *);

/*
 * The order of the attributes doesn't matter, this is simply the one hard-coded
 * by OpenZFS, based on a zdb dump of the SA_REGISTRY table.
 */
typedef enum zpl_attr {
	ZPL_ATIME,
	ZPL_MTIME,
	ZPL_CTIME,
	ZPL_CRTIME,
	ZPL_GEN,
	ZPL_MODE,
	ZPL_SIZE,
	ZPL_PARENT,
	ZPL_LINKS,
	ZPL_XATTR,
	ZPL_RDEV,
	ZPL_FLAGS,
	ZPL_UID,
	ZPL_GID,
	ZPL_PAD,
	ZPL_ZNODE_ACL,
	ZPL_DACL_COUNT,
	ZPL_SYMLINK,
	ZPL_SCANSTAMP,
	ZPL_DACL_ACES,
	ZPL_DXATTR,
	ZPL_PROJID,
} zpl_attr_t;

/*
 * This table must be kept in sync with zpl_attr_layout[] and zpl_attr_t.
 */
static const zfs_sattr_t zpl_attrs[] = {
#define	_ZPL_ATTR(n, s, b)	{ .name = #n, .id = n, .size = s, .bs = b }
	_ZPL_ATTR(ZPL_ATIME, sizeof(uint64_t) * 2, SA_UINT64_ARRAY),
	_ZPL_ATTR(ZPL_MTIME, sizeof(uint64_t) * 2, SA_UINT64_ARRAY),
	_ZPL_ATTR(ZPL_CTIME, sizeof(uint64_t) * 2, SA_UINT64_ARRAY),
	_ZPL_ATTR(ZPL_CRTIME, sizeof(uint64_t) * 2, SA_UINT64_ARRAY),
	_ZPL_ATTR(ZPL_GEN, sizeof(uint64_t), SA_UINT64_ARRAY),
	_ZPL_ATTR(ZPL_MODE, sizeof(uint64_t), SA_UINT64_ARRAY),
	_ZPL_ATTR(ZPL_SIZE, sizeof(uint64_t), SA_UINT64_ARRAY),
	_ZPL_ATTR(ZPL_PARENT, sizeof(uint64_t), SA_UINT64_ARRAY),
	_ZPL_ATTR(ZPL_LINKS, sizeof(uint64_t), SA_UINT64_ARRAY),
	_ZPL_ATTR(ZPL_XATTR, sizeof(uint64_t), SA_UINT64_ARRAY),
	_ZPL_ATTR(ZPL_RDEV, sizeof(uint64_t), SA_UINT64_ARRAY),
	_ZPL_ATTR(ZPL_FLAGS, sizeof(uint64_t), SA_UINT64_ARRAY),
	_ZPL_ATTR(ZPL_UID, sizeof(uint64_t), SA_UINT64_ARRAY),
	_ZPL_ATTR(ZPL_GID, sizeof(uint64_t), SA_UINT64_ARRAY),
	_ZPL_ATTR(ZPL_PAD, sizeof(uint64_t), SA_UINT64_ARRAY),
	_ZPL_ATTR(ZPL_ZNODE_ACL, 88, SA_UINT64_ARRAY),
	_ZPL_ATTR(ZPL_DACL_COUNT, sizeof(uint64_t), SA_UINT64_ARRAY),
	_ZPL_ATTR(ZPL_SYMLINK, 0, SA_UINT8_ARRAY),
	_ZPL_ATTR(ZPL_SCANSTAMP, sizeof(uint64_t) * 4, SA_UINT8_ARRAY),
	_ZPL_ATTR(ZPL_DACL_ACES, 0, SA_ACL),
	_ZPL_ATTR(ZPL_DXATTR, 0, SA_UINT8_ARRAY),
	_ZPL_ATTR(ZPL_PROJID, sizeof(uint64_t), SA_UINT64_ARRAY),
#undef ZPL_ATTR
};

#define	ZPL_ATTR_LAYOUT		\
	ZPL_MODE,		\
	ZPL_SIZE,		\
	ZPL_GEN,		\
	ZPL_UID,		\
	ZPL_GID,		\
	ZPL_PARENT,		\
	ZPL_FLAGS,		\
	ZPL_ATIME,		\
	ZPL_MTIME,		\
	ZPL_CTIME,		\
	ZPL_CRTIME,		\
	ZPL_LINKS,		\
	ZPL_DACL_COUNT,		\
	ZPL_DACL_ACES

/*
 * This layout matches that of a filesystem created using OpenZFS on FreeBSD.
 */
static const sa_attr_type_t zpl_attr_layout[] = {
	ZPL_MODE,
	ZPL_SIZE,
	ZPL_GEN,
	ZPL_UID,
	ZPL_GID,
	ZPL_PARENT,
	ZPL_FLAGS,
	ZPL_ATIME,
	ZPL_MTIME,
	ZPL_CTIME,
	ZPL_CRTIME,
	ZPL_LINKS,
	ZPL_DACL_COUNT,
	ZPL_DACL_ACES,
	ZPL_SYMLINK,
};

/*
 * Keys for the ZPL attribute tables in the layout ZAP.  The first two indices
 * are reserved for legacy attribute encoding.
 */
#define	SA_LAYOUT_INDEX		2
#define	SA_LAYOUT_INDEX_SYMLINK	3

void
zfs_prep_opts(fsinfo_t *fsopts)
{
	zfs_opt_t *zfs = ecalloc(1, sizeof(*zfs));

	const option_t zfs_options[] = {
		{ '\0', "poolname", &zfs->poolname, OPT_STRPTR,
		  0, 0, "ZFS pool name" },
		{ '\0', "mountpoint", &zfs->mountpoint, OPT_STRPTR,
		  0, 0, "ZFS root dataset mount point" },
		{ '\0', "ashift", &zfs->ashift, OPT_INT32,
		  MINBLOCKSHIFT, MAXBLOCKSHIFT, "ZFS pool ashift" },
		{ .name = NULL }
	};

	/* Set some default values. */
	zfs->ashift = 12;

	fsopts->fs_specific = zfs;
	fsopts->fs_options = copy_opts(zfs_options);
}

int
zfs_parse_opts(const char *option, fsinfo_t *fsopts)
{
	char buf[BUFSIZ];
	option_t *zfs_options;
	int rv;

	zfs_options = fsopts->fs_options;

	rv = set_option(zfs_options, option, buf, sizeof(buf));
	if (rv == -1)
		return (0);
	return (1);
}

void
zfs_cleanup_opts(fsinfo_t *fsopts)
{
	zfs_opt_t *zfs;

	zfs = fsopts->fs_specific;
	free(__DECONST(void *, zfs->poolname));

	free(fsopts->fs_specific);
	free(fsopts->fs_options);
}

static size_t
nvlist_size(const nvlist_t *nvl)
{
	return (sizeof(nvl->nv_header) + nvl->nv_size);
}

static void
nvlist_copy(const nvlist_t *nvl, char *buf, size_t sz)
{
	assert(sz >= nvlist_size(nvl));

	memcpy(buf, &nvl->nv_header, sizeof(nvl->nv_header));
	memcpy(buf + sizeof(nvl->nv_header), nvl->nv_data, nvl->nv_size);
}

static void
blkptr_set_level(blkptr_t *bp, off_t off, off_t size, uint8_t dntype,
    uint8_t level, uint64_t fill, enum zio_checksum cksumt, zio_cksum_t *cksum)
{
	dva_t *dva;

	assert(powerof2(size));

	BP_ZERO(bp);
	BP_SET_LSIZE(bp, size);
	BP_SET_PSIZE(bp, size);
	BP_SET_CHECKSUM(bp, cksumt);
	BP_SET_COMPRESS(bp, ZIO_COMPRESS_OFF);
	BP_SET_BYTEORDER(bp, ZFS_HOST_BYTEORDER);
	BP_SET_BIRTH(bp, TXG_INITIAL, TXG_INITIAL);
	BP_SET_LEVEL(bp, level);
	BP_SET_FILL(bp, fill);
	BP_SET_TYPE(bp, dntype);

	dva = BP_IDENTITY(bp);
	DVA_SET_VDEV(dva, 0);
	DVA_SET_OFFSET(dva, off);
	DVA_SET_ASIZE(dva, size);
	memcpy(&bp->blk_cksum, cksum, sizeof(*cksum));
}

static void
blkptr_set(blkptr_t *bp, off_t off, off_t size, uint8_t dntype,
    enum zio_checksum cksumt, zio_cksum_t *cksum)
{
	blkptr_set_level(bp, off, size, dntype, 0, 1, cksumt, cksum);
}

static void
vdev_init(zfs_opt_t *zfs, size_t size, const char *image)
{
	int oflags;

	oflags = O_RDWR | O_CREAT | O_TRUNC;

	assert(zfs->ashift >= MINBLOCKSHIFT);
	zfs->vdevsize = rounddown2(size, 1 << zfs->ashift);
	if (zfs->vdevsize < (off_t)SPA_MINDEVSIZE) {
		errx(1, "Maximum image size %ju is too small",
		    (uintmax_t)zfs->vdevsize);
	}
	zfs->asize = zfs->vdevsize - VDEV_LABEL_SPACE;

	zfs->fd = open(image, oflags, 0644);
	if (zfs->fd == -1)
		err(1, "Can't open `%s' for writing", image);
	if (ftruncate(zfs->fd, zfs->vdevsize) != 0)
		err(1, "Failed to extend image file `%s'", image);

	spacemap_init(zfs);
}

static void
vdev_fini(zfs_opt_t *zfs)
{
	assert(zfs->spacemap == NULL);

	if (zfs->fd != -1) {
		(void)close(zfs->fd);
		zfs->fd = -1;
	}
}

static void
vdev_pwrite(const zfs_opt_t *zfs, const void *buf, size_t len, off_t off)
{
	ssize_t n;

	assert(off >= 0 && off < zfs->asize);
	assert(powerof2(len));
	assert((off_t)len > 0 && off + (off_t)len > off &&
	    off + (off_t)len < zfs->asize);

	off += VDEV_LABEL_START_SIZE;
	for (size_t sofar = 0; sofar < len; sofar += n) {
		n = pwrite(zfs->fd, (const char *)buf + sofar, len - sofar,
		    off + sofar);
		if (n < 0)
			err(1, "pwrite");
		assert(n > 0);
	}
}

static void
vdev_pwrite_data(zfs_opt_t *zfs, uint8_t datatype, uint8_t cksumtype,
    const void *data, off_t sz, off_t loc, blkptr_t *bp)
{
	zio_cksum_t cksum;

	assert(cksumtype == ZIO_CHECKSUM_FLETCHER_4);

	fletcher_4_native(data, sz, NULL, &cksum);
	blkptr_set(bp, loc, sz, datatype, cksumtype, &cksum);
	/* XXX-MJ make sure this space is marked as allocated? */
	vdev_pwrite(zfs, data, sz, loc);
}

static void
vdev_pwrite_dnode_data(zfs_opt_t *zfs, dnode_phys_t *dnode, const void *data,
    off_t sz, off_t loc)
{
	vdev_pwrite_data(zfs, dnode->dn_type, dnode->dn_checksum, data, sz, loc,
	    &dnode->dn_blkptr[0]);

	assert((dnode->dn_flags & DNODE_FLAG_USED_BYTES) != 0);
	dnode->dn_used += sz;
}

static void
vdev_pwrite_dnode_indir(zfs_opt_t *zfs, dnode_phys_t *dnode, const void *data,
    off_t sz, off_t loc, blkptr_t *bp)
{
	vdev_pwrite_data(zfs, dnode->dn_type, dnode->dn_checksum, data, sz, loc,
	    bp);

	assert((dnode->dn_flags & DNODE_FLAG_USED_BYTES) != 0);
	dnode->dn_used += sz;
}

static void
vdev_label_set_checksum(void *buf, off_t off, off_t size)
{
	zio_cksum_t cksum;
	zio_eck_t *eck;

	assert(size > 0 && (size_t)size >= sizeof(zio_eck_t));

	eck = (zio_eck_t *)((char *)buf + size) - 1;
	eck->zec_magic = ZEC_MAGIC;
	ZIO_SET_CHECKSUM(&eck->zec_cksum, off, 0, 0, 0);
	zio_checksum_SHA256(buf, size, NULL, &cksum);
	eck->zec_cksum = cksum;
}

/*
 * Set embedded checksums and write the label at the specified index.
 */
static void
vdev_label_write(zfs_opt_t *zfs, int ind, const vdev_label_t *labelp)
{
	vdev_label_t *label;
	ssize_t n;
	off_t blksz, loff;

	assert(ind >= 0 && ind < VDEV_LABELS);

	label = ecalloc(1, sizeof(*label));
	memcpy(label, labelp, sizeof(*label));

	blksz = 1 << zfs->ashift;

	if (ind < 2) {
		loff = ind * sizeof(vdev_label_t);
	} else {
		loff = zfs->vdevsize -
		    (VDEV_LABELS - ind) * sizeof(vdev_label_t);
	}

	/*
	 * Set the verifier checksum for the boot block.  We don't use it, but
	 * the loader reads it and will complain if the checksum isn't valid.
	 */
	vdev_label_set_checksum(&label->vl_be,
	    loff + __offsetof(vdev_label_t, vl_be),
	    sizeof(vdev_boot_envblock_t));

	/*
	 * Set the verifier checksum for the label.
	 */
	vdev_label_set_checksum(&label->vl_vdev_phys,
	    loff + __offsetof(vdev_label_t, vl_vdev_phys), sizeof(vdev_phys_t));

	/*
	 * Set the verifier checksum for the uberblocks.  There is one uberblock
	 * per sector; for example, with an ashift of 12 we end up with
	 * 128KB/4KB=32 copies of the uberblock in the ring.
	 */
	assert(sizeof(label->vl_uberblock) % blksz == 0);
	for (size_t roff = 0; roff < sizeof(label->vl_uberblock);
	    roff += blksz) {
		vdev_label_set_checksum(&label->vl_uberblock[0] + roff,
		    loff + __offsetof(vdev_label_t, vl_uberblock) + roff,
		    blksz);
	}

	n = pwrite(zfs->fd, label, sizeof(*label), loff);
	if (n < 0)
		err(1, "writing vdev label");
	assert(n == sizeof(*label));

	free(label);
}

/*
 * Find a chunk of contiguous free space of length *lenp, according to the
 * following rules:
 * 1. If the length is less than or equal to 128KB, the returned run's length
 *    will be the smallest power of 2 equal to or larger than the length.
 * 2. If the length is larger than 128KB, the returned run's length will be
 *    the smallest multiple of 128KB that is larger than the length.
 * 3. The returned run's length will be size-aligned up to 128KB.
 *
 * XXX-MJ it seems the third rule isn't required, so this can just be a dumb
 * bump allocator.  Maybe there's some benefit to keeping large blocks aligned,
 * so let's keep it for now and hope we don't get too much fragmentation.
 * Alternately we could try to allocate all blocks of a certain size from the
 * same metaslab.
 */
static off_t
vdev_space_alloc(zfs_opt_t *zfs, off_t *lenp)
{
	off_t len;
	int align, loc, minblksz, nbits;

	minblksz = 1 << zfs->ashift;
	len = roundup2(*lenp, minblksz);

	assert(len != 0);
	assert(len / minblksz <= INT_MAX);

	if (len < MAXBLOCKSIZE) {
		if ((len & (len - 1)) != 0)
			len = (off_t)1 << flsll(len);
		align = len / minblksz;
	} else {
		len = roundup2(len, MAXBLOCKSIZE);
		align = MAXBLOCKSIZE / minblksz;
	}

	for (loc = 0, nbits = len / minblksz;; loc = roundup2(loc, align)) {
		int loc1 = loc;
		bit_ffc_area_at(zfs->spacemap, loc1, zfs->spacemapbits, nbits,
		    &loc);
		if (loc == -1) {
			errx(1, "failed to find %ju bytes of space",
			    (uintmax_t)len);
		}
		assert(loc >= loc1);
		if ((loc & (align - 1)) == 0)
			break;
	}
	assert(loc + nbits > loc);
	bit_nset(zfs->spacemap, loc, loc + nbits - 1);
	*lenp = len;

	return ((off_t)loc << zfs->ashift);
}

static void
spacemap_init(zfs_opt_t *zfs)
{
	uint64_t msshift, slabs;
	off_t nbits;

	nbits = zfs->asize >> zfs->ashift;
	if (nbits > INT_MAX) {
		/*
		 * With the smallest block size of 512B, the limit on the image
		 * size is 2TB.  That should be enough for anyone.
		 */
		errx(1, "image size is too large");
	}
	zfs->spacemapbits = (int)nbits;
	zfs->spacemap = bit_alloc(zfs->spacemapbits);
	if (zfs->spacemap == NULL)
		err(1, "bitstring allocation failed");

	/*
	 * XXX-MJ explain
	 */
	for (msshift = 24; msshift < 34; msshift++) {
		slabs = zfs->asize / ((uint64_t)1 << msshift);
		if (slabs >= 4 && slabs <= 200)
			break;
	}
	zfs->msshift = msshift;
	zfs->mscount = slabs;
}

static void
spacemap_write(zfs_opt_t *zfs)
{
	dnode_phys_t *objarr;
	zfs_objset_t *mos;
	bitstr_t *spacemap;
	uint64_t *objarrblk;
	off_t smblksz, objarrblksz, objarrloc;

	struct {
		dnode_phys_t	*dnode;
		uint64_t	dnid;
		off_t		loc;
	} *sma;

	mos = &zfs->mos;

	objarrblksz = sizeof(uint64_t) * zfs->mscount;
	assert(objarrblksz <= MAXBLOCKSIZE);
	objarrloc = objset_space_alloc(zfs, mos, &objarrblksz);
	objarrblk = ecalloc(1, objarrblksz);

	objarr = objset_dnode_lookup(mos, zfs->objarrid);
	objarr->dn_datablkszsec = objarrblksz >> MINBLOCKSHIFT;

	/*
	 * Use the smallest block size for space maps.  The space allocation
	 * algorithm should aim to minimize the number of holes.
	 */
	smblksz = 1 << zfs->ashift;

	/*
	 * First allocate dnodes and space for all of our space maps.  No more
	 * space will be allocated from the vdev after this point.
	 */
	sma = ecalloc(zfs->mscount, sizeof(*sma));
	for (uint64_t i = 0; i < zfs->mscount; i++) {
		sma[i].dnode = objset_dnode_bonus_alloc(mos, DMU_OT_SPACE_MAP,
		    DMU_OT_SPACE_MAP_HEADER, SPACE_MAP_SIZE_V0, &sma[i].dnid);
		sma[i].loc = objset_space_alloc(zfs, mos, &smblksz);
	}
	spacemap = zfs->spacemap;
	zfs->spacemap = NULL;

	/*
	 * Now that the set of allocated space is finalized, populate each space
	 * map.
	 */
	for (uint64_t i = 0; i < zfs->mscount; i++) {
		space_map_phys_t *sm;
		uint64_t alloc, length, *smblk;
		int shift, startb, endb, srunb, erunb;

		/*
		 * We only allocate a single block for this space map, but OpenZFS
		 * assumes that a space map object with sufficient bonus space supports
		 * histograms.
		 */
		sma[i].dnode->dn_nblkptr = 3;
		sma[i].dnode->dn_datablkszsec = smblksz >> MINBLOCKSHIFT;

		smblk = ecalloc(1, smblksz);

		alloc = length = 0;
		shift = zfs->msshift - zfs->ashift;
		for (srunb = startb = i * (1 << shift),
		    endb = (i + 1) * (1 << shift);
		    srunb < endb; srunb = erunb) {
			uint64_t runlen, runoff;

			/* Find a run of allocated space. */
			bit_ffs_at(spacemap, srunb, zfs->spacemapbits, &srunb);
			if (srunb == -1 || srunb >= endb)
				break;

			bit_ffc_at(spacemap, srunb, zfs->spacemapbits, &erunb);
			if (erunb == -1 || erunb > endb)
				erunb = endb;

			/*
			 * The space represented by [srunb, erunb) has been
			 * allocated.  Add a record to the space map to indicate
			 * this.  Run offsets are relative to the beginning of
			 * the metaslab.
			 */
			runlen = erunb - srunb;
			runoff = srunb - startb;

			assert(length * sizeof(uint64_t) < (uint64_t)smblksz);
			smblk[length] = SM_PREFIX_ENCODE(SM2_PREFIX) |
			    SM2_RUN_ENCODE(runlen) | SM2_VDEV_ENCODE(0);
			smblk[length + 1] = SM2_TYPE_ENCODE(SM_ALLOC) |
			    SM2_OFFSET_ENCODE(runoff);

			alloc += runlen << zfs->ashift;
			length += 2;
		}

		sm = DN_BONUS(sma[i].dnode);
		sm->smp_object = 0;
		sm->smp_length = length * sizeof(uint64_t);
		sm->smp_alloc = alloc;

		vdev_pwrite_dnode_data(zfs, sma[i].dnode, smblk, smblksz,
		    sma[i].loc);
		free(smblk);

		/* Record this space map in the space map object array. */
		objarrblk[i] = sma[i].dnid;
	}

	vdev_pwrite_dnode_data(zfs, objarr, objarrblk, objarrblksz, objarrloc);
	free(objarrblk);

	assert(zfs->spacemap == NULL);
	free(spacemap);
}

static void
objset_init(zfs_opt_t *zfs, zfs_objset_t *os, uint64_t type,
    uint64_t dnodecount)
{
	dnode_phys_t *mdnode;
	off_t blksz;

	/*
	 * Allocate space on the vdev for the objset and dnode array.  For other
	 * objects we do that only when going to actually write them to the
	 * vdev, but in this case it simplifies space map accounting to do it
	 * now.
	 */
	os->osblksz = sizeof(objset_phys_t);
	os->osloc = objset_space_alloc(zfs, os, &os->osblksz);

	/* Object zero is always the meta dnode. */
	os->dnodecount = dnodecount + 1;
	os->dnodenextfree = 1;
	blksz = roundup2(os->dnodecount * sizeof(dnode_phys_t),
	    DNODE_BLOCK_SIZE);
	os->dnodeloc = objset_space_alloc(zfs, os, &blksz);
	assert(blksz % DNODE_BLOCK_SIZE == 0);
	os->dnodes = ecalloc(1,
	    roundup2(dnodecount * sizeof(dnode_phys_t), DNODE_BLOCK_SIZE));

	/* XXX-MJ what else? */
	os->osphys = ecalloc(1, os->osblksz);
	os->osphys->os_type = type;
	mdnode = &os->osphys->os_meta_dnode;
	mdnode->dn_indblkshift = MAXBLOCKSHIFT;
	mdnode->dn_type = DMU_OT_DNODE;
	mdnode->dn_bonustype = DMU_OT_NONE;
	mdnode->dn_checksum = ZIO_CHECKSUM_FLETCHER_4;
	mdnode->dn_datablkszsec = DNODE_BLOCK_SIZE >> MINBLOCKSHIFT;
	mdnode->dn_nlevels = 1;
	for (uint64_t count = dnodecount / DNODES_PER_BLOCK; count > 1;
	    count /= BLKPTR_PER_INDIR)
		mdnode->dn_nlevels++;
	mdnode->dn_nblkptr = 1;
	mdnode->dn_maxblkid = howmany(dnodecount, DNODES_PER_BLOCK) - 1;
}

/*
 * Write the dnode array and physical object set to disk.
 */
static void
_objset_write(zfs_opt_t *zfs, zfs_objset_t *os, struct dnode_cursor *c)
{
	assert(os->dnodenextfree == os->dnodecount);

	/*
	 * Write out the dnode array.  For some reason data blocks must be 16KB
	 * in size no matter how large the array is.
	 */
	for (uint64_t i = 0; i < os->dnodecount; i += DNODES_PER_BLOCK) {
		dnode_phys_t *blk;
		blkptr_t *bp;
		uint64_t fill;
		off_t loc;

		blk = os->dnodes + i;
		loc = os->dnodeloc + i * sizeof(dnode_phys_t);
		fill = os->dnodecount - i < DNODES_PER_BLOCK ?
		    os->dnodecount - i : 0;

		bp = dnode_cursor_next(zfs, c, i * sizeof(dnode_phys_t));
		vdev_pwrite_dnode_indir(zfs, &os->osphys->os_meta_dnode,
		    blk, DNODE_BLOCK_SIZE, loc, bp);
		/* XXX-MJ ugly fixup */
		BP_SET_FILL(bp, fill);
	}
	dnode_cursor_finish(zfs, c);
	free(os->dnodes);
	os->dnodes = NULL;

	vdev_pwrite_data(zfs, DMU_OT_OBJSET, ZIO_CHECKSUM_FLETCHER_4,
	    os->osphys, os->osblksz, os->osloc, &os->osbp);
}

static void
objset_write(zfs_opt_t *zfs, zfs_objset_t *os)
{
	struct dnode_cursor *c;

	c = dnode_cursor_init(zfs, os, &os->osphys->os_meta_dnode,
	    os->dnodecount * sizeof(dnode_phys_t), DNODE_BLOCK_SIZE);
	_objset_write(zfs, os, c);
}

static void
objset_mos_write(zfs_opt_t *zfs)
{
	struct dnode_cursor *c;
	zfs_objset_t *mos;

	mos = &zfs->mos;

	/*
	 * There is a chicken-and-egg problem here: we cannot write space maps
	 * before we're finished allocating space from the vdev, and we can't
	 * write the MOS without having allocated space for indirect dnode
	 * blocks.  Thus, rather than lazily allocating indirect blocks for the
	 * meta-dnode (which would be simpler), they are allocated up-front and
	 * before writing space maps.
	 */
	c = dnode_cursor_init(zfs, mos, &mos->osphys->os_meta_dnode,
	    mos->dnodecount * sizeof(dnode_phys_t), DNODE_BLOCK_SIZE);
	spacemap_write(zfs);
	_objset_write(zfs, mos, c);
}

static dnode_phys_t *
objset_dnode_bonus_alloc(zfs_objset_t *os, uint8_t type, uint8_t bonustype,
    uint16_t bonuslen, uint64_t *idp)
{
	dnode_phys_t *dnode;

	assert(os->dnodenextfree < os->dnodecount);
	assert(bonuslen <= DN_OLD_MAX_BONUSLEN);

	if (idp != NULL)
		*idp = os->dnodenextfree;
	dnode = &os->dnodes[os->dnodenextfree++];
	dnode->dn_indblkshift = MAXBLOCKSHIFT;
	dnode->dn_datablkszsec = os->osblksz >> MINBLOCKSHIFT;
	dnode->dn_nlevels = 1;
	dnode->dn_nblkptr = 1;
	dnode->dn_type = type;
	dnode->dn_bonustype = bonustype;
	dnode->dn_bonuslen = bonuslen;
	dnode->dn_checksum = ZIO_CHECKSUM_FLETCHER_4;
	dnode->dn_compress = ZIO_COMPRESS_OFF;
	dnode->dn_flags = DNODE_FLAG_USED_BYTES;
	return (dnode);
}

static dnode_phys_t *
objset_dnode_alloc(zfs_objset_t *os, uint8_t type, uint64_t *idp)
{
	return (objset_dnode_bonus_alloc(os, type, DMU_OT_NONE, 0, idp));
}

static dnode_phys_t *
objset_dnode_lookup(zfs_objset_t *os, uint64_t id)
{
	assert(id > 0 && id <= os->dnodecount);

	return (&os->dnodes[id]);
}

static off_t
objset_space_alloc(zfs_opt_t *zfs, zfs_objset_t *os, off_t *lenp)
{
	off_t loc;

	loc = vdev_space_alloc(zfs, lenp);
	os->space += *lenp;
	return (loc);
}

static dsl_dir_phys_t *
dsl_dir_alloc(zfs_opt_t *zfs, uint64_t parentdir, uint64_t *dnidp)
{
	zfs_zap_t propszap;
	zfs_objset_t *mos;
	dnode_phys_t *dnode, *props;
	dsl_dir_phys_t *dsldir;
	uint64_t childdirid, propsid;

	mos = &zfs->mos;

	dnode = objset_dnode_bonus_alloc(mos, DMU_OT_DSL_DIR, DMU_OT_DSL_DIR,
	    sizeof(dsl_dir_phys_t), dnidp);

	props = objset_dnode_alloc(mos, DMU_OT_DSL_PROPS, &propsid);
	/* XXXMJ maybe initialize in the caller as well */
	zap_init(&propszap, mos, props);
	zap_add_uint64(&propszap, "compression", ZIO_COMPRESS_OFF);
	/* XXXMJ should only be for the root dir */
	if (zfs->mountpoint != NULL)
		zap_add_string(&propszap, "mountpoint", zfs->mountpoint);
	zap_write(zfs, &propszap);

	/* Initialized by the caller. */
	(void)objset_dnode_alloc(mos, DMU_OT_DSL_DIR_CHILD_MAP,
	    &childdirid);

	dsldir = (dsl_dir_phys_t *)DN_BONUS(dnode);
	dsldir->dd_parent_obj = parentdir;
	dsldir->dd_props_zapobj = propsid;
	dsldir->dd_child_dir_zapobj = childdirid;

	return (dsldir);
}

static dsl_dataset_phys_t *
dsl_dataset_alloc(zfs_opt_t *zfs, uint64_t dir, uint64_t *dnidp)
{
	zfs_zap_t deadlistzap;
	dnode_phys_t *dnode;
	dsl_dataset_phys_t *ds;
	uint64_t deadlistid;

	dnode = objset_dnode_bonus_alloc(&zfs->mos, DMU_OT_DSL_DATASET,
	    DMU_OT_DSL_DATASET, sizeof(dsl_dataset_phys_t), dnidp);
	ds = (dsl_dataset_phys_t *)DN_BONUS(dnode);

	dnode = objset_dnode_bonus_alloc(&zfs->mos, DMU_OT_DEADLIST,
	    DMU_OT_DEADLIST_HDR, sizeof(dsl_deadlist_phys_t), &deadlistid);
	zap_init(&deadlistzap, &zfs->mos, dnode);
	zap_write(zfs, &deadlistzap);

	/* XXX-MJ what else? */
	ds->ds_dir_obj = dir;
	ds->ds_deadlist_obj = deadlistid;
	ds->ds_creation_txg = TXG_INITIAL;

	return (ds);
}

static uint16_t
zap_entry_chunks(zfs_zap_entry_t *ent)
{
	return (1 + howmany(strlen(ent->name) + 1, ZAP_LEAF_ARRAY_BYTES) +
	    howmany(ent->intsz * ent->intcnt, ZAP_LEAF_ARRAY_BYTES));
}

static uint64_t
zap_hash(uint64_t salt, const char *name)
{
	static uint64_t crc64_table[256];
	const uint64_t crc64_poly = 0xC96C5795D7870F42UL;
	const uint8_t *cp;
	uint64_t crc;
	uint8_t c;

	assert(salt != 0);
	if (crc64_table[128] == 0) {
		for (int i = 0; i < 256; i++) {
			uint64_t *t;

			t = crc64_table + i;
			*t = i;
			for (int j = 8; j > 0; j--)
				*t = (*t >> 1) ^ (-(*t & 1) & crc64_poly);
		}
	}
	assert(crc64_table[128] == crc64_poly);

	for (cp = (const uint8_t *)name, crc = salt; (c = *cp) != '\0'; cp++)
		crc = (crc >> 8) ^ crc64_table[(crc ^ c) & 0xFF];

	/*
	 * Only use 28 bits, since we need 4 bits in the cookie for the
	 * collision differentiator.  We MUST use the high bits, since
	 * those are the ones that we first pay attention to when
	 * choosing the bucket.
	 */
	crc &= ~((1ULL << (64 - ZAP_HASHBITS)) - 1);

	return (crc);
}

static void
zap_init(zfs_zap_t *zap, zfs_objset_t *os, dnode_phys_t *dnode)
{
	STAILQ_INIT(&zap->kvps);
	zap->hashsalt = ((uint64_t)random() << 32) | random();
	zap->micro = true;
	zap->kvpcnt = 0;
	zap->chunks = 0;
	zap->dnode = dnode;
	zap->os = os;
}

static void
zap_add(zfs_zap_t *zap, const char *name, size_t intsz, size_t intcnt,
    const uint8_t *val)
{
	zfs_zap_entry_t *ent;

	assert(intsz == 1 || intsz == 2 || intsz == 4 || intsz == 8);
	assert(strlen(name) + 1 <= ZAP_MAXNAMELEN);
	assert(intcnt <= ZAP_MAXVALUELEN && intcnt * intsz <= ZAP_MAXVALUELEN);

	ent = ecalloc(1, sizeof(*ent));
	ent->name = estrdup(name);
	ent->hash = zap_hash(zap->hashsalt, ent->name);
	ent->intsz = intsz;
	ent->intcnt = intcnt;
	if (intsz == sizeof(uint64_t) && intcnt == 1)
		ent->val64p = &ent->val64;
	else
		ent->valp = ecalloc(intcnt, intsz);
	memcpy(ent->valp, val, intcnt * intsz);
	zap->kvpcnt++;
	zap->chunks += zap_entry_chunks(ent);
	STAILQ_INSERT_TAIL(&zap->kvps, ent, next);

	if (zap->micro && (intcnt != 1 || intsz != sizeof(uint64_t) ||
	    strlen(name) + 1 > MZAP_NAME_LEN || zap->kvpcnt > MZAP_ENT_MAX))
		zap->micro = false;
}

static void
zap_add_uint64(zfs_zap_t *zap, const char *name, uint64_t val)
{
	zap_add(zap, name, sizeof(uint64_t), 1, (uint8_t *)&val);
}

static void
zap_add_string(zfs_zap_t *zap, const char *name, const char *val)
{
	zap_add(zap, name, 1, strlen(val) + 1, val);
}

static void
zap_micro_write(zfs_opt_t *zfs, zfs_zap_t *zap)
{
	dnode_phys_t *dnode;
	zfs_zap_entry_t *ent;
	mzap_phys_t *mzap;
	mzap_ent_phys_t *ment;
	off_t bytes, loc;

	memset(zfs->filebuf, 0, sizeof(zfs->filebuf));
	mzap = (mzap_phys_t *)&zfs->filebuf[0];
	mzap->mz_block_type = ZBT_MICRO;
	mzap->mz_salt = zap->hashsalt;
	mzap->mz_normflags = 0;

	bytes = sizeof(*mzap) + (zap->kvpcnt - 1) * sizeof(*ment);
	assert(bytes <= (off_t)MZAP_MAX_BLKSZ);

	ment = &mzap->mz_chunk[0];
	STAILQ_FOREACH(ent, &zap->kvps, next) {
		memcpy(&ment->mze_value, ent->valp, ent->intsz * ent->intcnt);
		ment->mze_cd = 0; /* XXX-MJ */
		strlcpy(ment->mze_name, ent->name, sizeof(ment->mze_name));
		ment++;
	}

	loc = objset_space_alloc(zfs, zap->os, &bytes);

	dnode = zap->dnode;
	dnode->dn_maxblkid = 0;
	dnode->dn_datablkszsec = bytes >> MINBLOCKSHIFT;
	dnode->dn_flags = DNODE_FLAG_USED_BYTES;

	vdev_pwrite_dnode_data(zfs, dnode, zfs->filebuf, bytes, loc);
}

/*
 * Write some data to the fat ZAP leaf chunk starting at index "li".
 */
static void
zap_fat_write_array_chunk(zap_leaf_t *l, uint16_t li, size_t sz,
    const uint8_t *val)
{
	struct zap_leaf_array *la;

	assert(sz <= ZAP_MAXVALUELEN);

	for (uint16_t n, resid = sz; resid > 0; resid -= n, val += n, li++) {
		n = MIN(resid, ZAP_LEAF_ARRAY_BYTES);

		la = &ZAP_LEAF_CHUNK(l, li).l_array;
		assert(la->la_type == ZAP_CHUNK_FREE);
		la->la_type = ZAP_CHUNK_ARRAY;
		memcpy(la->la_array, val, n);
		la->la_next = li + 1;
	}
	la->la_next = 0xffff;
}

/*
 * Find the shortest hash prefix length which lets us distribute keys without
 * overflowing a leaf block.  This is not (space) optimal, but is simple, and
 * directories large enough to overflow a single 128KB leaf block are uncommon.
 */
static unsigned int
zap_fat_write_prefixlen(zfs_zap_t *zap, zap_leaf_t *l)
{
	zfs_zap_entry_t *ent;
	unsigned int prefixlen;

	if (zap->chunks <= ZAP_LEAF_NUMCHUNKS(l)) {
		/*
		 * All chunks will fit in a single leaf block.
		 */
		return (0);
	}

	for (prefixlen = 1; prefixlen < (unsigned int)l->l_bs; prefixlen++) {
		uint32_t *leafchunks;

		leafchunks = ecalloc(1u << prefixlen, sizeof(*leafchunks));
		STAILQ_FOREACH(ent, &zap->kvps, next) {
			uint64_t li;
			uint16_t chunks;

			li = ZAP_HASH_IDX(ent->hash, prefixlen);

			chunks = zap_entry_chunks(ent);
			if (ZAP_LEAF_NUMCHUNKS(l) - leafchunks[li] < chunks) {
				/*
				 * Not enough space, grow the prefix and retry.
				 */
				break;
			}
			leafchunks[li] += chunks;
		}
		free(leafchunks);

		if (ent == NULL) {
			/*
			 * Everything fits, we're done.
			 */
			break;
		}
	}

	/*
	 * If this fails, then we need to expand the pointer table.  For now
	 * this situation is unhandled since it is hard to trigger.
	 */
	assert(prefixlen < (unsigned int)l->l_bs);

	return (prefixlen);
}

/*
 * Initialize a fat ZAP leaf block.
 */
static void
zap_fat_write_leaf_init(zap_leaf_t *l, uint64_t prefix, int prefixlen)
{
	zap_leaf_phys_t *leaf;

	leaf = l->l_phys;

	leaf->l_hdr.lh_block_type = ZBT_LEAF;
	leaf->l_hdr.lh_magic = ZAP_LEAF_MAGIC;
	leaf->l_hdr.lh_nfree = ZAP_LEAF_NUMCHUNKS(l);
	leaf->l_hdr.lh_prefix = prefix;
	leaf->l_hdr.lh_prefix_len = prefixlen;

	/* Initialize the leaf hash table. */
	assert(leaf->l_hdr.lh_nfree < 0xffff);
	memset(leaf->l_hash, 0xff,
	    ZAP_LEAF_HASH_NUMENTRIES(l) * sizeof(*leaf->l_hash));

	/* Initialize the leaf chunks. */
	for (uint16_t i = 0; i < ZAP_LEAF_NUMCHUNKS(l); i++) {
		struct zap_leaf_free *lf;

		lf = &ZAP_LEAF_CHUNK(l, i).l_free;
		lf->lf_type = ZAP_CHUNK_FREE;
		if (i + 1 == ZAP_LEAF_NUMCHUNKS(l))
			lf->lf_next = 0xffff;
		else
			lf->lf_next = i + 1;
	}
}

static void
zap_fat_write(zfs_opt_t *zfs, zfs_zap_t *zap)
{
	struct dnode_cursor *c;
	blkptr_t *bp;
	zap_leaf_t l;
	zap_phys_t *zaphdr;
	struct zap_table_phys *zt;
	zfs_zap_entry_t *ent;
	dnode_phys_t *dnode;
	uint8_t *leafblks;
	uint64_t lblkcnt, *ptrhasht;
	off_t loc, blksz;
	size_t blkshift;
	unsigned int prefixlen;
	int ptrcnt;

	/*
	 * For simplicity, always use the largest block size.  This should be ok
	 * since most directories will be micro ZAPs, but it's space inefficient
	 * for small ZAPs and might need to be revisited.
	 */
	blkshift = MAXBLOCKSHIFT;
	blksz = (off_t)1 << blkshift;

	/*
	 * Embedded pointer tables give up to 8192 entries.  This ought to be
	 * enough for anything except massive directories.
	 */
	ptrcnt = (blksz / 2) / sizeof(uint64_t);

	memset(zfs->filebuf, 0, sizeof(zfs->filebuf));
	zaphdr = (zap_phys_t *)&zfs->filebuf[0];
	zaphdr->zap_block_type = ZBT_HEADER;
	zaphdr->zap_magic = ZAP_MAGIC;
	zaphdr->zap_num_entries = zap->kvpcnt;
	zaphdr->zap_salt = zap->hashsalt;

	l.l_bs = blkshift;
	l.l_phys = NULL;

	zt = &zaphdr->zap_ptrtbl;
	zt->zt_blk = 0;
	zt->zt_numblks = 0;
	zt->zt_shift = flsl(ptrcnt) - 1;
	zt->zt_nextblk = 0;
	zt->zt_blks_copied = 0;

	/*
	 * How many leaf blocks do we need?  Initialize them and update the
	 * header.
	 */
	prefixlen = zap_fat_write_prefixlen(zap, &l);
	lblkcnt = 1 << prefixlen;
	leafblks = ecalloc(lblkcnt, blksz);
	for (unsigned int li = 0; li < lblkcnt; li++) {
		l.l_phys = (zap_leaf_phys_t *)(leafblks + li * blksz);
		zap_fat_write_leaf_init(&l, li, prefixlen);
	}
	zaphdr->zap_num_leafs = lblkcnt;
	zaphdr->zap_freeblk = lblkcnt + 1;

	/*
	 * For each entry, figure out which leaf block it belongs to based on
	 * the upper bits of its hash, allocate chunks from that leaf, and fill
	 * them out.
	 */
	ptrhasht = (uint64_t *)(&zfs->filebuf[0] + blksz / 2);
	STAILQ_FOREACH(ent, &zap->kvps, next) {
		struct zap_leaf_entry *le;
		uint16_t *lptr;
		uint64_t hi, li;
		uint16_t namelen, nchunks, nnamechunks, nvalchunks;

		hi = ZAP_HASH_IDX(ent->hash, zt->zt_shift);
		li = ZAP_HASH_IDX(ent->hash, prefixlen);
		assert(ptrhasht[hi] == 0 || ptrhasht[hi] == li + 1);
		ptrhasht[hi] = li + 1;
		l.l_phys = (zap_leaf_phys_t *)(leafblks + li * blksz);

		namelen = strlen(ent->name) + 1;

		/*
		 * How many leaf chunks do we need for this entry?
		 */
		nnamechunks = howmany(namelen, ZAP_LEAF_ARRAY_BYTES);
		nvalchunks = howmany(ent->intcnt,
		    ZAP_LEAF_ARRAY_BYTES / ent->intsz);
		nchunks = 1 + nnamechunks + nvalchunks;

		/*
		 * Allocate a run of free leaf chunks for this entry,
		 * potentially extending a hash chain.
		 */
		assert(l.l_phys->l_hdr.lh_nfree >= nchunks);
		l.l_phys->l_hdr.lh_nfree -= nchunks;
		l.l_phys->l_hdr.lh_nentries++;
		lptr = ZAP_LEAF_HASH_ENTPTR(&l, ent->hash);
		while (*lptr != 0xffff) {
			assert(*lptr < ZAP_LEAF_NUMCHUNKS(&l));
			le = ZAP_LEAF_ENTRY(&l, *lptr);
			assert(le->le_type == ZAP_CHUNK_ENTRY);
			le->le_cd++;
			lptr = &le->le_next;
		}
		*lptr = l.l_phys->l_hdr.lh_freelist;
		l.l_phys->l_hdr.lh_freelist += nchunks;
		assert(l.l_phys->l_hdr.lh_freelist <=
		    ZAP_LEAF_NUMCHUNKS(&l));
		if (l.l_phys->l_hdr.lh_freelist ==
		    ZAP_LEAF_NUMCHUNKS(&l))
			l.l_phys->l_hdr.lh_freelist = 0xffff;

		/*
		 * Integer values must be stored in big-endian format.
		 */
		switch (ent->intsz) {
		case 1:
			break;
		case 2:
			for (uint16_t *v = ent->val16p;
			    v - ent->val16p < (ptrdiff_t)ent->intcnt;
			    v++)
				*v = htobe16(*v);
			break;
		case 4:
			for (uint32_t *v = ent->val32p;
			    v - ent->val32p < (ptrdiff_t)ent->intcnt;
			    v++)
				*v = htobe32(*v);
			break;
		case 8:
			for (uint64_t *v = ent->val64p;
			    v - ent->val64p < (ptrdiff_t)ent->intcnt;
			    v++)
				*v = htobe64(*v);
			break;
		default:
			assert(0);
		}

		/*
		 * Finally, write out the leaf chunks for this entry.
		 */
		le = ZAP_LEAF_ENTRY(&l, *lptr);
		assert(le->le_type == ZAP_CHUNK_FREE);
		le->le_type = ZAP_CHUNK_ENTRY;
		le->le_next = 0xffff;
		le->le_name_chunk = *lptr + 1;
		le->le_name_numints = namelen;
		le->le_value_chunk = *lptr + 1 + nnamechunks;
		le->le_value_intlen = ent->intsz;
		le->le_value_numints = ent->intcnt;
		le->le_hash = ent->hash;
		zap_fat_write_array_chunk(&l, *lptr + 1, namelen, ent->name);
		zap_fat_write_array_chunk(&l, *lptr + 1 + nnamechunks,
		    ent->intcnt * ent->intsz, ent->valp);
	}

	/*
	 * Initialize unused slots of the pointer table.
	 */
	for (int i = 0; i < ptrcnt; i++)
		if (ptrhasht[i] == 0)
			ptrhasht[i] = (i >> (zt->zt_shift - prefixlen)) + 1;

	/*
	 * Write the whole thing to disk.
	 */
	dnode = zap->dnode;
	dnode->dn_nblkptr = 1;
	dnode->dn_datablkszsec = blksz >> MINBLOCKSHIFT;
	dnode->dn_maxblkid = lblkcnt + 1;
	dnode->dn_flags = DNODE_FLAG_USED_BYTES;

	c = dnode_cursor_init(zfs, zap->os, zap->dnode,
	    (lblkcnt + 1) * blksz, blksz);

	bp = dnode_cursor_next(zfs, c, 0);
	loc = objset_space_alloc(zfs, zap->os, &blksz);
	assert(blksz == MAXBLOCKSIZE);

	vdev_pwrite_dnode_indir(zfs, dnode, zfs->filebuf, blksz, loc, bp);

	for (uint64_t i = 0; i < lblkcnt; i++) {
		bp = dnode_cursor_next(zfs, c, (i + 1) * blksz);

		loc = objset_space_alloc(zfs, zap->os, &blksz);
		assert(blksz == MAXBLOCKSIZE);
		vdev_pwrite_dnode_indir(zfs, dnode, leafblks + i * blksz, blksz,
		    loc, bp);
	}

	dnode_cursor_finish(zfs, c);

	free(leafblks);
}

static void
zap_write(zfs_opt_t *zfs, zfs_zap_t *zap)
{
	zfs_zap_entry_t *ent;

	if (zap->micro) {
		zap_micro_write(zfs, zap);
	} else {
		assert(!STAILQ_EMPTY(&zap->kvps));
		assert(zap->kvpcnt > 0);
		zap_fat_write(zfs, zap);
	}

	while ((ent = STAILQ_FIRST(&zap->kvps)) != NULL) {
		STAILQ_REMOVE_HEAD(&zap->kvps, next);
		if (ent->val64p != &ent->val64)
			free(ent->valp);
		free(ent->name);
		free(ent);
	}
}

static nvlist_t *
pool_config_nvcreate(zfs_opt_t *zfs)
{
	nvlist_t *featuresnv, *poolnv;

	poolnv = nvlist_create(NV_UNIQUE_NAME);
	nvlist_add_uint64(poolnv, ZPOOL_CONFIG_POOL_TXG, TXG_INITIAL);
	nvlist_add_uint64(poolnv, ZPOOL_CONFIG_VERSION, SPA_VERSION);
	nvlist_add_uint64(poolnv, ZPOOL_CONFIG_POOL_STATE, POOL_STATE_EXPORTED);
	nvlist_add_string(poolnv, ZPOOL_CONFIG_POOL_NAME, zfs->poolname);
	nvlist_add_uint64(poolnv, ZPOOL_CONFIG_POOL_GUID, zfs->guid);
	nvlist_add_uint64(poolnv, ZPOOL_CONFIG_TOP_GUID, zfs->guid);
	nvlist_add_uint64(poolnv, ZPOOL_CONFIG_GUID, zfs->guid);
	nvlist_add_uint64(poolnv, ZPOOL_CONFIG_VDEV_CHILDREN, 1);

	featuresnv = nvlist_create(NV_UNIQUE_NAME);
	nvlist_add_nvlist(poolnv, ZPOOL_CONFIG_FEATURES_FOR_READ, featuresnv);
	nvlist_destroy(featuresnv);

	return (poolnv);
}

static nvlist_t *
pool_disk_vdev_config_nvcreate(zfs_opt_t *zfs)
{
	nvlist_t *diskvdevnv;

	assert(zfs->objarrid != 0);

	diskvdevnv = nvlist_create(NV_UNIQUE_NAME);
	nvlist_add_string(diskvdevnv, ZPOOL_CONFIG_TYPE, VDEV_TYPE_DISK);
	nvlist_add_uint64(diskvdevnv, ZPOOL_CONFIG_ASHIFT, zfs->ashift);
	nvlist_add_uint64(diskvdevnv, ZPOOL_CONFIG_ASIZE, zfs->asize);
	nvlist_add_uint64(diskvdevnv, ZPOOL_CONFIG_GUID, zfs->guid);
	nvlist_add_uint64(diskvdevnv, ZPOOL_CONFIG_ID, 0);
	nvlist_add_string(diskvdevnv, ZPOOL_CONFIG_PATH, "/dev/null");
	nvlist_add_uint64(diskvdevnv, ZPOOL_CONFIG_WHOLE_DISK, 1);
	nvlist_add_uint64(diskvdevnv, ZPOOL_CONFIG_CREATE_TXG, TXG_INITIAL);
	nvlist_add_uint64(diskvdevnv, ZPOOL_CONFIG_METASLAB_ARRAY,
	    zfs->objarrid);
	nvlist_add_uint64(diskvdevnv, ZPOOL_CONFIG_METASLAB_SHIFT,
	    zfs->msshift);

	return (diskvdevnv);
}

static nvlist_t *
pool_root_vdev_config_nvcreate(zfs_opt_t *zfs)
{
	nvlist_t *diskvdevnv, *rootvdevnv;

	diskvdevnv = pool_disk_vdev_config_nvcreate(zfs);
	rootvdevnv = nvlist_create(NV_UNIQUE_NAME);

	nvlist_add_uint64(rootvdevnv, ZPOOL_CONFIG_ID, 0);
	nvlist_add_uint64(rootvdevnv, ZPOOL_CONFIG_GUID, zfs->guid);
	nvlist_add_string(rootvdevnv, ZPOOL_CONFIG_TYPE, VDEV_TYPE_ROOT);
	nvlist_add_uint64(rootvdevnv, ZPOOL_CONFIG_CREATE_TXG, TXG_INITIAL);
	nvlist_add_nvlist_array(rootvdevnv, ZPOOL_CONFIG_CHILDREN, &diskvdevnv,
	    1);
	nvlist_destroy(diskvdevnv);

	return (rootvdevnv);
}

/*
 * Create the pool's "config" object, which contains an nvlist describing pool
 * parameters and the vdev topology.  It is similar but not identical to the
 * nvlist stored in vdev labels.
 */
static void
pool_init_objdir_config(zfs_opt_t *zfs, zfs_zap_t *objdir)
{
	dnode_phys_t *dnode;
	nvlist_t *poolconfig, *vdevconfig;
	zfs_objset_t *mos;
	void *configbuf;
	uint64_t dnid;
	off_t configloc, configblksz;
	int error;

	mos = &zfs->mos;

	dnode = objset_dnode_bonus_alloc(mos, DMU_OT_PACKED_NVLIST,
	    DMU_OT_PACKED_NVLIST_SIZE, sizeof(uint64_t), &dnid);

	poolconfig = pool_config_nvcreate(zfs);

	vdevconfig = pool_root_vdev_config_nvcreate(zfs);
	nvlist_add_nvlist(poolconfig, ZPOOL_CONFIG_VDEV_TREE, vdevconfig);
	nvlist_destroy(vdevconfig);

	error = nvlist_export(poolconfig);
	if (error != 0)
		errc(1, error, "nvlist_export");

	configblksz = nvlist_size(poolconfig);
	configloc = objset_space_alloc(zfs, mos, &configblksz);
	configbuf = ecalloc(1, configblksz);
	nvlist_copy(poolconfig, configbuf, configblksz);

	vdev_pwrite_dnode_data(zfs, dnode, configbuf, configblksz, configloc);

	dnode->dn_datablkszsec = configblksz >> MINBLOCKSHIFT;
	dnode->dn_flags = DNODE_FLAG_USED_BYTES;
	*(uint64_t *)DN_BONUS(dnode) = nvlist_size(poolconfig);

	zap_add_uint64(objdir, DMU_POOL_CONFIG, dnid);

	nvlist_destroy(poolconfig);
	free(configbuf);
}

/*
 * Add objects block pointer list objects, used for deferred frees.  We don't do
 * anything with them, but they need to be present or OpenZFS will refuse to
 * import the pool.
 */
static void
pool_init_objdir_bplists(zfs_opt_t *zfs __unused, zfs_zap_t *objdir)
{
	zfs_objset_t *mos;
	uint64_t dnid;

	mos = &zfs->mos;

	(void)objset_dnode_bonus_alloc(mos, DMU_OT_BPOBJ, DMU_OT_BPOBJ_HDR,
	    BPOBJ_SIZE_V2, &dnid);
	zap_add_uint64(objdir, DMU_POOL_FREE_BPOBJ, dnid);

	(void)objset_dnode_bonus_alloc(mos, DMU_OT_BPOBJ, DMU_OT_BPOBJ_HDR,
	    BPOBJ_SIZE_V2, &dnid);
	zap_add_uint64(objdir, DMU_POOL_SYNC_BPLIST, dnid);
}

/*
 * Add required feature metadata objects.  We don't know anything about ZFS
 * features, so the objects are just empty ZAPs.
 */
static void
pool_init_objdir_feature_maps(zfs_opt_t *zfs, zfs_zap_t *objdir)
{
	zfs_zap_t zap;
	zfs_objset_t *mos;
	dnode_phys_t *dnode;
	uint64_t dnid;

	mos = &zfs->mos;

	dnode = objset_dnode_alloc(mos, DMU_OTN_ZAP_METADATA, &dnid);
	zap_add_uint64(objdir, DMU_POOL_FEATURES_FOR_READ, dnid);
	zap_init(&zap, mos, dnode);
	zap_write(zfs, &zap);

	dnode = objset_dnode_alloc(mos, DMU_OTN_ZAP_METADATA, &dnid);
	zap_add_uint64(objdir, DMU_POOL_FEATURES_FOR_WRITE, dnid);
	zap_init(&zap, mos, dnode);
	zap_write(zfs, &zap);

	dnode = objset_dnode_alloc(mos, DMU_OTN_ZAP_METADATA, &dnid);
	zap_add_uint64(objdir, DMU_POOL_FEATURE_DESCRIPTIONS, dnid);
	zap_init(&zap, mos, dnode);
	zap_write(zfs, &zap);
}

static void
pool_init_objdir_dsl(zfs_opt_t *zfs, zfs_zap_t *objdir)
{
	assert(zfs->rootdsldirid > 0);

	zap_add_uint64(objdir, DMU_POOL_ROOT_DATASET, zfs->rootdsldirid);
}

static void
pool_init_objdir(zfs_opt_t *zfs)
{
	zfs_zap_t zap;
	dnode_phys_t *objdir;

	objdir = objset_dnode_lookup(&zfs->mos, DMU_POOL_DIRECTORY_OBJECT);

	zap_init(&zap, &zfs->mos, objdir);
	pool_init_objdir_config(zfs, &zap);
	pool_init_objdir_bplists(zfs, &zap);
	pool_init_objdir_feature_maps(zfs, &zap);
	pool_init_objdir_dsl(zfs, &zap);
	zap_write(zfs, &zap);
}

/*
 * Initialize the meta-object set and immediately write out several special
 * objects whose contents are already finalized, including the object directory.
 */
static void
pool_init(zfs_opt_t *zfs)
{
	zfs_objset_t *mos;
	uint64_t dnid, dnodecount;

	zfs->guid = 0xdeadbeefc0deface;

	mos = &zfs->mos;

	dnodecount = 0;
	dnodecount++; /* object directory (ZAP)               */
	dnodecount++; /* |-> vdev config object (nvlist)      */
	dnodecount++; /* |-> features for read                */
	dnodecount++; /* |-> features for write               */
	dnodecount++; /* |-> feature descriptions             */
	dnodecount++; /* |-> sync bplist                      */
	dnodecount++; /* |-> free bplist                      */
	dnodecount++; /* L-> root DSL directory               */
	dnodecount++; /*     |-> DSL child directory (ZAP)    */
	dnodecount++; /*     |   |-> $MOS (DSL dir)           */
	dnodecount++; /*     |   |   |-> child map            */
	dnodecount++; /*     |   |   L-> props (ZAP)          */
	dnodecount++; /*     |   |-> $FREE (DSL dir)          */
	dnodecount++; /*     |   |   |-> child map            */
	dnodecount++; /*     |   |   L-> props (ZAP)          */
	dnodecount++; /*     |   L-> $ORIGIN (DSL dir)        */
	dnodecount++; /*     |   |   |-> child map            */
	dnodecount++; /*     |       |-> dataset              */
	dnodecount++; /*     |       |   L-> deadlist         */
	dnodecount++; /*     |       |-> snapshot             */
	dnodecount++; /*     |       |   |-> deadlist         */
	dnodecount++; /*     |       |   L-> snapshot names   */
	dnodecount++; /*     |       L-> props (ZAP)          */
	dnodecount++; /*     |-> DSL root dataset             */
	dnodecount++; /*     |   L-> deadlist                 */
	dnodecount++; /*     L-> props (ZAP)                  */
	dnodecount++; /* space map object array               */
	dnodecount += zfs->mscount; /* space maps        */

	objset_init(zfs, mos, DMU_OST_META, dnodecount);

	(void)objset_dnode_alloc(mos, DMU_OT_OBJECT_DIRECTORY, &dnid);
	assert(dnid == DMU_POOL_DIRECTORY_OBJECT);

	(void)objset_dnode_alloc(mos, DMU_OT_OBJECT_ARRAY, &zfs->objarrid);
	(void)dsl_dir_alloc(zfs, 0, &zfs->rootdsldirid);

	pool_init_objdir(zfs);
}

static void
pool_labels_write(zfs_opt_t *zfs)
{
	uberblock_t *ub;
	vdev_label_t *label;
	nvlist_t *poolconfig, *vdevconfig;
	int error;

	poolconfig = pool_config_nvcreate(zfs);

	vdevconfig = pool_disk_vdev_config_nvcreate(zfs);
	nvlist_add_nvlist(poolconfig, ZPOOL_CONFIG_VDEV_TREE, vdevconfig);
	nvlist_destroy(vdevconfig);

	error = nvlist_export(poolconfig);
	if (error != 0)
		errc(1, error, "nvlist_export");

	label = ecalloc(1, sizeof(*label));
	nvlist_copy(poolconfig, label->vl_vdev_phys.vp_nvlist,
	    sizeof(label->vl_vdev_phys.vp_nvlist));

	nvlist_destroy(poolconfig);

	/*
	 * Fill out the uberblock.  Just make each one the same.  The embedded
	 * checksum is calculated in vdev_label_write().
	 */
	for (size_t uoff = 0; uoff < sizeof(label->vl_uberblock);
	    uoff += (1 << zfs->ashift)) {
		ub = (uberblock_t *)(&label->vl_uberblock[0] + uoff);
		ub->ub_magic = UBERBLOCK_MAGIC;
		ub->ub_version = SPA_VERSION;
		ub->ub_txg = TXG_INITIAL;
		ub->ub_guid_sum = zfs->guid + zfs->guid; /* root + disk */
		ub->ub_timestamp = 0; /* XXX-MJ */

		ub->ub_software_version = SPA_VERSION;
		ub->ub_mmp_magic = MMP_MAGIC;
		ub->ub_mmp_delay = 0;
		ub->ub_mmp_config = 0;
		ub->ub_checkpoint_txg = 0;
		memcpy(&ub->ub_rootbp, &zfs->mos.osbp, sizeof(blkptr_t));
	}

	/*
	 * Write out four copies of the label.
	 */
	for (int i = 0; i < VDEV_LABELS; i++)
		vdev_label_write(zfs, i, label);

	free(label);
}

static void
pool_fini(zfs_opt_t *zfs)
{
	zfs_zap_t childdirzap, snapnameszap;
	zfs_objset_t *rootos, *mos;
	dnode_phys_t *dnode, *snapnames;
	dsl_dir_phys_t *mosdsldir, *rootdsldir, *origindsldir;
	dsl_dataset_phys_t *rootds, *originds, *snapds;
	uint64_t freedirid, mosdirid, origindirid, origindsid, snapdsid;
	uint64_t rootdsldirid, rootdsid, snapmapid;

	objset_write(zfs, &zfs->rootfs.os);

	mos = &zfs->mos;
	rootos = &zfs->rootfs.os;

	rootdsldirid = zfs->rootdsldirid;
	dnode = objset_dnode_lookup(mos, rootdsldirid);

	rootdsldir = (dsl_dir_phys_t *)DN_BONUS(dnode);

	zap_init(&childdirzap, mos,
	    objset_dnode_lookup(mos, rootdsldir->dd_child_dir_zapobj));

	mosdsldir = dsl_dir_alloc(zfs, rootdsldirid, &mosdirid);
	mosdsldir->dd_used_bytes = mos->space; /* XXX-MJ not all counted yet */
	mosdsldir->dd_compressed_bytes = mosdsldir->dd_uncompressed_bytes =
	    mosdsldir->dd_used_bytes;
	zap_add_uint64(&childdirzap, "$MOS", mosdirid);

	(void)dsl_dir_alloc(zfs, rootdsldirid, &freedirid);
	zap_add_uint64(&childdirzap, "$FREE", freedirid);

	origindsldir = dsl_dir_alloc(zfs, rootdsldirid, &origindirid);
	zap_add_uint64(&childdirzap, "$ORIGIN", origindirid);
	originds = dsl_dataset_alloc(zfs, origindirid, &origindsid);
	snapds = dsl_dataset_alloc(zfs, origindirid, &snapdsid);

	snapnames = objset_dnode_alloc(mos, DMU_OT_DSL_DS_SNAP_MAP, &snapmapid);

	origindsldir->dd_head_dataset_obj = origindsid;
	originds->ds_prev_snap_obj = snapdsid;
	originds->ds_snapnames_zapobj = snapmapid;
	snapds->ds_next_snap_obj = origindsid;
	snapds->ds_num_children = 2; /* XXX-MJ one for each dataset */

	zap_init(&snapnameszap, mos, snapnames);
	zap_add_uint64(&snapnameszap, "$ORIGIN", snapdsid);
	zap_write(zfs, &snapnameszap);
	zap_write(zfs, &childdirzap);

	rootds = dsl_dataset_alloc(zfs, rootdsldirid, &rootdsid);
	/* XXX-MJ more fields */
	rootds->ds_used_bytes = rootos->space;
	/* XXX-MJ not sure what the difference is here... */
	rootds->ds_uncompressed_bytes = rootds->ds_used_bytes;
	rootds->ds_compressed_bytes = rootds->ds_used_bytes;
	rootds->ds_prev_snap_obj = snapdsid;
	memcpy(&rootds->ds_bp, &rootos->osbp, sizeof(blkptr_t));

	/* XXX-MJ more fields */
	rootdsldir->dd_head_dataset_obj = rootdsid;
	rootdsldir->dd_used_bytes = rootds->ds_used_bytes; /* XXX-MJ add subdirs, $MOS? */
	rootdsldir->dd_compressed_bytes = rootdsldir->dd_uncompressed_bytes =
	    rootdsldir->dd_used_bytes;

	objset_mos_write(zfs);
	pool_labels_write(zfs);
}

/*
 * Visit each node in a directory hierarchy, in pre-order depth-first order.
 */
static void
fsnode_foreach(fsnode *root, void (*cb)(fsnode *, void *), void *arg)
{
	assert(root->type == S_IFDIR);

	for (fsnode *cur = root; cur != NULL; cur = cur->next) {
		assert(cur->type == S_IFREG || cur->type == S_IFDIR ||
		    cur->type == S_IFLNK);

		cb(cur, arg);
		if (cur->type == S_IFDIR && cur->child != NULL)
			fsnode_foreach(cur->child, cb, arg);
	}
}

static void
fs_foreach_count(fsnode *cur, void *arg)
{
	uint64_t *countp;

	countp = arg;
	if (cur->type == S_IFDIR && strcmp(cur->name, ".") == 0)
		return;

	if (cur->inode->ino == 0) {
		cur->inode->ino = ++(*countp);
		cur->inode->nlink = 1;
	} else {
		cur->inode->nlink++;
	}
}

static struct dnode_cursor *
dnode_cursor_init(zfs_opt_t *zfs, zfs_objset_t *os, dnode_phys_t *dnode,
    off_t size, off_t blksz)
{
	struct dnode_cursor *c;
	uint64_t nbppindir, indlevel, ndatablks, nindblks;

	assert(dnode->dn_nblkptr == 1);
	assert(blksz <= MAXBLOCKSIZE);

	if (blksz == 0) {
		/* Must be between 1<<ashift and 128KB. */
		blksz = MIN(MAXBLOCKSIZE, MAX(1 << zfs->ashift,
		    powerof2(size) ? size : (1ul << flsl(size))));
	}
	assert(powerof2(blksz));

	/*
	 * Do we need indirect blocks?  Figure out how many levels are needed
	 * (indlevel == 1 means no indirect blocks) and how much space is needed
	 * (it has to be allocated up-front to break the dependency cycle
	 * described in objset_mos_write()).
	 */
	ndatablks = size == 0 ? 0 : howmany(size, blksz);
	nindblks = 0;
	for (indlevel = 1, nbppindir = 1; ndatablks > nbppindir; indlevel++) {
		nbppindir *= BLKPTR_PER_INDIR;
		nindblks += howmany(ndatablks, indlevel * nbppindir);
	}
	assert(indlevel < INDIR_LEVELS);

	dnode->dn_nlevels = (uint8_t)indlevel;
	dnode->dn_maxblkid = ndatablks > 0 ? ndatablks - 1 : 0;
	dnode->dn_datablkszsec = blksz >> MINBLOCKSHIFT;
	dnode->dn_flags = DNODE_FLAG_USED_BYTES;
	assert(dnode->dn_used == 0);
	dnode->dn_used = nindblks * MAXBLOCKSIZE;

	c = ecalloc(1, sizeof(*c));
	if (nindblks > 0) {
		c->indspace = nindblks * MAXBLOCKSIZE;
		c->indloc = objset_space_alloc(zfs, os, &c->indspace);
	}
	c->dnode = dnode;
	c->dataoff = 0;
	c->datablksz = blksz;

	return (c);
}

static void
_dnode_cursor_flush(zfs_opt_t *zfs, struct dnode_cursor *c, int levels)
{
	blkptr_t *bp, *pbp;
	void *buf;
	uint64_t fill;
	off_t blkid, blksz, loc;

	assert(levels > 0);
	assert(levels <= c->dnode->dn_nlevels - 1);

	blksz = MAXBLOCKSIZE;
	blkid = (c->dataoff / c->datablksz) / BLKPTR_PER_INDIR;
	for (int level = 1; level <= levels; level++) {
		buf = c->inddir[level - 1];

		if (level == c->dnode->dn_nlevels - 1) {
			pbp = &c->dnode->dn_blkptr[0];
		} else {
			uint64_t iblkid;

			iblkid = blkid & (BLKPTR_PER_INDIR - 1);
			pbp = (blkptr_t *)
			    &c->inddir[level][iblkid * sizeof(blkptr_t)];
		}

		/*
		 * Space for indirect blocks is allocated up-front; see the
		 * comment in objset_mos_write().
		 */
		loc = c->indloc;
		c->indloc += blksz;
		assert(c->indspace >= blksz);
		c->indspace -= blksz;

		bp = buf;
		fill = 0;
		for (size_t i = 0; i < BLKPTR_PER_INDIR; i++)
			fill += BP_GET_FILL(&bp[i]);

		vdev_pwrite_dnode_indir(zfs, c->dnode, buf, blksz, loc, pbp);
		/* XXXMJ ugly fixup */
		BP_SET_FILL(bp, fill);
		memset(buf, 0, MAXBLOCKSIZE);

		blkid /= BLKPTR_PER_INDIR;
	}
}

static blkptr_t *
dnode_cursor_next(zfs_opt_t *zfs, struct dnode_cursor *c, off_t off)
{
	off_t blkid, l1id;
	int levels;

	if (c->dnode->dn_nlevels == 1) {
		assert(off < MAXBLOCKSIZE);
		return (&c->dnode->dn_blkptr[0]);
	}

	assert(off % c->datablksz == 0);

	/* Do we need to flush any full indirect blocks? */
	if (off > 0) {
		blkid = off / c->datablksz;
		for (levels = 0; levels < c->dnode->dn_nlevels - 1; levels++) {
			if (blkid % BLKPTR_PER_INDIR != 0)
				break;
			blkid /= BLKPTR_PER_INDIR;
		}
		if (levels > 0)
			_dnode_cursor_flush(zfs, c, levels);
	}

	c->dataoff = off;
	l1id = (off / c->datablksz) & (BLKPTR_PER_INDIR - 1);
	return ((blkptr_t *)&c->inddir[0][l1id * sizeof(blkptr_t)]);
}

static void
dnode_cursor_finish(zfs_opt_t *zfs, struct dnode_cursor *c)
{
	int levels;

	levels = c->dnode->dn_nlevels - 1;
	if (levels > 0)
		_dnode_cursor_flush(zfs, c, levels);
	assert(c->indspace == 0);
	free(c);
}

struct fs_populate_dir {
	SLIST_ENTRY(fs_populate_dir) next;
	int			dirfd;
	uint64_t		objid;
	zfs_zap_t		zap;
};

struct fs_populate_arg {
	zfs_opt_t	*zfs;
	zfs_fs_t	*fs;			/* owning filesystem */
	int		dirfd;			/* root directory fd */
	uint64_t	rootdirid;		/* root directory dnode ID */
	SLIST_HEAD(, fs_populate_dir) dirs;	/* stack of directories */
};

static void
fs_populate_dirent(struct fs_populate_arg *arg, fsnode *cur, uint64_t dnid)
{
	struct fs_populate_dir *dir;
	uint64_t type;

	switch (cur->type) {
	case S_IFREG:
		type = DT_REG;
		break;
	case S_IFDIR:
		type = DT_DIR;
		break;
	case S_IFLNK:
		type = DT_LNK;
		break;
	default:
		assert(0);
	}

	dir = SLIST_FIRST(&arg->dirs);
	zap_add_uint64(&dir->zap, cur->name, ZFS_DIRENT_MAKE(type, dnid));
}

static void
fs_populate_attr(zfs_fs_t *fs, char *attrbuf, const void *val, uint16_t ind,
    size_t *szp)
{
	assert(ind < fs->sacnt);
	assert(fs->saoffs[ind] != 0xffff);

	memcpy(attrbuf + fs->saoffs[ind], val, fs->satab[ind].size);
	*szp += fs->satab[ind].size;
}

static void
fs_populate_varszattr(zfs_fs_t *fs, char *attrbuf, const void *val,
    size_t valsz, size_t varoff, uint16_t ind, size_t *szp)
{
	assert(ind < fs->sacnt);
	assert(fs->saoffs[ind] != 0xffff);
	assert(fs->satab[ind].size == 0);

	memcpy(attrbuf + fs->saoffs[ind] + varoff, val, valsz);
	*szp += valsz;
}

static void
fs_populate_sattrs(struct fs_populate_arg *arg, const fsnode *cur,
    dnode_phys_t *dnode)
{
	char target[PATH_MAX];
	const fsnode *child;
	zfs_fs_t *fs;
	zfs_ace_hdr_t aces[3];
	struct stat *sb;
	sa_hdr_phys_t *sahdr;
	uint64_t daclcount, flags, gen, gid, links, mode, parent, objsize, uid;
	char *attrbuf;
	size_t bonussz, hdrsz;
	int layout;

	assert(dnode->dn_bonustype == DMU_OT_SA);
	assert(dnode->dn_nblkptr == 1);

	fs = arg->fs;
	sb = &cur->inode->st;

	switch (cur->type) {
	case S_IFREG:
		layout = SA_LAYOUT_INDEX;
		links = cur->inode->nlink;
		objsize = sb->st_size;
		break;
	case S_IFDIR: {
		unsigned int children, subdirs;

		children = 1; /* .. */
		subdirs = 0;
		if (cur->type == S_IFDIR) {
			/*
			 * A weird special case for the root directory: if the
			 * directory has no parent, it's the root and its
			 * children are linked as siblings.
			 */
			for (child =
			    (cur->parent == NULL && cur->first == cur) ?
			    cur->next : cur->child;
			    child != NULL; child = child->next) {
				if (child->type == S_IFDIR)
					subdirs++;
				children++;
			}
		}

		layout = SA_LAYOUT_INDEX;
		links = subdirs + 1;
		objsize = children;
		break;
		}
	case S_IFLNK:
		if (readlinkat(SLIST_FIRST(&arg->dirs)->dirfd, cur->name,
		    target, sizeof(target)) == -1)
			err(1, "readlink(%s)", cur->name);

		layout = SA_LAYOUT_INDEX_SYMLINK;
		links = 1;
		objsize = strlen(target);
		break;
	default:
		assert(0);
	}

	daclcount = nitems(aces);
	flags = ZFS_ACL_TRIVIAL | ZFS_ACL_AUTO_INHERIT | ZFS_NO_EXECS_DENIED |
	    ZFS_ARCHIVE | ZFS_AV_MODIFIED; /* XXX-MJ */
	gen = 1;
	gid = sb->st_gid;
	mode = sb->st_mode;
	parent = SLIST_FIRST(&arg->dirs)->objid;
	uid = sb->st_uid;

	/* XXX-MJ need to review these */
	memset(aces, 0, sizeof(aces));
	aces[0].z_flags = ACE_OWNER;
	aces[0].z_type = ACE_ACCESS_ALLOWED_ACE_TYPE;
	aces[0].z_access_mask = ACE_READ_DATA | ACE_WRITE_ATTRIBUTES |
	    ACE_WRITE_OWNER | ACE_WRITE_ACL | ACE_WRITE_NAMED_ATTRS |
	    ACE_READ_ACL | ACE_READ_ATTRIBUTES | ACE_READ_NAMED_ATTRS |
	    ACE_SYNCHRONIZE;
	aces[1].z_flags = ACE_GROUP | ACE_IDENTIFIER_GROUP;
	aces[1].z_type = ACE_ACCESS_ALLOWED_ACE_TYPE;
	aces[1].z_access_mask = ACE_READ_DATA | ACE_READ_ACL |
	    ACE_READ_ATTRIBUTES | ACE_READ_NAMED_ATTRS | ACE_SYNCHRONIZE;
	aces[2].z_flags = ACE_EVERYONE;
	aces[2].z_type = ACE_ACCESS_ALLOWED_ACE_TYPE;
	aces[2].z_access_mask = ACE_READ_DATA | ACE_READ_ACL |
	    ACE_READ_ATTRIBUTES | ACE_READ_NAMED_ATTRS | ACE_SYNCHRONIZE;

	/*
	 * With a header size of 8, there is room for at most 3 variable-length
	 * attributes.
	 */
	if (layout == SA_LAYOUT_INDEX)
		hdrsz = sizeof(uint64_t);
	else
		hdrsz = sizeof(uint64_t) * 2;

	sahdr = (sa_hdr_phys_t *)DN_BONUS(dnode);
	sahdr->sa_magic = SA_MAGIC;
	SA_HDR_LAYOUT_INFO_ENCODE(sahdr->sa_layout_info, layout, hdrsz);

	bonussz = SA_HDR_SIZE(sahdr);
	attrbuf = (char *)sahdr + SA_HDR_SIZE(sahdr);

	fs_populate_attr(fs, attrbuf, &daclcount, ZPL_DACL_COUNT, &bonussz);
	fs_populate_attr(fs, attrbuf, &flags, ZPL_FLAGS, &bonussz);
	fs_populate_attr(fs, attrbuf, &gen, ZPL_GEN, &bonussz);
	fs_populate_attr(fs, attrbuf, &gid, ZPL_GID, &bonussz);
	fs_populate_attr(fs, attrbuf, &links, ZPL_LINKS, &bonussz);
	fs_populate_attr(fs, attrbuf, &mode, ZPL_MODE, &bonussz);
	fs_populate_attr(fs, attrbuf, &parent, ZPL_PARENT, &bonussz);
	fs_populate_attr(fs, attrbuf, &objsize, ZPL_SIZE, &bonussz);
	fs_populate_attr(fs, attrbuf, &uid, ZPL_UID, &bonussz);

	assert(sizeof(sb->st_atim) == fs->satab[ZPL_ATIME].size);
	fs_populate_attr(fs, attrbuf, &sb->st_atim, ZPL_ATIME, &bonussz);
	assert(sizeof(sb->st_ctim) == fs->satab[ZPL_CTIME].size);
	fs_populate_attr(fs, attrbuf, &sb->st_ctim, ZPL_CTIME, &bonussz);
	assert(sizeof(sb->st_mtim) == fs->satab[ZPL_MTIME].size);
	fs_populate_attr(fs, attrbuf, &sb->st_mtim, ZPL_MTIME, &bonussz);
	assert(sizeof(sb->st_birthtim) == fs->satab[ZPL_CRTIME].size);
	fs_populate_attr(fs, attrbuf, &sb->st_birthtim, ZPL_CRTIME, &bonussz);

	fs_populate_varszattr(fs, attrbuf, aces, sizeof(aces), 0,
	    ZPL_DACL_ACES, &bonussz);
	sahdr->sa_lengths[0] = sizeof(aces);

	if (cur->type == S_IFLNK) {
		/* Need to use a spill block pointer if the target is long. */
		assert(bonussz + objsize <= DN_OLD_MAX_BONUSLEN);
		fs_populate_varszattr(fs, attrbuf, target, objsize,
		    sahdr->sa_lengths[0], ZPL_SYMLINK, &bonussz);
		sahdr->sa_lengths[1] = (uint16_t)objsize;
	}

	dnode->dn_bonuslen = bonussz;
}

static void
fs_populate_file(fsnode *cur, struct fs_populate_arg *arg)
{
	struct dnode_cursor *c;
	dnode_phys_t *dnode;
	zfs_opt_t *zfs;
	uint64_t dnid;
	ssize_t n;
	size_t bufsz;
	off_t size, target;
	int fd;

	assert(cur->type == S_IFREG);

	zfs = arg->zfs;

	if ((cur->inode->flags & FI_ALLOCATED) != 0) {
		/*
		 * This is a hard link of an existing file.
		 *
		 * XXX-MJ need to check whether it crosses datasets, add a test
		 * case for that
		 */
		fs_populate_dirent(arg, cur, cur->inode->ino);
		return;
	}

	dnid = cur->inode->ino;
	assert(dnid != 0);
	size = cur->inode->st.st_size;

	dnode = objset_dnode_bonus_alloc(&arg->fs->os,
	    DMU_OT_PLAIN_FILE_CONTENTS, DMU_OT_SA, 0, &dnid);
	c = dnode_cursor_init(zfs, &arg->fs->os, dnode, size, 0);

	bufsz = sizeof(zfs->filebuf);

	fd = openat(SLIST_FIRST(&arg->dirs)->dirfd, cur->name, O_RDONLY);
	if (fd == -1)
		err(1, "openat(%s)", cur->name);
	for (off_t foff = 0; foff < size; foff += target) {
		blkptr_t *bp;
		off_t loc, sofar;

		/* Fill up our buffer, handling partial reads. */
		sofar = 0;
		target = MIN(size - foff, (off_t)bufsz);
		do {
			n = read(fd, zfs->filebuf + sofar, target);
			if (n < 0)
				err(1, "reading from '%s'", cur->name);
			if (n == 0)
				errx(1, "unexpected EOF reading '%s'",
				    cur->name);
			sofar += n;
		} while (sofar < target);

		if (target < (off_t)bufsz)
			memset(zfs->filebuf + target, 0, bufsz - target);

		loc = objset_space_alloc(zfs, &arg->fs->os, &target);
		assert(target <= MAXBLOCKSIZE);

		bp = dnode_cursor_next(zfs, c, foff);
		vdev_pwrite_dnode_indir(zfs, c->dnode, zfs->filebuf, target,
		    loc, bp);
	}
	(void)close(fd);
	dnode_cursor_finish(zfs, c);

	fs_populate_sattrs(arg, cur, dnode);
	fs_populate_dirent(arg, cur, dnid);

	cur->inode->ino = dnid;
	cur->inode->flags |= FI_ALLOCATED;
}

static void
fs_populate_dir(fsnode *cur, struct fs_populate_arg *arg)
{
	struct fs_populate_dir *dir;
	dnode_phys_t *dnode;
	zfs_objset_t *os;
	uint64_t dnid;
	int dirfd;

	assert(cur->type == S_IFDIR);
	assert((cur->inode->flags & FI_ALLOCATED) == 0);

	os = &arg->fs->os;

	dnode = objset_dnode_bonus_alloc(os, DMU_OT_DIRECTORY_CONTENTS,
	    DMU_OT_SA, 0, &dnid);

	/*
	 * Add an entry to the parent directory and open this directory.
	 *
	 * fsnodes in theory provide the full path relative to the root
	 * directory, but in practice do not when an mtree manifest is used to
	 * describe the input tree.
	 */
	if (!SLIST_EMPTY(&arg->dirs)) {
		fs_populate_dirent(arg, cur, dnid);
		dirfd = openat(SLIST_FIRST(&arg->dirs)->dirfd, cur->name,
		    O_DIRECTORY);
		if (dirfd < 0)
			err(1, "open(%s)", cur->name);
	} else {
		arg->rootdirid = dnid;
		dirfd = arg->dirfd;
	}

	dir = ecalloc(1, sizeof(*dir));
	dir->dirfd = dirfd;
	dir->objid = dnid;
	zap_init(&dir->zap, os, dnode);
	SLIST_INSERT_HEAD(&arg->dirs, dir, next);

	fs_populate_sattrs(arg, cur, dnode);
}

static void
fs_populate_symlink(fsnode *cur, struct fs_populate_arg *arg)
{
	dnode_phys_t *dnode;
	uint64_t dnid;

	assert(cur->type == S_IFLNK);
	assert((cur->inode->flags & FI_ALLOCATED) == 0);

	dnode = objset_dnode_bonus_alloc(&arg->fs->os,
	    DMU_OT_PLAIN_FILE_CONTENTS, DMU_OT_SA, 0, &dnid);

	fs_populate_dirent(arg, cur, dnid);

	fs_populate_sattrs(arg, cur, dnode);
}

static void
fs_foreach_populate(fsnode *cur, void *_arg)
{
	struct fs_populate_arg *arg;
	struct fs_populate_dir *dir;

	arg = _arg;
	switch (cur->type) {
	case S_IFREG:
		fs_populate_file(cur, arg);
		break;
	case S_IFDIR:
		if (strcmp(cur->name, ".") == 0)
			break;
		fs_populate_dir(cur, arg);
		break;
	case S_IFLNK:
		fs_populate_symlink(cur, arg);
		break;
	default:
		assert(0);
	}

	if (cur->next == NULL && cur->child == NULL) {
		/*
		 * We reached a terminal node in a subtree.  Walk back up and
		 * write out directories.
		 */
		do {
			dir = SLIST_FIRST(&arg->dirs);
			SLIST_REMOVE_HEAD(&arg->dirs, next);
			zap_write(arg->zfs, &dir->zap);
			(void)close(dir->dirfd);
			free(dir);
			cur = cur->parent;
		} while (cur != NULL && cur->next == NULL);
	}
}

static void
fs_add_zpl_attr_layout(zfs_zap_t *zap, unsigned int index,
    const sa_attr_type_t layout[], size_t sacnt)
{
	char ti[16];

	assert(sizeof(layout[0]) == 2);

	snprintf(ti, sizeof(ti), "%u", index);
	zap_add(zap, ti, sizeof(sa_attr_type_t), sacnt,
	    (const uint8_t *)layout);
}

/*
 * Initialize system attribute tables.
 *
 * There are two elements to this.  First, we write the zpl_attrs[] and
 * zpl_attr_layout[] tables to disk.  Then we create a lookup table which
 * allows us to set file attributes quickly.
 */
static uint64_t
fs_add_zpl_attrs(zfs_opt_t *zfs, zfs_fs_t *fs)
{
	zfs_zap_t sazap, salzap, sarzap;
	zfs_objset_t *os;
	dnode_phys_t *saobj, *salobj, *sarobj;
	uint64_t saobjid, salobjid, sarobjid;
	uint16_t offset;

	os = &fs->os;

	/*
	 * The on-disk tables are stored in two ZAP objects, the registry object
	 * and the layout object.  Individual attributes are described by
	 * entries in the registry object; for example, the value for the
	 * "ZPL_SIZE" key gives the size and encoding of the ZPL_SIZE attribute.
	 * The attributes of a file are ordered according to one of the layouts
	 * defined in the layout object.  The master node object is simply used
	 * to locate the registry and layout objects.
	 */
	saobj = objset_dnode_alloc(os, DMU_OT_SA_MASTER_NODE, &saobjid);
	salobj = objset_dnode_alloc(os, DMU_OT_SA_ATTR_LAYOUTS, &salobjid);
	sarobj = objset_dnode_alloc(os, DMU_OT_SA_ATTR_REGISTRATION, &sarobjid);

	zap_init(&sarzap, os, sarobj);
	for (size_t i = 0; i < nitems(zpl_attrs); i++) {
		const zfs_sattr_t *sa;
		uint64_t attr;

		attr = 0;
		sa = &zpl_attrs[i];
		SA_ATTR_ENCODE(attr, (uint64_t)i, sa->size, sa->bs);
		zap_add_uint64(&sarzap, sa->name, attr);
	}
	zap_write(zfs, &sarzap);

	/*
	 * Layouts are arrays of indices into the registry.  We define two
	 * layouts for use by the ZPL, one for non-symlinks and one for
	 * symlinks.  They are identical except that the symlink layout includes
	 * ZPL_SYMLINK as its final attribute.
	 */
	zap_init(&salzap, os, salobj);
	assert(zpl_attr_layout[nitems(zpl_attr_layout) - 1] == ZPL_SYMLINK);
	fs_add_zpl_attr_layout(&salzap, SA_LAYOUT_INDEX, zpl_attr_layout,
	    nitems(zpl_attr_layout) - 1);
	fs_add_zpl_attr_layout(&salzap, SA_LAYOUT_INDEX_SYMLINK,
	    zpl_attr_layout, nitems(zpl_attr_layout));
	zap_write(zfs, &salzap);

	zap_init(&sazap, os, saobj);
	zap_add_uint64(&sazap, SA_LAYOUTS, salobjid);
	zap_add_uint64(&sazap, SA_REGISTRY, sarobjid);
	zap_write(zfs, &sazap);

	/* Sanity check. */
	for (size_t i = 0; i < nitems(zpl_attrs); i++)
		assert(i == zpl_attrs[i].id);

	/*
	 * Build the offset table used when setting file attributes.  File
	 * attributes are stored in the object's bonus buffer; this table
	 * provides the buffer offset of attributes referenced by the layout
	 * table.
	 */
	fs->sacnt = nitems(zpl_attrs);
	fs->saoffs = ecalloc(fs->sacnt, sizeof(*fs->saoffs));
	for (size_t i = 0; i < fs->sacnt; i++)
		fs->saoffs[i] = 0xffff;
	offset = 0;
	for (size_t i = 0; i < nitems(zpl_attr_layout); i++) {
		uint16_t size;

		assert(zpl_attr_layout[i] < fs->sacnt);

		fs->saoffs[zpl_attr_layout[i]] = offset;
		size = zpl_attrs[zpl_attr_layout[i]].size;
		offset += size;
	}
	fs->satab = zpl_attrs;

	return (saobjid);
}

static void
fs_build(zfs_opt_t *zfs, zfs_fs_t *fs, int rootdirfd, fsnode *root)
{
	struct fs_populate_arg poparg;
	zfs_zap_t deleteqzap, masterzap;
	zfs_objset_t *os;
	dnode_phys_t *deleteq, *masterobj;
	uint64_t deleteqid, dnodecount, moid, saobjid;

	os = &fs->os;

	/*
	 * Figure out how many dnodes we need.  One for each ZPL object (file,
	 * directory, etc.), plus some objects for metadata.
	 */
	dnodecount = 0;
	fsnode_foreach(root, fs_foreach_count, &dnodecount);
	dnodecount++; /* meta dnode */
	dnodecount++; /* master object */
	dnodecount++; /* delete queue */
	dnodecount++; /* system attributes master node */
	dnodecount++; /* system attributes registry */
	dnodecount++; /* system attributes layout */

	/*
	 * Initialize our object set and allocate the dnode array.  Each
	 * filesystem object gets a 512-byte dnode, so the memory usage is
	 * significant.  However, we can build a FreeBSD distribution with less
	 * than 50MB devoted to dnodes, which doesn't seem prohibitive, so let's
	 * keep it simple for now.
	 */
	objset_init(zfs, os, DMU_OST_ZFS, dnodecount);
	masterobj = objset_dnode_alloc(os, DMU_OT_MASTER_NODE, &moid);
	assert(moid == MASTER_NODE_OBJ);

	/*
	 * Create the ZAP SA layout now since filesystem object dnodes will
	 * refer to those attributes.
	 */
	saobjid = fs_add_zpl_attrs(zfs, fs);

	/*
	 * Build the filesystem hierarchy.  The bulk of this program's runtime
	 * is spent here.
	 */
	poparg.dirfd = rootdirfd;
	poparg.zfs = zfs;
	poparg.fs = fs;
	SLIST_INIT(&poparg.dirs);
	fs_populate_dir(root, &poparg);
	assert(!SLIST_EMPTY(&poparg.dirs));
	fsnode_foreach(root, fs_foreach_populate, &poparg);
	assert(SLIST_EMPTY(&poparg.dirs));

	/*
	 * Create an empty delete queue.  We don't do anything with it, but
	 * OpenZFS will refuse to mount filesystems that don't have one.
	 */
	deleteq = objset_dnode_alloc(os, DMU_OT_UNLINKED_SET, &deleteqid);
	zap_init(&deleteqzap, os, deleteq);
	zap_write(zfs, &deleteqzap);

	/*
	 * Populate the master node object.  This is a ZAP object containing
	 * various dataset properties and the object IDs of the root directory
	 * and delete queue.
	 */
	zap_init(&masterzap, os, masterobj);
	zap_add_uint64(&masterzap, ZFS_ROOT_OBJ, poparg.rootdirid);
	zap_add_uint64(&masterzap, ZFS_UNLINKED_SET, deleteqid);
	zap_add_uint64(&masterzap, ZFS_SA_ATTRS, saobjid);
	/* XXX-MJ create a ZFS_SHARES_DIR directory, OpenZFS won't do it */
	zap_add_uint64(&masterzap, ZPL_VERSION_OBJ, 5 /* ZPL_VERSION_SA */);
	zap_add_uint64(&masterzap, "normalization", 0 /* off */);
	zap_add_uint64(&masterzap, "utf8only", 0 /* off */);
	zap_add_uint64(&masterzap, "casesensitivity", 0 /* case sensitive */);
	zap_add_uint64(&masterzap, "acltype", 2 /* NFSv4 */);
	zap_write(zfs, &masterzap);
}

void
zfs_makefs(const char *image, const char *dir, fsnode *root, fsinfo_t *fsopts)
{
	zfs_opt_t *zfs;
	int dirfd;

	zfs = fsopts->fs_specific;

	/*
	 * Use a fixed seed to provide reproducible pseudo-random numbers for
	 * on-disk structures when needed (e.g., ZAP hash salts).
	 */
	srandom(1729);

	if (fsopts->offset != 0)
		errx(1, "unhandled offset option");

	dirfd = open(dir, O_DIRECTORY | O_RDONLY);
	if (dirfd < 0)
		err(1, "open(%s)", dir);

	vdev_init(zfs, fsopts->maxsize, image);
	pool_init(zfs);
	fs_build(zfs, &zfs->rootfs, dirfd, root);
	pool_fini(zfs);
	vdev_fini(zfs);

	(void)close(dirfd);
}
