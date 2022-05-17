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
#include <sys/errno.h>
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
 * - documentation
 * - review checksum algorithm selection (most should likely be "inherit"?)
 * - review vdev_space_alloc()
 * - review type usage (off_t vs. size_t vs. uint64_t)
 * - inconsistency in variable/field naming (how to name a dnode vs dnode id)
 * - bootfs property, bootenvs
 * - ZFS_SHARES_DIR
 */

#define	MAXBLOCKSHIFT		17	/* 128KB */
#define	MAXBLOCKSIZE		((off_t)(1 << MAXBLOCKSHIFT))
_Static_assert(MAXBLOCKSIZE == SPA_OLDMAXBLOCKSIZE, "");
#define	MINBLOCKSHIFT		9	/* 512B */
#define	MINBLOCKSIZE		((off_t)(1 << MINBLOCKSHIFT))
_Static_assert(MINBLOCKSIZE == SPA_MINBLOCKSIZE, "");

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
	objset_phys_t	*phys;
	off_t		osloc;
	off_t		osblksz;
	blkptr_t	osbp;		/* set in objset_write() */

	off_t		space;		/* bytes allocated to this objset */

	dnode_phys_t	*dnodes;	/* dnode array */
	uint64_t	dnodenextfree;	/* dnode ID bump allocator */
	uint64_t	dnodecount;	/* total number of dnodes */
	off_t		dnodeloc;	/* preallocated vdev space */
} zfs_objset_t;

typedef struct zfs_zap_entry {
	char		*name;		/* entry key, private copy */
	uint64_t	hash;		/* key hash */
	union {
		uint8_t	 *valp;
		uint16_t *val16p;
		uint32_t *val32p;
		uint64_t *val64p;
	};				/* entry value, an integer array */
	uint64_t	val64;		/* embedded value for a common case */
	size_t		intsz;		/* array element size; 1, 2, 4 or 8 */
	size_t		intcnt;		/* array size */
	STAILQ_ENTRY(zfs_zap_entry) next;
} zfs_zap_entry_t;

typedef struct zfs_zap {
	STAILQ_HEAD(, zfs_zap_entry) kvps;
	uint64_t	hashsalt;	/* key hash input */
	unsigned long	kvpcnt;		/* number of key-value pairs */
	unsigned long	chunks;		/* count of chunks needed for fat ZAP */
	bool		micro;		/* can this be a micro ZAP? */

	dnode_phys_t	*dnode;		/* backpointer */
	zfs_objset_t	*os;		/* backpointer */
} zfs_zap_t;

struct zfs_dsl_dir;

typedef struct zfs_dsl_dataset {
	zfs_objset_t	*os;
	dsl_dataset_phys_t *phys;
	uint64_t	dsid;		/* DSL dataset dnode */

	struct zfs_dsl_dir *dir;	/* containing parent */
} zfs_dsl_dataset_t;

typedef STAILQ_HEAD(zfs_dsl_dir_list, zfs_dsl_dir) zfs_dsl_dir_list_t;

typedef struct zfs_dsl_dir {
	char		*fullname;	/* full dataset name */
	char		*name;		/* basename(fullname) */
	dsl_dir_phys_t	*phys;
	nvlist_t	*propsnv;	/* properties saved in propszap */

	zfs_dsl_dataset_t *headds;

	uint64_t	dirid;		/* DSL directory dnode */
	zfs_zap_t	propszap;	/* dataset properties */
	zfs_zap_t	childzap;	/* child directories */

	/* DSL directory tree linkage. */
	struct zfs_dsl_dir *parent;
	zfs_dsl_dir_list_t children;
	STAILQ_ENTRY(zfs_dsl_dir) next;
} zfs_dsl_dir_t;

typedef struct zfs_fs {
	zfs_objset_t	*os;

	/* Offset table for system attributes, indexed by a zpl_attr_t. */
	uint16_t	*saoffs;
	size_t		sacnt;
	const zfs_sattr_t *satab;
} zfs_fs_t;

struct dataset_desc {
	char		*params;
	STAILQ_ENTRY(dataset_desc) next;
};

typedef struct {
	/* I/O buffer, just for convenience. */
	char		filebuf[MAXBLOCKSIZE];

	/* Pool parameters. */
	const char	*poolname;
	char		*rootpath;	/* XXX-MJ */
	int		ashift;		/* vdev block size */
	STAILQ_HEAD(, dataset_desc) datasets;

	/* Pool state. */
	uint64_t	guid;		/* pool and vdev GUID */

	/* MOS state. */
	zfs_objset_t	mos;		/* meta object set */
	uint64_t	objarrid;	/* space map object array */

	/* DSL state. */
	zfs_dsl_dir_t	rootdsldir;
	zfs_dsl_dataset_t rootds;
	zfs_dsl_dir_t	origindsldir;
	zfs_dsl_dataset_t originds;
	zfs_dsl_dataset_t snapds;
	zfs_dsl_dir_t	freedsldir;
	zfs_dsl_dir_t	mosdsldir;

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

static void dsl_dir_init(zfs_opt_t *, const char *, zfs_dsl_dir_t *);
static void dsl_dataset_init(zfs_opt_t *, zfs_dsl_dir_t *, zfs_dsl_dataset_t *);

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

static void fs_build_one(zfs_opt_t *, fsnode *, int);

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

/*
 * This layout matches that of a filesystem created using OpenZFS on FreeBSD.
 * It need not match in general, but FreeBSD's loader doesn't bother parsing the
 * layout and just hard-codes attribute offsets.
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
 * Keys for the ZPL attribute tables in the SA layout ZAP.  The first two
 * indices are reserved for legacy attribute encoding.
 */
#define	SA_LAYOUT_INDEX_DEFAULT	2
#define	SA_LAYOUT_INDEX_SYMLINK	3

void
zfs_prep_opts(fsinfo_t *fsopts)
{
	zfs_opt_t *zfs = ecalloc(1, sizeof(*zfs));

	const option_t zfs_options[] = {
		{ '\0', "poolname", &zfs->poolname, OPT_STRPTR,
		  0, 0, "ZFS pool name" },
		{ '\0', "rootpath", &zfs->rootpath, OPT_STRPTR,
		  0, 0, "XXX-MJ call it rootpath" },
		{ '\0', "ashift", &zfs->ashift, OPT_INT32,
		  MINBLOCKSHIFT, MAXBLOCKSHIFT, "ZFS pool ashift" },
		{ .name = NULL }
	};

	/* Set some default values. */
	zfs->ashift = 12;

	STAILQ_INIT(&zfs->datasets);

	fsopts->fs_specific = zfs;
	fsopts->fs_options = copy_opts(zfs_options);
}

int
zfs_parse_opts(const char *option, fsinfo_t *fsopts)
{
	zfs_opt_t *zfs;
	struct dataset_desc *dsdesc;
	char buf[BUFSIZ], *opt, *val;
	int rv;

	zfs = fsopts->fs_specific;

	opt = val = estrdup(option);
	opt = strsep(&val, "=");
	if (strcmp(opt, "fs") == 0) {
		if (val == NULL)
			errx(1, "invalid filesystem parameters `%s'", option);

		/*
		 * Dataset descriptions will be parsed later, in dsl_init().
		 * Just stash them away for now.
		 */
		dsdesc = ecalloc(1, sizeof(*dsdesc));
		dsdesc->params = estrdup(val);
		free(opt);
		STAILQ_INSERT_TAIL(&zfs->datasets, dsdesc, next);
		return (1);
	}
	free(opt);

	rv = set_option(fsopts->fs_options, option, buf, sizeof(buf));
	return (rv == -1 ? 0 : 1);
}

static void
zfs_check_opts(fsinfo_t *fsopts)
{
	zfs_opt_t *zfs;

	zfs = fsopts->fs_specific;

	if (fsopts->offset != 0)
		errx(1, "unhandled offset option");
	if (zfs->poolname == NULL)
		errx(1, "a pool name must be specified");
	if (zfs->rootpath == NULL)
		easprintf(&zfs->rootpath, "/%s", zfs->poolname);
	if (zfs->rootpath[0] != '/')
		errx(1, "mountpoint `%s' must be absolute", zfs->rootpath);
}

void
zfs_cleanup_opts(fsinfo_t *fsopts)
{
	struct dataset_desc *d, *tmp;
	zfs_opt_t *zfs;

	zfs = fsopts->fs_specific;
	free(zfs->rootpath);
	free(__DECONST(void *, zfs->poolname));
	STAILQ_FOREACH_SAFE(d, &zfs->datasets, next, tmp) {
		free(d->params);
		free(d);
	}
	free(zfs);
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
blkptr_set(blkptr_t *bp, off_t off, off_t size, uint8_t dntype, uint8_t level,
    uint64_t fill, enum zio_checksum cksumt, zio_cksum_t *cksum)
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
vdev_init(zfs_opt_t *zfs, size_t size, const char *image)
{
	assert(zfs->ashift >= MINBLOCKSHIFT);

	zfs->vdevsize = rounddown2(size, 1 << zfs->ashift);
	if (zfs->vdevsize < (off_t)SPA_MINDEVSIZE) {
		errx(1, "Maximum image size %ju is too small",
		    (uintmax_t)zfs->vdevsize);
	}
	zfs->asize = zfs->vdevsize - VDEV_LABEL_SPACE;

	zfs->fd = open(image, O_RDWR | O_CREAT | O_TRUNC, 0644);
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

/*
 * Write a block of data to the vdev.  The offset is always relative to the end
 * of the second leading vdev label.
 *
 * Consumers should generally use the helpers below, which provide block
 * pointers and update dnode accounting, rather than calling this function
 * directly.
 */
static void
vdev_pwrite(const zfs_opt_t *zfs, const void *buf, size_t len, off_t off)
{
	ssize_t n;

	assert(off >= 0 && off < zfs->asize);
	assert(powerof2(len));
	assert((off_t)len > 0 && off + (off_t)len > off &&
	    off + (off_t)len < zfs->asize);
	if (zfs->spacemap != NULL) {
		/*
		 * Verify that the blocks being written were in fact allocated.
		 *
		 * The space map isn't available once the on-disk space map is
		 * finalized, so this check doesn't quite catch everything.
		 */
		assert(bit_ntest(zfs->spacemap, off >> zfs->ashift,
		    (off + len - 1) >> zfs->ashift, 1));
	}

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
    uint8_t level, uint64_t fill, const void *data, off_t sz, off_t loc,
    blkptr_t *bp)
{
	zio_cksum_t cksum;

	assert(cksumtype == ZIO_CHECKSUM_FLETCHER_4);

	fletcher_4_native(data, sz, NULL, &cksum);
	blkptr_set(bp, loc, sz, datatype, level, fill, cksumtype, &cksum);
	vdev_pwrite(zfs, data, sz, loc);
}

static void
vdev_pwrite_dnode_indir(zfs_opt_t *zfs, dnode_phys_t *dnode, uint8_t level,
    uint64_t fill, const void *data, off_t sz, off_t loc, blkptr_t *bp)
{
	vdev_pwrite_data(zfs, dnode->dn_type, dnode->dn_checksum, level, fill,
	    data, sz, loc, bp);

	assert((dnode->dn_flags & DNODE_FLAG_USED_BYTES) != 0);
	dnode->dn_used += sz;
}

static void
vdev_pwrite_dnode_data(zfs_opt_t *zfs, dnode_phys_t *dnode, const void *data,
    off_t sz, off_t loc)
{
	vdev_pwrite_dnode_indir(zfs, dnode, 0, 1, data, sz, loc,
	    &dnode->dn_blkptr[0]);
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

	/*
	 * Make a copy since we have to modify the label to set checksums.
	 */
	label = ecalloc(1, sizeof(*label));
	memcpy(label, labelp, sizeof(*label));

	if (ind < 2)
		loff = ind * sizeof(*label);
	else
		loff = zfs->vdevsize - (VDEV_LABELS - ind) * sizeof(*label);

	/*
	 * Set the verifier checksum for the boot block.  We don't use it, but
	 * the FreeBSD loader reads it and will complain if the checksum isn't
	 * valid.
	 */
	vdev_label_set_checksum(&label->vl_be,
	    loff + __offsetof(vdev_label_t, vl_be), sizeof(label->vl_be));

	/*
	 * Set the verifier checksum for the label.
	 */
	vdev_label_set_checksum(&label->vl_vdev_phys,
	    loff + __offsetof(vdev_label_t, vl_vdev_phys),
	    sizeof(label->vl_vdev_phys));

	/*
	 * Set the verifier checksum for the uberblocks.  There is one uberblock
	 * per sector; for example, with an ashift of 12 we end up with
	 * 128KB/4KB=32 copies of the uberblock in the ring.
	 */
	blksz = 1 << zfs->ashift;
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
	free(sma);
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

	/*
	 * Object ID zero is always reserved for the meta dnode, which is
	 * embedded in the objset itself.
	 */
	dnodecount++;

	os->dnodenextfree = 1;
	os->dnodecount = dnodecount;
	blksz = roundup2(dnodecount * sizeof(dnode_phys_t), DNODE_BLOCK_SIZE);
	os->dnodeloc = objset_space_alloc(zfs, os, &blksz);
	assert(blksz % DNODE_BLOCK_SIZE == 0);
	os->dnodes = ecalloc(1, blksz);

	os->phys = ecalloc(1, os->osblksz);
	os->phys->os_type = type;

	mdnode = &os->phys->os_meta_dnode;
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
	mdnode->dn_flags = DNODE_FLAG_USED_BYTES;
}

/*
 * Write the dnode array and physical object set to disk.
 */
static void
_objset_write(zfs_opt_t *zfs, zfs_objset_t *os, struct dnode_cursor *c)
{
	assert(os->dnodenextfree == os->dnodecount);

	/*
	 * Write out the dnode array, i.e., the meta-dnode.  For some reason its
	 * data blocks must be 16KB in size no matter how large the array is.
	 */
	for (uint64_t i = 0; i < os->dnodecount; i += DNODES_PER_BLOCK) {
		dnode_phys_t *blk;
		uint64_t fill;
		off_t loc;

		blk = os->dnodes + i;
		loc = os->dnodeloc + i * sizeof(dnode_phys_t);
		fill = os->dnodecount - i < DNODES_PER_BLOCK ?
		    os->dnodecount - i : 0;

		vdev_pwrite_dnode_indir(zfs, &os->phys->os_meta_dnode,
		    0, fill, blk, DNODE_BLOCK_SIZE, loc,
		    dnode_cursor_next(zfs, c, i * sizeof(dnode_phys_t)));
	}
	dnode_cursor_finish(zfs, c);
	free(os->dnodes);
	os->dnodes = NULL;

	/*
	 * Write the object set itself.  The saved block pointer will be copied
	 * into the referencing DSL dataset or the uberblocks.
	 */
	vdev_pwrite_data(zfs, DMU_OT_OBJSET, ZIO_CHECKSUM_FLETCHER_4, 0, 1,
	    os->phys, os->osblksz, os->osloc, &os->osbp);
}

static void
objset_write(zfs_opt_t *zfs, zfs_objset_t *os)
{
	struct dnode_cursor *c;

	c = dnode_cursor_init(zfs, os, &os->phys->os_meta_dnode,
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
	c = dnode_cursor_init(zfs, mos, &mos->phys->os_meta_dnode,
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

	*idp = os->dnodenextfree;
	dnode = &os->dnodes[os->dnodenextfree++];
	dnode->dn_type = type;
	dnode->dn_indblkshift = MAXBLOCKSHIFT;
	dnode->dn_datablkszsec = os->osblksz >> MINBLOCKSHIFT;
	dnode->dn_nlevels = 1;
	dnode->dn_nblkptr = 1;
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

/*
 * Handle dataset properties that we know about; stash them into an nvlist to be
 * written later to the properties ZAP object.
 *
 * Some of this could perhaps be handled by libzfs...
 */
static void
dsl_dir_set_prop(zfs_dsl_dir_t *dir, const char *key, const char *val)
{
	nvlist_t *nvl;

	nvl = dir->propsnv;
	if (val == NULL || val[0] == '\0')
		errx(1, "missing value for property `%s'", key);
	if (nvpair_find(nvl, key) != NULL)
		errx(1, "property `%s' already set", key);

	if (strcmp(key, "mountpoint") == 0) {
		if (val[0] != '/')
			errx(1, "mountpoint `%s' is not absolute", val);
		nvlist_add_string(nvl, key, val);
	} else if (strcmp(key, "atime") == 0 || strcmp(key, "exec") == 0 ||
	    strcmp(key, "setuid") == 0) {
		if (strcmp(val, "on") == 0)
			nvlist_add_uint64(nvl, key, 1);
		else if (strcmp(val, "off") == 0)
			nvlist_add_uint64(nvl, key, 0);
		else
			errx(1, "invalid value `%s' for %s", val, key);
	} else if (strcmp(key, "canmount") == 0) {
		if (strcmp(val, "noauto") == 0)
			nvlist_add_uint64(nvl, key, 2);
		else if (strcmp(val, "on") == 0)
			nvlist_add_uint64(nvl, key, 1);
		else if (strcmp(val, "off") == 0)
			nvlist_add_uint64(nvl, key, 0);
		else
			errx(1, "invalid value `%s' for %s", val, key);
	} else {
		errx(1, "unknown property `%s'", key);
	}
}

static void
dsl_init_metadir(zfs_opt_t *zfs, const char *name, zfs_dsl_dir_t *dir)
{
	char *path;

	easprintf(&path, "%s/%s", zfs->poolname, name);
	dsl_dir_init(zfs, path, dir);
	free(path);
}

static void
dsl_init(zfs_opt_t *zfs)
{
	zfs_dsl_dir_t *dir;
	struct dataset_desc *d;

	dsl_dir_init(zfs, NULL, &zfs->rootdsldir);

	nvlist_add_uint64(zfs->rootdsldir.propsnv, "compression",
	    ZIO_COMPRESS_OFF);

	dsl_dataset_init(zfs, &zfs->rootdsldir, &zfs->rootds);
	zfs->rootdsldir.headds = &zfs->rootds;

	dsl_init_metadir(zfs, "$MOS", &zfs->mosdsldir);
	dsl_init_metadir(zfs, "$FREE", &zfs->freedsldir);
	dsl_init_metadir(zfs, "$ORIGIN", &zfs->origindsldir);
	dsl_dataset_init(zfs, &zfs->origindsldir, &zfs->originds);
	dsl_dataset_init(zfs, &zfs->origindsldir, &zfs->snapds);

	/*
	 * Go through the list of user-specified datasets and create DSL objects
	 * for them.
	 */
	STAILQ_FOREACH(d, &zfs->datasets, next) {
		char *dsname, *params, *param, *nextparam;

		params = d->params;
		dsname = strsep(&params, ":");

		if (strcmp(dsname, zfs->poolname) == 0) {
			/*
			 * This is the root dataset; it's already created, so
			 * we're just setting options.
			 */
			dir = &zfs->rootdsldir;
		} else {
			dir = ecalloc(1, sizeof(*dir));
			dsl_dir_init(zfs, dsname, dir);
			dir->headds = ecalloc(1, sizeof(*dir->headds));
			dsl_dataset_init(zfs, dir, dir->headds);
		}

		for (nextparam = param = params; nextparam != NULL;) {
			char *key, *val;

			param = strsep(&nextparam, ":");

			key = val = param;
			key = strsep(&val, "=");
			dsl_dir_set_prop(dir, key, val);
		}
	}

	/*
	 * Set the root dataset's mount point if the user didn't override the
	 * default.
	 */
	if (nvpair_find(zfs->rootdsldir.propsnv, "mountpoint") == NULL) {
		nvlist_add_string(zfs->rootdsldir.propsnv, "mountpoint",
		    zfs->rootpath);
	}
}

static void
dsl_dir_foreach_pre(zfs_opt_t *zfs, zfs_dsl_dir_t *dsldir,
    void (*cb)(zfs_opt_t *, zfs_dsl_dir_t *, void *), void *arg)
{
	zfs_dsl_dir_t *cdsldir;

	cb(zfs, dsldir, arg);
	STAILQ_FOREACH(cdsldir, &dsldir->children, next) {
		dsl_dir_foreach_pre(zfs, cdsldir, cb, arg);
	}
}

static void
dsl_dir_foreach_post(zfs_opt_t *zfs, zfs_dsl_dir_t *dsldir,
    void (*cb)(zfs_opt_t *, zfs_dsl_dir_t *, void *), void *arg)
{
	zfs_dsl_dir_t *cdsldir;

	STAILQ_FOREACH(cdsldir, &dsldir->children, next) {
		dsl_dir_foreach_post(zfs, cdsldir, cb, arg);
	}
	cb(zfs, dsldir, arg);
}

/*
 * Used when the caller doesn't care about the order one way or another.
 */
static void
dsl_dir_foreach(zfs_opt_t *zfs, zfs_dsl_dir_t *dsldir,
    void (*cb)(zfs_opt_t *, zfs_dsl_dir_t *, void *), void *arg)
{
	dsl_dir_foreach_pre(zfs, dsldir, cb, arg);
}

/*
 * Create a DSL directory, which is effectively an entry in the ZFS namespace.
 * We always create a root DSL directory, whose name is the pool's name, and
 * several metadata directories.
 *
 * Each directory has two ZAP objects, one pointing to child directories, and
 * one for properties (which are inherited by children unless overridden).
 * Directories typically reference a DSL dataset, the "head dataset", which
 * points to an object set.
 */
static void
dsl_dir_init(zfs_opt_t *zfs, const char *name, zfs_dsl_dir_t *dsldir)
{
	zfs_dsl_dir_list_t l, *lp;
	zfs_dsl_dir_t *parent;
	zfs_objset_t *mos;
	dnode_phys_t *dnode;
	char *dirname, *nextdir, *origname;
	uint64_t childid, propsid;

	mos = &zfs->mos;

	dnode = objset_dnode_bonus_alloc(mos, DMU_OT_DSL_DIR, DMU_OT_DSL_DIR,
	    sizeof(dsl_dir_phys_t), &dsldir->dirid);
	dsldir->phys = (dsl_dir_phys_t *)DN_BONUS(dnode);

	dnode = objset_dnode_alloc(mos, DMU_OT_DSL_PROPS, &propsid);
	zap_init(&dsldir->propszap, mos, dnode);

	dnode = objset_dnode_alloc(mos, DMU_OT_DSL_DIR_CHILD_MAP, &childid);
	zap_init(&dsldir->childzap, mos, dnode);

	dsldir->propsnv = nvlist_create(NV_UNIQUE_NAME);
	STAILQ_INIT(&dsldir->children);

	dsldir->phys->dd_child_dir_zapobj = childid;
	dsldir->phys->dd_props_zapobj = propsid;

	if (name == NULL) {
		/*
		 * This is the root DSL directory.
		 */
		assert(dsldir == &zfs->rootdsldir);
		dsldir->name = estrdup(zfs->poolname);
		dsldir->fullname = estrdup(zfs->poolname);
		dsldir->parent = NULL;
		dsldir->phys->dd_parent_obj = 0;
		return;
	}

	/*
	 * Insert the new directory into the hierarchy.  Currently this must be
	 * done in order, e.g., when creating pool/a/b, pool/a must already
	 * exist.
	 */
	STAILQ_INIT(&l);
	STAILQ_INSERT_HEAD(&l, &zfs->rootdsldir, next);
	origname = dirname = nextdir = estrdup(name);
	for (lp = &l;; lp = &parent->children) {
		dirname = strsep(&nextdir, "/");
		if (nextdir == NULL)
			break;

		STAILQ_FOREACH(parent, lp, next) {
			if (strcmp(parent->name, dirname) == 0)
				break;
		}
		if (parent == NULL) {
			errx(1, "no parent at `%s' for filesystem `%s'",
			    dirname, name);
		}
	}

	dsldir->fullname = estrdup(name);
	dsldir->name = estrdup(dirname);
	free(origname);
	STAILQ_INSERT_TAIL(lp, dsldir, next);
	zap_add_uint64(&parent->childzap, dsldir->name, dsldir->dirid);

	dsldir->parent = parent;
	dsldir->phys->dd_parent_obj = parent->dirid;
}

/*
 * Convert dataset properties into entries in the DSL directory's properties
 * ZAP.
 */
static void
dsl_dir_finalize_props(zfs_dsl_dir_t *dir)
{
	for (nvp_header_t *nvh = NULL;
	    (nvh = nvlist_next_nvpair(dir->propsnv, nvh)) != NULL;) {
		nv_string_t *nvname;
		nv_pair_data_t *nvdata;
		const char *name;

		nvname = (nv_string_t *)(nvh + 1);
		nvdata = (nv_pair_data_t *)(&nvname->nv_data[0] +
		    NV_ALIGN4(nvname->nv_size));

		name = nvstring_get(nvname);
		switch (nvdata->nv_type) {
		case DATA_TYPE_UINT64: {
			uint64_t val;

			memcpy(&val, &nvdata->nv_data[0], sizeof(uint64_t));
			zap_add_uint64(&dir->propszap, name, val);
			break;
		}
		case DATA_TYPE_STRING: {
			nv_string_t *nvstr;

			nvstr = (nv_string_t *)&nvdata->nv_data[0];
			zap_add_string(&dir->propszap, name,
			    nvstring_get(nvstr));
			break;
		}
		default:
			assert(0);
		}
	}
}

static void
dsl_dir_finalize(zfs_opt_t *zfs, zfs_dsl_dir_t *dir, void *arg __unused)
{
	zfs_dsl_dir_t *cdir;
	uint64_t bytes;

	dsl_dir_finalize_props(dir);
	zap_write(zfs, &dir->propszap);
	zap_write(zfs, &dir->childzap);

	if (dir->headds != NULL && dir->headds->os != NULL) {
		zfs_objset_t *os;

		os = dir->headds->os;
		objset_write(zfs, os);

		dir->phys->dd_head_dataset_obj = dir->headds->dsid;
		dir->headds->phys->ds_prev_snap_obj = zfs->snapds.dsid;
		zfs->snapds.phys->ds_num_children++;
		memcpy(&dir->headds->phys->ds_bp, &os->osbp, sizeof(blkptr_t));

		bytes = os->space;
		dir->headds->phys->ds_used_bytes = bytes;
		/* XXX-MJ not sure what the difference is here... */
		dir->headds->phys->ds_uncompressed_bytes = bytes;
		dir->headds->phys->ds_compressed_bytes = bytes;

		STAILQ_FOREACH(cdir, &dir->children, next) {
			bytes += cdir->phys->dd_used_bytes;
		}
		dir->phys->dd_used_bytes = bytes;
		dir->phys->dd_compressed_bytes = bytes;
		dir->phys->dd_uncompressed_bytes = bytes;
	}
}

static void
dsl_write(zfs_opt_t *zfs)
{
	zfs_zap_t snapnameszap;
	zfs_objset_t *mos;
	dnode_phys_t *snapnames;
	uint64_t snapmapid;

	mos = &zfs->mos;

	snapnames = objset_dnode_alloc(mos, DMU_OT_DSL_DS_SNAP_MAP, &snapmapid);

	zfs->origindsldir.phys->dd_head_dataset_obj = zfs->originds.dsid;
	zfs->originds.phys->ds_prev_snap_obj = zfs->snapds.dsid;
	zfs->originds.phys->ds_snapnames_zapobj = snapmapid;
	zfs->snapds.phys->ds_next_snap_obj = zfs->originds.dsid;
	zfs->snapds.phys->ds_num_children = 1;

	zap_init(&snapnameszap, mos, snapnames);
	zap_add_uint64(&snapnameszap, "$ORIGIN", zfs->snapds.dsid);
	zap_write(zfs, &snapnameszap);

	dsl_dir_foreach_post(zfs, &zfs->rootdsldir, dsl_dir_finalize, NULL);

	/*
	 * XXX-MJ this is too early, objset_mos_write() will allocate more space
	 */
	zfs->mosdsldir.phys->dd_used_bytes = mos->space;
	zfs->mosdsldir.phys->dd_compressed_bytes = mos->space;
	zfs->mosdsldir.phys->dd_uncompressed_bytes = mos->space;
}

static void
dsl_dataset_init(zfs_opt_t *zfs, zfs_dsl_dir_t *dir, zfs_dsl_dataset_t *ds)
{
	zfs_zap_t deadlistzap;
	dnode_phys_t *dnode;
	uint64_t deadlistid;

	dnode = objset_dnode_bonus_alloc(&zfs->mos, DMU_OT_DSL_DATASET,
	    DMU_OT_DSL_DATASET, sizeof(dsl_dataset_phys_t), &ds->dsid);
	ds->phys = (dsl_dataset_phys_t *)DN_BONUS(dnode);

	dnode = objset_dnode_bonus_alloc(&zfs->mos, DMU_OT_DEADLIST,
	    DMU_OT_DEADLIST_HDR, sizeof(dsl_deadlist_phys_t), &deadlistid);
	zap_init(&deadlistzap, &zfs->mos, dnode);
	zap_write(zfs, &deadlistzap);

	ds->phys->ds_dir_obj = dir->dirid;
	ds->phys->ds_deadlist_obj = deadlistid;
	ds->phys->ds_creation_txg = TXG_INITIAL;

	ds->dir = dir;
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
	if (intsz == sizeof(uint64_t) && intcnt == 1) {
		/*
		 * Micro-optimization to elide a memory allocation in that most
		 * common case where this is a directory entry.
		 */
		ent->val64p = &ent->val64;
	} else {
		ent->valp = ecalloc(intcnt, intsz);
	}
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
 *
 * Note that individual integers in the value may be split among consecutive
 * leaves.
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

	loc = objset_space_alloc(zfs, zap->os, &blksz);
	assert(blksz == MAXBLOCKSIZE);

	vdev_pwrite_dnode_indir(zfs, dnode, 0, 1, zfs->filebuf, blksz, loc,
	    dnode_cursor_next(zfs, c, 0));

	for (uint64_t i = 0; i < lblkcnt; i++) {
		loc = objset_space_alloc(zfs, zap->os, &blksz);
		assert(blksz == MAXBLOCKSIZE);
		vdev_pwrite_dnode_indir(zfs, dnode, 0, 1, leafblks + i * blksz,
		    blksz, loc, dnode_cursor_next(zfs, c, (i + 1) * blksz));
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
 * nvlist stored in vdev labels.  The main difference is that vdev labels do not
 * describe the full vdev tree and in particular do not contain the "root"
 * meta-vdev.
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
	uint64_t id;

	id = zfs->rootdsldir.dirid;
	assert(id > 0);
	zap_add_uint64(objdir, DMU_POOL_ROOT_DATASET, id);
}

/*
 * Initialize the MOS object directory, the root of virtually all of the pool's
 * data and metadata.
 */
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
	struct dataset_desc *d;
	zfs_objset_t *mos;
	uint64_t dnid, dnodecount;

	zfs->guid = 0xdeadfacec0debeef;

	mos = &zfs->mos;

	/*
	 * Figure out how many dnodes will be allocated from the MOS.
	 */
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
	dnodecount++; /*     |       |-> child map            */
	dnodecount++; /*     |       |-> dataset              */
	dnodecount++; /*     |       |   L-> deadlist         */
	dnodecount++; /*     |       |-> snapshot             */
	dnodecount++; /*     |       |   |-> deadlist         */
	dnodecount++; /*     |       |   L-> snapshot names   */
	dnodecount++; /*     |       L-> props (ZAP)          */
	dnodecount++; /*     |-> DSL root dataset             */
	dnodecount++; /*     |   L-> deadlist                 */
	dnodecount++; /*     L-> props (ZAP)                  */
	/*
	 * Space map stuff.
	 */
	dnodecount++; /* space map object array               */
	dnodecount += zfs->mscount; /* space maps             */
	/*
	 * Child datasets.
	 */
	STAILQ_FOREACH(d, &zfs->datasets, next) {
		char buf[BUFSIZ];

		/* Ugly hack to skip over root dataset parameters. */
		snprintf(buf, sizeof(buf), "%s:", zfs->poolname);
		if (strncmp(buf, d->params, strlen(buf)) == 0)
			continue;

		dnodecount++; /* DSL directory                */
		dnodecount++; /* |-> DSL dataset              */
		dnodecount++; /* |   L-> deadlist             */
		dnodecount++; /* |-> child map                */
		dnodecount++; /* L-> props                    */
	}

	objset_init(zfs, mos, DMU_OST_META, dnodecount);

	(void)objset_dnode_alloc(mos, DMU_OT_OBJECT_DIRECTORY, &dnid);
	assert(dnid == DMU_POOL_DIRECTORY_OBJECT);

	(void)objset_dnode_alloc(mos, DMU_OT_OBJECT_ARRAY, &zfs->objarrid);

	dsl_init(zfs);

	pool_init_objdir(zfs);
}

static void
pool_labels_write(zfs_opt_t *zfs)
{
	uberblock_t *ub;
	vdev_label_t *label;
	nvlist_t *poolconfig, *vdevconfig;
	int error;

	label = ecalloc(1, sizeof(*label));

	/*
	 * Assemble the vdev configuration and store it in the label.
	 */
	poolconfig = pool_config_nvcreate(zfs);
	vdevconfig = pool_disk_vdev_config_nvcreate(zfs);
	nvlist_add_nvlist(poolconfig, ZPOOL_CONFIG_VDEV_TREE, vdevconfig);
	nvlist_destroy(vdevconfig);

	error = nvlist_export(poolconfig);
	if (error != 0)
		errc(1, error, "nvlist_export");
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
	 * Write out four copies of the label: two at the beginning of the vdev
	 * and two at the end.
	 */
	for (int i = 0; i < VDEV_LABELS; i++)
		vdev_label_write(zfs, i, label);

	free(label);
}

static void
pool_fini(zfs_opt_t *zfs)
{
	dsl_write(zfs);
	objset_mos_write(zfs);
	pool_labels_write(zfs);
}

/*
 * Visit each node in a directory hierarchy, in pre-order depth-first order.
 */
static void
fsnode_foreach(fsnode *root, int (*cb)(fsnode *, void *), void *arg)
{
	assert(root->type == S_IFDIR);

	for (fsnode *cur = root; cur != NULL; cur = cur->next) {
		assert(cur->type == S_IFREG || cur->type == S_IFDIR ||
		    cur->type == S_IFLNK);

		if (cb(cur, arg) == 0)
			continue;
		if (cur->type == S_IFDIR && cur->child != NULL)
			fsnode_foreach(cur->child, cb, arg);
	}
}

static int
fs_foreach_count(fsnode *cur, void *arg)
{
	uint64_t *countp;

	countp = arg;
	if (cur->type == S_IFDIR && strcmp(cur->name, ".") == 0) {
		assert((cur->inode->flags & FI_ROOT) == 0);
		return (1);
	}

	if (cur->inode->ino == 0) {
		cur->inode->ino = ++(*countp);
		cur->inode->nlink = 1;
	} else {
		cur->inode->nlink++;
	}

	return ((cur->inode->flags & FI_ROOT) != 0 ? 0 : 1);
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

		vdev_pwrite_dnode_indir(zfs, c->dnode, level, fill, buf, blksz,
		    loc, pbp);
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
	int		dirfd;			/* current directory fd */
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
		layout = SA_LAYOUT_INDEX_DEFAULT;
		links = cur->inode->nlink;
		objsize = sb->st_size;
		parent = SLIST_FIRST(&arg->dirs)->objid;
		break;
	case S_IFDIR:
		layout = SA_LAYOUT_INDEX_DEFAULT;
		links = 1; /* .. */
		objsize = 1; /* .. */

		/*
		 * The size of a ZPL directory is the number of entries
		 * (including "." and ".."), and the link count is the number of
		 * entries which are directories (including "." and "..").
		 *
		 * The loop needs a weird special case for the input root
		 * directory: if the directory has no parent, it's the root and
		 * its children are linked as siblings.
		 */
		for (fsnode *c = (cur->parent == NULL && cur->first == cur) ?
		    cur->next : cur->child; c != NULL; c = c->next) {
			if (c->type == S_IFDIR)
				links++;
			objsize++;
		}

		/* The root directory is its own parent. */
		parent = SLIST_EMPTY(&arg->dirs) ?
		    arg->rootdirid : SLIST_FIRST(&arg->dirs)->objid;
		break;
	case S_IFLNK: {
		ssize_t n;

		if ((n = readlinkat(SLIST_FIRST(&arg->dirs)->dirfd, cur->name,
		    target, sizeof(target) - 1)) == -1)
			err(1, "readlinkat(%s)", cur->name);
		target[n] = '\0';

		layout = SA_LAYOUT_INDEX_SYMLINK;
		links = 1;
		objsize = strlen(target);
		parent = SLIST_FIRST(&arg->dirs)->objid;
		break;
		}
	default:
		assert(0);
	}

	daclcount = nitems(aces);
	flags = ZFS_ACL_TRIVIAL | ZFS_ACL_AUTO_INHERIT | ZFS_NO_EXECS_DENIED |
	    ZFS_ARCHIVE | ZFS_AV_MODIFIED; /* XXX-MJ */
	gen = 1;
	gid = sb->st_gid;
	mode = sb->st_mode;
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

	switch (layout) {
	case SA_LAYOUT_INDEX_DEFAULT:
		/* At most one variable-length attribute. */
		hdrsz = sizeof(uint64_t);
		break;
	case SA_LAYOUT_INDEX_SYMLINK:
		/* At most five variable-length attributes. */
		hdrsz = sizeof(uint64_t) * 2;
		break;
	default:
		assert(0);
	}

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

	/*
	 * We deliberately set atime = mtime here to ensure that images are
	 * reproducible.
	 */
	assert(sizeof(sb->st_mtim) == fs->satab[ZPL_ATIME].size);
	fs_populate_attr(fs, attrbuf, &sb->st_mtim, ZPL_ATIME, &bonussz);
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
		assert(layout == SA_LAYOUT_INDEX_SYMLINK);
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
	char *buf;
	uint64_t dnid;
	ssize_t n;
	size_t bufsz;
	off_t size, target;
	int fd;

	assert(cur->type == S_IFREG);
	assert((cur->inode->flags & FI_ROOT) == 0);

	zfs = arg->zfs;

	assert(cur->inode->ino != 0);
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

	dnode = objset_dnode_bonus_alloc(arg->fs->os,
	    DMU_OT_PLAIN_FILE_CONTENTS, DMU_OT_SA, 0, &dnid);
	cur->inode->ino = dnid;
	cur->inode->flags |= FI_ALLOCATED;

	fd = openat(SLIST_FIRST(&arg->dirs)->dirfd, cur->name, O_RDONLY);
	if (fd == -1)
		err(1, "openat(%s)", cur->name);

	buf = zfs->filebuf;
	bufsz = sizeof(zfs->filebuf);
	size = cur->inode->st.st_size;
	c = dnode_cursor_init(zfs, arg->fs->os, dnode, size, 0);
	for (off_t foff = 0; foff < size; foff += target) {
		off_t loc, sofar;

		/* Fill up our buffer, handling partial reads. */
		sofar = 0;
		target = MIN(size - foff, (off_t)bufsz);
		do {
			n = read(fd, buf + sofar, target);
			if (n < 0)
				err(1, "reading from '%s'", cur->name);
			if (n == 0)
				errx(1, "unexpected EOF reading '%s'",
				    cur->name);
			sofar += n;
		} while (sofar < target);

		if (target < (off_t)bufsz)
			memset(buf + target, 0, bufsz - target);

		loc = objset_space_alloc(zfs, arg->fs->os, &target);
		assert(target <= MAXBLOCKSIZE);

		vdev_pwrite_dnode_indir(zfs, c->dnode, 0, 1, buf, target, loc,
		    dnode_cursor_next(zfs, c, foff));
	}
	(void)close(fd);
	dnode_cursor_finish(zfs, c);

	fs_populate_sattrs(arg, cur, dnode);
	fs_populate_dirent(arg, cur, dnid);
}

static void
fs_populate_dir(fsnode *cur, struct fs_populate_arg *arg)
{
	dnode_phys_t *dnode;
	zfs_objset_t *os;
	uint64_t dnid;
	int dirfd;

	assert(cur->type == S_IFDIR);
	assert((cur->inode->flags & FI_ALLOCATED) == 0);

	os = arg->fs->os;

	dnode = objset_dnode_bonus_alloc(os, DMU_OT_DIRECTORY_CONTENTS,
	    DMU_OT_SA, 0, &dnid);

	/*
	 * Add an entry to the parent directory and open this directory.
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

	fs_populate_sattrs(arg, cur, dnode);

	/*
	 * If this is a root directory, then its children belong to a different
	 * dataset and this directory remains empty in the current objset.
	 */
	if ((cur->inode->flags & FI_ROOT) == 0) {
		struct fs_populate_dir *dir;

		dir = ecalloc(1, sizeof(*dir));
		dir->dirfd = dirfd;
		dir->objid = dnid;
		zap_init(&dir->zap, os, dnode);
		SLIST_INSERT_HEAD(&arg->dirs, dir, next);
	} else {
		zfs_zap_t dirzap;

		zap_init(&dirzap, os, dnode);
		zap_write(arg->zfs, &dirzap);

		fs_build_one(arg->zfs, cur, dirfd);
		(void)close(dirfd);
	}
}

static void
fs_populate_symlink(fsnode *cur, struct fs_populate_arg *arg)
{
	dnode_phys_t *dnode;
	uint64_t dnid;

	assert(cur->type == S_IFLNK);
	assert((cur->inode->flags & (FI_ALLOCATED | FI_ROOT)) == 0);

	dnode = objset_dnode_bonus_alloc(arg->fs->os,
	    DMU_OT_PLAIN_FILE_CONTENTS, DMU_OT_SA, 0, &dnid);

	fs_populate_dirent(arg, cur, dnid);

	fs_populate_sattrs(arg, cur, dnode);
}

static int
fs_foreach_populate(fsnode *cur, void *_arg)
{
	struct fs_populate_arg *arg;
	struct fs_populate_dir *dir;
	int ret;

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

	ret = (cur->inode->flags & FI_ROOT) != 0 ? 0 : 1;

	if (cur->next == NULL &&
	    (cur->child == NULL || (cur->inode->flags & FI_ROOT) != 0)) {
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
		} while (cur != NULL && cur->next == NULL &&
		    (cur->inode->flags & FI_ROOT) == 0);
	}

	return (ret);
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
fs_set_zpl_attrs(zfs_opt_t *zfs, zfs_fs_t *fs)
{
	zfs_zap_t sazap, salzap, sarzap;
	zfs_objset_t *os;
	dnode_phys_t *saobj, *salobj, *sarobj;
	uint64_t saobjid, salobjid, sarobjid;
	uint16_t offset;

	os = fs->os;

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
	fs_add_zpl_attr_layout(&salzap, SA_LAYOUT_INDEX_DEFAULT,
	    zpl_attr_layout, nitems(zpl_attr_layout) - 1);
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
fs_layout_one(zfs_opt_t *zfs __unused, zfs_dsl_dir_t *dsldir, void *arg)
{
	zfs_dsl_dir_t *pdir;
	char *mountpoint, *origmountpoint, *name, *next;
	fsnode *cur, *root;
	int error;

	if (dsldir->headds == NULL)
		return;

	error = nvlist_find(dsldir->propsnv, "mountpoint", DATA_TYPE_STRING,
	    NULL, &mountpoint, NULL);
	assert(error == 0 || error == ENOENT);
	if (error == 0) {
		if (strcmp(mountpoint, "none") == 0)
			return;

		/*
		 * nvlist_find() does not make a copy.
		 */
		mountpoint = estrdup(mountpoint);
	} else {
		/*
		 * If we don't have a mountpoint, it's inherited from one of our
		 * ancestors.  Walk up the hierarchy until we find it, building
		 * up our mountpoint along the way.  The mountpoint property is
		 * always set for the root dataset.
		 */
		pdir = dsldir->parent;
		mountpoint = estrdup(dsldir->name);
		do {
			origmountpoint = mountpoint;
			error = nvlist_find(pdir->propsnv, "mountpoint",
			    DATA_TYPE_STRING, NULL, &mountpoint, NULL);
			assert(error == 0 || error == ENOENT);
			if (error == 0) {
				easprintf(&mountpoint, "%s%s%s", mountpoint,
				    mountpoint[strlen(mountpoint) - 1] == '/' ?
				    "" : "/", origmountpoint);
			} else {
				easprintf(&mountpoint, "%s/%s", pdir->name,
				    origmountpoint);
			}
			free(origmountpoint);
			pdir = pdir->parent;
		} while (error == ENOENT);
	}
	assert(mountpoint[0] == '/');
	assert(strstr(mountpoint, zfs->rootpath) == mountpoint);

	origmountpoint = mountpoint;

	/*
	 * Figure out which fsnode corresponds to our mountpoint.
	 */
	root = arg;
	if (strcmp(mountpoint, zfs->rootpath) == 0) {
		cur = root;
	} else {
		mountpoint += strlen(zfs->rootpath);

		/*
		 * Look up the directory in the staged tree.  For example, if
		 * the dataset's mount point is /foo/bar/baz, we'll search the
		 * root directory for "foo", search "foo" for "baz", and so on.
		 * Each intermediate name must refer to a directory; the final
		 * component need not exist.
		 */
		cur = root->next;
		for (next = name = mountpoint; next != NULL;) {
			for (; *next == '/'; next++)
				;
			name = strsep(&next, "/");

			for (; cur != NULL && strcmp(cur->name, name) != 0;
			    cur = cur->next)
				;
			if (cur == NULL) {
				if (next == NULL)
					break;
				errx(1, "missing mountpoint directory for `%s'",
				    dsldir->fullname);
			}
			if (cur->type != S_IFDIR) {
				errx(1,
				    "mountpoint for `%s' is not a directory",
				    dsldir->fullname);
			}
			if (next != NULL)
				cur = cur->child;
		}
	}

	if (cur != NULL) {
		assert(cur->type == S_IFDIR);

		/*
		 * Multiple datasets shouldn't share a mountpoint.  It's
		 * technically allowed, but it's not clear what makefs should do
		 * in that case.
		 */
		assert((cur->inode->flags & FI_ROOT) == 0);
		if (cur != root)
			cur->inode->flags |= FI_ROOT;
		assert(cur->inode->param == NULL);
		cur->inode->param = dsldir;
	}

	free(origmountpoint);
}

/*
 * Create a filesystem dataset.  More specifically:
 * - create an object set for the dataset
 * - add required metadata (SA tables, property definitions, etc.) to that
 *   object set
 * - populate the object set with file objects
 *
 * The dataset will be the head dataset of the DSL directory "dsldir".
 */
static void
fs_build_one(zfs_opt_t *zfs, fsnode *root, int dirfd)
{
	zfs_fs_t fs;
	zfs_zap_t deleteqzap, masterzap;
	zfs_dsl_dir_t *dsldir;
	zfs_objset_t *os;
	dnode_phys_t *deleteq, *masterobj;
	uint64_t deleteqid, dnodecount, moid, rootdirid, saobjid;

	dsldir = root->inode->param;
	if ((root->inode->flags & FI_ROOT) != 0)
		root = root->child;
	assert(strcmp(root->name, ".") == 0);

	dsldir->headds->os = os = ecalloc(1, sizeof(*os));

	memset(&fs, 0, sizeof(fs));
	fs.os = os;

	/*
	 * How many dnodes do we need?  One for each file/directory/symlink plus
	 * several metadata objects.
	 */
	dnodecount = 0;
	if (root != NULL) {
		dnodecount++; /* root directory */
		fsnode_foreach(root, fs_foreach_count, &dnodecount);
	}
	dnodecount++; /* master object */
	dnodecount++; /* delete queue */
	dnodecount++; /* system attributes master node */
	dnodecount++; /* system attributes registry */
	dnodecount++; /* system attributes layout */

	objset_init(zfs, os, DMU_OST_ZFS, dnodecount);
	masterobj = objset_dnode_alloc(os, DMU_OT_MASTER_NODE, &moid);
	assert(moid == MASTER_NODE_OBJ);

	/*
	 * Create the ZAP SA layout now since filesystem object dnodes will
	 * refer to those attributes.
	 */
	saobjid = fs_set_zpl_attrs(zfs, &fs);

	/*
	 * Populate the dataset with files from the staging directory.  Most of
	 * our runtime is spent here.
	 */
	if (root != NULL) {
		struct fs_populate_arg poparg;

		poparg.dirfd = dirfd;
		poparg.zfs = zfs;
		poparg.fs = &fs;
		SLIST_INIT(&poparg.dirs);
		fs_populate_dir(root, &poparg);
		assert(!SLIST_EMPTY(&poparg.dirs));
		fsnode_foreach(root, fs_foreach_populate, &poparg);
		assert(SLIST_EMPTY(&poparg.dirs));
		rootdirid = poparg.rootdirid;
	} else {
		rootdirid = 0;
	}

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
	zap_add_uint64(&masterzap, ZFS_ROOT_OBJ, rootdirid);
	zap_add_uint64(&masterzap, ZFS_UNLINKED_SET, deleteqid);
	zap_add_uint64(&masterzap, ZFS_SA_ATTRS, saobjid);
	zap_add_uint64(&masterzap, ZPL_VERSION_OBJ, 5 /* ZPL_VERSION_SA */);
	zap_add_uint64(&masterzap, "normalization", 0 /* off */);
	zap_add_uint64(&masterzap, "utf8only", 0 /* off */);
	zap_add_uint64(&masterzap, "casesensitivity", 0 /* case sensitive */);
	zap_add_uint64(&masterzap, "acltype", 2 /* NFSv4 */);
	zap_write(zfs, &masterzap);

	free(fs.saoffs);
	/* XXX-MJ should we just write the object set now? */
}

static void
fs_build(zfs_opt_t *zfs, int dirfd, fsnode *root)
{
	dsl_dir_foreach(zfs, &zfs->rootdsldir, fs_layout_one, root);

	assert((root->inode->flags & FI_ROOT) == 0);
	assert(root->inode->param != NULL);

	fs_build_one(zfs, root, dirfd);
}

/*
 * The entry point to all other code in this file.
 */
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

	zfs_check_opts(fsopts);

	dirfd = open(dir, O_DIRECTORY | O_RDONLY);
	if (dirfd < 0)
		err(1, "open(%s)", dir);

	vdev_init(zfs, fsopts->maxsize, image);
	pool_init(zfs);
	fs_build(zfs, dirfd, root);
	pool_fini(zfs);
	vdev_fini(zfs);

	(void)close(dirfd);
}
