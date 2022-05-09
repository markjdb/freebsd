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

#include <sys/dirent.h>
#include <sys/endian.h>
#include <sys/queue.h>

#include <assert.h>
#include <bitstring.h>
#include <fcntl.h>
#include <stdbool.h>
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
 * XXXMJ
 * - review checksum algorithm selection (most should likely be "inherit"?)
 * - review vdev_space_alloc()
 * - objset accounting, dn_used
 * - support for multiple filesystems
 * - figure out how to handle fat ZAP collisions
 */

/*
 * XXXMJ this might wrong but I don't understand where DN_MAX_LEVELS' definition
 * comes from.  Be sure to test with large files...
 */
#define	INDIR_LEVELS		6
#define	BLKPTR_PER_INDIR	(SPA_OLDMAXBLOCKSIZE / sizeof(blkptr_t))

#define	VDEV_LABEL_SPACE	\
	((off_t)(VDEV_LABEL_START_SIZE + VDEV_LABEL_END_SIZE))

typedef struct {
	const char	*name;
	unsigned int	id;
	uint16_t	size;
	sa_bswap_type_t	bs;
} zfs_sattr_t;

typedef struct {
	objset_phys_t	*osphys;
	off_t		osloc;
	off_t		osblksz;
	dnode_phys_t	*dnodes;	/* dnode array */
	uint64_t	dnodenextfree;	/* dnode ID bump allocator */
	uint64_t	dnodecount;	/* total number of dnodes */
	off_t		dnodeloc;
} zfs_objset_t;

typedef struct zfs_zap_entry {
	char		*name;
	uint8_t		*valp;
	size_t		intsz;
	size_t		intcnt;
	STAILQ_ENTRY(zfs_zap_entry) next;
} zfs_zap_entry_t;

typedef struct zfs_zap {
	STAILQ_HEAD(, zfs_zap_entry) kvps;
	unsigned long		kvpcnt;
	bool			micro;
	dnode_phys_t		*dnode;
} zfs_zap_t;

typedef struct {
	zfs_objset_t	os;
	dnode_phys_t	*dnode;		/* meta dnode */

	/* Offset table for system attributes, indexed by a zpl_attr_t. */
	const zfs_sattr_t *satab;
	size_t		sacnt;
	uint16_t	*saoffs;
} zfs_fs_t;

typedef struct {
	/* Pool parameters. */
	const char	*poolname;
	int		ashift;		/* vdev block size */

	/* Pool state. */
	zfs_objset_t	mos;		/* meta object set */
	zfs_fs_t	rootfs;		/* root dataset */
	uint64_t	originsnap;

	/* I/O buffer. */
	char		filebuf[SPA_OLDMAXBLOCKSIZE];

	/* vdev state. */
	int		fd;		/* vdev disk fd */
	bitstr_t	*spacemap;	/* space allocator */
	int		spacemapbits;	/* one bit per ashift-sized block */
	off_t		vdevsize;	/* vdev size, including labels */
	uint64_t	msshift;	/* metaslab size */
	uint64_t	mscount;	/* number of metaslabs for this vdev */
} zfs_opt_t;

static void zap_init(zfs_zap_t *, dnode_phys_t *);
static void zap_add_uint64(zfs_zap_t *, const char *, uint64_t);
static void zap_write(zfs_opt_t *, zfs_zap_t *);

static dnode_phys_t *objset_dnode_alloc(zfs_objset_t *, uint8_t, uint64_t *);
static dnode_phys_t *objset_dnode_bonus_alloc(zfs_objset_t *, uint8_t, uint8_t,
    uint16_t, uint64_t *);

static int spacemap_init(zfs_opt_t *);

struct dnode_cursor {
	blkptr_t	inddir[INDIR_LEVELS][BLKPTR_PER_INDIR];
	dnode_phys_t	*dnode;
	off_t		off;
	off_t		datablksz;
};

static struct dnode_cursor *dnode_cursor_init(dnode_phys_t *, off_t, off_t);
static blkptr_t *dnode_cursor_next(zfs_opt_t *, struct dnode_cursor *,
    off_t);
static void dnode_cursor_finish(zfs_opt_t *, struct dnode_cursor *);

static off_t vdev_space_alloc(zfs_opt_t *, off_t *);

/*
 * The order of the attributes doesn't matter, this is simply the one hard-coded
 * by OpenZFS, based on a dump of the SA_REGISTRY table.
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
	zfs_opt_t *zfs_opts = ecalloc(1, sizeof(*zfs_opts));

	const option_t zfs_options[] = {
		{ '\0', "poolname", &zfs_opts->poolname, OPT_STRPTR,
		  0, 0, "ZFS pool name" },
		{ '\0', "ashift", &zfs_opts->ashift, OPT_INT32,
		  SPA_MINBLOCKSHIFT, SPA_OLDMAXBLOCKSHIFT, "ZFS pool ashift" },
		{ .name = NULL }
	};

	/* Set some default values. */
	zfs_opts->ashift = 12;

	fsopts->fs_specific = zfs_opts;
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
	zfs_opt_t *zfs_opts;

	zfs_opts = fsopts->fs_specific;
	free(__DECONST(void *, zfs_opts->poolname));

	free(fsopts->fs_specific);
	free(fsopts->fs_options);
}

static void
blkptr_set_level(blkptr_t *bp, off_t off, off_t size, uint8_t dntype,
    uint8_t level, enum zio_checksum cksumt, zio_cksum_t *cksum)
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
#if 0
	BP_SET_FILL(bp, 0); /* XXXMJ zdb -ddddd testpool/ crashes without this */
#endif
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
	blkptr_set_level(bp, off, size, dntype, 0, cksumt, cksum);
}

static int
vdev_init(zfs_opt_t *zfs_opts, size_t size, const char *image)
{
	int oflags;

	oflags = O_RDWR | O_CREAT | O_TRUNC;

	assert(zfs_opts->ashift >= SPA_MINBLOCKSHIFT);

	zfs_opts->fd = open(image, oflags, 0644);
	if (zfs_opts->fd == -1) {
		warn("Can't open `%s' for writing", image);
		return (-1);
	}
	zfs_opts->vdevsize = rounddown2(size, 1 << zfs_opts->ashift);
	if (zfs_opts->vdevsize < (off_t)SPA_MINDEVSIZE) {
		warnx("maximum image size %ju is too small",
		    (uintmax_t)zfs_opts->vdevsize);
		return (-1);
	}
	if (ftruncate(zfs_opts->fd, zfs_opts->vdevsize) != 0) {
		warn("Failed to extend image file `%s'", image);
		return (-1);
	}

	return (spacemap_init(zfs_opts));
}

static void
vdev_pwrite(const zfs_opt_t *zfs_opts, const void *buf, size_t len, off_t off)
{
	ssize_t n;

	assert(zfs_opts->vdevsize >= VDEV_LABEL_SPACE);
	assert(off >= 0 && off < zfs_opts->vdevsize - VDEV_LABEL_SPACE);
	assert((off_t)len > 0 && off + (off_t)len > off &&
	    off + (off_t)len < zfs_opts->vdevsize);

	off += VDEV_LABEL_START_SIZE;
	for (size_t sofar = 0; sofar < len; sofar += n) {
		n = pwrite(zfs_opts->fd, (const char *)buf + sofar, len - sofar,
		    off + sofar);
		if (n < 0)
			err(1, "pwrite");
		assert(n > 0);
	}
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
vdev_label_write(zfs_opt_t *zfs_opts, int ind, vdev_label_t *label)
{
	ssize_t n;
	off_t blksz, loff;

	assert(ind >= 0 && ind < VDEV_LABELS);

	blksz = 1 << zfs_opts->ashift;

	if (ind < 2) {
		loff = ind * sizeof(vdev_label_t);
	} else {
		loff = zfs_opts->vdevsize -
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

	n = pwrite(zfs_opts->fd, label, sizeof(*label), loff);
	if (n < 0)
		err(1, "writing vdev label");
	assert(n == sizeof(*label));
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
 * XXXMJ it seems the third rule isn't required, so this can just be a dumb
 * bump allocator.  Maybe there's some benefit to keeping large blocks aligned,
 * so let's keep it for now and hope we don't get too much fragmentation.
 * Alternately we could try to allocate all blocks of a certain size from the
 * same metaslab.
 *
 * XXXMJ must always be done in the context of an objset for accounting purposes
 */
static off_t
vdev_space_alloc(zfs_opt_t *zfs_opts, off_t *lenp)
{
	off_t len;
	int align, loc, minblksz, nbits;

	minblksz = 1 << zfs_opts->ashift;
	len = roundup2(*lenp, minblksz);

	assert(len != 0);
	assert(len / minblksz <= INT_MAX);
	if (len < (off_t)SPA_OLDMAXBLOCKSIZE) {
		if ((len & (len - 1)) != 0)
			len = (off_t)1 << flsll(len);
		align = len / minblksz;
	} else {
		len = roundup2(len, SPA_OLDMAXBLOCKSIZE);
		align = SPA_OLDMAXBLOCKSIZE / minblksz;
	}

	for (loc = 0, nbits = len / minblksz;; loc = roundup2(loc, align)) {
		bit_ffc_area_at(zfs_opts->spacemap, loc, zfs_opts->spacemapbits,
		    nbits, &loc);
		if (loc == -1) {
			errx(1, "failed to find %ju bytes of space",
			    (uintmax_t)len);
		}
		if ((loc & (align - 1)) == 0)
			break;
	}
	assert(loc + nbits > loc);
	bit_nset(zfs_opts->spacemap, loc, loc + nbits - 1);
	*lenp = len;

	return ((off_t)loc << zfs_opts->ashift);
}

static int
spacemap_init(zfs_opt_t *zfs_opts)
{
	uint64_t msshift, slabs;
	off_t nbits, size;

	size = zfs_opts->vdevsize;

	assert(size >= VDEV_LABEL_SPACE);

	nbits = (size - VDEV_LABEL_SPACE) >> zfs_opts->ashift;
	if (nbits > INT_MAX) {
		/*
		 * With the smallest block size of 512B, the limit on the image
		 * size is 2TB.  That should be enough for anyone.
		 */
		warnx("image size %ju is too large", (uintmax_t)size);
		return (-1);
	}
	zfs_opts->spacemapbits = (int)nbits;
	zfs_opts->spacemap = bit_alloc(zfs_opts->spacemapbits);
	if (zfs_opts->spacemap == NULL) {
		warn("bitstring allocation failed");
		return (-1);
	}

	/*
	 * XXXMJ explain
	 */
	for (msshift = 27; msshift < 34; msshift++) {
		slabs = (size - VDEV_LABEL_SPACE) / ((uint64_t)1 << msshift);
		if (slabs >= 4 && slabs <= 200)
			break;
	}
	zfs_opts->msshift = msshift;
	zfs_opts->mscount = slabs;

	return (0);
}

typedef struct zfs_sm {
	dnode_phys_t	*dnode;
	uint64_t	dnid;
	off_t		loc;
} zfs_sm_t;

static void
spacemap_write(zfs_opt_t *zfs_opts, dnode_phys_t *objarr)
{
	zio_cksum_t cksum;
	zfs_sm_t *sma;
	zfs_objset_t *mos;
	bitstr_t *spacemap;
	uint64_t *objarrblk;
	off_t smblksz, objarrblksz, objarrloc;

	spacemap = zfs_opts->spacemap;
	mos = &zfs_opts->mos;

	objarrblksz = sizeof(uint64_t) * zfs_opts->mscount;
	assert(objarrblksz <= (off_t)SPA_OLDMAXBLOCKSIZE);
	objarrloc = vdev_space_alloc(zfs_opts, &objarrblksz);
	objarrblk = ecalloc(1, objarrblksz);

	/*
	 * Use the smallest block size for space maps.  The space allocation
	 * algorithm should aim to minimize the number of holes.
	 */
	smblksz = 1 << zfs_opts->ashift;

	/*
	 * First allocate dnodes and space for all of our space maps.  No more
	 * space will be allocated from the vdev after this point.
	 */
	sma = ecalloc(zfs_opts->mscount, sizeof(*sma));
	for (uint64_t i = 0; i < zfs_opts->mscount; i++) {
		sma[i].dnode = objset_dnode_bonus_alloc(mos, DMU_OT_SPACE_MAP,
		    DMU_OT_SPACE_MAP_HEADER, SPACE_MAP_SIZE_V0, &sma[i].dnid);
		sma[i].loc = vdev_space_alloc(zfs_opts, &smblksz);
	}

	/*
	 * Now that the set of allocated space is finalized, populate each space
	 * map.
	 */
	for (uint64_t i = 0; i < zfs_opts->mscount; i++) {
		space_map_phys_t *sm;
		uint64_t alloc, length, *smblk;
		int startb, endb, srunb, erunb;

		/*
		 * We only allocate a single block for this space map, but OpenZFS
		 * assumes that a space map object with sufficient bonus space supports
		 * histograms.
		 */
		sma[i].dnode->dn_nblkptr = 3;
		sma[i].dnode->dn_datablkszsec = smblksz >> SPA_MINBLOCKSHIFT;
		/* XXXMJ dn_used */

		smblk = ecalloc(1, smblksz);

		alloc = length = 0;
		for (srunb = startb = i * ((uint64_t)1 << zfs_opts->msshift),
		    endb = (i + 1) * ((uint64_t)1 << zfs_opts->msshift);
		    srunb < endb; srunb = erunb) {
			uint64_t runlen, runoff;

			/* Find a run of allocated space. */
			bit_ffs_at(spacemap, srunb, zfs_opts->spacemapbits,
			    &srunb);
			if (srunb == -1 || srunb >= endb)
				break;

			bit_ffc_at(spacemap, srunb, zfs_opts->spacemapbits,
			    &erunb);
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

			alloc += runlen << zfs_opts->ashift;
			length += 2;
		}

		sm = DN_BONUS(sma[i].dnode);
		sm->smp_object = 0;
		sm->smp_length = length * sizeof(uint64_t);
		sm->smp_alloc = alloc;

		fletcher_4_native(smblk, smblksz, NULL, &cksum);
		blkptr_set(&sma[i].dnode->dn_blkptr[0], sma[i].loc, smblksz,
		    sma[i].dnode->dn_type, ZIO_CHECKSUM_FLETCHER_4, &cksum);
		vdev_pwrite(zfs_opts, smblk, smblksz, sma[i].loc);
		free(smblk);

		/* Record this space map in the space map object array. */
		objarrblk[i] = sma[i].dnid;
	}

	objarr->dn_datablkszsec = objarrblksz >> SPA_MINBLOCKSHIFT;
	objarr->dn_nblkptr = 1;
	objarr->dn_nlevels = 1;
	objarr->dn_used = objarr->dn_datablkszsec; /* XXXMJ not quite right */

	fletcher_4_native(objarrblk, objarrblksz, NULL, &cksum);
	blkptr_set(&objarr->dn_blkptr[0], objarrloc, objarrblksz,
	    objarr->dn_type, ZIO_CHECKSUM_FLETCHER_4, &cksum);
	vdev_pwrite(zfs_opts, objarrblk, objarrblksz, objarrloc);
	free(objarrblk);

	free(zfs_opts->spacemap);
	zfs_opts->spacemap = NULL;
}

static void
objset_init(zfs_opt_t *zfs_opts, zfs_objset_t *os, uint64_t type,
    uint64_t dnodecount)
{
	dnode_phys_t *mdnode;
	off_t blksz;

	/* Object zero is always the meta dnode. */
	os->dnodecount = dnodecount + 1;
	os->dnodenextfree = 1;

	/*
	 * Allocate space on the vdev for the objset and dnode array.  For other
	 * object types we do that only when going to actually write them to the
	 * vdev, but in this case it simplifies space map accounting to do it
	 * now.
	 */
	os->osblksz = sizeof(objset_phys_t);
	os->osloc = vdev_space_alloc(zfs_opts, &os->osblksz);

	blksz = roundup2(os->dnodecount * sizeof(dnode_phys_t),
	    DNODE_BLOCK_SIZE);
	os->dnodeloc = vdev_space_alloc(zfs_opts, &blksz);

	/* XXXMJ what else? */
	os->osphys = ecalloc(1, os->osblksz);
	mdnode = &os->osphys->os_meta_dnode;
	mdnode->dn_indblkshift = SPA_OLDMAXBLOCKSHIFT;
	mdnode->dn_type = DMU_OT_DNODE;
	mdnode->dn_bonustype = DMU_OT_NONE;
	mdnode->dn_datablkszsec = DNODE_BLOCK_SIZE >> SPA_MINBLOCKSHIFT;
	mdnode->dn_nlevels = 1;
	for (uint64_t count = dnodecount / DNODES_PER_BLOCK; count > 1;
	    count /= BLKPTR_PER_INDIR)
		mdnode->dn_nlevels++;
	mdnode->dn_nblkptr = 1;
	mdnode->dn_maxblkid = howmany(dnodecount, DNODES_PER_BLOCK) - 1;
	os->osphys->os_type = type;

	os->dnodes = ecalloc(1,
	    roundup2(dnodecount * sizeof(dnode_phys_t), DNODE_BLOCK_SIZE));
}

/*
 * Write the dnode array and physical object set to disk, optionally returning
 * the checksum for the latter for use when populating the uberblock (which
 * contains a block pointer to the MOS).
 */
static void
objset_write(zfs_opt_t *zfs_opts, zfs_objset_t *os, zio_cksum_t *cksump)
{
	zio_cksum_t cksum;
	struct dnode_cursor *c;

	/*
	 * Write out the dnode array.  For some reason data blocks must be 16KB
	 * in size no matter how large the array is.
	 */
	c = dnode_cursor_init(&os->osphys->os_meta_dnode,
	    os->dnodecount * sizeof(dnode_phys_t), DNODE_BLOCK_SIZE);
	for (uint64_t i = 0; i < os->dnodecount; i += DNODES_PER_BLOCK) {
		dnode_phys_t *blk;
		blkptr_t *bp;
		off_t loc;

		blk = os->dnodes + i;
		loc = os->dnodeloc + i * sizeof(dnode_phys_t);

		bp = dnode_cursor_next(zfs_opts, c, i * sizeof(dnode_phys_t));
		fletcher_4_native(blk, DNODE_BLOCK_SIZE, NULL, &cksum);
		blkptr_set(bp, loc, DNODE_BLOCK_SIZE, DMU_OT_DNODE,
		    ZIO_CHECKSUM_FLETCHER_4, &cksum);

		vdev_pwrite(zfs_opts, blk, DNODE_BLOCK_SIZE, loc);
	}
	dnode_cursor_finish(zfs_opts, c);
	free(os->dnodes);
	os->dnodes = NULL;

	/* Now write out the object set itself, including the meta dnode. */
	vdev_pwrite(zfs_opts, os->osphys, os->osblksz, os->osloc);

	if (cksump != NULL)
		fletcher_4_native(os->osphys, os->osblksz, NULL, cksump);
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
	dnode->dn_indblkshift = SPA_OLDMAXBLOCKSHIFT; /* XXXMJ zfs_default_ibs */
	dnode->dn_datablkszsec = 1 << (12 /* XXXMJ ashift */ - SPA_MINBLOCKSHIFT);
	dnode->dn_nlevels = 1;
	dnode->dn_nblkptr = 1;
	dnode->dn_type = type;
	dnode->dn_bonustype = bonustype;
	dnode->dn_bonuslen = bonuslen;
	dnode->dn_compress = ZIO_COMPRESS_OFF;
	return (dnode);
}

static dnode_phys_t *
objset_dnode_alloc(zfs_objset_t *os, uint8_t type, uint64_t *idp)
{
	return (objset_dnode_bonus_alloc(os, type, DMU_OT_NONE, 0, idp));
}

static dsl_dir_phys_t *
dsl_dir_alloc(zfs_opt_t *zfs_opts, zfs_objset_t *os, uint64_t parentdir,
    uint64_t *dnidp)
{
	zfs_zap_t propszap;
	dnode_phys_t *dnode, *props;
	dsl_dir_phys_t *dsldir;
	uint64_t propsid;

	dnode = objset_dnode_bonus_alloc(os, DMU_OT_DSL_DIR, DMU_OT_DSL_DIR,
	    sizeof(dsl_dir_phys_t), dnidp);

	props = objset_dnode_alloc(os, DMU_OT_DSL_PROPS, &propsid);
	zap_init(&propszap, props);
	zap_add_uint64(&propszap, "compression", ZIO_COMPRESS_OFF);
	zap_write(zfs_opts, &propszap);

	dsldir = (dsl_dir_phys_t *)DN_BONUS(dnode);
	dsldir->dd_parent_obj = parentdir;
	dsldir->dd_props_zapobj = propsid;

	return (dsldir);
}

static dsl_deadlist_phys_t *
dsl_deadlist_alloc(zfs_opt_t *zfs_opts, zfs_objset_t *mos, uint64_t *dnidp)
{
	zfs_zap_t deadlistzap;
	dnode_phys_t *dnode;

	dnode = objset_dnode_bonus_alloc(mos, DMU_OT_DEADLIST,
	    DMU_OT_DEADLIST_HDR, sizeof(dsl_deadlist_phys_t), dnidp);

	zap_init(&deadlistzap, dnode);
	zap_write(zfs_opts, &deadlistzap);

	return ((dsl_deadlist_phys_t *)DN_BONUS(dnode));
}

static dsl_dataset_phys_t *
dsl_dataset_alloc(zfs_opt_t *zfs_opts, zfs_objset_t *mos, uint64_t dir,
    uint64_t *dnidp)
{
	dnode_phys_t *dnode;
	dsl_dataset_phys_t *ds;
	uint64_t deadlistid;

	dnode = objset_dnode_bonus_alloc(mos, DMU_OT_DSL_DATASET,
	    DMU_OT_DSL_DATASET, sizeof(dsl_dataset_phys_t), dnidp);

	(void)dsl_deadlist_alloc(zfs_opts, mos, &deadlistid);

	ds = (dsl_dataset_phys_t *)DN_BONUS(dnode);
	/* XXXMJ what else? */
	ds->ds_dir_obj = dir;
	ds->ds_deadlist_obj = deadlistid;
	ds->ds_creation_txg = TXG_INITIAL;

	return (ds);
}

/* XXXMJ from zfssubr.c */
static uint64_t
zap_hash(uint64_t salt, const char *name)
{
#define	ZFS_CRC64_POLY	0xC96C5795D7870F42UL	/* ECMA-182, reflected form */
	static uint64_t zfs_crc64_table[256];
	const uint8_t *cp;
	uint8_t c;
	uint64_t crc = salt;

	assert(crc != 0);
	if (zfs_crc64_table[128] == 0) {
		for (int i = 0; i < 256; i++) {
			uint64_t *t;

			t = zfs_crc64_table + i;
			*t = i;
			for (int j = 8; j > 0; j--)
				*t = (*t >> 1) ^ (-(*t & 1) & ZFS_CRC64_POLY);
		}
	}
	assert(zfs_crc64_table[128] == ZFS_CRC64_POLY);

	for (cp = (const uint8_t *)name; (c = *cp) != '\0'; cp++)
		crc = (crc >> 8) ^ zfs_crc64_table[(crc ^ c) & 0xFF];

	/*
	 * Only use 28 bits, since we need 4 bits in the cookie for the
	 * collision differentiator.  We MUST use the high bits, since
	 * those are the onces that we first pay attention to when
	 * chosing the bucket.
	 */
	crc &= ~((1ULL << (64 - ZAP_HASHBITS)) - 1);

	return (crc);
#undef ZFS_CRC64_POLY
}

static void
zap_init(zfs_zap_t *zap, dnode_phys_t *dnode)
{
	STAILQ_INIT(&zap->kvps);
	zap->micro = true;
	zap->kvpcnt = 0;
	zap->dnode = dnode;
}

static void
zap_add(zfs_zap_t *zap, const char *name, size_t intsz, size_t intcnt,
    const uint8_t *val)
{
	zfs_zap_entry_t *ent;

	assert(intsz == 1 || intsz == 2 || intsz == 4 || intsz == 8);
	assert(strlen(name) + 1 <= 256 /* XXXMJ ZAP_MAXNAMELEN */);
	assert(intcnt * intsz <= 8192 /* XXXMJ ZAP_MAXVALUELEN */);

	ent = ecalloc(1, sizeof(*ent));
	ent->name = estrdup(name);
	ent->intsz = intsz;
	ent->intcnt = intcnt;
	ent->valp = ecalloc(intcnt, intsz);
	memcpy(ent->valp, val, intcnt * intsz);
	if (intcnt != 1 || intsz != sizeof(uint64_t))
		zap->micro = false;
	if (strlen(name) + 1 > MZAP_NAME_LEN)
		zap->micro = false;
	if (++zap->kvpcnt > MZAP_ENT_MAX)
		zap->micro = false;

	STAILQ_INSERT_TAIL(&zap->kvps, ent, next);
}

static void
zap_add_uint64(zfs_zap_t *zap, const char *name, uint64_t val)
{
	zap_add(zap, name, sizeof(uint64_t), 1, (uint8_t *)&val);
}

static void
zap_micro_write(zfs_opt_t *zfs_opts, zfs_zap_t *zap)
{
	zio_cksum_t cksum;
	dnode_phys_t *dnode;
	zfs_zap_entry_t *ent;
	mzap_phys_t *mzap;
	mzap_ent_phys_t *ment;
	off_t bytes, loc;

	memset(zfs_opts->filebuf, 0, sizeof(zfs_opts->filebuf));
	mzap = (mzap_phys_t *)&zfs_opts->filebuf[0];
	mzap->mz_block_type = ZBT_MICRO;
	mzap->mz_salt = random();
	mzap->mz_normflags = 0;

	bytes = sizeof(*mzap) + (zap->kvpcnt - 1) * sizeof(*ment);
	assert(bytes <= (off_t)MZAP_MAX_BLKSZ);

	ment = &mzap->mz_chunk[0];
	STAILQ_FOREACH(ent, &zap->kvps, next) {
		memcpy(&ment->mze_value, ent->valp, ent->intsz * ent->intcnt);
		ment->mze_cd = 0; /* XXXMJ */
		strlcpy(ment->mze_name, ent->name, sizeof(ment->mze_name));
		ment++;
	}

	loc = vdev_space_alloc(zfs_opts, &bytes);

	dnode = zap->dnode;
	dnode->dn_used = bytes >> SPA_MINBLOCKSHIFT;
	dnode->dn_nblkptr = 1;
	dnode->dn_nlevels = 1;
	dnode->dn_checksum = ZIO_CHECKSUM_FLETCHER_4;
	dnode->dn_datablkszsec = bytes >> SPA_MINBLOCKSHIFT;

	fletcher_4_native(zfs_opts->filebuf, bytes, NULL, &cksum);
	blkptr_set(&dnode->dn_blkptr[0], loc, bytes, dnode->dn_type, ZIO_CHECKSUM_FLETCHER_4,
	    &cksum);

	vdev_pwrite(zfs_opts, zfs_opts->filebuf, bytes, loc);
}

static void
zap_fat_write_array_chunk(zap_leaf_t *l, uint16_t li, size_t intcnt,
    size_t intsz, const uint8_t *val)
{
	struct zap_leaf_array *la;

	assert(intsz == 1 || intsz == 2 || intsz == 4 || intsz == 8);

	for (uint16_t n, resid = intcnt * intsz; resid > 0;
	    resid -= n, val += n, li++) {
		n = MIN(resid, ZAP_LEAF_ARRAY_BYTES);

		la = &ZAP_LEAF_CHUNK(l, li).l_array;
		la->la_type = ZAP_CHUNK_ARRAY;
		memcpy(la->la_array, val, n);
		la->la_next = li + 1;
	}
	la->la_next = 0xffff;
}

static void
zap_fat_write(zfs_opt_t *zfs_opts, zfs_zap_t *zap)
{
	zio_cksum_t cksum;
	zap_leaf_t l;
	zap_phys_t *zaphdr;
	zap_leaf_phys_t *leaf;
	zfs_zap_entry_t *ent;
	dnode_phys_t *dnode;
	uint64_t blkid, *ptrhashent, *ptrhasht;
	off_t loc, blksz;
	size_t blkshift;

	blkshift = SPA_OLDMAXBLOCKSHIFT;
	blksz = (off_t)1 << blkshift;

	memset(zfs_opts->filebuf, 0, sizeof(zfs_opts->filebuf));
	zaphdr = (zap_phys_t *)&zfs_opts->filebuf[0];
	zaphdr->zap_block_type = ZBT_HEADER;
	zaphdr->zap_magic = ZAP_MAGIC;

	/*
	 * For simplicity, always embed the pointer table in the first block,
	 * and always use the maximum block size.  This approach may need to be
	 * re-evaluated if the output image contains many fat ZAPs or if some of
	 * them are truly large.  Since most directories will be encoded using
	 * the micro ZAP layout, this is not a concern for now.
	 */
	zaphdr->zap_ptrtbl.zt_blk = 0;
	zaphdr->zap_ptrtbl.zt_numblks = 0;
	zaphdr->zap_ptrtbl.zt_shift = blkshift - 1 - 3;
	zaphdr->zap_ptrtbl.zt_nextblk = 0;
	zaphdr->zap_ptrtbl.zt_blks_copied = 0;

	zaphdr->zap_num_entries = zap->kvpcnt;
	zaphdr->zap_salt = random();

	/* The embedded pointer hash table starts half way through the block. */
	ptrhasht = (uint64_t *)(&zfs_opts->filebuf[0] + (1 << (blkshift - 1)));

	l.l_bs = blkshift;
	l.l_phys = NULL;
	blkid = 0;
	STAILQ_FOREACH(ent, &zap->kvps, next) {
		struct zap_leaf_entry *le;
		const char *name;
		uint16_t *lptr;
		uint64_t hash;
		uint16_t namelen, nchunks, nnamechunks, nvalchunks;

		name = ent->name;
		namelen = strlen(name) + 1;
		hash = zap_hash(zaphdr->zap_salt, name);

		leaf = l.l_phys;
		if (leaf == NULL) {
			l.l_phys = leaf = ecalloc(1, SPA_OLDMAXBLOCKSIZE);

			blkid++;
			zaphdr->zap_num_leafs++;
			zaphdr->zap_freeblk = blkid;

			leaf->l_hdr.lh_block_type = ZBT_LEAF;
			leaf->l_hdr.lh_magic = ZAP_LEAF_MAGIC;
			leaf->l_hdr.lh_nfree = ZAP_LEAF_NUMCHUNKS(&l);

			/* Initialize the leaf hash table. */
			assert(leaf->l_hdr.lh_nfree < 0xffff);
			memset(leaf->l_hash, 0xff,
			    ZAP_LEAF_HASH_NUMENTRIES(&l) *
			    sizeof(*leaf->l_hash));

			/* XXXMJ should we initialize the leaves too? */
		}

		/* How many leaf chunks do we need for this KVP? */
		nnamechunks = howmany(namelen, ZAP_LEAF_ARRAY_BYTES);
		nvalchunks = howmany(ent->intcnt,
		    ZAP_LEAF_ARRAY_BYTES / ent->intsz);
		nchunks = 1 + nnamechunks + nvalchunks;
		/* XXXMJ if this is false, we need a new leaf. */
		assert(leaf->l_hdr.lh_nfree >= nchunks);

		/* Allocate a run of free leaf chunks for this KVP. */
		leaf->l_hdr.lh_nfree -= nchunks;
		leaf->l_hdr.lh_nentries++;
		lptr = ZAP_LEAF_HASH_ENTPTR(&l, hash);
		while (*lptr != 0xffff) {
			le = ZAP_LEAF_ENTRY(&l, *lptr);
			lptr = &le->le_next;
			assert(*lptr <= 0xffff);
		}
		*lptr = leaf->l_hdr.lh_freelist;
		leaf->l_hdr.lh_freelist += nchunks;
		leaf->l_hdr.lh_nentries++;

		/* Write out the leaf chunks for this KVP. */
		le = ZAP_LEAF_ENTRY(&l, *lptr);
		le->le_type = ZAP_CHUNK_ENTRY;
		le->le_value_intlen = ent->intsz;
		le->le_next = 0xffff;
		le->le_name_chunk = *lptr + 1;
		le->le_name_numints = namelen;
		le->le_value_chunk = *lptr + 1 + nnamechunks;
		le->le_value_numints = ent->intcnt;
		le->le_hash = hash;
		zap_fat_write_array_chunk(&l, *lptr + 1, namelen, 1, name);
		zap_fat_write_array_chunk(&l, *lptr + 1 + nnamechunks,
		    ent->intcnt, ent->intsz, ent->valp);

		/* Now update the pointer hash table. */
		ptrhashent =
		    &ptrhasht[ZAP_HASH_IDX(hash, zaphdr->zap_ptrtbl.zt_shift)];
		/* XXXMJ collisions are unhandled */
		assert(*ptrhashent == 0 || *ptrhashent == blkid);
		*ptrhashent = blkid;
	}

	/* Initialize unused slots of the pointer table. */
	for (uint64_t i = 0; i < ((uint64_t)1 << zaphdr->zap_ptrtbl.zt_shift);
	    i++)
		if (ptrhasht[i] == 0)
			ptrhasht[i] = blkid;

	dnode = zap->dnode;
	dnode->dn_nblkptr = 2;
	dnode->dn_nlevels = 1;
	dnode->dn_datablkszsec = blksz >> SPA_MINBLOCKSHIFT;
	dnode->dn_maxblkid = blkid;
	dnode->dn_checksum = ZIO_CHECKSUM_FLETCHER_4;

	loc = vdev_space_alloc(zfs_opts, &blksz);
	fletcher_4_native(zfs_opts->filebuf, blksz, NULL, &cksum);
	blkptr_set(&dnode->dn_blkptr[0], loc, blksz, dnode->dn_type,
	    ZIO_CHECKSUM_FLETCHER_4, &cksum);
	vdev_pwrite(zfs_opts, zfs_opts->filebuf, blksz, loc);

	blksz = 1 << l.l_bs;
	loc = vdev_space_alloc(zfs_opts, &blksz);
	fletcher_4_native(l.l_phys, blksz, NULL, &cksum);
	blkptr_set(&dnode->dn_blkptr[1], loc, blksz, dnode->dn_type,
	    ZIO_CHECKSUM_FLETCHER_4, &cksum);
	vdev_pwrite(zfs_opts, l.l_phys, blksz, loc);

	free(l.l_phys);
}

static void
zap_write(zfs_opt_t *zfs_opts, zfs_zap_t *zap)
{
	zfs_zap_entry_t *ent;

	if (zap->micro) {
		zap_micro_write(zfs_opts, zap);
	} else {
		assert(!STAILQ_EMPTY(&zap->kvps));
		assert(zap->kvpcnt > 0);
		zap_fat_write(zfs_opts, zap);
	}

	while ((ent = STAILQ_FIRST(&zap->kvps)) != NULL) {
		STAILQ_REMOVE_HEAD(&zap->kvps, next);
		free(ent->valp);
		free(ent->name);
		free(ent);
	}
}

/*
 * Initialize the meta-object set.
 */
static void
pool_init(zfs_opt_t *zfs_opts)
{
	uint64_t dnodecount;

	assert(zfs_opts->mscount >= 2);

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
	dnodecount++; /*     |   |   L-> props (ZAP)          */
	dnodecount++; /*     |   |-> $FREE (DSL dir)          */
	dnodecount++; /*     |   |   L-> props (ZAP)          */
	dnodecount++; /*     |   L-> $ORIGIN (DSL dir)        */
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
	dnodecount += zfs_opts->mscount; /* space maps        */

	objset_init(zfs_opts, &zfs_opts->mos, DMU_OST_META, dnodecount);
}

static void
pool_add_bplists(zfs_objset_t *mos, zfs_zap_t *objdir)
{
	uint64_t dnid;

	(void)objset_dnode_bonus_alloc(mos, DMU_OT_BPOBJ, DMU_OT_BPOBJ_HDR,
	    BPOBJ_SIZE_V2, &dnid);
	zap_add_uint64(objdir, DMU_POOL_FREE_BPOBJ, dnid);

	/* Object used for deferred frees. */
	(void)objset_dnode_bonus_alloc(mos, DMU_OT_BPOBJ, DMU_OT_BPOBJ_HDR,
	    BPOBJ_SIZE_V2, &dnid);
	zap_add_uint64(objdir, DMU_POOL_SYNC_BPLIST, dnid);
}

/*
 * Add required feature metadata objects.  We don't know anything about ZFS
 * features, so the objects are just empty ZAPs.
 */
static void
pool_add_feature_objects(zfs_opt_t *zfs_opts, zfs_objset_t *mos,
    zfs_zap_t *objdir)
{
	zfs_zap_t zap;
	dnode_phys_t *dnode;
	uint64_t dnid;

	dnode = objset_dnode_alloc(mos, DMU_OTN_ZAP_METADATA, &dnid);
	zap_add_uint64(objdir, DMU_POOL_FEATURES_FOR_READ, dnid);
	zap_init(&zap, dnode);
	zap_write(zfs_opts, &zap);

	dnode = objset_dnode_alloc(mos, DMU_OTN_ZAP_METADATA, &dnid);
	zap_add_uint64(objdir, DMU_POOL_FEATURES_FOR_WRITE, dnid);
	zap_init(&zap, dnode);
	zap_write(zfs_opts, &zap);

	dnode = objset_dnode_alloc(mos, DMU_OTN_ZAP_DATA, &dnid);
	zap_add_uint64(objdir, DMU_POOL_FEATURE_DESCRIPTIONS, dnid);
	zap_init(&zap, dnode);
	zap_write(zfs_opts, &zap);
}

static uint64_t
pool_add_child_map(zfs_opt_t *zfs_opts, zfs_objset_t *mos, uint64_t parentdir)
{
	zfs_zap_t childzap;
	dnode_phys_t *childdir, *snapnames;
	dsl_dir_phys_t *dsldir;
	dsl_dataset_phys_t *originds, *snapds;
	uint64_t childdirid, dnid, dsdnid, snapdnid, snapmapid;

	childdir = objset_dnode_alloc(mos, DMU_OT_DSL_DIR_CHILD_MAP, &childdirid);

	zap_init(&childzap, childdir);

	dsldir = dsl_dir_alloc(zfs_opts, mos, parentdir, &dnid);
	dsldir->dd_used_bytes = 200 * sizeof(dnode_phys_t); /* XXXMJ plus what else? */
	dsldir->dd_compressed_bytes = dsldir->dd_uncompressed_bytes = dsldir->dd_used_bytes;
	zap_add_uint64(&childzap, "$MOS", dnid);

	dsldir = dsl_dir_alloc(zfs_opts, mos, parentdir, &dnid);
	zap_add_uint64(&childzap, "$ORIGIN", dnid);
	originds = dsl_dataset_alloc(zfs_opts, mos, dnid, &dsdnid);
	dsldir->dd_head_dataset_obj = dsdnid;
	snapds = dsl_dataset_alloc(zfs_opts, mos, dnid, &snapdnid);
	originds->ds_prev_snap_obj = snapdnid;
	snapds->ds_next_snap_obj = dsdnid;
	/* XXXMJ need to add one per dataset */
	snapds->ds_num_children = 2;
	zfs_opts->originsnap = snapdnid;

	snapnames = objset_dnode_alloc(mos, DMU_OT_DSL_DS_SNAP_MAP, &snapmapid);
	originds->ds_snapnames_zapobj = snapmapid;
	zfs_zap_t snapnameszap;
	zap_init(&snapnameszap, snapnames);
	zap_add_uint64(&snapnameszap, "$ORIGIN", snapdnid);
	zap_write(zfs_opts, &snapnameszap);

	(void)dsl_dir_alloc(zfs_opts, mos, parentdir, &dnid);
	zap_add_uint64(&childzap, "$FREE", dnid);

	/* XXXMJ add actual datasets here */

	zap_write(zfs_opts, &childzap);

	return (childdirid);
}

static void
pool_finish(zfs_opt_t *zfs_opts)
{
	zio_cksum_t cksum;
	zfs_objset_t *mos;
	nvlist_t *poolconfig, *vdevconfig;
	uberblock_t *ub;
	dnode_phys_t *objarr;
	vdev_label_t *label;
	char *vdevnv;
	uint64_t guid, txg, msid;
	int error;

	mos = &zfs_opts->mos;

	txg = TXG_INITIAL;
	guid = 0xdeadbeefc0deface;

	/* XXXMJ not sure what needs to be where */

	vdevconfig = nvlist_create(NV_UNIQUE_NAME);
	nvlist_add_string(vdevconfig, ZPOOL_CONFIG_TYPE, VDEV_TYPE_DISK);
	nvlist_add_uint64(vdevconfig, ZPOOL_CONFIG_ASHIFT, zfs_opts->ashift);
	nvlist_add_uint64(vdevconfig, ZPOOL_CONFIG_ASIZE, zfs_opts->vdevsize -
	    VDEV_LABEL_SPACE);
	nvlist_add_uint64(vdevconfig, ZPOOL_CONFIG_GUID, guid);
	nvlist_add_uint64(vdevconfig, ZPOOL_CONFIG_ID, 0);
	nvlist_add_string(vdevconfig, ZPOOL_CONFIG_PATH, "/dev/null");

	poolconfig = nvlist_create(NV_UNIQUE_NAME);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_POOL_TXG, txg);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_VERSION, SPA_VERSION);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_POOL_STATE,
	    POOL_STATE_EXPORTED);
	nvlist_add_string(poolconfig, ZPOOL_CONFIG_POOL_NAME,
	    zfs_opts->poolname);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_POOL_GUID, guid);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_TOP_GUID, guid);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_GUID, guid);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_VDEV_CHILDREN, 1);

	nvlist_t *features = nvlist_create(NV_UNIQUE_NAME);
	nvlist_add_nvlist(poolconfig, ZPOOL_CONFIG_FEATURES_FOR_READ,
	    features);

	/* XXXMJ most of this code should live in pool_init(). */
	{
	dsl_dir_phys_t *dsldir;
	dsl_dataset_phys_t *ds;
	uint64_t dnid, dsldirid, dslid, configid;

	dnode_phys_t *objdirdn = objset_dnode_alloc(mos,
	    DMU_OT_OBJECT_DIRECTORY, &dnid);
	assert(dnid == DMU_POOL_DIRECTORY_OBJECT);

	dnode_phys_t *configdn = objset_dnode_bonus_alloc(mos,
	    DMU_OT_PACKED_NVLIST, DMU_OT_PACKED_NVLIST_SIZE, sizeof(uint64_t),
	    &configid);

	objarr = objset_dnode_alloc(mos, DMU_OT_OBJECT_ARRAY, &msid);
	nvlist_add_uint64(vdevconfig, ZPOOL_CONFIG_METASLAB_ARRAY, msid);
	nvlist_add_uint64(vdevconfig, ZPOOL_CONFIG_METASLAB_SHIFT,
	    zfs_opts->msshift);
	nvlist_add_nvlist(poolconfig, ZPOOL_CONFIG_VDEV_TREE, vdevconfig);

	{
		nvlist_t *nv, *rootvdev;
		off_t configloc, configblksz;

		rootvdev = nvlist_create(NV_UNIQUE_NAME);
		nvlist_add_uint64(rootvdev, ZPOOL_CONFIG_ID, 0);
		nvlist_add_uint64(rootvdev, ZPOOL_CONFIG_GUID, guid);
		nvlist_add_string(rootvdev, ZPOOL_CONFIG_TYPE, VDEV_TYPE_ROOT);
		nvlist_add_nvlist_array(rootvdev, ZPOOL_CONFIG_CHILDREN,
		    &vdevconfig, 1);

		nv = nvlist_create(NV_UNIQUE_NAME);
		nvlist_add_uint64(nv, ZPOOL_CONFIG_POOL_GUID, guid);
		nvlist_add_uint64(nv, ZPOOL_CONFIG_ASIZE, zfs_opts->vdevsize -
		    VDEV_LABEL_SPACE);
		nvlist_add_uint64(nv, ZPOOL_CONFIG_VDEV_CHILDREN, 1);
		nvlist_add_nvlist(nv, ZPOOL_CONFIG_VDEV_TREE, rootvdev);
		nvlist_add_uint64(nv, ZPOOL_CONFIG_POOL_TXG, txg);

		error = nvlist_export(nv);
		if (error != 0)
			errc(1, error, "nvlist_export");

		configblksz = nv->nv_size + sizeof(nv->nv_header);
		assert(configblksz <= (off_t)SPA_OLDMAXBLOCKSIZE);
		configloc = vdev_space_alloc(zfs_opts, &configblksz);

		char *buf = ecalloc(1, configblksz);
		memcpy(buf, &nv->nv_header, sizeof(nv->nv_header));
		memcpy(buf + sizeof(nv->nv_header), nv->nv_data, nv->nv_size);

		vdev_pwrite(zfs_opts, buf, configblksz, configloc);

		fletcher_4_native(buf, configblksz, NULL, &cksum);
		blkptr_set(&configdn->dn_blkptr[0], configloc, configblksz,
		    configdn->dn_type, ZIO_CHECKSUM_FLETCHER_4, &cksum);
		configdn->dn_datablkszsec = configblksz >> SPA_MINBLOCKSHIFT;
		configdn->dn_used = configblksz >> SPA_MINBLOCKSHIFT;
		configdn->dn_nlevels = 1;
		configdn->dn_nblkptr = 1;
		*(uint64_t *)DN_BONUS(configdn) = nv->nv_size + sizeof(nv->nv_header);

		nvlist_destroy(nv);
		free(buf);
	}

	dsldir = dsl_dir_alloc(zfs_opts, mos, 0, &dsldirid);

	{
	zfs_zap_t objdirzap;
	zap_init(&objdirzap, objdirdn);
	zap_add_uint64(&objdirzap, DMU_POOL_ROOT_DATASET, dsldirid);
	zap_add_uint64(&objdirzap, DMU_POOL_CONFIG, configid);
	pool_add_bplists(mos, &objdirzap);
	pool_add_feature_objects(zfs_opts, mos, &objdirzap);
	zap_write(zfs_opts, &objdirzap);
	}

	uint64_t childdirid = pool_add_child_map(zfs_opts, mos, dsldirid);

	ds = dsl_dataset_alloc(zfs_opts, mos, dsldirid, &dslid);
	/* XXXMJ more fields */
	ds->ds_prev_snap_obj = zfs_opts->originsnap;
	ds->ds_used_bytes = 1 << 20; /* XXXMJ */
	ds->ds_uncompressed_bytes = ds->ds_compressed_bytes = ds->ds_used_bytes;
	zfs_objset_t *os = &zfs_opts->rootfs.os;
	fletcher_4_native(os->osphys, os->osblksz, NULL, &cksum);
	blkptr_set(&ds->ds_bp, os->osloc, os->osblksz, DMU_OT_OBJSET,
	    ZIO_CHECKSUM_FLETCHER_4, &cksum);

	/* XXXMJ more fields */
	dsldir->dd_head_dataset_obj = dslid;
	dsldir->dd_child_dir_zapobj = childdirid;
	dsldir->dd_used_bytes = 260 * sizeof(dnode_phys_t); /* XXXMJ plus what else? */
	dsldir->dd_compressed_bytes = dsldir->dd_uncompressed_bytes = dsldir->dd_used_bytes;
	}

	spacemap_write(zfs_opts, objarr);

	label = ecalloc(1, sizeof(*label));

	/* Fill out vdev metadata. */
	error = nvlist_export(poolconfig);
	if (error != 0)
		errc(1, error, "nvlist_export");
	vdevnv = label->vl_vdev_phys.vp_nvlist;
	memcpy(vdevnv, &poolconfig->nv_header, sizeof(poolconfig->nv_header));
	memcpy(vdevnv + sizeof(poolconfig->nv_header), poolconfig->nv_data,
	    poolconfig->nv_size);

	nvlist_destroy(poolconfig);
	nvlist_destroy(vdevconfig);

	objset_write(zfs_opts, mos, &cksum);

	/*
	 * Fill out the uberblock.  Just make each one the same.  The embedded
	 * checksum is calculated in vdev_label_write().
	 */
	for (size_t uoff = 0; uoff < sizeof(label->vl_uberblock);
	    uoff += (1 << zfs_opts->ashift)) {
		ub = (uberblock_t *)(&label->vl_uberblock[0] + uoff);
		ub->ub_magic = UBERBLOCK_MAGIC;
		ub->ub_version = SPA_VERSION;
		ub->ub_txg = txg;
		ub->ub_guid_sum = guid + guid; /* XXXMJ */
		ub->ub_timestamp = 0; /* XXXMJ */

		ub->ub_software_version = SPA_VERSION;
		ub->ub_mmp_magic = MMP_MAGIC;
		ub->ub_mmp_delay = 0;
		ub->ub_mmp_config = 0;
		ub->ub_checkpoint_txg = 0;
		blkptr_set(&ub->ub_rootbp, mos->osloc, mos->osblksz, DMU_OT_OBJSET,
		    ZIO_CHECKSUM_FLETCHER_4, &cksum);
	}

	for (int i = 0; i < VDEV_LABELS; i++)
		vdev_label_write(zfs_opts, i, label);
}

/*
 * Visit each node in a directory hierarchy, in pre-order depth-first order.
 */
static void
fsnode_foreach(fsnode *root, const char *dir,
    void (*cb)(fsnode *, const char *, void *), void *arg)
{
	char path[PATH_MAX];

	assert(root->type == S_IFDIR);
	snprintf(path, sizeof(path), "%s/%s", dir, root->path);

	for (fsnode *cur = root; cur != NULL; cur = cur->next) {
		assert(cur->type == S_IFREG || cur->type == S_IFDIR ||
		    cur->type == S_IFLNK);

		cb(cur, path, arg);
		if (cur->type == S_IFDIR && cur->child != NULL)
			fsnode_foreach(cur->child, path, cb, arg);
	}
}

static void
fsnode_foreach_count(fsnode *cur, const char *dir __unused, void *arg)
{
	uint64_t *countp;

	countp = arg;
	if (cur->type != S_IFDIR || strcmp(cur->name, ".") != 0)
		(*countp)++;
}

static struct dnode_cursor *
dnode_cursor_init(dnode_phys_t *dnode, off_t size, off_t blksz)
{
	struct dnode_cursor *c;
	off_t indcount, nblocks;
	int indlevel;

	assert(dnode->dn_nblkptr == 1);
	assert(blksz <= (off_t)SPA_OLDMAXBLOCKSIZE);

	if (blksz == 0)
		blksz = MIN(SPA_OLDMAXBLOCKSIZE,
		    powerof2(size) ? size : (1ul << flsl(size)));
	else
		assert(powerof2(blksz));

	c = ecalloc(1, sizeof(*c));
	c->dnode = dnode;
	c->off = 0;
	c->datablksz = blksz;

	/*
	 * Do we need indirect blocks?
	 */
	nblocks = blksz == 0 ? 1 : howmany(size, blksz);
	for (indlevel = 1, indcount = 1; nblocks > indcount; indlevel++)
		indcount *= SPA_OLDMAXBLOCKSIZE / sizeof(blkptr_t);
	assert(indlevel < INDIR_LEVELS);

	dnode->dn_nlevels = indlevel;
	dnode->dn_maxblkid = nblocks - 1;
	dnode->dn_datablkszsec = blksz >> SPA_MINBLOCKSHIFT;
	dnode->dn_used = size; /* XXXMJ just data blocks or also indirect? */

	return (c);
}

static void
_dnode_cursor_flush(zfs_opt_t *zfs_opts, struct dnode_cursor *c, int levels)
{
	zio_cksum_t cksum;
	blkptr_t *pbp;
	void *buf;
	off_t blkid, blksz, loc;

	assert(levels > 0);
	assert(levels <= c->dnode->dn_nlevels - 1);

	blksz = SPA_OLDMAXBLOCKSIZE;
	blkid = c->off / c->datablksz;
	for (int i = 0; i < levels; i++) {
		buf = c->inddir[i];

		if (i + 1 == c->dnode->dn_nlevels - 1)
			pbp = &c->dnode->dn_blkptr[0];
		else
			pbp = &c->inddir[i + 1][blkid & BLKPTR_PER_INDIR];

		loc = vdev_space_alloc(zfs_opts, &blksz);
		fletcher_4_native(buf, blksz, NULL, &cksum);
		blkptr_set_level(pbp, loc, blksz, c->dnode->dn_type, i + 1,
		    ZIO_CHECKSUM_FLETCHER_4, &cksum);
		vdev_pwrite(zfs_opts, buf, blksz, loc);
		memset(buf, 0, SPA_OLDMAXBLOCKSIZE);

		blkid /= BLKPTR_PER_INDIR;
	}
}

static blkptr_t *
dnode_cursor_next(zfs_opt_t *zfs_opts, struct dnode_cursor *c, off_t off)
{
	off_t blkid, l1id;
	int levels;

	if (c->dnode->dn_nlevels == 1) {
		assert(off < (off_t)SPA_OLDMAXBLOCKSIZE);
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
			_dnode_cursor_flush(zfs_opts, c, levels);
	}

	c->off = off;
	l1id = (off / c->datablksz) & (BLKPTR_PER_INDIR - 1);
	return (&c->inddir[0][l1id]);
}

static void
dnode_cursor_finish(zfs_opt_t *zfs_opts, struct dnode_cursor *c)
{
	int levels;

	levels = c->dnode->dn_nlevels - 1;
	if (levels > 0)
		_dnode_cursor_flush(zfs_opts, c, levels);
	free(c);
}

struct fsnode_populate_dir_s {
	zfs_zap_t		zap;
	uint64_t		objid;
	SLIST_ENTRY(fsnode_populate_dir_s) next;
};

struct fsnode_foreach_populate_arg {
	zfs_opt_t	*zfs_opts;
	zfs_fs_t	*fs;
	uint64_t	rootdirid;
	char		path[PATH_MAX];
	SLIST_HEAD(, fsnode_populate_dir_s) dirs;
};

static void
fsnode_populate_dirent(struct fsnode_foreach_populate_arg *arg,
    fsnode *cur, uint64_t dnid)
{
	struct fsnode_populate_dir_s *dir;
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
fsnode_populate_attr(zfs_fs_t *fs, char *attrbuf, const void *val, uint16_t ind,
    size_t *szp)
{
	assert(ind < fs->sacnt);
	assert(fs->saoffs[ind] != 0xffff);

	memcpy(attrbuf + fs->saoffs[ind], val, fs->satab[ind].size);
	*szp += fs->satab[ind].size;
}

static void
fsnode_populate_varszattr(zfs_fs_t *fs, char *attrbuf, const void *val,
    size_t valsz, size_t varoff, uint16_t ind, size_t *szp)
{
	assert(ind < fs->sacnt);
	assert(fs->saoffs[ind] != 0xffff);
	assert(fs->satab[ind].size == 0);

	memcpy(attrbuf + fs->saoffs[ind] + varoff, val, valsz);
	*szp += valsz;
}

static void
fsnode_populate_sattrs(struct fsnode_foreach_populate_arg *arg,
    const fsnode *cur, const char *path, dnode_phys_t *dnode)
{
	char symlinktarget[PATH_MAX];
	const fsnode *child;
	zfs_fs_t *fs;
	zfs_ace_hdr_t aces[3];
	struct stat *sb;
	sa_hdr_phys_t *sahdr;
	uint64_t daclcount, flags, gen, gid, links, mode, parent, size, uid;
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
		links = 1;
		size = sb->st_size;
		break;
	case S_IFDIR: {
		unsigned int children, subdirs;

		children = subdirs = 0;
		if (cur->type == S_IFDIR) {
			/*
			 * Handle weird non-uniformity of the root directory: if
			 * the directory has no parent, it's the root and its
			 * children are linked as siblings.
			 */
			child = (cur->parent == NULL && cur->first == cur) ?
			    cur->next : cur->child;
			for (; child != NULL; child = child->next) {
				if (child->type == S_IFDIR)
					subdirs++;
				children++;
			}
		}

		layout = SA_LAYOUT_INDEX;
		links = subdirs + 1;
		size = children;
		break;
	}
	case S_IFLNK:
		memset(symlinktarget, 0, sizeof(symlinktarget));
		if (readlink(path, symlinktarget, sizeof(symlinktarget)) == -1)
			err(1, "readlink(%s)", path);

		layout = SA_LAYOUT_INDEX_SYMLINK;
		links = 1;
		size = strlen(symlinktarget);
		break;
	default:
		assert(0);
	}

	/* XXXMJ hard link support? */
	daclcount = nitems(aces);
	flags = ZFS_ACL_TRIVIAL | ZFS_ACL_AUTO_INHERIT | ZFS_NO_EXECS_DENIED |
	    ZFS_ARCHIVE | ZFS_AV_MODIFIED; /* XXXMJ */
	gen = 1;
	gid = sb->st_gid;
	mode = sb->st_mode;
	parent = SLIST_FIRST(&arg->dirs)->objid;
	uid = sb->st_uid;

	/* XXXMJ need to review these */
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

	fsnode_populate_attr(fs, attrbuf, &daclcount, ZPL_DACL_COUNT, &bonussz);
	fsnode_populate_attr(fs, attrbuf, &flags, ZPL_FLAGS, &bonussz);
	fsnode_populate_attr(fs, attrbuf, &gen, ZPL_GEN, &bonussz);
	fsnode_populate_attr(fs, attrbuf, &gid, ZPL_GID, &bonussz);
	fsnode_populate_attr(fs, attrbuf, &links, ZPL_LINKS, &bonussz);
	fsnode_populate_attr(fs, attrbuf, &mode, ZPL_MODE, &bonussz);
	fsnode_populate_attr(fs, attrbuf, &parent, ZPL_PARENT, &bonussz);
	fsnode_populate_attr(fs, attrbuf, &size, ZPL_SIZE, &bonussz);
	fsnode_populate_attr(fs, attrbuf, &uid, ZPL_UID, &bonussz);

	assert(sizeof(sb->st_atim) == fs->satab[ZPL_ATIME].size);
	fsnode_populate_attr(fs, attrbuf, &sb->st_atim, ZPL_ATIME, &bonussz);
	assert(sizeof(sb->st_ctim) == fs->satab[ZPL_CTIME].size);
	fsnode_populate_attr(fs, attrbuf, &sb->st_ctim, ZPL_CTIME, &bonussz);
	assert(sizeof(sb->st_mtim) == fs->satab[ZPL_MTIME].size);
	fsnode_populate_attr(fs, attrbuf, &sb->st_mtim, ZPL_MTIME, &bonussz);
	assert(sizeof(sb->st_birthtim) == fs->satab[ZPL_CRTIME].size);
	fsnode_populate_attr(fs, attrbuf, &sb->st_birthtim, ZPL_CRTIME,
	    &bonussz);

	fsnode_populate_varszattr(fs, attrbuf, aces, sizeof(aces), 0,
	    ZPL_DACL_ACES, &bonussz);
	sahdr->sa_lengths[0] = sizeof(aces);

	if (cur->type == S_IFLNK) {
		/* Need to use a spill block pointer if the target is long. */
		assert(bonussz + size <= DN_OLD_MAX_BONUSLEN);
		fsnode_populate_varszattr(fs, attrbuf, symlinktarget,
		    size, sahdr->sa_lengths[0], ZPL_SYMLINK, &bonussz);
		sahdr->sa_lengths[1] = (uint16_t)size;
	}

	dnode->dn_bonuslen = bonussz;
}

static void
fsnode_populate_file(fsnode *cur, const char *dir,
    struct fsnode_foreach_populate_arg *arg)
{
	struct dnode_cursor *c;
	dnode_phys_t *dnode;
	zfs_opt_t *zfs_opts;
	char path[PATH_MAX];
	uint64_t dnid;
	ssize_t n;
	size_t bufsz;
	off_t size, target;
	int fd;

	assert(cur->type == S_IFREG);

	zfs_opts = arg->zfs_opts;

	size = cur->inode->st.st_size;

	dnode = objset_dnode_bonus_alloc(&arg->fs->os,
	    DMU_OT_PLAIN_FILE_CONTENTS, DMU_OT_SA, 0, &dnid);

	c = dnode_cursor_init(dnode, size, 0);

	/* Leave room for attributes in the bonus buffer. */
	dnode->dn_checksum = ZIO_CHECKSUM_FLETCHER_4; /* XXXMJ yes? */
	dnode->dn_datablkszsec = MIN(SPA_OLDMAXBLOCKSIZE, 1 << MAX(zfs_opts->ashift, flsl(size))) >>
	    SPA_MINBLOCKSHIFT;
#if 0 /* XXXMJ */
	dnode->dn_maxblkid = 0;
	dnode->dn_used = 0;
#endif

	bufsz = sizeof(zfs_opts->filebuf);
	snprintf(path, sizeof(path), "%s/%s", dir, cur->name);

	fd = open(path, O_RDONLY);
	if (fd == -1)
		err(1, "open(%s)", path);
	for (off_t foff = 0; foff < size; foff += target) {
		zio_cksum_t cksum;
		blkptr_t *bp;
		off_t blkoff, sofar;

		/* Fill up our buffer, handling partial reads. */
		sofar = 0;
		target = MIN(size - foff, (off_t)bufsz);
		do {
			n = read(fd, zfs_opts->filebuf + sofar, target);
			if (n < 0)
				err(1, "reading from '%s'", path);
			if (n == 0)
				errx(1, "unexpected EOF reading '%s'", path);
			sofar += n;
		} while (sofar < target);

		if (target < (off_t)bufsz)
			memset(zfs_opts->filebuf + target, 0, bufsz - target);

		blkoff = vdev_space_alloc(zfs_opts, &target);
		assert(target <= (off_t)SPA_OLDMAXBLOCKSIZE);

		bp = dnode_cursor_next(zfs_opts, c, foff);
		fletcher_4_native(zfs_opts->filebuf, target, NULL, &cksum);
		blkptr_set(bp, blkoff, target, DMU_OT_PLAIN_FILE_CONTENTS,
		    ZIO_CHECKSUM_FLETCHER_4, &cksum);

		vdev_pwrite(zfs_opts, zfs_opts->filebuf, target, blkoff);
	}
	dnode_cursor_finish(zfs_opts, c);

	(void)close(fd);

	fsnode_populate_sattrs(arg, cur, path, dnode);

	fsnode_populate_dirent(arg, cur, dnid);
}

static void
fsnode_populate_dir(fsnode *cur, const char *dir __unused,
    struct fsnode_foreach_populate_arg *arg)
{
	char path[PATH_MAX];
	struct fsnode_populate_dir_s *dirinfo;
	dnode_phys_t *dnode;
	uint64_t dnid;

	assert(cur->type == S_IFDIR);

	dnode = objset_dnode_bonus_alloc(&arg->fs->os,
	    DMU_OT_DIRECTORY_CONTENTS, DMU_OT_SA, 0, &dnid);

	/*
	 * Add an entry to the parent directory.  This must be done before
	 * allocating a ZAP object for this directory's children.
	 */
	if (!SLIST_EMPTY(&arg->dirs))
		fsnode_populate_dirent(arg, cur, dnid);
	else
		arg->rootdirid = dnid;

	dirinfo = ecalloc(1, sizeof(*dirinfo));
	zap_init(&dirinfo->zap, dnode);
	dirinfo->objid = dnid;
	SLIST_INSERT_HEAD(&arg->dirs, dirinfo, next);

	snprintf(path, sizeof(path), "%s/%s", dir, cur->name);

	fsnode_populate_sattrs(arg, cur, path, dnode);
}

static void
fsnode_populate_symlink(fsnode *cur, const char *dir __unused,
    struct fsnode_foreach_populate_arg *arg)
{
	char path[PATH_MAX];
	dnode_phys_t *dnode;
	uint64_t dnid;

	assert(cur->type == S_IFLNK);

	dnode = objset_dnode_bonus_alloc(&arg->fs->os,
	    DMU_OT_PLAIN_FILE_CONTENTS, DMU_OT_SA, 0, &dnid);

	fsnode_populate_dirent(arg, cur, dnid);

	snprintf(path, sizeof(path), "%s/%s", dir, cur->name);
	fsnode_populate_sattrs(arg, cur, path, dnode);
}

static void
fsnode_foreach_populate(fsnode *cur, const char *dir, void *_arg)
{
	struct fsnode_foreach_populate_arg *arg;
	struct fsnode_populate_dir_s *dirs;

	arg = _arg;
	switch (cur->type) {
	case S_IFREG:
		fsnode_populate_file(cur, dir, arg);
		break;
	case S_IFDIR:
		if (strcmp(cur->name, ".") == 0)
			break;
		fsnode_populate_dir(cur, dir, arg);
		break;
	case S_IFLNK:
		fsnode_populate_symlink(cur, dir, arg);
		break;
	default:
		assert(0);
	}

	if (cur->next == NULL) {
		dirs = SLIST_FIRST(&arg->dirs);
		SLIST_REMOVE_HEAD(&arg->dirs, next);

		zap_write(arg->zfs_opts, &dirs->zap);

		free(dirs);
	}
}

static void
fs_add_zpl_attr_layout(zfs_zap_t *zap, unsigned int index,
    const sa_attr_type_t layout[], size_t sacnt)
{
	sa_attr_type_t *sas;
	char ti[8];

	sas = ecalloc(sacnt, sizeof(sa_attr_type_t));
	for (size_t i = 0; i < sacnt; i++)
		sas[i] = htobe16(layout[i]);
	snprintf(ti, sizeof(ti), "%u", index);
	zap_add(zap, ti, sizeof(*sas), sacnt, (uint8_t *)sas);
	free(sas);
}

/*
 * Initialize system attribute tables.
 *
 * There are two elements to this.  First, we write the zpl_attrs[] and
 * zpl_attr_layout[] tables to disk.  Then we create a lookup table which
 * allows us to set file attributes quickly.
 */
static uint64_t
fs_add_zpl_attrs(zfs_opt_t *zfs_opts, zfs_fs_t *fs)
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

	zap_init(&sarzap, sarobj);
	for (size_t i = 0; i < nitems(zpl_attrs); i++) {
		const zfs_sattr_t *sa;
		uint64_t attr;

		attr = 0;
		sa = &zpl_attrs[i];
		SA_ATTR_ENCODE(attr, (uint64_t)i, sa->size, sa->bs);
		zap_add_uint64(&sarzap, sa->name, attr);
	}
	zap_write(zfs_opts, &sarzap);

	/*
	 * Layouts are arrays of indices into the registry.  We define two
	 * layouts for use by the ZPL, one for non-symlinks and one for
	 * symlinks.  They are identical except that the symlink layout includes
	 * ZPL_SYMLINK as its final attribute.
	 */
	zap_init(&salzap, salobj);
	assert(zpl_attr_layout[nitems(zpl_attr_layout) - 1] == ZPL_SYMLINK);
	fs_add_zpl_attr_layout(&salzap, SA_LAYOUT_INDEX, zpl_attr_layout,
	    nitems(zpl_attr_layout) - 1);
	fs_add_zpl_attr_layout(&salzap, SA_LAYOUT_INDEX_SYMLINK,
	    zpl_attr_layout, nitems(zpl_attr_layout));
	zap_write(zfs_opts, &salzap);

	zap_init(&sazap, saobj);
	zap_add_uint64(&sazap, SA_LAYOUTS, salobjid);
	zap_add_uint64(&sazap, SA_REGISTRY, sarobjid);
	zap_write(zfs_opts, &sazap);

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
mkfs(zfs_opt_t *zfs_opts, zfs_fs_t *fs, const char *dir, fsnode *root)
{
	struct fsnode_foreach_populate_arg poparg;
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
	fsnode_foreach(root, dir, fsnode_foreach_count, &dnodecount);
	dnodecount++; /* meta dnode */
	dnodecount++; /* master object */
	dnodecount++; /* root directory */
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
	objset_init(zfs_opts, os, DMU_OST_ZFS, dnodecount);
	masterobj = objset_dnode_alloc(os, DMU_OT_MASTER_NODE, &moid);
	assert(moid == MASTER_NODE_OBJ);

	/*
	 * Create the ZAP SA layout now, since filesystem object dnodes will
	 * refer to those attributes.
	 */
	saobjid = fs_add_zpl_attrs(zfs_opts, fs);

	/*
	 * Build the filesystem.  This is where most of the work happens.
	 */
	poparg.zfs_opts = zfs_opts;
	poparg.fs = fs;
	SLIST_INIT(&poparg.dirs);
	fsnode_populate_dir(root, dir, &poparg);
	assert(!SLIST_EMPTY(&poparg.dirs));
	fsnode_foreach(root, dir, fsnode_foreach_populate, &poparg);
	assert(SLIST_EMPTY(&poparg.dirs));

	/*
	 * Create an empty delete queue.  We don't do anything with it, but
	 * OpenZFS will refuse to mount filesystems that don't have one.
	 */
	deleteq = objset_dnode_alloc(os, DMU_OT_UNLINKED_SET, &deleteqid);
	zap_init(&deleteqzap, deleteq);
	zap_write(zfs_opts, &deleteqzap);

	/*
	 * Populate the master node object.  This is a ZAP object containing
	 * various dataset properties and the object IDs of the root directory
	 * and delete queue.
	 */
	zap_init(&masterzap, masterobj);
	zap_add_uint64(&masterzap, ZFS_ROOT_OBJ, poparg.rootdirid);
	zap_add_uint64(&masterzap, ZFS_UNLINKED_SET, deleteqid);
	zap_add_uint64(&masterzap, ZFS_SA_ATTRS, saobjid);
	/* XXXMJ create a ZFS_SHARES_DIR directory, OpenZFS won't do it */
	zap_add_uint64(&masterzap, ZPL_VERSION_OBJ, 5 /* ZPL_VERSION_SA */);
	zap_add_uint64(&masterzap, "normalization", 0 /* off */);
	zap_add_uint64(&masterzap, "utf8only", 0 /* off */);
	zap_add_uint64(&masterzap, "casesensitivity", 0 /* case sensitive */);
	zap_add_uint64(&masterzap, "acltype", 2 /* NFSv4 */);
	zap_write(zfs_opts, &masterzap);

	/* Finally, write the dnode array and objset set itself. */
	objset_write(zfs_opts, &fs->os, NULL);
}

void
zfs_makefs(const char *image, const char *dir, fsnode *root, fsinfo_t *fsopts)
{
	zfs_opt_t *zfs_opts;

	zfs_opts = fsopts->fs_specific;

	if (fsopts->offset != 0)
		errx(1, "unhandled offset option");

	/*
	 * Use a fixed seed to provide reproducible pseudo-random numbers for
	 * on-disk structures when needed (e.g., ZAP hash salts).
	 */
	srandom(1729);

	if (vdev_init(zfs_opts, fsopts->maxsize, image) != 0)
		goto out;

	pool_init(zfs_opts);

	mkfs(zfs_opts, &zfs_opts->rootfs, dir, root);

	pool_finish(zfs_opts);
out:
	if (zfs_opts->fd != -1)
		(void)close(zfs_opts->fd);
	free(zfs_opts->spacemap);
}
