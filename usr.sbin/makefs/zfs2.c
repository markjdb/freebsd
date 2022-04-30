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

#define	ASSERT	assert
#include "zfs/libzfs.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#include "fletcher.c"
#include "sha256.c"
#pragma clang diagnostic pop

/*
 * XXXMJ
 * - dn_checksum should be set at dnode initialization time
 */

/*
 * XXXMJ this might wrong but I don't understand where DN_MAX_LEVELS' definition
 * comes from.  Be sure to test with large files...
 */
#define	INDIR_LEVELS	6

typedef struct {
	objset_phys_t	*osphys;
	off_t		osloc;
	off_t		osblksz;
	dnode_phys_t	*dnodes;	/* dnode array */
	uint64_t	dnodenextfree;	/* dnode ID bump allocator */
	uint64_t	dnodecount;	/* total number of dnodes */
	off_t		dnodeloc;
	off_t		dnodeblksz;
} zfs_objset_t;

typedef struct zfs_zap_entry {
	char		*name;
	union {
		uint8_t	*valp;
		uint64_t val;
	};
	size_t		intsz;
	size_t		intcnt;
	STAILQ_ENTRY(zfs_zap_entry) next;
} zfs_zap_entry_t;

typedef struct zfs_zap {
	off_t			loc;
	off_t			blksz;
	mzap_ent_phys_t		*ent;
	off_t			zapblksz;	/* XXXMJ confusing with blksz */
	char			zapblk[SPA_OLDMAXBLOCKSIZE];
	zap_leaf_chunk_t	*firstchunk;
	char			leafblk[SPA_OLDMAXBLOCKSIZE];

	STAILQ_HEAD(, zfs_zap_entry) kvps;
	unsigned long		kvcnt;
	bool			micro;
	dnode_phys_t		*dnode;
} zfs_zap_t;

typedef struct {
	zfs_objset_t	os;
	dnode_phys_t	*dnode;		/* object set dnode */
	uint64_t	dnodeid;	/* objset set dnode ID */
} zfs_fs_t;

typedef struct {
	/* Pool parameters. */
	const char	*poolname;
	int		ashift;
	off_t		size;

	/* Pool info. */
	zfs_objset_t	mos;		/* meta object set */
	bitstr_t	*spacemap;	/* space allocator */
	int		spacemapbits;	/* one bit per ashift-sized block */
	zfs_fs_t	rootfs;

	/* I/O buffer. */
	char		filebuf[SPA_OLDMAXBLOCKSIZE];
} zfs_opt_t;

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
blkptr_set(blkptr_t *bp, off_t off, off_t size, enum zio_checksum cksumt,
    zio_cksum_t *cksum)
{
	dva_t *dva;

	/* XXXMJ assert size is a power of 2? */

	BP_ZERO(bp);
	BP_SET_LSIZE(bp, size);
	BP_SET_PSIZE(bp, size);
	BP_SET_CHECKSUM(bp, cksumt);
	BP_SET_COMPRESS(bp, ZIO_COMPRESS_OFF);
	BP_SET_BYTEORDER(bp, ZFS_HOST_BYTEORDER);
	BP_SET_BIRTH(bp, TXG_INITIAL, TXG_INITIAL);

	dva = BP_IDENTITY(bp);
	DVA_SET_VDEV(dva, 0);
	DVA_SET_OFFSET(dva, off);
	DVA_SET_ASIZE(dva, size);
	memcpy(&bp->blk_cksum, cksum, sizeof(*cksum));
}

static void
vdev_pwrite(fsinfo_t *fsopts, void *buf, size_t len, off_t off)
{
	ssize_t n;

	/* XXXMJ check that [off,off+len) is in bounds */

	off += VDEV_LABEL_START_SIZE;
	do {
		n = pwrite(fsopts->fd, buf, len, off);
		if (n < 0)
			err(1, "writing image");
		len -= n;
		off += n;
	} while (len > 0);
}

static void
vdev_write_label_checksum(void *buf, off_t off, off_t size)
{
	zio_cksum_t cksum;
	zio_eck_t *eck;

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
vdev_write_label(fsinfo_t *fsopts, int ind, vdev_label_t *label)
{
	zfs_opt_t *zfs_opts;
	ssize_t n;
	off_t blksz, loff;

	assert(ind >= 0 && ind < VDEV_LABELS);

	zfs_opts = fsopts->fs_specific;
	blksz = 1 << zfs_opts->ashift;

	if (ind < 2)
		loff = ind * sizeof(vdev_label_t);
	else
		loff = zfs_opts->size - (VDEV_LABELS - ind) * sizeof(vdev_label_t);

	/*
	 * Set the verifier checksum for the boot block.  We don't use it, but
	 * the loader reads it and will complain if the checksum isn't valid.
	 */
	vdev_write_label_checksum(&label->vl_be,
	    loff + __offsetof(vdev_label_t, vl_be),
	    sizeof(vdev_boot_envblock_t));

	/*
	 * Set the verifier checksum for the label.
	 */
	vdev_write_label_checksum(&label->vl_vdev_phys,
	    loff + __offsetof(vdev_label_t, vl_vdev_phys), sizeof(vdev_phys_t));

	/*
	 * Set the verifier checksum for the uberblocks.
	 */
	assert(sizeof(label->vl_uberblock) % blksz == 0);
	for (size_t roff = 0; roff < sizeof(label->vl_uberblock);
	    roff += blksz) {
		vdev_write_label_checksum(&label->vl_uberblock[0] + roff,
		    loff + __offsetof(vdev_label_t, vl_uberblock) + roff,
		    blksz);
	}

	n = pwrite(fsopts->fd, label, sizeof(*label), loff);
	if (n < 0)
		err(1, "writing vdev label");
	assert(n == sizeof(*label));
}

static int
spacemap_init(zfs_opt_t *zfs_opts)
{
	off_t nbits, size;

	size = zfs_opts->size;

	assert(size >= (off_t)(VDEV_LABEL_START_SIZE + VDEV_LABEL_END_SIZE));

	nbits = (size - VDEV_LABEL_START_SIZE - VDEV_LABEL_END_SIZE) >>
	    zfs_opts->ashift;
	if (nbits > INT_MAX) {
		/*
		 * With the smallest block size of 512B, the limit on the image
		 * size is 2TB.
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
	return (0);
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
 */
static off_t
space_alloc(zfs_opt_t *zfs_opts, off_t *lenp)
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

static void
objset_init(zfs_opt_t *zfs_opts, zfs_objset_t *os, uint64_t type,
    uint64_t dnodecount)
{
	dnode_phys_t *mdnode;

	/* Object zero is always meta dnode. */
	os->dnodecount = dnodecount + 1;
	os->dnodenextfree = 1;

	/* Allocate space on the vdev for the objset and dnode array. */
	os->osblksz = sizeof(objset_phys_t);
	os->osloc = space_alloc(zfs_opts, &os->osblksz);

	os->dnodeblksz = sizeof(dnode_phys_t) * os->dnodecount;
	os->dnodeloc = space_alloc(zfs_opts, &os->dnodeblksz);

	/* XXXMJ what else? */
	os->osphys = ecalloc(1, os->osblksz);
	mdnode = &os->osphys->os_meta_dnode;
	mdnode->dn_type = DMU_OT_DNODE;
	mdnode->dn_datablkszsec = os->dnodeblksz >> SPA_MINBLOCKSHIFT;
	mdnode->dn_bonustype = DMU_OT_NONE;
	mdnode->dn_nlevels = 1;
	os->osphys->os_type = type;

	os->dnodes = ecalloc(1, os->dnodeblksz);
}

static void
objset_write(fsinfo_t *fsopts, zfs_objset_t *os)
{
	/* XXXMJ this will need to be revisited */
	assert(os->dnodeblksz <= (off_t)SPA_OLDMAXBLOCKSIZE);
	vdev_pwrite(fsopts, os->dnodes, os->dnodeblksz, os->dnodeloc);

	/* XXXMJ update block pointers */
	vdev_pwrite(fsopts, os->osphys, os->osblksz, os->osloc);

	/* XXXMJ can't free the (root) objset buffer here */
}

static dnode_phys_t *
objset_dnode_bonus_alloc(zfs_objset_t *os, uint8_t type, uint8_t bonustype,
    uint64_t *idp)
{
	dnode_phys_t *dnode;

	assert(os->dnodenextfree < os->dnodecount);
	if (idp != NULL)
		*idp = os->dnodenextfree;
	dnode = &os->dnodes[os->dnodenextfree++];
	dnode->dn_type = type;
	dnode->dn_bonustype = bonustype;
	dnode->dn_compress = ZIO_COMPRESS_OFF;
	return (dnode);
}

static dnode_phys_t *
objset_dnode_alloc(zfs_objset_t *os, uint8_t type, uint64_t *idp)
{
	return (objset_dnode_bonus_alloc(os, type, DMU_OT_NONE, idp));
}

/* XXXMJ from zfssubr.c */
static uint64_t
zap_hash(uint64_t salt, const char *name)
{
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
}

static void
zap_init(zfs_zap_t *zap, dnode_phys_t *dnode)
{
	mzap_phys_t *zaphdr;

	memset(zap, 0, sizeof(*zap));

	zaphdr = (mzap_phys_t *)&zap->zapblk[0];
	zaphdr->mz_block_type = ZBT_MICRO;
	zaphdr->mz_salt = 0; /* XXXMJ */
	zaphdr->mz_normflags = 0;

	zap->blksz = __offsetof(mzap_phys_t, mz_chunk);
	zap->ent = &zaphdr->mz_chunk[0];

	STAILQ_INIT(&zap->kvps);
	zap->micro = true;
	zap->kvcnt = 0;
	zap->dnode = dnode;
}

static void
fzap_init(zfs_zap_t *zap, off_t blksz)
{
	zap_phys_t *zaphdr;

	memset(zap, 0, sizeof(*zap));

	zap->zapblksz = blksz;

	zaphdr = (zap_phys_t *)&zap->zapblk[0];
	zaphdr->zap_block_type = ZBT_HEADER;
	zaphdr->zap_magic = ZAP_MAGIC;

	zaphdr->zap_ptrtbl.zt_blk = 0;	/* embedded in the same block */
	zaphdr->zap_ptrtbl.zt_numblks = 0; /* embedded in the same block */
	zaphdr->zap_ptrtbl.zt_shift = 0; /* XXX */ /* required for embedded hash table */
	zaphdr->zap_ptrtbl.zt_nextblk = 0;
	zaphdr->zap_ptrtbl.zt_blks_copied = 0;

	zaphdr->zap_freeblk = 0;
	zaphdr->zap_num_leafs = 0;
	zaphdr->zap_num_entries = 0;
	zaphdr->zap_salt = 1; /* XXXMJ */
	zaphdr->zap_normflags = 0;
	zaphdr->zap_flags = 0;
}

static void
fzap_add_array(zfs_zap_t *zap, const char *name, uint64_t intsz,
    uint64_t intcnt, uint8_t *array)
{
	zap_leaf_t l;
	zap_phys_t *zaphdr;
	size_t len;
	uint64_t hash;

	l.l_bs = flsl(zap->zapblksz) - 1;
	l.l_phys = (zap_leaf_phys_t *)&zap->leafblk[0];

	zaphdr = (zap_phys_t *)&zap->zapblk[0];
	zaphdr->zap_num_leafs++;
	zaphdr->zap_num_entries++;

	hash = zap_hash(zaphdr->zap_salt, name);

	l.l_phys->l_hdr.lh_block_type = ZBT_LEAF;
	l.l_phys->l_hdr.lh_prefix = 0 /* XXXMJ */;
	l.l_phys->l_hdr.lh_magic = ZAP_LEAF_MAGIC;
	l.l_phys->l_hdr.lh_nfree = 0 /* XXXMJ */;
	l.l_phys->l_hdr.lh_nentries = 0 /* XXXMJ */;
	l.l_phys->l_hdr.lh_prefix_len = 0 /* XXXMJ */;
	l.l_phys->l_hdr.lh_freelist = 0 /* XXXMJ */;

	uint16_t *hashentp = ZAP_LEAF_HASH_ENTPTR(&l, hash);
	*hashentp = 0; /* XXXMJ should be whatever the next free one is */

	struct zap_leaf_entry *le = ZAP_LEAF_ENTRY(&l, *hashentp);
	le->le_type = ZAP_CHUNK_ENTRY;
	le->le_value_intlen = intsz;
	le->le_next = 0; /* XXXMJ */
	le->le_name_chunk = 1; /* XXXMJ */
	le->le_name_numints = strlen(name) + 1;
	le->le_value_chunk = 2;
	le->le_value_numints = intcnt;
	le->le_cd = 0; /* XXXMJ */
	le->le_hash = hash;

	/* XXXMJ hard-coding offsets */
	struct zap_leaf_array *la = &ZAP_LEAF_CHUNK(&l, 1).l_array;
	la->la_type = ZAP_CHUNK_ARRAY;
	/* XXXMJ need to check for truncation */
	assert(strlen(name) + 1 <= ZAP_LEAF_ARRAY_BYTES);
	(void)strlcpy(la->la_array, name, sizeof(la->la_array));
	la->la_next = 2;

	len = intcnt * intsz;

	size_t resid = len;
	int i;
	for (i = 2; resid > 0; i++) {
		size_t tocopy;

		la->la_next = i;
		assert(i < ZAP_LEAF_NUMCHUNKS(&l));
		la = &ZAP_LEAF_CHUNK(&l, i).l_array;
		tocopy = MIN(ZAP_LEAF_ARRAY_BYTES, resid);
		memcpy(la->la_array, array, tocopy);
		resid -= tocopy;
	}
	la = &ZAP_LEAF_CHUNK(&l, i).l_array;
	la->la_next = 0xffff;
}

static void
zap_add(zfs_zap_t *zap, const char *name, size_t intsz, size_t intcnt,
    const uint8_t *val)
{
	zfs_zap_entry_t *ent;

	ent = ecalloc(1, sizeof(*ent));
	ent->name = estrdup(name);
	ent->intsz = intsz;
	ent->intcnt = intcnt;
	if (intsz == sizeof(uint64_t) && intcnt == 1) {
		memcpy(&ent->val, val, sizeof(uint64_t));
	} else {
		ent->valp = ecalloc(intcnt, intsz);
		memcpy(ent->valp, val, intcnt * intsz);
		zap->micro = false;
	}
	if (strlen(name) + 1 > MZAP_NAME_LEN)
		zap->micro = false;
	if (++zap->kvcnt > MZAP_ENT_MAX)
		zap->micro = false;

	STAILQ_INSERT_TAIL(&zap->kvps, ent, next);
}

static void
zap_add_uint64(zfs_zap_t *zap, const char *name, uint64_t val)
{
	zap_add(zap, name, sizeof(uint64_t), 1, (uint8_t *)&val);
}

static void
zap_micro_write(fsinfo_t *fsopts, zfs_zap_t *zap)
{
	zio_cksum_t cksum;
	dnode_phys_t *dnode;
	zfs_zap_entry_t *ent, *tmp;
	zfs_opt_t *zfs_opts;
	mzap_phys_t *mzap;
	mzap_ent_phys_t *ment;
	off_t bytes, loc;

	zfs_opts = fsopts->fs_specific;

	memset(zfs_opts->filebuf, 0, sizeof(zfs_opts->filebuf));
	mzap = (mzap_phys_t *)&zfs_opts->filebuf[0];
	mzap->mz_block_type = ZBT_MICRO;
	mzap->mz_salt = 1; /* XXXMJ */
	mzap->mz_normflags = 0;

	bytes = sizeof(*mzap) + (zap->kvcnt - 1) * sizeof(*ment);
	assert(bytes <= (off_t)MZAP_MAX_BLKSZ);

	ment = &mzap->mz_chunk[0];
	STAILQ_FOREACH_SAFE(ent, &zap->kvps, next, tmp) {
		ment->mze_value = ent->val;
		ment->mze_cd = 0; /* XXXMJ */
		strlcpy(ment->mze_name, ent->name, sizeof(ment->mze_name));

		free(ent->name);
		free(ent);

		ment++;
	}

	loc = space_alloc(zfs_opts, &bytes);

	dnode = zap->dnode;
	dnode->dn_nblkptr = 1;
	dnode->dn_nlevels = 1;
	dnode->dn_checksum = ZIO_CHECKSUM_FLETCHER_4;
	dnode->dn_datablkszsec = bytes >> SPA_MINBLOCKSHIFT;

	fletcher_4_native(zfs_opts->filebuf, bytes, NULL, &cksum);
	blkptr_set(&dnode->dn_blkptr[0], loc, bytes, ZIO_CHECKSUM_FLETCHER_4,
	    &cksum);

	vdev_pwrite(fsopts, zfs_opts->filebuf, bytes, loc);
}

static void
zap_fat_write(fsinfo_t *fsopts, zfs_zap_t *zap)
{
	(void)fsopts;
	(void)zap;
	assert(0);
}

static void
zap_write(fsinfo_t *fsopts, zfs_zap_t *zap)
{
	if (zap->micro)
		zap_micro_write(fsopts, zap);
	else
		zap_fat_write(fsopts, zap);
}

static void
fzap_write(fsinfo_t *fsopts, zfs_zap_t *zap, dnode_phys_t *dnode)
{
	zfs_opt_t *zfs_opts;
	zio_cksum_t cksum;
	off_t lloc;

	zfs_opts = fsopts->fs_specific;

	zap->loc = space_alloc(zfs_opts, &zap->zapblksz);
	lloc = space_alloc(zfs_opts, &zap->zapblksz);

	dnode->dn_nblkptr = 2;
	dnode->dn_nlevels = 1;
	dnode->dn_bonustype = DMU_OT_NONE;
	dnode->dn_checksum = ZIO_CHECKSUM_FLETCHER_4;
	dnode->dn_datablkszsec = zap->zapblksz >> SPA_MINBLOCKSHIFT;

	fletcher_4_native(zap->zapblk, zap->zapblksz, NULL, &cksum);
	blkptr_set(&dnode->dn_blkptr[0], zap->loc, zap->zapblksz,
	    ZIO_CHECKSUM_FLETCHER_4, &cksum);
	fletcher_4_native(zap->leafblk, zap->zapblksz, NULL, &cksum);
	blkptr_set(&dnode->dn_blkptr[1], lloc, zap->zapblksz,
	    ZIO_CHECKSUM_FLETCHER_4, &cksum);

	vdev_pwrite(fsopts, zap->zapblk, zap->zapblksz, zap->loc);
	vdev_pwrite(fsopts, zap->leafblk, zap->zapblksz, lloc);
}

/*
 * Initialize the meta-object set.
 */
static void
pool_init(fsinfo_t *fsopts)
{
	zfs_opt_t *zfs_opts;
	uint64_t dnodecount;

	zfs_opts = fsopts->fs_specific;

	dnodecount = 0;
	dnodecount++; /* object directory (ZAP)               */
	dnodecount++; /* |-> vdev config object (nvlist)      */
	dnodecount++; /* |-> DSL directory                    */
	dnodecount++; /*     |-> DSL child directory (ZAP)    */
	dnodecount++; /*     |   |-> $MOS                     */
	dnodecount++; /*     |   |-> $FREE                    */
	dnodecount++; /*     |   L-> $ORIGIN                  */
	dnodecount++; /*     |-> DSL root dataset             */
	objset_init(zfs_opts, &zfs_opts->mos, DMU_OST_META, dnodecount);
}

static void
pool_add_feature_objects(fsinfo_t *fsopts, zfs_objset_t *mos, zfs_zap_t *objdir)
{
	zfs_zap_t zap;
	dnode_phys_t *dnode;
	uint64_t dnid;

	dnode = objset_dnode_alloc(mos, DMU_OTN_ZAP_METADATA, &dnid);
	zap_add_uint64(objdir, DMU_POOL_FEATURES_FOR_READ, dnid);

	zap_init(&zap, dnode);
	zap_write(fsopts, &zap);

	dnode = objset_dnode_alloc(mos, DMU_OTN_ZAP_METADATA, &dnid);
	zap_add_uint64(objdir, DMU_POOL_FEATURES_FOR_WRITE, dnid);

	dnode = objset_dnode_alloc(mos, DMU_OTN_ZAP_DATA, &dnid);
	zap_add_uint64(objdir, DMU_POOL_FEATURE_DESCRIPTIONS, dnid);

	dnode = objset_dnode_bonus_alloc(mos, DMU_OT_BPLIST, DMU_OT_BPLIST_HDR,
	    &dnid);
	zap_add_uint64(objdir, DMU_POOL_FREE_BPOBJ, dnid);
}

static void
pool_finish(fsinfo_t *fsopts)
{
	zio_cksum_t cksum;
	zfs_objset_t *mos;
	nvlist_t *poolconfig, *vdevconfig;
	uberblock_t *ub;
	vdev_label_t *label;
	zfs_opt_t *zfs_opts;
	char *vdevnv;
	uint64_t guid, txg;
	int error;

	zfs_opts = fsopts->fs_specific;
	mos = &zfs_opts->mos;

	txg = TXG_INITIAL;
	guid = 0xdeadbeefc0deface;

	/* XXXMJ not sure what needs to be where */

	vdevconfig = nvlist_create(NV_UNIQUE_NAME);
	nvlist_add_string(vdevconfig, ZPOOL_CONFIG_TYPE, VDEV_TYPE_DISK);
	nvlist_add_uint64(vdevconfig, ZPOOL_CONFIG_ASHIFT, zfs_opts->ashift);
	nvlist_add_uint64(vdevconfig, ZPOOL_CONFIG_ASIZE, zfs_opts->size -
	    VDEV_LABEL_START_SIZE - VDEV_LABEL_END_SIZE);
	nvlist_add_uint64(vdevconfig, ZPOOL_CONFIG_GUID, guid);
	nvlist_add_uint64(vdevconfig, ZPOOL_CONFIG_ID, 0);
	nvlist_add_string(vdevconfig, ZPOOL_CONFIG_PATH, "/dev/null");

	poolconfig = nvlist_create(NV_UNIQUE_NAME);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_POOL_TXG, txg);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_VERSION, SPA_VERSION);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_POOL_STATE,
	    POOL_STATE_ACTIVE);
	nvlist_add_string(poolconfig, ZPOOL_CONFIG_POOL_NAME,
	    zfs_opts->poolname);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_POOL_GUID, guid);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_TOP_GUID, guid);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_GUID, guid);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_VDEV_CHILDREN, 1);
	nvlist_add_nvlist(poolconfig, ZPOOL_CONFIG_VDEV_TREE, vdevconfig);

	nvlist_t *features = nvlist_create(NV_UNIQUE_NAME);
	nvlist_add_nvlist(poolconfig, ZPOOL_CONFIG_FEATURES_FOR_READ,
	    features);

	/* XXXMJ most of this code should live in pool_init(). */
	{
	dsl_dir_phys_t *dsldir;
	dsl_dataset_phys_t *ds;
	zfs_zap_t objdirzap;
	uint64_t dnid, dsldirid, dslid, configid;

	dnode_phys_t *objdirdn = objset_dnode_alloc(mos,
	    DMU_OT_OBJECT_DIRECTORY, &dnid);
	assert(dnid == DMU_POOL_DIRECTORY_OBJECT);

	dnode_phys_t *dsldirdn = objset_dnode_bonus_alloc(mos, DMU_OT_DSL_DIR,
	    DMU_OT_DSL_DIR, &dsldirid);

	dnode_phys_t *configdn = objset_dnode_bonus_alloc(mos,
	    DMU_OT_PACKED_NVLIST, DMU_OT_PACKED_NVLIST_SIZE, &configid);
	configdn->dn_bonuslen = sizeof(uint64_t);

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
		nvlist_add_uint64(nv, ZPOOL_CONFIG_ASIZE, zfs_opts->size -
		    VDEV_LABEL_START_SIZE - VDEV_LABEL_END_SIZE);
		nvlist_add_uint64(nv, ZPOOL_CONFIG_VDEV_CHILDREN, 1);
		nvlist_add_nvlist(nv, ZPOOL_CONFIG_VDEV_TREE, rootvdev);
		nvlist_add_uint64(nv, ZPOOL_CONFIG_POOL_TXG, txg);

		error = nvlist_export(nv);
		if (error != 0)
			errc(1, error, "nvlist_export");

		configblksz = nv->nv_size + sizeof(nv->nv_header);
		assert(configblksz <= (off_t)SPA_OLDMAXBLOCKSIZE);
		configloc = space_alloc(zfs_opts, &configblksz);

		char *buf = ecalloc(1, configblksz);
		memcpy(buf, &nv->nv_header, sizeof(nv->nv_header));
		memcpy(buf + sizeof(nv->nv_header), nv->nv_data, nv->nv_size);

		vdev_pwrite(fsopts, buf, configblksz, configloc);

		fletcher_4_native(buf, configblksz, NULL, &cksum);
		blkptr_set(&configdn->dn_blkptr[0], configloc, configblksz,
		    ZIO_CHECKSUM_FLETCHER_4, &cksum);
		configdn->dn_datablkszsec = configblksz >> SPA_MINBLOCKSHIFT;
		configdn->dn_nlevels = 1;
		configdn->dn_nblkptr = 1;
		*(uint64_t *)DN_BONUS(configdn) = nv->nv_size + sizeof(nv->nv_header);

		nvlist_destroy(nv);
		free(buf);
	}

	dsldirdn->dn_datablkszsec = zfs_opts->ashift - SPA_MINBLOCKSHIFT;
	dsldirdn->dn_nlevels = 1;
	dsldirdn->dn_nblkptr = 1;
	dsldirdn->dn_bonuslen = sizeof(dsl_dir_phys_t);
	dsldir = (dsl_dir_phys_t *)DN_BONUS(dsldirdn);

	/* XXXMJ large thing to put on the stack */
	zap_init(&objdirzap, objdirdn);
	zap_add_uint64(&objdirzap, DMU_POOL_ROOT_DATASET, dsldirid);
	zap_add_uint64(&objdirzap, DMU_POOL_CONFIG, configid);

	/* XXXMJ these must be valid object IDs */
	pool_add_feature_objects(fsopts, mos, &objdirzap);
	/* XXXMJ add other keys */
	zap_write(fsopts, &objdirzap);

	dnode_phys_t *dsldn = objset_dnode_bonus_alloc(mos, DMU_OTN_ZAP_DATA,
	    DMU_OT_OBJECT_DIRECTORY, &dslid);
	dsldn->dn_nblkptr = 1;
	dsldn->dn_bonuslen = sizeof(dsl_dataset_phys_t);

	zfs_objset_t *os = &zfs_opts->rootfs.os;
	fletcher_4_native(os->osphys, os->osblksz, NULL, &cksum);

	/* XXXMJ more fields */
	ds = (dsl_dataset_phys_t *)DN_BONUS(dsldn);
	ds->ds_dir_obj = dsldirid;
	blkptr_set(&ds->ds_bp, os->osloc, os->osblksz,
	    ZIO_CHECKSUM_FLETCHER_4, &cksum);

	/* XXXMJ more fields */
	dsldir->dd_head_dataset_obj = dslid;
	}

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

	fletcher_4_native(mos->dnodes, mos->dnodeblksz, NULL, &cksum);
	mos->osphys->os_meta_dnode.dn_nblkptr = 1;
	blkptr_set(&mos->osphys->os_meta_dnode.dn_blkptr[0], mos->dnodeloc,
	    mos->dnodeblksz, ZIO_CHECKSUM_FLETCHER_4, &cksum);

	fletcher_4_native(mos->osphys, mos->osblksz, NULL, &cksum);
	objset_write(fsopts, mos);

	/*
	 * Fill out the uberblock.  Just make each one the same.  The embedded
	 * checksum is calculated in vdev_write_label().
	 */
	for (size_t roff = 0; roff < sizeof(label->vl_uberblock);
	    roff += (1 << zfs_opts->ashift)) {
		ub = (uberblock_t *)(&label->vl_uberblock[0] + roff);
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
		blkptr_set(&ub->ub_rootbp, mos->osloc, mos->osblksz,
		    ZIO_CHECKSUM_FLETCHER_4, &cksum);
	}

	for (int i = 0; i < VDEV_LABELS; i++)
		vdev_write_label(fsopts, i, label);
}

static void
mkspacemap(fsinfo_t *fsopts)
{
	zfs_opt_t *zfs_opts;
	bitstr_t *spacemap;
	int bits;

	zfs_opts = fsopts->fs_specific;
	spacemap = zfs_opts->spacemap;
	bits = zfs_opts->spacemapbits;

	/*
	 * Figure out how many space map entries we need.  We have yet to
	 * allocate blocks for the space map itself.
	 */
	int loc = 0, loc1, nent;
	int allocbits = 0;
	off_t smbytes = 0;
	for (nent = 0; loc != -1; nent++) {
		bit_ffs_at(spacemap, loc, bits, &loc);
		if (loc == -1)
			break;
		loc1 = loc;
		bit_ffc_at(spacemap, loc, bits, &loc);
		if (loc == -1)
			allocbits += bits - loc1;
		else
			allocbits += loc - loc1;
		smbytes += 2;
	}
}

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

/* XXXMJ fold this into populate arg? */
struct blkptr_alloc_s {
	char		buf[INDIR_LEVELS][SPA_OLDMAXBLOCKSIZE];
	dnode_phys_t	*dnode;
	off_t		off;
	int		indblksz;
	int		levels;
};

static void
blkptr_alloc_init(fsinfo_t *fsopts, struct blkptr_alloc_s *s,
    dnode_phys_t *dnode, off_t size)
{
	zfs_opt_t *zfs_opts;
	off_t max, nblocks;
	int indlevel;

	zfs_opts = fsopts->fs_specific;

	/*
	 * Do we need indirect blocks?
	 */
	nblocks = howmany(size, SPA_OLDMAXBLOCKSIZE);
	for (indlevel = 0, max = 1; nblocks > max; indlevel++)
		max *= SPA_OLDMAXBLOCKSIZE / sizeof(blkptr_t);
	assert(indlevel < INDIR_LEVELS);

	/*
	 * XXXMJ does the "rightmost" indirect block in a level have to have the
	 * same block size as the rest?  If not then we can save space at the
	 * expsense of some complexity.  Or maybe (probably) it's not worth it
	 * once you have a large enough indir tree.
	 */
	s->dnode = dnode;
	s->off = 0;
	s->levels = indlevel;
	switch (s->levels) {
	case 0:
		s->indblksz = 0;
		break;
	case 1:
		assert(size > (off_t)SPA_OLDMAXBLOCKSIZE);
		if (size > (off_t)(SPA_OLDMAXBLOCKSIZE / sizeof(blkptr_t)) *
		    (off_t)SPA_OLDMAXBLOCKSIZE) {
			s->indblksz = SPA_OLDMAXBLOCKSIZE;
		} else {
			s->indblksz = nblocks * sizeof(blkptr_t);
			s->indblksz = 1 << flsll(s->indblksz);
			if (s->indblksz < (1 << zfs_opts->ashift))
				s->indblksz = (1 << zfs_opts->ashift);
		}
		break;
	default:
		s->indblksz = SPA_OLDMAXBLOCKSIZE;
		break;
	}

	/* XXXMJ now need to allocate indirect block pointers for offset 0 */
}

static blkptr_t *
blkptr_alloc(fsinfo_t *fsopts, struct blkptr_alloc_s *s, off_t off)
{
	zfs_opt_t *zfs_opts;
	off_t blk, loc, blksz;

	if (s->levels == 0) {
		assert(off < (off_t)SPA_MAXBLOCKSIZE);
		return (&s->dnode->dn_blkptr[off / SPA_MAXBLOCKSIZE]);
	}

	zfs_opts = fsopts->fs_specific;
	assert(off % SPA_OLDMAXBLOCKSIZE == 0);

	/*
	 * First see if the previous allocation filled a level 1 indirect block.
	 * If so, flush that block and visit its ancestors to see if they need
	 * to be flushed as well.
	 */
	s->off = off;
	blk = off >> SPA_OLDMAXBLOCKSHIFT;
	for (int i = 1; i <= s->levels; i++) {
		zio_cksum_t cksum;
		blkptr_t *pbp;

		if (blk == 0) {
			/*
			 * Don't need to do anything for the very first
			 * allocation.
			 */
			break;
		}
		if (blk % (1ull << 10 /* XXXMJ log2(OLDMAXBLOCKSIZE / sizeof(blkptr_t)) */) != 0)
			break;
		blk >>= 10;

		blksz = s->indblksz;
		loc = space_alloc(zfs_opts, &blksz);
		/*
		 * XXXMJ do we checksum the whole block or just the part we
		 * used?
		 */
		fletcher_4_native(s->buf[i], s->indblksz, NULL, &cksum);

		assert(blk > 0);
		if (i < s->levels) {
			assert(blk - 1 < (off_t)(SPA_OLDMAXBLOCKSIZE / sizeof(blkptr_t)));
			pbp = (blkptr_t *)&s->buf[i + 1][(blk - 1) * sizeof(blkptr_t)];
		} else {
			assert(blk - 1 <= 2);
			pbp = &s->dnode->dn_blkptr[blk - 1];
		}
		blkptr_set(pbp, loc, blksz, ZIO_CHECKSUM_FLETCHER_4, &cksum);
		vdev_pwrite(fsopts, s->buf[i], blksz, loc);
		memset(s->buf[i], 0, SPA_OLDMAXBLOCKSIZE);
	}
	off_t l1id = ((off >> SPA_OLDMAXBLOCKSHIFT) &
	    ((SPA_OLDMAXBLOCKSIZE / sizeof(blkptr_t))) - 1);
	return ((blkptr_t *)&s->buf[1][l1id * sizeof(blkptr_t)]);
}

static void
blkptr_alloc_flush(fsinfo_t *fsopts, struct blkptr_alloc_s *s)
{
	zfs_opt_t *zfs_opts;
	off_t blkid, blksz, loc;

	zfs_opts = fsopts->fs_specific;

	/* XXXMJ largely duplicates similar logic in blkptr_alloc(). */
	blkid = s->off >> SPA_OLDMAXBLOCKSHIFT;
	for (int i = 1; i <= s->levels; i++) {
		zio_cksum_t cksum;
		blkptr_t *pbp;

		blksz = s->indblksz;
		loc = space_alloc(zfs_opts, &blksz);

		fletcher_4_native(s->buf[i], s->indblksz, NULL, &cksum);

		blkid >>= 10;

		if (i < s->levels) {
			assert(blkid < (off_t)(SPA_OLDMAXBLOCKSIZE / sizeof(blkptr_t)));
			pbp = (blkptr_t *)&s->buf[i + 1][(blkid) * sizeof(blkptr_t)];
		} else {
			assert(blkid <= 2);
			pbp = &s->dnode->dn_blkptr[blkid];
		}
		blkptr_set(pbp, loc, blksz, ZIO_CHECKSUM_FLETCHER_4, &cksum);
		vdev_pwrite(fsopts, s->buf[i], blksz, loc);
		memset(s->buf[i], 0, SPA_OLDMAXBLOCKSIZE);
	}
}

struct fsnode_populate_dir_s {
	zfs_zap_t		zap;
	SLIST_ENTRY(fsnode_populate_dir_s) next;
};

struct fsnode_foreach_populate_arg {
	fsinfo_t	*fsopts;
	zfs_fs_t	*fs;
	uint64_t	rootdirid;
	char		path[PATH_MAX];
	SLIST_HEAD(, fsnode_populate_dir_s) dirs;
};

static void
fsnode_populate_dirent(struct fsnode_foreach_populate_arg *arg,
    const char *name, uint64_t dnid)
{
	struct fsnode_populate_dir_s *dir;

	dir = SLIST_FIRST(&arg->dirs);
	zap_add_uint64(&dir->zap, name, dnid);
}

static void
fsnode_populate_file(fsnode *cur, const char *dir,
    struct fsnode_foreach_populate_arg *arg)
{
	struct blkptr_alloc_s *bpas;
	dnode_phys_t *dnode;
	fsinfo_t *fsopts;
	zfs_opt_t *zfs_opts;
	char path[PATH_MAX];
	uint64_t dnid;
	ssize_t n;
	size_t bufsz;
	off_t size, target;
	int fd;

	assert(cur->type == S_IFREG);

	fsopts = arg->fsopts;
	zfs_opts = fsopts->fs_specific;

	size = cur->inode->st.st_size;

	dnode = objset_dnode_bonus_alloc(&arg->fs->os,
	    DMU_OT_PLAIN_FILE_CONTENTS, DMU_OT_SA, &dnid);

	bpas = ecalloc(1, sizeof(*bpas));
	blkptr_alloc_init(fsopts, bpas, dnode, size);

	dnode->dn_indblkshift = (uint8_t)flsll(bpas->indblksz);
	dnode->dn_nlevels = (uint8_t)bpas->levels;
	/* Leave room for attributes in the bonus buffer. */
	dnode->dn_nblkptr = 1;
	dnode->dn_checksum = ZIO_CHECKSUM_FLETCHER_4; /* XXXMJ yes? */
	dnode->dn_flags = 0; /* XXXMJ ??? */
#if 0 /* XXXMJ */
	dnode->dn_datablkszsec = 0;
#endif
	dnode->dn_bonuslen = 0;
	dnode->dn_extra_slots = 0;
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

		blkoff = space_alloc(zfs_opts, &target);
		assert(target <= (off_t)SPA_OLDMAXBLOCKSIZE);

		bp = blkptr_alloc(fsopts, bpas, foff);
		fletcher_4_native(zfs_opts->filebuf, target, NULL, &cksum);
		blkptr_set(bp, blkoff, target, ZIO_CHECKSUM_FLETCHER_4, &cksum);

		vdev_pwrite(fsopts, zfs_opts->filebuf, target, blkoff);
	}
	blkptr_alloc_flush(fsopts, bpas);

	free(bpas);
	(void)close(fd);

	/* XXXMJ */
	sa_hdr_phys_t *sahdr = (sa_hdr_phys_t *)DN_BONUS(dnode);
	sahdr->sa_magic = SA_MAGIC;
	SA_HDR_LAYOUT_INFO_ENCODE(sahdr->sa_layout_info, 2 /* XXXMJ */, 8);
	*(uint64_t *)((char *)sahdr + 8 + SA_MODE_OFFSET) = cur->inode->st.st_mode;
	dnode->dn_bonuslen = SA_HDR_SIZE(sahdr);

	/* Add an entry to the parent directory. */
	fsnode_populate_dirent(arg, cur->name, dnid);
}

static void
fsnode_populate_dir(fsnode *cur, const char *dir __unused,
    struct fsnode_foreach_populate_arg *arg)
{
	dnode_phys_t *dnode;
	fsinfo_t *fsopts;
	uint64_t dnid;

	assert(cur->type == S_IFDIR);

	fsopts = arg->fsopts;

	dnode = objset_dnode_bonus_alloc(&arg->fs->os,
	    DMU_OT_DIRECTORY_CONTENTS, DMU_OT_SA, &dnid);

	/*
	 * Add an entry to the parent directory.  This must be done before
	 * allocating a ZAP object for this directory's children.
	 */
	if (!SLIST_EMPTY(&arg->dirs))
		fsnode_populate_dirent(arg, cur->name, dnid);
	else
		arg->rootdirid = dnid;

	struct fsnode_populate_dir_s *zap = ecalloc(1, sizeof(*zap));

	zap_init(&zap->zap, dnode);
	SLIST_INSERT_HEAD(&arg->dirs, zap, next);

	/* XXXMJ shouldn't be here, but needed for DN_BONUS to work. */
	dnode->dn_nblkptr = 1;

	sa_hdr_phys_t *sahdr = (sa_hdr_phys_t *)DN_BONUS(dnode);
	sahdr->sa_magic = SA_MAGIC;
	SA_HDR_LAYOUT_INFO_ENCODE(sahdr->sa_layout_info, 2 /* XXXMJ */, 8);
	*(uint64_t *)((char *)sahdr + 8 + SA_MODE_OFFSET) = cur->inode->st.st_mode;
	dnode->dn_bonuslen = SA_HDR_SIZE(sahdr); /* XXXMJ no */
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
	default:
		break;
	}

	if (cur->next == NULL) {
		dirs = SLIST_FIRST(&arg->dirs);
		SLIST_REMOVE_HEAD(&arg->dirs, next);

		zap_write(arg->fsopts, &dirs->zap);

		free(dirs);
	}
}

static void
mkfs(fsinfo_t *fsopts, zfs_fs_t *fs, const char *dir, fsnode *root)
{
	struct fsnode_foreach_populate_arg poparg;
	zio_cksum_t cksum;
	zfs_objset_t *os;
	zfs_opt_t *zfs_opts;
	dnode_phys_t *masterobj, *saobj, *salobj, *sarobj;
	uint64_t dnodecount, moid, saobjid, salobjid, sarobjid;

	zfs_opts = fsopts->fs_specific;
	os = &fs->os;

	/*
	 * Figure out how many dnodes we need.  One for each ZPL object (file,
	 * directory, etc.), one for the master object (always with ID 1), one
	 * for the meta dnode (embedded in the object set, always with ID 0).
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
	 * XXXMJ allocating them all up front like this might be too painful for
	 * really large filesystems.  Check to see how much this costs for a
	 * FreeBSD tree.
	 */
	objset_init(zfs_opts, os, DMU_OST_ZFS, dnodecount);
	masterobj = objset_dnode_alloc(os, DMU_OT_MASTER_NODE, &moid);
	assert(moid == MASTER_NODE_OBJ);

	/*
	 * Create the SA layout(s) now, since filesystem object dnodes will
	 * refer to them.
	 *
	 * SA:
	 * - files/dirs/etc. have a bonus buffer of type DMU_OT_SA, starts with
	 *   a sa_hdr_phys
	 */
	saobj = objset_dnode_alloc(os, DMU_OT_SA_MASTER_NODE, &saobjid);

	salobj = objset_dnode_alloc(os, DMU_OT_SA_ATTR_LAYOUTS, &salobjid);

	sarobj = objset_dnode_alloc(os, DMU_OT_SA_ATTR_REGISTRATION, &sarobjid);

	{
	zfs_zap_t sarzap;
	zap_init(&sarzap, sarobj);
#define	ATTR_REG(name, ind, size, bs) do {		\
	uint64_t attr = 0;				\
	SA_ATTR_ENCODE(attr, ind, size, bs);		\
	zap_add_uint64(&sarzap, name, attr);		\
} while (0)
	ATTR_REG("ZPL_ATIME", 0, sizeof(uint64_t) * 2, SA_UINT64_ARRAY);
	ATTR_REG("ZPL_MTIME", 1, sizeof(uint64_t) * 2, SA_UINT64_ARRAY);
	ATTR_REG("ZPL_CTIME", 2, sizeof(uint64_t) * 2, SA_UINT64_ARRAY);
	ATTR_REG("ZPL_CRTIME", 3, sizeof(uint64_t) * 2, SA_UINT64_ARRAY);
	ATTR_REG("ZPL_GEN", 4, sizeof(uint64_t), SA_UINT64_ARRAY);
	ATTR_REG("ZPL_MODE", 5, sizeof(uint64_t), SA_UINT64_ARRAY);
	ATTR_REG("ZPL_SIZE", 6, sizeof(uint64_t), SA_UINT64_ARRAY);
	ATTR_REG("ZPL_PARENT", 7, sizeof(uint64_t), SA_UINT64_ARRAY);
	ATTR_REG("ZPL_LINKS", 8, sizeof(uint64_t), SA_UINT64_ARRAY);
	ATTR_REG("ZPL_XATTR", 9, sizeof(uint64_t), SA_UINT64_ARRAY);
	ATTR_REG("ZPL_RDEV", 10, sizeof(uint64_t), SA_UINT64_ARRAY);
	ATTR_REG("ZPL_FLAGS", 11, sizeof(uint64_t), SA_UINT64_ARRAY);
	ATTR_REG("ZPL_UID", 12, sizeof(uint64_t), SA_UINT64_ARRAY);
	ATTR_REG("ZPL_GID", 13, sizeof(uint64_t), SA_UINT64_ARRAY);
	ATTR_REG("ZPL_PAD", 14, sizeof(uint64_t), SA_UINT64_ARRAY);
	ATTR_REG("ZPL_ZNODE_ACL", 15, 88, SA_UINT64_ARRAY);
	ATTR_REG("ZPL_DACL_COUNT", 16, sizeof(uint64_t), SA_UINT64_ARRAY);
	ATTR_REG("ZPL_SYMLINK", 17, 0, SA_UINT8_ARRAY);
	ATTR_REG("ZPL_SCANSTAMP", 18, sizeof(uint64_t) * 4, SA_UINT8_ARRAY);
	ATTR_REG("ZPL_DACL_ACES", 19, 0, SA_ACL);
	ATTR_REG("ZPL_DXATTR", 20, 0, SA_UINT8_ARRAY);
	ATTR_REG("ZPL_PROJID", 21, sizeof(uint64_t), SA_UINT64_ARRAY);
#undef ATTR_REGISTER
	zap_write(fsopts, &sarzap);
	}

	{
	zfs_zap_t salzap;
	uint16_t sas[14];

	sas[0] = 5;	/* ZPL_MODE */
	sas[1] = 6;	/* ZPL_SIZE */
	sas[2] = 4;	/* ZPL_GEN */
	sas[3] = 12;	/* ZPL_UID */
	sas[4] = 13;	/* ZPL_GID */
	sas[5] = 7;	/* ZPL_PARENT */
	sas[6] = 11;	/* ZPL_FLAGS */
	sas[7] = 0;	/* ZPL_ATIME */
	sas[8] = 1;	/* ZPL_MTIME */
	sas[9] = 2;	/* ZPL_CTIME */
	sas[10] = 3;	/* ZPL_CRTIME */
	sas[11] = 8;	/* ZPL_LINKS */
	sas[12] = 16;	/* ZPL_DACL_COUNT */
	sas[13] = 19;	/* ZPL_DACL_ACES */

	char attr[16];
	snprintf(attr, sizeof(attr), "%u", 2u);

	fzap_init(&salzap, 8192 /* XXXMJ */);
	fzap_add_array(&salzap, "2", sizeof(sa_attr_type_t), 14, (uint8_t *)&sas[0]);
	fzap_write(fsopts, &salzap, salobj);
	}

	{
	zfs_zap_t sazap;
	zap_init(&sazap, saobj);
	zap_add_uint64(&sazap, SA_LAYOUTS, salobjid);
	zap_add_uint64(&sazap, SA_REGISTRY, sarobjid);
	zap_write(fsopts, &sazap);
	}

	poparg.fsopts = fsopts;
	poparg.fs = fs;
	SLIST_INIT(&poparg.dirs);

	fsnode_populate_dir(root, dir, &poparg);
	assert(!SLIST_EMPTY(&poparg.dirs));
	fsnode_foreach(root, dir, fsnode_foreach_populate, &poparg);
	assert(SLIST_EMPTY(&poparg.dirs));

	/*
	 * Allocate and populate the master node object.  This is a ZAP object
	 * containing various dataset properties and the object IDs of the root
	 * directory and delete queue.
	 */
	zfs_zap_t masterzap;
	zap_init(&masterzap, masterobj);
	/* XXXMJ add a variant that can check that the object ID is valid */
	zap_add_uint64(&masterzap, ZFS_ROOT_OBJ, poparg.rootdirid);
	/* XXXMJ DMU_OT_UNLINKED_SET */
	zap_add_uint64(&masterzap, ZFS_UNLINKED_SET, 0 /* XXXMJ */);
	zap_add_uint64(&masterzap, ZFS_SA_ATTRS, saobjid);
	/* XXXMJ create a shares (ZFS_SHARES_DIR) directory? */
	zap_add_uint64(&masterzap, "version", 5 /* ZPL_VERSION_SA */);
	zap_add_uint64(&masterzap, "normalization", 0 /* off */);
	zap_add_uint64(&masterzap, "utf8only", 0 /* off */);
	zap_add_uint64(&masterzap, "casesensitivity", 0 /* case sensitive */);
	zap_add_uint64(&masterzap, "acltype", 2 /* NFSv4 */);
	zap_write(fsopts, &masterzap);

	fletcher_4_native(os->dnodes, os->dnodeblksz, NULL, &cksum);
	os->osphys->os_meta_dnode.dn_nblkptr = 1;
	blkptr_set(&os->osphys->os_meta_dnode.dn_blkptr[0], os->dnodeloc,
	    os->dnodeblksz, ZIO_CHECKSUM_FLETCHER_4, &cksum);
	objset_write(fsopts, &fs->os);
}

void
zfs_makefs(const char *image, const char *dir, fsnode *root, fsinfo_t *fsopts)
{
	zfs_opt_t *zfs_opts;
	int oflags;

	zfs_opts = fsopts->fs_specific;

	oflags = O_RDWR | O_CREAT;
	if (fsopts->offset == 0)
		oflags |= O_TRUNC;

	fsopts->fd = open(image, oflags, 0644 /* XXXMJ */);
	if (fsopts->fd == -1) {
		warn("Can't open `%s' for writing", image);
		goto out;
	}
	zfs_opts->size = rounddown2(fsopts->maxsize, 1 << zfs_opts->ashift);
	if (zfs_opts->size < (off_t)SPA_MINDEVSIZE) {
		warnx("maximum image size %ju is too small",
		    (uintmax_t)zfs_opts->size);
		goto out;
	}
	if (ftruncate(fsopts->fd, zfs_opts->size) != 0) {
		warn("Failed to extend image file `%s'", image);
		goto out;
	}
	if (spacemap_init(zfs_opts) != 0)
		goto out;

	pool_init(fsopts);

	mkfs(fsopts, &zfs_opts->rootfs, dir, root);

	mkspacemap(fsopts);

	pool_finish(fsopts);
out:
	if (fsopts->fd != -1)
		(void)close(fsopts->fd);
	free(zfs_opts->spacemap);
}
