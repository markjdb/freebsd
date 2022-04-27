#include <assert.h>
#include <bitstring.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <util.h>

#include "makefs.h"

#define	ASSERT	assert
#include "zfs/libzfs.h"

#include "fletcher.c"
#include "sha256.c"

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
	free((void *)zfs_opts->poolname);

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

/*
 * Set embedded checksums in the vdev metadata and uberblocks, and write the
 * label at the specified index.
 */
static void
vdev_write_label(fsinfo_t *fsopts, int ind, vdev_label_t *label)
{
	zfs_opt_t *zfs_opts;
	zio_cksum_t cksum;
	zio_eck_t *eck;
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
	 * Set the verifier checksum for the label.
	 */
	eck = &label->vl_vdev_phys.vp_zbt;
	eck->zec_magic = ZEC_MAGIC; 
	ZIO_SET_CHECKSUM(&eck->zec_cksum,
	    loff + __offsetof(vdev_label_t, vl_vdev_phys), 0, 0, 0);
	zio_checksum_SHA256(&label->vl_vdev_phys, sizeof(vdev_phys_t), NULL,
	    &cksum);
	eck->zec_cksum = cksum;

	/*
	 * Set the verifier checksum for the uberblocks.
	 */
	assert(sizeof(label->vl_uberblock) % blksz == 0);
	for (size_t roff = 0; roff < sizeof(label->vl_uberblock);
	    roff += blksz) {
		eck = (zio_eck_t *)(&label->vl_uberblock[0] + roff + blksz) - 1;
		eck->zec_magic = ZEC_MAGIC;
		ZIO_SET_CHECKSUM(&eck->zec_cksum,
		    loff + __offsetof(vdev_label_t, vl_uberblock) + roff,
		    0, 0, 0);
		zio_checksum_SHA256(&label->vl_uberblock[0] + roff, blksz, NULL,
		    &cksum);
		eck->zec_cksum = cksum;
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

	assert(size >= VDEV_LABEL_START_SIZE + VDEV_LABEL_END_SIZE);

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
	if (len < SPA_OLDMAXBLOCKSIZE) {
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

	os->dnodes = ecalloc(os->dnodecount, sizeof(dnode_phys_t));
}

static void
objset_write(fsinfo_t *fsopts, zfs_objset_t *os)
{
	/* XXXMJ this will need to be revisited */
	assert(os->dnodeblksz <= SPA_OLDMAXBLOCKSIZE);
	vdev_pwrite(fsopts, os->dnodes, os->dnodeblksz, os->dnodeloc);

	/* XXXMJ update block pointers */
	vdev_pwrite(fsopts, os->osphys, os->osblksz, os->osloc);
}

static dnode_phys_t *
objset_dnode_alloc(zfs_objset_t *os, uint64_t *idp)
{
	assert(os->dnodenextfree < os->dnodecount);
	if (idp != NULL)
		*idp = os->dnodenextfree;
	return (&os->dnodes[os->dnodenextfree++]);
}

typedef struct zfs_zap {
	off_t			loc;
	off_t			blksz;
	mzap_ent_phys_t		*ent;
	char			zapblk[SPA_OLDMAXBLOCKSIZE];
} zfs_zap_t;

static void
zap_init(zfs_zap_t *zap)
{
	mzap_phys_t *zaphdr;

	zaphdr = (mzap_phys_t *)&zap->zapblk[0];
	zaphdr->mz_block_type = ZBT_MICRO;
	zaphdr->mz_salt = 0; /* XXXMJ */
	zaphdr->mz_normflags = 0;

	zap->blksz = __offsetof(mzap_phys_t, mz_chunk);
	zap->ent = &zaphdr->mz_chunk[0];
}

static void
zap_add_uint64(zfs_zap_t *zap, const char *name, uint64_t val)
{
	mzap_ent_phys_t *ent;

	/* XXXMJ assert no overflow in the block */

	ent = zap->ent;
	zap->ent++;

	ent->mze_value = val;
	ent->mze_cd = 0; /* XXXMJ */
	assert(strlen(name) < sizeof(ent->mze_name));
	strlcpy(ent->mze_name, name, sizeof(ent->mze_name));

	zap->blksz += sizeof(mzap_ent_phys_t);
}

static void
zap_write(fsinfo_t *fsopts, zfs_zap_t *zap, dnode_phys_t *dnode)
{
	zfs_opt_t *zfs_opts;
	zio_cksum_t cksum;

	zfs_opts = fsopts->fs_specific;

	zap->loc = space_alloc(zfs_opts, &zap->blksz);

	fletcher_4_native(zap->zapblk, zap->blksz, NULL, &cksum);

	dnode->dn_nblkptr = 1;
	dnode->dn_nlevels = 1;
	dnode->dn_bonustype = DMU_OT_NONE;
	dnode->dn_checksum = ZIO_CHECKSUM_FLETCHER_4;
	dnode->dn_compress = ZIO_COMPRESS_OFF;
	dnode->dn_datablkszsec = zap->blksz >> SPA_MINBLOCKSHIFT;

	blkptr_set(&dnode->dn_blkptr[0], zap->loc, zap->blksz,
	    ZIO_CHECKSUM_FLETCHER_4, &cksum);

	vdev_pwrite(fsopts, zap->zapblk, zap->blksz, zap->loc);
}

/*
 * Initialize the meta-object set.
 */
static void
pool_init(fsinfo_t *fsopts)
{
#if 0
	dsl_dir_phys_t *dsldir;
	dsl_dataset_phys_t *ds;
#endif
	zfs_opt_t *zfs_opts;
#if 0
	zfs_zap_t objdirzap;
	uint64_t dnid, dsldirid, dslid;
#endif
	uint64_t dnodecount;

	zfs_opts = fsopts->fs_specific;

	/*
	 * XXXMJ dnode count:
	 * - object directory
	 * - DSL directory
	 * - DSL dataset
	 * - space maps
	 * - ?
	 */
	dnodecount = 0;
	dnodecount++; /* object directory */
	dnodecount++; /* DSL directory */
	dnodecount++; /* DSL root dataset */
	dnodecount++; /* config object, pointed to by the object directory */ 
	objset_init(zfs_opts, &zfs_opts->mos, DMU_OST_META, dnodecount);

#if 0
	dnode_phys_t *objdirdn = objset_dnode_alloc(&zfs_opts->mos, &dnid);
	assert(dnid == DMU_POOL_DIRECTORY_OBJECT);
	objdirdn->dn_type = DMU_OT_OBJECT_DIRECTORY;

	dnode_phys_t *dsldirdn = objset_dnode_alloc(&zfs_opts->mos, &dsldirid);
	objdirdn->dn_type = DMU_OT_DSL_DIR;
	objdirdn->dn_bonustype = DMU_OT_DSL_DIR;

	dsldir = (dsl_dir_phys_t *)&dsldirdn->dn_bonus;

	zap_init(&objdirzap);
	zap_add_uint64(&objdirzap, DMU_POOL_ROOT_DATASET, dsldirid);
	/* XXXMJ add other keys */

	dnode_phys_t *dsldn = objset_dnode_alloc(&zfs_opts->mos, &dslid);
	dsldn->dn_type = DMU_OTN_ZAP_DATA;
	dsldn->dn_bonustype = DMU_OT_OBJECT_DIRECTORY;

	ds = (dsl_dataset_phys_t *)&dsldn->dn_bonus;

	dsldir->dd_head_dataset_obj = dslid;
#endif
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
	uint64_t txg;
	int error;

	zfs_opts = fsopts->fs_specific;
	mos = &zfs_opts->mos;

	/* The initial TXG can't be zero. */
	txg = 1;

	vdevconfig = nvlist_create(NV_UNIQUE_NAME);
	nvlist_add_string(vdevconfig, ZPOOL_CONFIG_TYPE, VDEV_TYPE_DISK);
	nvlist_add_uint64(vdevconfig, ZPOOL_CONFIG_ASHIFT, zfs_opts->ashift);
	nvlist_add_uint64(vdevconfig, ZPOOL_CONFIG_ASIZE, fsopts->size -
	    VDEV_LABEL_START_SIZE - VDEV_LABEL_END_SIZE);
	nvlist_add_uint64(vdevconfig, ZPOOL_CONFIG_ID, 0);

	poolconfig = nvlist_create(NV_UNIQUE_NAME);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_POOL_TXG, txg);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_VERSION, SPA_VERSION);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_POOL_STATE,
	    POOL_STATE_ACTIVE);
	nvlist_add_string(poolconfig, ZPOOL_CONFIG_POOL_NAME,
	    zfs_opts->poolname);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_POOL_GUID, 0 /* XXXMJ configurable */);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_TOP_GUID, 0 /* XXXMJ configurable */);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_GUID, 0 /* XXXMJ configurable */);
	nvlist_add_uint64(poolconfig, ZPOOL_CONFIG_VDEV_CHILDREN, 1);
	nvlist_add_nvlist(poolconfig, ZPOOL_CONFIG_VDEV_TREE, vdevconfig);

	/* XXXMJ most of this code should live in pool_init(). */
	{
	dsl_dir_phys_t *dsldir;
	dsl_dataset_phys_t *ds;
	zfs_zap_t objdirzap;
	uint64_t dnid, dsldirid, dslid, configid;

	dnode_phys_t *objdirdn = objset_dnode_alloc(mos, &dnid);
	assert(dnid == DMU_POOL_DIRECTORY_OBJECT);
	objdirdn->dn_type = DMU_OT_OBJECT_DIRECTORY;

	dnode_phys_t *dsldirdn = objset_dnode_alloc(mos, &dsldirid);
	dsldirdn->dn_type = DMU_OT_DSL_DIR;
	dsldirdn->dn_bonustype = DMU_OT_DSL_DIR;

	dnode_phys_t *configdn = objset_dnode_alloc(mos, &configid);
	configdn->dn_type = DMU_OT_PACKED_NVLIST;
	configdn->dn_bonustype = DMU_OT_PACKED_NVLIST_SIZE;
	configdn->dn_bonuslen = sizeof(uint64_t);

	{
		nvlist_t *nv, *children[1];
		off_t configloc, configblksz;

		children[0] = nvlist_create(NV_UNIQUE_NAME);
		nvlist_add_uint64(children[0], ZPOOL_CONFIG_GUID, 0 /* XXXMJ configurable */);

		nv = nvlist_create(NV_UNIQUE_NAME);
		nvlist_add_uint64(nv, ZPOOL_CONFIG_POOL_GUID, 0 /* XXXMJ configurable */);
		nvlist_add_uint64(nv, ZPOOL_CONFIG_VDEV_CHILDREN, 1);
		nvlist_add_nvlist_array(vdevconfig, ZPOOL_CONFIG_CHILDREN, children,
		    nitems(children));
		nvlist_add_nvlist(nv, ZPOOL_CONFIG_VDEV_TREE, vdevconfig);
		error = nvlist_export(nv);
		if (error != 0)
			errc(1, error, "nvlist_export");

		configblksz = nv->nv_size + sizeof(nv->nv_header);
		char *buf = ecalloc(1, configblksz);
		memcpy(buf, &nv->nv_header, sizeof(nv->nv_header));
		memcpy(buf + sizeof(nv->nv_header), nv->nv_data, nv->nv_size);

		assert(configblksz <= SPA_OLDMAXBLOCKSIZE);
		configloc = space_alloc(zfs_opts, &configblksz);

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

	dsldir = (dsl_dir_phys_t *)&dsldirdn->dn_bonus;

	/* XXXMJ large thing to put on the stack */
	zap_init(&objdirzap);
	zap_add_uint64(&objdirzap, DMU_POOL_ROOT_DATASET, dsldirid);
	zap_add_uint64(&objdirzap, DMU_POOL_CONFIG, configid);
	/* XXXMJ add other keys */
	zap_write(fsopts, &objdirzap, objdirdn);

	dnode_phys_t *dsldn = objset_dnode_alloc(mos, &dslid);
	dsldn->dn_type = DMU_OTN_ZAP_DATA;
	dsldn->dn_bonustype = DMU_OT_OBJECT_DIRECTORY;

	ds = (dsl_dataset_phys_t *)&dsldn->dn_bonus;

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
		ub->ub_guid_sum = 0; /* XXXMJ configurable */
		ub->ub_timestamp = 0; /* XXXMJ */

		ub->ub_software_version = SPA_VERSION;
		ub->ub_mmp_magic = 0;
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
	for (indlevel = 0, max = 1; nblocks > 3 * max; indlevel++)
		max *= SPA_OLDMAXBLOCKSIZE / sizeof(blkptr_t);
	assert(indlevel < INDIR_LEVELS); /* XXXMJ magic */

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
		assert(size > 3 * SPA_OLDMAXBLOCKSIZE);
		if (size > (SPA_OLDMAXBLOCKSIZE / sizeof(blkptr_t)) *
		    SPA_OLDMAXBLOCKSIZE) {
			s->indblksz = SPA_OLDMAXBLOCKSIZE;
		} else {
			s->indblksz = nblocks * sizeof(blkptr_t);
			s->indblksz = 1ul << flsll(s->indblksz);
			if (s->indblksz < (1ul << zfs_opts->ashift))
				s->indblksz = (1ul << zfs_opts->ashift);
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
		assert(off < 3 * SPA_MAXBLOCKSIZE);
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
			assert(blk - 1 < SPA_OLDMAXBLOCKSIZE / sizeof(blkptr_t));
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
			assert(blkid < SPA_OLDMAXBLOCKSIZE / sizeof(blkptr_t));
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

	printf("%s:%d adding %s\n", __func__, __LINE__, name);

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

	dnode = objset_dnode_alloc(&arg->fs->os, &dnid);

	bpas = ecalloc(1, sizeof(*bpas));
	blkptr_alloc_init(fsopts, bpas, dnode, size);

	dnode->dn_type = DMU_OT_PLAIN_FILE_CONTENTS;
	dnode->dn_indblkshift = (uint8_t)flsll(bpas->indblksz);
	dnode->dn_nlevels = (uint8_t)bpas->levels;
#if 0 /* XXXMJ */
	dnode->dn_nblkptr = 0;
#endif
	dnode->dn_bonustype = DMU_OT_NONE;
	dnode->dn_checksum = ZIO_CHECKSUM_FLETCHER_4; /* XXXMJ yes? */
	dnode->dn_compress = ZIO_COMPRESS_OFF;
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

	printf("%s:%d opening %s, %lu bytes\n", __func__, __LINE__, path, size);

	fd = open(path, O_RDONLY);
	if (fd == -1)
		err(1, "open(%s)", path);
	for (off_t foff = 0; foff < size; foff += target) {
		zio_cksum_t cksum;
		blkptr_t *bp;
		off_t blkoff, sofar;

		/* Fill up our buffer, handling partial reads. */
		sofar = 0;
		target = MIN(size - foff, bufsz);
		do {
			n = read(fd, zfs_opts->filebuf + sofar, target);
			if (n < 0)
				err(1, "reading from '%s'", path);
			if (n == 0)
				errx(1, "unexpected EOF reading '%s'", path);
			sofar += n;
		} while (sofar < target);
		if (target < bufsz)
			memset(zfs_opts->filebuf + target, 0, bufsz - target);

		blkoff = space_alloc(zfs_opts, &target);
		assert(target <= SPA_OLDMAXBLOCKSIZE);

		bp = blkptr_alloc(fsopts, bpas, foff);
		fletcher_4_native(zfs_opts->filebuf, target, NULL, &cksum);
		blkptr_set(bp, blkoff, target, ZIO_CHECKSUM_FLETCHER_4, &cksum);

		vdev_pwrite(fsopts, zfs_opts->filebuf, target, blkoff);
	}
	blkptr_alloc_flush(fsopts, bpas);

	free(bpas);
	(void)close(fd);

	/* Add an entry to the parent directory. */
	fsnode_populate_dirent(arg, cur->name, dnid);
}

static void
fsnode_populate_dir(fsnode *cur, const char *dir,
    struct fsnode_foreach_populate_arg *arg)
{
	dnode_phys_t *dnode;
	fsinfo_t *fsopts;
	fsnode *child;
	zfs_opt_t *zfs_opts;
	uint64_t dnid;

	assert(cur->type == S_IFDIR);

	fsopts = arg->fsopts;
	zfs_opts = fsopts->fs_specific;

	dnode = objset_dnode_alloc(&arg->fs->os, &dnid);
	dnode->dn_type = DMU_OT_DIRECTORY_CONTENTS;
#if 0 /* XXXMJ */
	dnode->dn_indblkshift = 0;
	dnode->dn_nlevels = 0;
	dnode->dn_nblkptr = 0;
#endif
	dnode->dn_bonustype = DMU_OT_NONE;
	dnode->dn_checksum = ZIO_CHECKSUM_FLETCHER_4; /* XXXMJ yes? */
	dnode->dn_compress = ZIO_COMPRESS_OFF;
	dnode->dn_flags = 0; /* XXXMJ */
#if 0 /* XXXMJ */
	dnode->dn_datablkszsec = 0;
#endif
	dnode->dn_bonuslen = 0;
	dnode->dn_extra_slots = 0;
#if 0 /* XXXMJ */
	dnode->dn_maxblkid = 0;
	dnode->dn_used = 0;
#endif

	/*
	 * Add an entry to the parent directory.  This must be done before
	 * allocating a ZAP object for this directory's children.
	 */
	if (cur->parent != NULL)
		fsnode_populate_dirent(arg, cur->name, dnid);
	else
		arg->rootdirid = dnid;

	int count = 0;
	size_t maxlen = 0;
	off_t blksz;
	for (child = cur->child; child != NULL; child = child->next) {
		size_t len;

		if (strcmp(child->name, ".") == 0)
			continue;
		len = strlen(child->name) + 1;
		if (len > maxlen)
			maxlen = len;
		count++;
	}
	if (count <= 2047 && maxlen <= 50) {
		/* We can use a microzap! */
		struct fsnode_populate_dir_s *zap = ecalloc(1, sizeof(*zap));

		zap_init(&zap->zap);

		/* XXXMJ space allocation could be done later. */
		blksz = (count + 1) * MZAP_ENT_LEN;
		zap->zap.loc = space_alloc(zfs_opts, &blksz);
		zap->zap.blksz = blksz;

		SLIST_INSERT_HEAD(&arg->dirs, zap, next);
	} else {
		/* XXXMJ fatzaps are not implemented for now. */
		assert(0);
	}
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

		/* XXXMJ need to set up the directory dnode here */

		vdev_pwrite(arg->fsopts, dirs->zap.zapblk, dirs->zap.blksz,
		    dirs->zap.loc);

		free(dirs);
	}
}

static void
mkfs(fsinfo_t *fsopts, zfs_fs_t *fs, const char *dir, fsnode *root)
{
	struct fsnode_foreach_populate_arg poparg;
	zfs_opt_t *zfs_opts;
	dnode_phys_t *masterobj;
	uint64_t dnodecount, moid;

	zfs_opts = fsopts->fs_specific;

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
	dnodecount++; /* system attributes */

	/*
	 * XXXMJ allocating them all up front like this might be too painful for
	 * really large filesystems.  Check to see how much this costs for a
	 * FreeBSD tree.
	 */
	objset_init(zfs_opts, &fs->os, DMU_OST_ZFS, dnodecount);
	masterobj = objset_dnode_alloc(&fs->os, &moid);
	assert(moid == MASTER_NODE_OBJ);
	masterobj->dn_type = DMU_OT_MASTER_NODE;
	masterobj->dn_bonustype = DMU_OT_NONE;

	poparg.fsopts = fsopts;
	poparg.fs = fs;
	SLIST_INIT(&poparg.dirs);

	fsnode_populate_dir(root, dir, &poparg);
	assert(!SLIST_EMPTY(&poparg.dirs));
	fsnode_foreach(root, dir, fsnode_foreach_populate, &poparg);

	/*
	 * Allocate and populate the master node object.  This is a ZAP object
	 * containing various dataset properties and the object IDs of the root
	 * directory and delete queue.
	 */
	zfs_zap_t masterzap;
	zap_init(&masterzap);

	/* XXXMJ add a variant that can check that the object ID is valid */
	zap_add_uint64(&masterzap, ZFS_ROOT_OBJ, poparg.rootdirid);
	/* XXXMJ DMU_OT_UNLINKED_SET */
	zap_add_uint64(&masterzap, ZFS_UNLINKED_SET, 0 /* XXXMJ */);
	/* XXXMJ DMU_OT_SA_MASTER_NODE */
	zap_add_uint64(&masterzap, "SA_ATTRS", 0 /* XXXMJ */);
	/* XXXMJ create a shares (ZFS_SHARES_DIR) directory? */

	zap_add_uint64(&masterzap, "version", 5 /* ZPL_VERSION_SA */);
	zap_add_uint64(&masterzap, "normalization", 0 /* off */);
	zap_add_uint64(&masterzap, "utf8only", 0 /* off */);
	zap_add_uint64(&masterzap, "casesensitivity", 0 /* case sensitive */);
	zap_add_uint64(&masterzap, "acltype", 2 /* NFSv4 */);

	/* XXXMJ write object set */
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
	if (zfs_opts->size < SPA_MINDEVSIZE) {
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

	printf("%s:%d\n", __func__, __LINE__);

	mkfs(fsopts, &zfs_opts->rootfs, dir, root);

	//mkpool(fsopts);
	mkspacemap(fsopts);

	pool_finish(fsopts);
out:
	if (fsopts->fd != -1)
		(void)close(fsopts->fd);
	free(zfs_opts->spacemap);
}
