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

struct _zfs_fs;

typedef struct {
	uint64_t	id;
	struct _zfs_fs	*fs;
} zfs_obj_t;

typedef struct _zfs_fs {
} zfs_fs_t;

typedef struct {
	/* Pool parameters. */
	const char	*poolname;
	int		ashift;

	/* Pool info. */
	spa_t		*spa;
	bitstr_t	*spacemap;
	int		spacemapbits;

	/* Root filesystem info. */
	zfs_fs_t	rootfs;
} zfs_opt_t;

void
zfs_prep_opts(fsinfo_t *fsopts)
{
	zfs_opt_t *zfs_opts = ecalloc(1, sizeof(*zfs_opts));

	const option_t zfs_options[] = {
		{ '\0', "poolname", &zfs_opts->poolname, OPT_STRPTR,
		  0, 0, "ZFS pool name" },
		{ '\0', "ashift", &zfs_opts->ashift, OPT_INT32,
		  SPA_MINBLOCKSHIFT, SPA_MAXBLOCKSHIFT, "ZFS pool ashift" },
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
			len = (off_t)1 << ffsll(len);
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
blkptr_set(blkptr_t *bp, off_t offset, off_t size, enum zio_checksum cksum)
{
	dva_t *dva;

	BP_ZERO(bp);
	BP_SET_LSIZE(bp, size);
	BP_SET_PSIZE(bp, size);
	BP_SET_CHECKSUM(bp, cksum);
	BP_SET_COMPRESS(bp, ZIO_COMPRESS_OFF);

	dva = BP_IDENTITY(bp);
	DVA_SET_VDEV(dva, 0);
	DVA_SET_OFFSET(dva, 0);
	DVA_SET_ASIZE(dva, size);
	/* XXXMJ checksum */
}

static void
mkpool(fsinfo_t *fsopts)
{
	zfs_opt_t *zfs_opts;
	nvlist_t *poolconfig, *vdevconfig;
	uberblock_t *ub;
	vdev_label_t *label;
	void *vdevnv;
	int error;

	zfs_opts = fsopts->fs_specific;

	vdevconfig = nvlist_create(0);
	nvlist_add_string(vdevconfig,
	    ZPOOL_CONFIG_TYPE, VDEV_TYPE_DISK);
	nvlist_add_uint64(vdevconfig,
	    ZPOOL_CONFIG_ASHIFT, 12 /* XXXMJ configurable */);
	nvlist_add_uint64(vdevconfig,
	    ZPOOL_CONFIG_ASIZE, 0 /* XXXMJ */);
	nvlist_add_uint64(vdevconfig,
	    ZPOOL_CONFIG_ID, 0);

	poolconfig = nvlist_create(0);
	nvlist_add_uint64(poolconfig,
	    ZPOOL_CONFIG_POOL_TXG, 0);
	nvlist_add_nvlist(poolconfig,
	    ZPOOL_CONFIG_VDEV_TREE, vdevconfig);
	nvlist_add_uint64(poolconfig,
	    ZPOOL_CONFIG_VERSION, SPA_VERSION);
	nvlist_add_uint64(poolconfig,
	    ZPOOL_CONFIG_POOL_STATE, POOL_STATE_ACTIVE);
	nvlist_add_string(poolconfig,
	    ZPOOL_CONFIG_POOL_NAME, zfs_opts->poolname);
	nvlist_add_uint64(poolconfig,
	    ZPOOL_CONFIG_POOL_GUID, 0 /* XXXMJ configurable */);
	nvlist_add_uint64(poolconfig,
	    ZPOOL_CONFIG_TOP_GUID, 0 /* XXXMJ configurable */);
	nvlist_add_uint64(poolconfig,
	    ZPOOL_CONFIG_GUID, 0 /* XXXMJ configurable */);
	nvlist_add_uint64(poolconfig,
	    ZPOOL_CONFIG_VDEV_CHILDREN, 1);

	zfs_opts->spa = spa_create(0 /* XXXMJ configurable */, zfs_opts->poolname);
	zfs_opts->spa->spa_root_vdev->v_nchildren = 1;

	label = ecalloc(1, sizeof(*label));

	/* Fill out vdev metadata. */
	vdevnv = label->vl_vdev_phys.vp_nvlist;
	memcpy(vdevnv, &poolconfig->nv_header,
	    sizeof(poolconfig->nv_header));
	poolconfig->nv_data = vdevnv + sizeof(nvs_header_t);
	poolconfig->nv_size = VDEV_PHYS_SIZE - sizeof(nvs_header_t);
	error = nvlist_export(poolconfig);
	if (error != 0)
		errc(1, error, "nvlist_export");
	/* XXXMJ calculate checksum */

	/* Fill out the uberblock. */
	ub = (void *)&label->vl_uberblock[0];
	ub->ub_magic = UBERBLOCK_MAGIC;
	ub->ub_version = SPA_VERSION;
	ub->ub_txg = 0;
	ub->ub_guid_sum = 0; /* XXXMJ configurable */
	ub->ub_timestamp = 0; /* XXXMJ */

	objset_phys_t *os = ecalloc(1, sizeof(*os));

	os->os_meta_dnode.dn_type = DMU_OT_DNODE;
	os->os_type = DMU_OST_META;

	ub->ub_software_version = SPA_VERSION;
	ub->ub_mmp_magic = 0;
	ub->ub_mmp_delay = 0;
	ub->ub_mmp_config = 0;
	ub->ub_checkpoint_txg = 0;

	/* Allocate space for the MOS. */
	off_t len = sizeof(objset_phys_t);
	off_t loc = space_alloc(zfs_opts, &len);
	blkptr_set(&ub->ub_rootbp, loc, len, ZIO_CHECKSUM_FLETCHER_4);

	/* XXXMJ write labels at the end */
}

void
zfs_makefs(const char *image, const char *dir, fsnode *root, fsinfo_t *fsopts)
{
	zfs_opt_t *zfs_opts;
	off_t nbits, size;
	int oflags;

	zfs_opts = fsopts->fs_specific;

	oflags = O_RDWR | O_CREAT;
	if (fsopts->offset == 0)
		oflags |= O_TRUNC;

	fsopts->fd = open(image, oflags, 0666 /* XXXMJ */);
	if (fsopts->fd == -1) {
		warn("Can't open `%s' for writing", image);
		goto out;
	}
	size = rounddown2(fsopts->maxsize, 1ul << zfs_opts->ashift);
	if (size < SPA_MINDEVSIZE) {
		warnx("maximum image size %ju is too small",
		    (uintmax_t)size);
		goto out;
	}
	if (ftruncate(fsopts->fd, size) != 0) {
		warn("Failed to extend image file `%s'", image);
		goto out;
	}
	nbits = (size - VDEV_LABEL_START_SIZE - VDEV_LABEL_END_SIZE) >>
	    zfs_opts->ashift;
	if (nbits > INT_MAX) {
		warnx("image size %ju is too large",
		    (uintmax_t)size);
		goto out;
	}
	zfs_opts->spacemapbits = (int)nbits;
	zfs_opts->spacemap = bit_alloc(zfs_opts->spacemapbits);
	if (zfs_opts->spacemap == NULL) {
		warn("bitstring allocation failed");
		goto out;
	}

	mkpool(fsopts);

out:
	if (fsopts->fd != -1)
		(void)close(fsopts->fd);
	free(zfs_opts->spacemap);
}
