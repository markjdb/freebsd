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

/*
 * XXXMJ this might wrong but I don't understand where DN_MAX_LEVELS' definition
 * comes from.  Be sure to test with large files...
 */
#define	INDIR_LEVELS	6

struct _zfs_fs;

typedef struct {
	uint64_t	id;
	struct _zfs_fs	*fs;
} zfs_obj_t;

typedef struct _zfs_fs {
	objset_phys_t	osphys;
	dnode_phys_t	*dnodes;
	uint64_t	dnodecount;
	uint64_t	dnodenextfree;	/* dnode ID bump allocator */
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

typedef struct zfs_zap {
	off_t			loc;
	off_t			blksz;
	mzap_ent_phys_t		*ent;
	char			zapblk[SPA_OLDMAXBLOCKSIZE];
} zfs_zap_t;

static void
zap_add_dnid(zfs_zap_t *zap, const char *name, uint64_t id)
{
	mzap_ent_phys_t *ent;

	ent = zap->ent;
	zap->ent++;

	ent->mze_value = id;
	ent->mze_cd = 0; /* XXXMJ */
	assert(strlen(name) < sizeof(ent->mze_name));
	strlcpy(ent->mze_name, name, sizeof(ent->mze_name));
}

static dnode_phys_t *
dnode_alloc(zfs_fs_t *fs, uint64_t *idp)
{
	assert(fs->dnodenextfree < fs->dnodecount);
	if (idp != NULL)
		*idp = fs->dnodenextfree;
	return (&fs->dnodes[fs->dnodenextfree++]);
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
blkptr_set(blkptr_t *bp, off_t off, off_t size, enum zio_checksum cksumt,
    zio_cksum_t *cksum)
{
	dva_t *dva;

	BP_ZERO(bp);
	BP_SET_LSIZE(bp, size);
	BP_SET_PSIZE(bp, size);
	BP_SET_CHECKSUM(bp, cksumt);
	BP_SET_COMPRESS(bp, ZIO_COMPRESS_OFF);

	dva = BP_IDENTITY(bp);
	DVA_SET_VDEV(dva, 0);
	DVA_SET_OFFSET(dva, off);
	DVA_SET_ASIZE(dva, size);
	bp->blk_cksum = *cksum;
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

	/* XXXMJ checksum will be wrong at this point. */
	zio_cksum_t cksum;
	fletcher_4_native(label, len, NULL, &cksum);
	blkptr_set(&ub->ub_rootbp, loc, len, ZIO_CHECKSUM_FLETCHER_4,
	    &cksum);

	/* XXXMJ write labels at the end */
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
	zap_add_dnid(&dir->zap, name, dnid);
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

	dnode = dnode_alloc(arg->fs, &dnid);

	bpas = ecalloc(1, sizeof(*bpas));
	blkptr_alloc_init(fsopts, bpas, dnode, size);

	dnode->dn_type = DMU_OT_PLAIN_FILE_CONTENTS;
	dnode->dn_indblkshift = (uint8_t)flsll(bpas->indblksz);
	dnode->dn_nlevels = (uint8_t)bpas->levels;
#if 0
	dnode->dn_nblkptr = ?;
#endif
	dnode->dn_bonustype = DMU_OT_NONE;
	dnode->dn_checksum = ZIO_CHECKSUM_FLETCHER_4; /* XXXMJ yes? */
	dnode->dn_compress = ZIO_COMPRESS_OFF;
	dnode->dn_flags = 0; /* XXXMJ ??? */
#if 0
	dnode->dn_datablkszsec = ?;
#endif
	dnode->dn_bonuslen = 0;
	dnode->dn_extra_slots = 0;
#if 0
	dnode->dn_maxblkid = ?;
	dnode->dn_used = ?;
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

	dnode = dnode_alloc(arg->fs, &dnid);
	dnode->dn_type = DMU_OT_DIRECTORY_CONTENTS;
#if 0
	dnode->dn_indblkshift = ?;
	dnode->dn_nlevels = ?;
	dnode->dn_nblkptr = ?;
#endif
	dnode->dn_bonustype = DMU_OT_NONE;
	dnode->dn_checksum = ZIO_CHECKSUM_FLETCHER_4; /* XXXMJ yes? */
	dnode->dn_compress = ZIO_COMPRESS_OFF;
	dnode->dn_flags = 0; /* XXXMJ */
#if 0
	dnode->dn_datablkszsec = ?;
#endif
	dnode->dn_bonuslen = 0;
	dnode->dn_extra_slots = 0;
#if 0
	dnode->dn_maxblkid = ?;
	dnode->dn_used = ?;
#endif

	/*
	 * Add an entry to the parent directory.  This must be done before
	 * allocating a ZAP object for this directory's children.
	 */
	if (cur->parent != NULL)
		fsnode_populate_dirent(arg, cur->name, dnid);

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

		mzap_phys_t *zaphdr = (mzap_phys_t *)&zap->zap.zapblk[0];
		zaphdr->mz_block_type = ZBT_MICRO;
		zaphdr->mz_salt = 0; /* XXXMJ */
		zaphdr->mz_normflags = 0;

		/* XXXMJ use mz_chunk */
		/* XXXMJ allocation could be done later. */
		blksz = (count + 1) * MZAP_ENT_LEN;
		zap->zap.loc = space_alloc(zfs_opts, &blksz);
		zap->zap.blksz = blksz;
		zap->zap.ent = (mzap_ent_phys_t *)&zap->zap.zapblk[sizeof(mzap_phys_t)];

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

		printf("%s:%d writing ZAP for %s\n", __func__, __LINE__, cur->name);
		vdev_pwrite(arg->fsopts, dirs->zap.zapblk, dirs->zap.blksz,
		    dirs->zap.loc);

		free(dirs);
	}
}

static void
mkfs(fsinfo_t *fsopts, zfs_fs_t *fs, const char *dir, fsnode *root)
{
	struct fsnode_foreach_populate_arg poparg;
	uint64_t dnodecount;

	/* XXXMJ what else? */
	fs->osphys.os_meta_dnode.dn_type = DMU_OT_DNODE;
	fs->osphys.os_type = DMU_OST_ZFS;

	/*
	 * Figure out how many dnodes we need.  One for each ZPL object (file,
	 * directory, etc.), one for the master dnode (always with ID 1), one
	 * for the meta dnode (embedded in the object set, always with ID 0).
	 *
	 * XXXMJ SA table?
	 */
	dnodecount = 1;
	fsnode_foreach(root, dir, fsnode_foreach_count, &dnodecount);
	dnodecount++;
	dnodecount++;

	/*
	 * XXXMJ allocating them all up front like this might be too painful for
	 * really large filesystems.  Check to see how much this costs for a
	 * FreeBSD tree.
	 */
	fs->dnodecount = dnodecount;
	fs->dnodes = ecalloc(fs->dnodecount, sizeof(dnode_phys_t));
	fs->dnodenextfree = MASTER_NODE_OBJ + 1;

	poparg.fsopts = fsopts;
	poparg.fs = fs;
	SLIST_INIT(&poparg.dirs);

	fsnode_populate_dir(root, dir, &poparg);
	assert(!SLIST_EMPTY(&poparg.dirs));
	fsnode_foreach(root, dir, fsnode_foreach_populate, &poparg);

	/* XXXMJ allocate master node ZAP object */

	/* XXXMJ write dnode array */
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

	fsopts->fd = open(image, oflags, 0644 /* XXXMJ */);
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

	mkfs(fsopts, &zfs_opts->rootfs, dir, root);

out:
	if (fsopts->fd != -1)
		(void)close(fsopts->fd);
	free(zfs_opts->spacemap);
}
