#include <sys/zfs_context.h>
#include <sys/multilist.h>
#include <sys/arc.h>
#include <sys/arc_impl.h>
#include <sys/dbuf.h>
#include <sys/dmu_objset.h>
#include <sys/dnode.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_pool.h>
#include <sys/sa.h>
#include <sys/spa.h>
#include <sys/zap.h>
#include <sys/zfs_acl.h>
#include <sys/zfs_sa.h>
#include <sys/zfs_znode.h>

#include <sys/fs/zfs.h>

#include <libnvpair.h>
#include <util.h>

#include "makefs.h"

typedef struct {
	uint64_t	id;
	sa_handle_t	*sahdl;
} zfs_obj_t;

typedef struct {
	objset_t	*os;
	dsl_dataset_t	*ds;
	sa_attr_type_t	*satab;
	zfs_obj_t	rootdir;
} zfs_fs_t;

typedef struct {
	/* Pool info. */
	const char	*poolname;
	spa_t		*spa;

	/* Root filesystem info. */
	zfs_fs_t	rootfs;

	/* Miscellaneous stuff. */
	void		*fbuf;
	size_t		fbufsz;
} zfs_opt_t;

void
zfs_prep_opts(fsinfo_t *fsopts)
{
	zfs_opt_t *zfs_opts = ecalloc(1, sizeof(*zfs_opts));

	const option_t zfs_options[] = {
		{ '\0', "poolname", &zfs_opts->poolname, OPT_STRPTR,
		  0, 0, "ZFS pool name" },
		{ .name = NULL }
	};

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
mknode(zfs_fs_t *fs, dmu_tx_t *tx, uint_t type, uint64_t mode,
    uint64_t size, uint64_t links, zfs_obj_t *obj)
{
	zfs_ace_hdr_t aces[3];
	zfs_acl_phys_t acl_phys;
	dmu_buf_t *db;
	sa_bulk_attr_t *attrs;
	uint64_t dnodesize;
	int error, i;

	dnodesize = dmu_objset_dnodesize(fs->os);

	obj->id = zap_create_norm_dnsize(fs->os, 0, DMU_OT_DIRECTORY_CONTENTS,
	    DMU_OT_SA, DN_BONUS_SIZE(dnodesize), dnodesize, tx);

	error = sa_buf_hold(fs->os, obj->id, NULL, &db);
	if (error != 0)
		errc(1, error, "sa_buf_hold");

	error = sa_handle_get_from_db(fs->os, db, NULL, SA_HDL_SHARED, &obj->sahdl);
	if (error != 0)
		errc(1, error, "sa_handle_get_from_db");

	attrs = ecalloc(ZPL_END, sizeof(sa_bulk_attr_t));

	uint64_t aclcount, gen, pflags, time[2];
	uint64_t gid, uid;

	aclcount = 3;
	gen = 1; /* can't be 0 */
	mode |= type;
	pflags = ZFS_ACL_TRIVIAL | ZFS_ACL_AUTO_INHERIT /* XXXMJ dir only */| ZFS_NO_EXECS_DENIED |
	    ZFS_ARCHIVE | ZFS_AV_MODIFIED; /* XXXMJ */
	time[0] = time[1] = 0;

	gid = uid = 0; /* XXXMJ */
	memset(&acl_phys, 0, sizeof(acl_phys));

	memset(aces, 0, sizeof(aces));
	aces[0].z_flags = ACE_OWNER;
	aces[0].z_type = ACE_ACCESS_ALLOWED_ACE_TYPE;
	aces[0].z_access_mask = ACE_READ_DATA | ACE_WRITE_ATTRIBUTES | ACE_WRITE_OWNER |
	    ACE_WRITE_ACL | ACE_WRITE_NAMED_ATTRS | ACE_READ_ACL | ACE_READ_ATTRIBUTES |
	    ACE_READ_NAMED_ATTRS | ACE_SYNCHRONIZE;
	aces[1].z_flags = ACE_GROUP | ACE_IDENTIFIER_GROUP;
	aces[1].z_type = ACE_ACCESS_ALLOWED_ACE_TYPE;
	aces[1].z_access_mask = ACE_READ_DATA |
	    ACE_READ_ACL | ACE_READ_ATTRIBUTES |
	    ACE_READ_NAMED_ATTRS | ACE_SYNCHRONIZE;
	aces[2].z_flags = ACE_EVERYONE;
	aces[2].z_type = ACE_ACCESS_ALLOWED_ACE_TYPE;
	aces[2].z_access_mask = ACE_READ_DATA |
	    ACE_READ_ACL | ACE_READ_ATTRIBUTES |
	    ACE_READ_NAMED_ATTRS | ACE_SYNCHRONIZE;

	i = 0;
	SA_ADD_BULK_ATTR(attrs, i, fs->satab[ZPL_MODE], NULL, &mode, 8);
	SA_ADD_BULK_ATTR(attrs, i, fs->satab[ZPL_SIZE], NULL, &size, 8);
	SA_ADD_BULK_ATTR(attrs, i, fs->satab[ZPL_GEN], NULL, &gen, 8);
	SA_ADD_BULK_ATTR(attrs, i, fs->satab[ZPL_UID], NULL, &uid, 8);
	SA_ADD_BULK_ATTR(attrs, i, fs->satab[ZPL_GID], NULL, &gid, 8);
	SA_ADD_BULK_ATTR(attrs, i, fs->satab[ZPL_ZNODE_ACL], NULL, &acl_phys,
	    sizeof(acl_phys));
	SA_ADD_BULK_ATTR(attrs, i, fs->satab[ZPL_DACL_COUNT], NULL, &aclcount, 8);
	SA_ADD_BULK_ATTR(attrs, i, fs->satab[ZPL_DACL_ACES], NULL, aces, sizeof(aces));
	SA_ADD_BULK_ATTR(attrs, i, fs->satab[ZPL_PARENT], NULL, &obj->id, 8);
	SA_ADD_BULK_ATTR(attrs, i, fs->satab[ZPL_FLAGS], NULL, &pflags, 8);
	SA_ADD_BULK_ATTR(attrs, i, fs->satab[ZPL_ATIME], NULL, time, 16);
	SA_ADD_BULK_ATTR(attrs, i, fs->satab[ZPL_MTIME], NULL, time, 16);
	SA_ADD_BULK_ATTR(attrs, i, fs->satab[ZPL_CTIME], NULL, time, 16);
	SA_ADD_BULK_ATTR(attrs, i, fs->satab[ZPL_CRTIME], NULL, time, 16);
	SA_ADD_BULK_ATTR(attrs, i, fs->satab[ZPL_LINKS], NULL, &links, 8); 

	error = sa_replace_all_by_template(obj->sahdl, attrs, i, tx);
	if (error != 0)
		errc(1, error, "sa_replace_all_by_template");

	free(attrs);
}

/*
 * Create the pool.
 */
static int
mkpool(const char *image, fsinfo_t *fsopts)
{
	char path[PATH_MAX];
	nvlist_t *cvdev, *rvdev, *props;
	zfs_opt_t *zfs_opts;
	int error, oflags;

	zfs_opts = fsopts->fs_specific;
	if (zfs_opts->poolname == NULL) {
		warnx("No pool name specified");
		return (-1);
	}

	oflags = O_RDWR | O_CREAT;
	if (fsopts->offset == 0)
		oflags |= O_TRUNC;

	fsopts->fd = open(image, oflags, 0666);
	if (fsopts->fd == -1) {
		warn("Can't open `%s' for writing", image);
		return (-1);
	}
	if (ftruncate(fsopts->fd, fsopts->maxsize) != 0) {
		warn("Failed to extend image file `%s'", image);
		return (-1);
	}

	/* The path backing the vdev must be absolute. */
	if (realpath(image, path) != path)
		err(1, "realpath(%s)", image);

	cvdev = fnvlist_alloc();
	fnvlist_add_string(cvdev, ZPOOL_CONFIG_TYPE, VDEV_TYPE_DISK);
	fnvlist_add_string(cvdev, ZPOOL_CONFIG_PATH, path);
	fnvlist_add_uint64(cvdev, ZPOOL_CONFIG_IS_LOG, 0);

	rvdev = fnvlist_alloc();
	fnvlist_add_string(rvdev, ZPOOL_CONFIG_TYPE, VDEV_TYPE_ROOT);
	fnvlist_add_nvlist_array(rvdev, ZPOOL_CONFIG_CHILDREN,
	    (const nvlist_t **)&cvdev, 1);

	props = fnvlist_alloc();
	fnvlist_add_string(props, "cachefile", "none");
	/* XXXMJ hack to try and ensure that the cache file isn't written */
	fnvlist_add_string(props, "altroot", "/");

	/* XXXMJ this opens zpool.cache? */
	error = spa_create(zfs_opts->poolname, rvdev, props, NULL, NULL);
	if (error != 0) {
		warnc(error, "spa_create");
		return (-1);
	}

	fnvlist_free(props);
	fnvlist_free(rvdev);

	return (0);
}

static void
mkfs(zfs_fs_t *fs, fsnode *root, dmu_tx_t *tx)
{
	uint64_t dqobj, saobj, version;
	int error;

	error = zap_create_claim(fs->os, MASTER_NODE_OBJ, DMU_OT_MASTER_NODE,
	    DMU_OT_NONE, 0, tx);
	if (error != 0)
		errc(1, error, "zap_create_claim");

	version = ZPL_VERSION;
	error = zap_update(fs->os, MASTER_NODE_OBJ, ZPL_VERSION_STR, 8, 1,
	    &version, tx);
	if (error != 0)
		errc(1, error, "zap_update");

	saobj = zap_create(fs->os, DMU_OT_SA_MASTER_NODE, DMU_OT_NONE, 0, tx);

	error = zap_add(fs->os, MASTER_NODE_OBJ, ZFS_SA_ATTRS, 8, 1, &saobj, tx);
	if (error != 0)
		errc(1, error, "zap_add");

	dqobj = zap_create(fs->os, DMU_OT_UNLINKED_SET, DMU_OT_NONE, 0, tx);

	error = zap_add(fs->os, MASTER_NODE_OBJ, ZFS_UNLINKED_SET, 8, 1, &dqobj,
	    tx);
	if (error != 0)
		errc(1, error, "zap_add");

	error = sa_setup(fs->os, saobj, zfs_attr_table, ZPL_END, &fs->satab);
	if (error != 0)
		errc(1, error, "sa_setup");

	mknode(fs, tx, root->type, 0755, 2 /* XXXMJ "." and ".." */, 2,
	    &fs->rootdir);

	error = zap_add(fs->os, MASTER_NODE_OBJ, ZFS_ROOT_OBJ, 8, 1, &fs->rootdir.id, tx);
	if (error != 0)
		errc(1, error, "zap_add");
}

static void
mkrootfs(zfs_fs_t *fs, fsnode *root, fsinfo_t *fsopts)
{
	zfs_opt_t *zfs_opts;
	dsl_pool_t *dp;
	dmu_tx_t *tx;
	int error;

	zfs_opts = fsopts->fs_specific;

	error = dsl_pool_hold(zfs_opts->poolname, FTAG, &dp);
	if (error != 0)
		errc(1, error, "dsl_pool_hold");

	error = dsl_dataset_hold(dp, zfs_opts->poolname, FTAG, &fs->ds);
	if (error != 0)
		errc(1, error, "dsl_dataset_hold");

	error = dmu_objset_from_ds(fs->ds, &fs->os);
	if (error != 0)
		errc(1, error, "dmu_objset_from_ds");

	tx = dmu_tx_create(fs->os);

	error = dmu_tx_assign(tx, TXG_NOWAIT);
	if (error != 0)
		errc(1, error, "dmu_tx_assign");

	mkfs(fs, root, tx);

	dmu_tx_commit(tx);

	dsl_pool_rele(dp, FTAG);
}

static void
fspopulate(fsnode *cur, zfs_obj_t *parent, fsinfo_t *fsopts)
{
	zfs_fs_t *fs;
	zfs_obj_t obj;
	zfs_opt_t *zfs_opts;
	dmu_tx_t *tx;
	int error;

	if (cur == NULL)
		return;
	if (cur->type != S_IFREG)
		goto next;

	zfs_opts = fsopts->fs_specific;
	fs = &zfs_opts->rootfs;

	tx = dmu_tx_create(fs->os);

	/* XXXMJ review these holds */
	dmu_tx_hold_sa_create(tx, ZFS_SA_BASE_ATTR_SIZE);
	dmu_tx_hold_zap(tx, parent->id, TRUE, cur->name);
	dmu_tx_hold_sa(tx, parent->sahdl, B_FALSE);

	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error != 0)
		errc(1, error, "dmu_tx_assign");

	mknode(fs, tx, cur->type, 0666, 0, 0, &obj);

	/* zfs_link_create BEGIN */
	{
	sa_bulk_attr_t bulk[5];
	uint64_t links, nsize, pflags, value;
	int i;

	/* XXXMJ link count */

	value = obj.id | ((uint64_t)cur->type << 48);
	error = zap_add(fs->os, parent->id, cur->name, 8, 1, &value, tx);
	if (error != 0)
		errc(1, error, "zap_add");

	pflags = ZFS_ACL_TRIVIAL | ZFS_ACL_AUTO_INHERIT | ZFS_NO_EXECS_DENIED | ZFS_ARCHIVE | ZFS_AV_MODIFIED; /* XXXMJ */
	links = 1;
	i = 0;
	SA_ADD_BULK_ATTR(bulk, i, fs->satab[ZPL_LINKS], NULL, &links,
	    sizeof(links));
	SA_ADD_BULK_ATTR(bulk, i, fs->satab[ZPL_PARENT], NULL, &parent->id,
	    sizeof(parent->id));
	SA_ADD_BULK_ATTR(bulk, i, fs->satab[ZPL_FLAGS], NULL, &pflags,
	    sizeof(pflags));

	error = sa_bulk_update(obj.sahdl, bulk, i, tx);
	if (error != 0)
		errc(1, error, "sa_bulk_update");

	nsize = 3;
	i = 0;
	SA_ADD_BULK_ATTR(bulk, i, fs->satab[ZPL_SIZE], NULL, &nsize,
	    sizeof(nsize));

	error = sa_bulk_update(parent->sahdl, bulk, i, tx);
	if (error != 0)
		errc(1, error, "sa_bulk_update");
	}
	/* zfs_link_create END */

	dmu_tx_commit(tx);

	/* Write to the file. */
	{
	char path[PATH_MAX];
	uint64_t nbytes, size;
	ssize_t n;
	off_t off;
	int fd;

	snprintf(path, sizeof(path), "%s/%s/%s", cur->root, cur->path,
	    cur->name);

	fd = open(path, O_RDONLY);
	if (fd == -1)
		err(1, "open(%s)", path);

	size = cur->inode->st.st_size;
	nbytes = off = 0;

	/* XXXMJ investigate preserving file holes */
	for (nbytes = off = 0; nbytes < size; off += n) {
		printf("%s:%d off %lu\n", __func__, __LINE__, off);
		n = read(fd, zfs_opts->fbuf, MIN(size - off, zfs_opts->fbufsz));
		if (n < 0)
			err(1, "read");

		tx = dmu_tx_create(fs->os);

		dmu_tx_hold_write(tx, obj.id, off, n);
		dmu_tx_hold_sa(tx, obj.sahdl, B_TRUE);

		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error != 0)
			errc(1, error, "dmu_tx_assign");

		if (n > 0)
			dmu_write(fs->os, obj.id, off, n, zfs_opts->fbuf, tx);

		nbytes += n;
		error = sa_update(obj.sahdl, fs->satab[ZPL_SIZE],
		    &nbytes, sizeof(nbytes), tx);
		if (error != 0)
			errc(1, error, "sa_update");

		dmu_tx_commit(tx);
	}

	(void)close(fd);
	}

	sa_handle_destroy(obj.sahdl);

next:
	/* XXXMJ this is not tail recursive */
	fspopulate(cur->next, parent, fsopts);
}

extern uint64_t physmem;

void
zfs_makefs(const char *image, const char *dir __unused, fsnode *root, fsinfo_t *fsopts)
{
	zfs_opt_t *zfs_opts;
	int argc, error;

	/* Initialize ZFS debugging. */
	argc = 0;
	dprintf_setup(&argc, NULL);

	zfs_opts = fsopts->fs_specific;

	/* Empirically, a larger buffer doesn't help with throughput. */
	zfs_opts->fbufsz = 2 * 1024 * 1024;
	zfs_opts->fbuf = emalloc(zfs_opts->fbufsz);

	kernel_init(SPA_MODE_READ | SPA_MODE_WRITE);

	if (mkpool(image, fsopts) != 0)
		return;

	error = spa_open(zfs_opts->poolname, &zfs_opts->spa, FTAG);
	if (error != 0)
		errc(1, error, "spa_open");

	mkrootfs(&zfs_opts->rootfs, root, fsopts);

	fspopulate(root->next, &zfs_opts->rootfs.rootdir, fsopts);

	/* XXXMJ fs cleanup routine */
	sa_handle_destroy(zfs_opts->rootfs.rootdir.sahdl);
	dsl_dataset_rele(zfs_opts->rootfs.ds, FTAG);

	spa_close(zfs_opts->spa, FTAG);

	error = spa_export(zfs_opts->poolname, NULL, B_FALSE, B_FALSE);
	if (error != 0)
		errc(1, error, "spa_export");

	kernel_fini();
}
