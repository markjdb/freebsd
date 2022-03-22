#include <sys/zfs_context.h>
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

void
zfs_prep_opts(fsinfo_t *fsopts)
{
}

int
zfs_parse_opts(const char *option, fsinfo_t *fsopts)
{
	return (1);
}

void
zfs_cleanup_opts(fsinfo_t *fsopts)
{
}

static void
objset_create_cb(objset_t *os, void *arg __unused, cred_t *cr __unused,
    dmu_tx_t *tx)
{
	dmu_buf_t *db;
	sa_attr_type_t *satab;
	sa_bulk_attr_t *attrs;
	sa_handle_t *sahdl;
	uint64_t dnodesize, dqobj, rootobj, saobj, version;
	int error, i;

	error = zap_create_claim(os, MASTER_NODE_OBJ, DMU_OT_MASTER_NODE,
	    DMU_OT_NONE, 0, tx);
	if (error != 0)
		errc(1, error, "zap_create_claim");

	version = ZPL_VERSION;
	error = zap_update(os, MASTER_NODE_OBJ, ZPL_VERSION_STR, 8, 1,
	    &version, tx);
	if (error != 0)
		errc(1, error, "zap_update");

	saobj = zap_create(os, DMU_OT_SA_MASTER_NODE, DMU_OT_NONE, 0, tx);

	error = zap_add(os, MASTER_NODE_OBJ, ZFS_SA_ATTRS, 8, 1, &saobj, tx);
	if (error != 0)
		errc(1, error, "zap_add");

	dqobj = zap_create(os, DMU_OT_UNLINKED_SET, DMU_OT_NONE, 0, tx);

	error = zap_add(os, MASTER_NODE_OBJ, ZFS_UNLINKED_SET, 8, 1, &dqobj,
	    tx);
	if (error != 0)
		errc(1, error, "zap_add");

	error = sa_setup(os, saobj, zfs_attr_table, ZPL_END, &satab);
	if (error != 0)
		errc(1, error, "sa_setup");

	/* XXXMJ ACL IDs?? */

	/* XXXMJ zfs_mknode start */

	dnodesize = dmu_objset_dnodesize(os);
	printf("dnodesize %lu\n", dnodesize);

	rootobj = zap_create_norm_dnsize(os, 0, DMU_OT_DIRECTORY_CONTENTS,
	    DMU_OT_SA, DN_BONUS_SIZE(dnodesize), dnodesize, tx);
	printf("root obj %lu\n", rootobj);

	error = sa_buf_hold(os, rootobj, NULL, &db);
	if (error != 0)
		errc(1, error, "sa_buf_hold");

	error = sa_handle_get_from_db(os, db, NULL, SA_HDL_SHARED, &sahdl);
	if (error != 0)
		errc(1, error, "sa_handle_get_from_db");

	attrs = ecalloc(ZPL_END, sizeof(sa_bulk_attr_t));

	uint64_t gen, links, mode, pflags, size, time[2];
	uint64_t gid, uid;

	gen = 1; /* can't be 0 */
	mode = S_IFDIR | 0755;
	pflags = 0; /* XXXMJ */
	links = 2;
	size = 2; /* "." and ".." */
	time[0] = time[1] = 0;

	gid = uid = 0; /* XXXMJ */

	i = 0;
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_MODE], NULL, &mode, 8);
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_SIZE], NULL, &size, 8);
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_GEN], NULL, &gen, 8);
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_UID], NULL, &uid, 8);
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_GID], NULL, &gid, 8);
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_PARENT], NULL, &rootobj, 8);
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_FLAGS], NULL, &pflags, 8);
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_ATIME], NULL, time, 16);
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_MTIME], NULL, time, 16);
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_CTIME], NULL, time, 16);
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_CRTIME], NULL, time, 16);
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_LINKS], NULL, &links, 8); 

	error = sa_replace_all_by_template(sahdl, attrs, i, tx);
	if (error != 0)
		errc(1, error, "sa_replace_all_by_template");

	/* XXXMJ zfs_mknode end */

	error = zap_add(os, MASTER_NODE_OBJ, ZFS_ROOT_OBJ, 8, 1, &rootobj, tx);
	if (error != 0)
		errc(1, error, "zap_add");

	sa_handle_destroy(sahdl);
}

static int
check(void *arg __unused, dmu_tx_t *tx __unused)
{
	return (0);
}

static void
create(void *arg, dmu_tx_t *tx)
{
	objset_create_cb(arg, NULL, NULL, tx);
}

void
zfs_makefs(const char *image, const char *dir, fsnode *root, fsinfo_t *fsopts)
{
	char path[PATH_MAX];
	const char *pool = "testpool";
	const char *ds = "testpool/ROOT";
	objset_t *os;
	dsl_dataset_t *rds;
	dsl_pool_t *dp;
	nvlist_t *cvdev, *rvdev, *props;
	spa_t *spa;
	int error, fd;

	fd = open(image, O_RDWR | O_CREAT, 0644);
	if (fd < 0)
		err(1, "open(%s)", path);
	if (ftruncate(fd, 1024 * 1024 * 1024ul /* XXXMJ */) != 0)
		err(1, "ftruncate");
	if (close(fd) != 0)
		err(1, "close");

	/* The path backing the vdev must be absolute. */
	if (realpath(image, path) != path)
		err(1, "realpath(%s)", image);

	kernel_init(SPA_MODE_READ | SPA_MODE_WRITE);

	cvdev = fnvlist_alloc();
	fnvlist_add_string(cvdev, ZPOOL_CONFIG_TYPE, VDEV_TYPE_DISK);
	fnvlist_add_string(cvdev, ZPOOL_CONFIG_PATH, path);
	fnvlist_add_uint64(cvdev, ZPOOL_CONFIG_IS_LOG, 0);

	rvdev = fnvlist_alloc();
	fnvlist_add_string(rvdev, ZPOOL_CONFIG_TYPE, VDEV_TYPE_ROOT);
	fnvlist_add_nvlist_array(rvdev, ZPOOL_CONFIG_CHILDREN,
	    (const nvlist_t **)&cvdev, 1);

	props = fnvlist_alloc();

	/* XXXMJ this opens zpool.cache? */
	error = spa_create(pool, rvdev, props, NULL, NULL);
	if (error != 0)
		errc(1, error, "spa_create");

	error = spa_open(pool, &spa, FTAG);
	if (error != 0)
		errc(1, error, "spa_open");

	error = dsl_pool_hold(pool, FTAG, &dp);
	if (error != 0)
		errc(1, error, "dsl_pool_hold");

	error = dsl_dataset_hold(dp, "testpool", FTAG, &rds);
	if (error != 0)
		errc(1, error, "dsl_dataset_hold");

	error = dmu_objset_from_ds(rds, &os);
	if (error != 0)
		errc(1, error, "dmu_objset_from_ds");

	dmu_tx_t *tx = dmu_tx_create(os);

	error = dmu_tx_assign(tx, TXG_NOWAIT);
	if (error != 0)
		errc(1, error, "dmu_tx_assign");

	objset_create_cb(os, NULL, NULL, tx);

	dmu_tx_commit(tx);
	dsl_dataset_rele(rds, FTAG);
	dsl_pool_rele(dp, FTAG);

	error = dmu_objset_create(ds, DMU_OST_ZFS, 0, NULL, objset_create_cb,
	    NULL);
	if (error != 0)
		errc(1, error, "dmu_objset_create");

	spa_close(spa, FTAG);

	error = spa_export(pool, NULL, B_FALSE, B_FALSE);
	if (error != 0)
		errc(1, error, "spa_export");
}
