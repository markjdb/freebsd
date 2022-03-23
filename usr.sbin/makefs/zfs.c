#include <sys/zfs_context.h>
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

/* XXXMJ */
static sa_handle_t *g_sahdl;
static sa_attr_type_t *g_satab; 
static uint64_t g_rootobj;

typedef struct {
	const char	*poolname;
} zfs_opt_t;

void
zfs_prep_opts(fsinfo_t *fsopts)
{
	zfs_opt_t *zfs_opts = ecalloc(1, sizeof(*zfs_opts));

	const option_t zfs_options[] = {
		{ '\0', "poolname", &zfs_opts->poolname, OPT_STRPTR,
		  0, 0, "ZFS pool name" },
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
	free(fsopts->fs_specific);
	/* XXXMJ need to free strduped strings */
	free(fsopts->fs_options);
}

static void
mknode(objset_t *os, sa_attr_type_t *satab, dmu_tx_t *tx, uint_t type, uint64_t mode,
    uint64_t size, uint64_t links, sa_handle_t **sahdlp, uint64_t *rootobjp)
{
	zfs_ace_hdr_t aces[3];
	zfs_acl_phys_t acl_phys;
	dmu_buf_t *db;
	sa_bulk_attr_t *attrs;
	sa_handle_t *sahdl;
	uint64_t dnodesize, rootobj;
	int error, i;

	dnodesize = dmu_objset_dnodesize(os);

	rootobj = zap_create_norm_dnsize(os, 0, DMU_OT_DIRECTORY_CONTENTS,
	    DMU_OT_SA, DN_BONUS_SIZE(dnodesize), dnodesize, tx);

	error = sa_buf_hold(os, rootobj, NULL, &db);
	if (error != 0)
		errc(1, error, "sa_buf_hold");

	error = sa_handle_get_from_db(os, db, NULL, SA_HDL_SHARED, &sahdl);
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
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_MODE], NULL, &mode, 8);
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_SIZE], NULL, &size, 8);
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_GEN], NULL, &gen, 8);
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_UID], NULL, &uid, 8);
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_GID], NULL, &gid, 8);
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_ZNODE_ACL], NULL, &acl_phys,
	    sizeof(acl_phys));
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_DACL_COUNT], NULL, &aclcount, 8);
	SA_ADD_BULK_ATTR(attrs, i, satab[ZPL_DACL_ACES], NULL, aces, sizeof(aces));
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

	if (sahdlp != NULL)
		*sahdlp = sahdl;
	if (rootobjp != NULL)
		*rootobjp = rootobj;

	free(attrs);
}

static void
objset_create_cb(objset_t *os, void *arg __unused, cred_t *cr __unused,
    dmu_tx_t *tx)
{
	sa_attr_type_t *satab;
	sa_handle_t *sahdl;
	uint64_t dqobj, rootobj, saobj, version;
	int error;

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

	mknode(os, satab, tx, S_IFDIR, 0755, 2 /* XXXMJ "." and ".." */, 2, &sahdl, &rootobj);

	error = zap_add(os, MASTER_NODE_OBJ, ZFS_ROOT_OBJ, 8, 1, &rootobj, tx);
	if (error != 0)
		errc(1, error, "zap_add");

	g_sahdl = sahdl;
	g_satab = satab;
	g_rootobj = rootobj;
}

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

void
zfs_makefs(const char *image, const char *dir __unused, fsnode *root __unused, fsinfo_t *fsopts)
{
	const char *file = "foo.txt";
	const char *poolname;
	zfs_opt_t *zfs_opts;
#if 0
	const char *ds = "testpool/ROOT";
#endif
	objset_t *os;
	dsl_dataset_t *rds;
	dsl_pool_t *dp;
	spa_t *spa;
	int error;

	zfs_opts = fsopts->fs_specific;

	poolname = zfs_opts->poolname;

	kernel_init(SPA_MODE_READ | SPA_MODE_WRITE);

	if (mkpool(image, fsopts) != 0)
		return;

	error = spa_open(poolname, &spa, FTAG);
	if (error != 0)
		errc(1, error, "spa_open");

	error = dsl_pool_hold(poolname, FTAG, &dp);
	if (error != 0)
		errc(1, error, "dsl_pool_hold");

	error = dsl_dataset_hold(dp, poolname, FTAG, &rds);
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

#if 0
	error = dmu_objset_create(ds, DMU_OST_ZFS, 0, NULL, objset_create_cb,
	    NULL);
	if (error != 0)
		errc(1, error, "dmu_objset_create");
#endif

	/* Create a file. */
	tx = dmu_tx_create(os);

	/* XXXMJ acls? */
	dmu_tx_hold_sa_create(tx, ZFS_SA_BASE_ATTR_SIZE);

	dmu_tx_hold_zap(tx, g_rootobj, TRUE, file);
	dmu_tx_hold_sa(tx, g_sahdl, B_FALSE);

	error = dmu_tx_assign(tx, TXG_NOWAIT);
	if (error != 0)
		errc(1, error, "dmu_tx_assign");

	sa_handle_t *sahdl;
	uint64_t newid;
	mknode(os, g_satab, tx, S_IFREG, 0666, 0, 0, &sahdl, &newid);

	/* zfs_link_create BEGIN */
	{
	sa_bulk_attr_t bulk[5];
	uint64_t links, nsize, pflags, value;
	int i;

	/* XXXMJ link count */

	value = newid | ((uint64_t)S_IFREG << 48);
	error = zap_add(os, g_rootobj, file, 8, 1, &value, tx);
	if (error != 0)
		errc(1, error, "zap_add");

	pflags = ZFS_ACL_TRIVIAL | ZFS_ACL_AUTO_INHERIT | ZFS_NO_EXECS_DENIED | ZFS_ARCHIVE | ZFS_AV_MODIFIED; /* XXXMJ */
	links = 1;
	i = 0;
	SA_ADD_BULK_ATTR(bulk, i, g_satab[ZPL_LINKS], NULL, &links,
	    sizeof(links));
	SA_ADD_BULK_ATTR(bulk, i, g_satab[ZPL_PARENT], NULL, &g_rootobj,
	    sizeof(g_rootobj));
	SA_ADD_BULK_ATTR(bulk, i, g_satab[ZPL_FLAGS], NULL, &pflags,
	    sizeof(pflags));

	error = sa_bulk_update(sahdl, bulk, i, tx);
	if (error != 0)
		errc(1, error, "sa_bulk_update");

	nsize = 3;
	i = 0;
	SA_ADD_BULK_ATTR(bulk, i, g_satab[ZPL_SIZE], NULL, &nsize,
	    sizeof(nsize));

	error = sa_bulk_update(g_sahdl, bulk, i, tx);
	if (error != 0)
		errc(1, error, "sa_bulk_update");
	}
	/* zfs_link_create END */

	dmu_tx_commit(tx);

	/* Write to the file. */
	{
	const char *str = "hello, world\n";
	uint64_t nsize;

	tx = dmu_tx_create(os);

	dmu_tx_hold_sa(tx, sahdl, B_FALSE);
	dmu_tx_hold_write(tx, newid, 0, strlen(str));

	error = dmu_tx_assign(tx, TXG_NOWAIT);
	if (error != 0)
		errc(1, error, "dmu_tx_assign");

	dmu_write(os, newid, 0, strlen(str), str, tx);

	nsize = strlen(str);
	error = sa_update(sahdl, g_satab[ZPL_SIZE], &nsize, sizeof(nsize), tx);
	if (error != 0)
		errc(1, error, "sa_update");

	dmu_tx_commit(tx);
	}

	sa_handle_destroy(g_sahdl);
	sa_handle_destroy(sahdl);

	spa_close(spa, FTAG);

	error = spa_export(poolname, NULL, B_FALSE, B_FALSE);
	if (error != 0)
		errc(1, error, "spa_export");

	/* XXXMJ this is rather slow and probably not necessary */
	kernel_fini();
}
