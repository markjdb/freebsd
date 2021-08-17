#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <libctf.h>

int
main(int argc, char **argv)
{
	Ctf *ctf;
	int fd, ofd;

	if (argc != 2)
		errx(1, "usage: %s <file>", getprogname());

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		err(1, "open(%s)", argv[1]);

	/* XXX */
	ctf = ctf_convert_dwarf(fd, NULL);
	if (ctf == NULL)
		errx(1, "ctf_convert_dwarf() failed");

	ofd = open("/tmp/ctf", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (ofd < 0)
		err(1, "open(/tmp/ctf)");

	if (ctf_update(ctf) != 0)
		err(1, "ctf_update");

	if (ctf_write(ctf, ofd) != 0)
		err(1, "ctf_write");

#if 0
	if (cap_enter() != 0)
		err(1, "cap_enter");

	for (i = 0; i < BASE_TYPE_HASHSZ; i++)
		STAILQ_INIT(&g_base_types[i]);
	for (i = 0; i < ENUM_TYPE_HASHSZ; i++)
		STAILQ_INIT(&g_enum_types[i]);
	for (i = 0; i < STRUCT_TYPE_HASHSZ; i++)
		LIST_INIT(&g_struct_types[i]);
	for (i = 0; i < UNION_TYPE_HASHSZ; i++)
		LIST_INIT(&g_union_types[i]);

	TAILQ_INIT(&g_dangling);
	if (dwarf_init(fd, DW_DLC_READ, NULL, NULL, &dbg, &derr) != DW_DLV_OK)
		errx(1, "dwarf_init: %s", dwarf_errmsg(derr));

	sc.sc_dbg = dbg;
	SLIST_INIT(&sc.sc_cus);

	sc.sc_void.t_off = 0;
	sc.sc_void.t_tag = DW_TAG_base_type;
	sc.sc_void.t_name = "void";
	sc.sc_void.t_bsz = 0;
	sc.sc_void.t_canonical = true;
	sc.sc_void.t_base.enc = 0;
	STAILQ_INSERT_HEAD(&g_base_types[strhash(sc.sc_void.t_name) &
	    (BASE_TYPE_HASHSZ - 1)], &sc.sc_void, t_stailq);

	while (dwarf_next_cu_header_b(dbg, NULL, NULL, NULL, NULL, NULL, NULL,
	    NULL, &derr) == DW_DLV_OK) {
		cu = NULL;
		if (dwarf_siblingof(dbg, cu, &cu, &derr) != DW_DLV_OK)
			errx(1, "dwarf_siblingof: %s", dwarf_errmsg(derr));

		if (dwarf_tag(cu, &tag, &derr) != DW_DLV_OK)
			errx(1, "dwarf_tag: %s", dwarf_errmsg(derr));
		if (tag != DW_TAG_compile_unit)
			errx(1, "top-level DIE isn't a CU");

		cuctx = cuctx_new(&sc, cu);
		process_cu(cuctx);
		cuctx->cu_die = NULL;
		dwarf_dealloc(dbg, cu, DW_DLA_DIE);
	}

	printf("phase 1 done\n");

	struct tnode_list canonical;
	LIST_INIT(&canonical);
	int count = 0;

	for (i = 0; i < STRUCT_TYPE_HASHSZ; i++) {
		l = &g_struct_types[i];
		while ((t = LIST_FIRST(l)) != NULL) {
			LIST_REMOVE(t, t_list);
			assert(!tnode_is_canonical(t));
			t->t_canonical = true;
			canonicalize_references(t);

			LIST_FOREACH_SAFE(t1, l, t_list, ttmp) {
				if (tnode_equiv(t, t1)) {
					LIST_REMOVE(t1, t_list);

					remap_references(t, t1);
					doffmap_remap(t1, t);
					tnode_free(t1);
				}
				gen = currgen + 1;
			}

			LIST_INSERT_HEAD(&canonical, t, t_list);
			count++;
		}
	}

	printf("%d canonical structures\n", count);
#if 0
	LIST_FOREACH(t, &canonical, t_list)
		printf("%s\n", t->t_name);
#endif
	count = 0;

	for (i = 0; i < UNION_TYPE_HASHSZ; i++) {
		l = &g_union_types[i];
		while ((t = LIST_FIRST(l)) != NULL) {
			LIST_REMOVE(t, t_list);
			assert(!tnode_is_canonical(t));
			t->t_canonical = true;
			canonicalize_references(t);

			LIST_FOREACH_SAFE(t1, l, t_list, ttmp) {
				if (tnode_equiv(t, t1)) {
					LIST_REMOVE(t1, t_list);

					remap_references(t, t1);
					doffmap_remap(t1, t);
					tnode_free(t1);
				}
				gen = currgen + 1;
			}

			LIST_INSERT_HEAD(&canonical, t, t_list);
			count++;
		}
	}
	printf("%d canonical unions\n", count);
#endif
	return (0);
}
