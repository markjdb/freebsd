# $FreeBSD$

.PATH: ${SRCTOP}/cddl/contrib/opensolaris/common/ctf
.PATH: ${SRCTOP}/cddl/contrib/opensolaris/lib/libctf/common
.PATH: ${SRCTOP}/cddl/contrib/opensolaris/lib/mergeq

LIB=		ctf
SRCS=		ctf_convert.c \
		ctf_create.c \
		ctf_decl.c \
		ctf_diff.c \
		ctf_dwarf.c \
		ctf_elfwrite.c \
		ctf_error.c \
		ctf_hash.c \
		ctf_labels.c \
		ctf_lib.c \
		ctf_lookup.c \
		ctf_merge.c \
		ctf_open.c \
		ctf_subr.c \
		ctf_types.c \
		ctf_util.c \
		mergeq.c \
		workq.c
MAN=		ctf.5

WARNS?=		2
CFLAGS+=	-DCTF_OLD_VERSIONS
CWARNFLAGS.ctf_dwarf.c+=	-Wno-format
CWARNFLAGS.ctf_lib.c+=		-Wno-format

CFLAGS+= -DIN_BASE
CFLAGS+= -I${SRCTOP}/cddl/contrib/opensolaris/lib/mergeq
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/os/freebsd
CFLAGS+= -include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h
CFLAGS+= -DHAVE_ISSETUGID

CFLAGS+=	-I${SRCTOP}/sys/cddl/compat/opensolaris \
		-I${SRCTOP}/cddl/compat/opensolaris/include \
		-I${OPENSOLARIS_USR_DISTDIR}/head \
		-I${OPENSOLARIS_USR_DISTDIR}/common/ctf \
		-I${OPENSOLARIS_USR_DISTDIR}/lib/libctf/common \
		-I${OPENSOLARIS_SYS_DISTDIR}/uts/common

LIBADD+=	avl dwarf elf spl z

.include <bsd.lib.mk>
