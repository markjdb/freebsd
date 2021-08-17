# $FreeBSD$

.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	ctf
MAN=

SRCS=	ctf_add.c	\
	ctf_errmsg.c	\
	ctf_model.c	\
	ctf_open.c	\
	ctf_specific.c	\
	libctf_add.c	\
	libctf_create.c	\
	libctf_dwarf.c

.PATH: ${SRCTOP}/contrib/elftoolchain/libelftc

SRCS+=	elftc_string_table.c libelftc_hash.c
CFLAGS+= -I${SRCTOP}/contrib/elftoolchain/common
CFLAGS+= -I${SRCTOP}/contrib/elftoolchain/libelftc

INCS=	libctf.h

#CFLAGS+= -O0
#CFLAGS+= -fno-inline

LIBADD+= dwarf z
#LDADD+= -L/usr/local/lib -ltcmalloc

SHLIB_MAJOR=	1

.include <bsd.lib.mk>
