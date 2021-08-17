# $FreeBSD$

ATF_TESTS_C+=	libctf_dwarf_test

CFLAGS+= -I${.CURDIR:H:H:H}/contrib/elftoolchain/libelftc
LIBADD=	ctf dwarf elf elftc

.include <bsd.test.mk>
