# $FreeBSD$

PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/netmap
TEST_METADATA+=	required_user="root"
TEST_METADATA+=	is_exclusive=true

PLAIN_TESTS_C+=	ctrl-api-test

CFLAGS+=	-I${SRCTOP}/tests
LIBADD+= 	pthread
LIBADD+= 	netmap

TESTS_SUBDIRS+=	ifnet

.include <bsd.test.mk>
