# $FreeBSD$

PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/netinet6
FILESDIR=	${TESTSDIR}

ATF_TESTS_SH=	divert \
		exthdr \
		fibs6 \
		forward6 \
		lpm6 \
		mld \
		nd6 \
		output6 \
		redirect \
		scapyi386
TEST_METADATA.output6+=	required_programs="python"

${PACKAGE}FILES+=	exthdr.py
${PACKAGE}FILES+=	mld.py
${PACKAGE}FILES+=	nd6.py
${PACKAGE}FILES+=	scapyi386.py
${PACKAGE}FILES+=	redirect.py

${PACKAGE}FILESMODE_exthdr.py=	0555
${PACKAGE}FILESMODE_mld.py=	0555
${PACKAGE}FILESMODE_nd6.py=	0555
${PACKAGE}FILESMODE_scapyi386.py=0555
${PACKAGE}FILESMODE_redirect.py=0555

TESTS_SUBDIRS+=	frag6

.include <bsd.test.mk>
