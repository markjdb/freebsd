.include <src.opts.mk>

SUBDIR=		dso

.if ${MK_MSAN} != "yes"
TESTS_SUBDIRS=	dynamic
.endif
TESTS_SUBDIRS+=	dynamiclib
TESTS_SUBDIRS+=	dynamicpie
.if ${MK_MSAN} != "yes"
TESTS_SUBDIRS+=	static
.endif

SUBDIR_DEPEND_dynamiclib=dso

.include <bsd.test.mk>
