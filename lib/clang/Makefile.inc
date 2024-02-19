.include <src.opts.mk>

PACKAGE=	clang

.if ${MK_MSAN} == "yes"
# Build only PIE static libraries; bsd.lib.mk does not support this directly.
CFLAGS+=	${PIEFLAG} ${SHARED_CFLAGS}
CXXFLAGS+=	${PIEFLAG} ${SHARED_CXXFLAGS}
.else
MK_PIE:=	no	# Explicit libXXX.a references
.endif

.if ${MK_LLVM_FULL_DEBUGINFO} == "no"
.if ${COMPILER_TYPE} == "clang"
DEBUG_FILES_CFLAGS= -gline-tables-only
.else
DEBUG_FILES_CFLAGS= -g1
.endif
.endif

WARNS?=		0
