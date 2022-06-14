/*
 * SPDX-License-Identifier: CDDL 1.0
 */
#ifndef _EXTERN_H_
#define _EXTERN_H_

#define KINST_LOG_HELPER(fmt, ...) \
	printf("%s:%d: " fmt "%s\n", __func__, __LINE__, __VA_ARGS__)
#define KINST_LOG(...) \
	KINST_LOG_HELPER(__VA_ARGS__, "")

#ifdef __amd64__
#define KINST_PATCHVAL	0xcc
#else
#define KINST_PATCHVAL	0xf0
#endif /* __amd64__ */

typedef uint8_t kinst_patchval_t;

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_KINST);
#endif /* MALLOC_DECLARE */

#endif /* _EXTERN_H_ */
