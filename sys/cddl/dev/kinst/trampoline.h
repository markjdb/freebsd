/*
 * SPDX-License-Identifier: CDDL 1.0
 */
#ifndef _TRAMPOLINE_H_
#define _TRAMPOLINE_H_

uint8_t	*kinst_trampoline_alloc(void);
void	kinst_trampoline_dealloc(uint8_t *);

#endif /* _TRAMPOLINE_H_ */
