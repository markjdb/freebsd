/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright(c) 2007 - 2021 Intel Corporation */
/* $FreeBSD$ */
#ifndef _QAT_OCF_UTILS_H_
#define _QAT_OCF_UTILS_H_

#include <opencrypto/cryptodev.h>
#include "qat_ocf_mem_pool.h"

static inline CpaBoolean
is_gmac_exception(const struct crypto_session_params *csp)
{
	if (CSP_MODE_DIGEST == csp->csp_mode)
		if (CRYPTO_AES_NIST_GMAC == csp->csp_auth_alg)
			return CPA_TRUE;

	return CPA_FALSE;
}

static inline CpaBoolean
is_sep_aad_supported(const struct crypto_session_params *csp)
{
	if (CPA_TRUE == is_gmac_exception(csp))
		return CPA_FALSE;

	if (CSP_MODE_AEAD == csp->csp_mode) {
		if (CRYPTO_AES_NIST_GCM_16 == csp->csp_cipher_alg ||
		    CRYPTO_AES_NIST_GMAC == csp->csp_cipher_alg) {
			return CPA_TRUE;
		}
	}

	return CPA_FALSE;
}

static inline CpaBoolean
is_use_sep_digest(const struct crypto_session_params *csp)
{
	/* Use separated digest for all digest/hash operations,
	 * including GMAC */
	if (CSP_MODE_DIGEST == csp->csp_mode) {
		return CPA_TRUE;
	}

	return CPA_FALSE;
}

#endif /* _QAT_OCF_UTILS_H_ */
