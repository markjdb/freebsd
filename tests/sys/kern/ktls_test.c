/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 The FreeBSD Foundation
 *
 * This software was developed by Mark Johnston under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/ktls.h>
#include <sys/socket.h>

#include <crypto/cryptodev.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <errno.h>

#include <atf-c.h>

#define	FMT_ERR(s)		s ": %s", strerror(errno)

/* XXX need to load a module */
/* XXX need to save/restore the kern.ipc.tls.enable sysctl */
ATF_TC_WITH_CLEANUP(ktls_sendto_baddst);
ATF_TC_HEAD(ktls_sendto_baddst, tc)
{
	atf_tc_set_md_var(tc, "require.config", "allow_sysctl_side_effects");
}
ATF_TC_BODY(ktls_sendto_baddst, tc)
{
	struct tls_enable tls;
	struct sockaddr_in sin;
	char akey[SHA1_BLOCK_LEN], ckey[16], buf[128];
	ssize_t n;
	int error, sd;

	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ATF_REQUIRE_MSG(sd >= 0, FMT_ERR("socket"));

	memset(akey, 0, sizeof(akey));
	memset(ckey, 0, sizeof(ckey));

	memset(&tls, 0, sizeof(tls));
	tls.cipher_key = ckey;
	tls.iv = NULL;
	tls.auth_key = akey;
	tls.cipher_algorithm = CRYPTO_AES_CBC;
	tls.cipher_key_len = sizeof(ckey);
	tls.iv_len = 0;
	tls.auth_algorithm = CRYPTO_SHA1_HMAC;
	tls.auth_key_len = sizeof(akey);
	tls.flags = 0;
	tls.tls_vmajor = TLS_MAJOR_VER_ONE;
	tls.tls_vminor = TLS_MINOR_VER_TWO;

	error = setsockopt(sd, IPPROTO_TCP, TCP_TXTLS_ENABLE, &tls, sizeof(tls));
	ATF_REQUIRE_MSG(error == 0, FMT_ERR("setsockopt"));

	memset(buf, 0, sizeof(buf));
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
	sin.sin_port = htons(12345);

	n = sendto(sd, buf, sizeof(buf), 0, (struct sockaddr *)&sin,
	    sizeof(sin));
	ATF_REQUIRE_ERRNO(EACCES, n == -1);

	ATF_REQUIRE_MSG(close(sd) == 0, FMT_ERR("close"));
}
ATF_TC_CLEANUP(ktls_sendto_baddst, tc)
{
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, ktls_sendto_baddst);
	return (atf_no_error());
}
