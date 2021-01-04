#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2020 Klara, Inc.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

. $(atf_get_srcdir)/../common/vnet.subr

atf_test_case "nd6_prefix_flush" "cleanup"
nd6_prefix_flush_head()
{
        atf_set descr "Check that prefix flush removes only autoconf addresses"
        atf_set require.user root
        atf_set require.progs scapy
}

nd6_prefix_flush_body()
{
        local epair prefix prefixlen

        prefix=2001:db8:42
        prefixlen=64

        vnet_init

        epair=$(vnet_mkepair)
        vnet_mkjail nd6 ${epair}b

        ifconfig ${epair}a up
        ifconfig ${epair}a inet6 -ifdisabled

        jexec nd6 ifconfig ${epair}b up
        jexec nd6 ifconfig ${epair}b inet6 -ifdisabled accept_rtadv

        atf_check -s exit:0 \
            $(atf_get_srcdir)/nd6.py --sendif=${epair}a --dst=ff02::1 --src=fe80::1 \
                                     --prefix=${prefix}::${prefixlen}

        # Configure a static address on the same prefix.
        jexec nd6 ifconfig ${epair}b inet6 ${prefix}::1

        # Verify that a prefix and autoconfigured address were added.
        atf_check -s exit:0 \
            -e empty -o match:"^${prefix}::/${prefixlen} if=${epair}b" \
            jexec nd6 ndp -p
        atf_check -s exit:0 \
            -e empty -o match:"^[[:space:]]inet6 ${prefix}:.* prefixlen ${prefixlen} (tentative )?autoconf" \
            jexec nd6 ifconfig ${epair}b inet6

        # Purge learned prefixes and autoconfigured addresses.
        atf_check -s exit:0 jexec nd6 ndp -P

        atf_check -s exit:0 \
            -e empty -o not-match:"^${prefix}::/${prefixlen} if=${epair}b" \
            jexec nd6 ndp -p
        atf_check -s exit:0 \
            -e empty -o not-match:"^[[:space:]]inet6 ${prefix}:.* prefixlen ${prefixlen} (tentative )?autoconf" \
            jexec nd6 ifconfig ${epair}b inet6
}

nd6_prefix_flush_cleanup()
{
        vnet_cleanup
}

atf_init_test_cases()
{
        atf_add_test_case "nd6_prefix_flush"
}
