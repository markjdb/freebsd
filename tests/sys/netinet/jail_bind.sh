#!/usr/bin/env atf-sh
#-
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2023 Mark Johnston <markj@FreeBSD.org>
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

#
# Test connection handling with classic jails.  This exercises the inpcb
# lookup code in the kernel, which must how to handle incoming connections
# when multiple listeners are present.
#
# Each test case creates a vnet jail containing one or more classic jails.
# The vnet jail's lo0 interface is assigned a set of addresses, and the
# child jails inherit some of those addresses.  Then we use nc(1) to listen
# on port 4242 both in and outside the classic jails and verify that the
# kernel routes incoming connections to the right place.
#

_listen()
{
	local af jname port addr outf pid

	af=$1
	jname=$2
	cjname=$3
	addr=$4
	port=$5
	outf=$6

	if [ "$addr" = "wild" ]; then
		addr=""
	fi
	if [ "$cjname" != "none" ]; then
		cjname="jexec $cjname"
	else
		cjname=""
	fi

	jexec $jname $cjname nc $af -k -l $addr $port > $outf 2>&1 &
	pid=$!
	# Give nc(1) a bit of time to bind.
	sleep 0.1
	echo $pid
}

listen4()
{
	_listen -4 $*
}

listen6()
{
	_listen -6 $*
}

stop_listen()
{
	atf_check kill $@
	wait $@
}

# Create the parent jail and initialize it.  This should be called once per
# test case.
make_parent_jail()
{
	local jname

	jname=${1}; shift
	atf_check jail -c name=$jname children.max=8 vnet persist $@
	atf_check jexec $jname ifconfig lo0 inet 127.0.0.1
	atf_check jexec $jname ifconfig lo0 alias 127.0.0.2
	atf_check jexec $jname ifconfig lo0 alias 127.0.0.3
	atf_check jexec $jname ifconfig lo0 alias 127.0.0.4

	atf_check jexec $jname ifconfig lo0 inet6 fc00::1
	atf_check jexec $jname ifconfig lo0 inet6 fc00::2
	atf_check jexec $jname ifconfig lo0 inet6 fc00::3
	atf_check jexec $jname ifconfig lo0 inet6 fc00::4
}

# Create a classic jail within the main vnet jail for the test.
make_classic_jail()
{
	local pjname jname

	pjname=${1}; shift
	jname=${1}; shift
	atf_check jexec $pjname jail -c name=$jname persist $@
}

atf_test_case "single_ip4" "cleanup"
single_ip4_head()
{
	atf_set descr "Check handling of IPv4 in a jail with one address"
	atf_set require.user root
}
single_ip4_body()
{
	local nc1 nc2

	make_parent_jail single_ip4

	make_classic_jail single_ip4 foo ip4.addr=127.0.0.2

	# Don't specify an address to bind to.  The jailed socket will get
	# precedence because the address will be rewritten for single-IP jails.
	nc1=$(listen4 single_ip4 none wild 4242 nc1.out)
	nc2=$(listen4 single_ip4 foo wild 4242 nc2.out)
	echo 123 | jexec single_ip4 nc -N 127.0.0.1 4242
	echo 456 | jexec single_ip4 nc -N 127.0.0.2 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"123\n" cat nc1.out
	atf_check -o inline:"456\n" cat nc2.out
	# Same test again, but bind in the other order.
	nc2=$(listen4 single_ip4 foo wild 4242 nc2.out)
	nc1=$(listen4 single_ip4 none wild 4242 nc1.out)
	echo 123 | jexec single_ip4 nc -N 127.0.0.1 4242
	echo 456 | jexec single_ip4 nc -N 127.0.0.2 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"123\n" cat nc1.out
	atf_check -o inline:"456\n" cat nc2.out

	# Bind to the jail address.  The jailed socket should receive the
	# connection.
	nc1=$(listen4 single_ip4 foo 127.0.0.2 4242 nc1.out)
	nc2=$(listen4 single_ip4 none 127.0.0.2 4242 nc2.out)
	echo 123 | jexec single_ip4 nc -N 127.0.0.2 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"123\n" cat nc1.out
	# Same test again, but bind in the other order.
	nc2=$(listen4 single_ip4 none 127.0.0.2 4242 nc2.out)
	nc1=$(listen4 single_ip4 foo 127.0.0.2 4242 nc1.out)
	echo 123 | jexec single_ip4 nc -N 127.0.0.2 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"123\n" cat nc1.out
}
single_ip4_cleanup()
{
	jexec single_ip4 jail -r foo
	jail -r single_ip4
}

atf_test_case "single_ip6" "cleanup"
single_ip6_head()
{
	atf_set descr "Check handling of IPv6 in a jail with one address"
	atf_set require.user root
}
single_ip6_body()
{
	local nc1 nc2

	make_parent_jail single_ip6

	make_classic_jail single_ip6 foo ip6.addr=fc00::2

	# Don't specify an address to bind to.  The jailed socket will get
	# precedence because the address will be rewritten for single-IP jails.
	nc1=$(listen6 single_ip6 none wild 4242 nc1.out)
	nc2=$(listen6 single_ip6 foo wild 4242 nc2.out)
	echo 123 | jexec single_ip6 nc -N fc00::1 4242
	echo 456 | jexec single_ip6 nc -N fc00::2 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"123\n" cat nc1.out
	atf_check -o inline:"456\n" cat nc2.out
	# Same test again, but bind in the other order.
	nc2=$(listen6 single_ip6 foo wild 4242 nc2.out)
	nc1=$(listen6 single_ip6 none wild 4242 nc1.out)
	echo 123 | jexec single_ip6 nc -N fc00::1 4242
	echo 456 | jexec single_ip6 nc -N fc00::2 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"123\n" cat nc1.out
	atf_check -o inline:"456\n" cat nc2.out

	# Bind to the jail address.  The jailed socket should receive the
	# connection.
	nc1=$(listen6 single_ip6 foo fc00::2 4242 nc1.out)
	nc2=$(listen6 single_ip6 none fc00::2 4242 nc2.out)
	echo 123 | jexec single_ip6 nc -N fc00::2 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"123\n" cat nc1.out
	# Same test again, but bind in the other order.
	nc2=$(listen6 single_ip6 none fc00::2 4242 nc2.out)
	nc1=$(listen6 single_ip6 foo fc00::2 4242 nc1.out)
	echo 123 | jexec single_ip6 nc -N fc00::2 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"123\n" cat nc1.out
}
single_ip6_cleanup()
{
	jexec single_ip6 jail -r foo
	jail -r single_ip6
}

atf_test_case "multi_ip4" "cleanup"
multi_ip4_head()
{
	atf_set descr "Check handling of IPv4 in a jail with multiple addresses"
	atf_set require.user root
}
multi_ip4_body()
{
	local nc1 nc2

	make_parent_jail multi_ip4

	make_classic_jail multi_ip4 foo ip4.addr=127.0.0.2,127.0.0.3

        # Jailed non-wildcard sockets are preferred over jailed wildcard
        # sockets.
	nc1=$(listen4 multi_ip4 foo 127.0.0.2 4242 nc1.out)
	nc2=$(listen4 multi_ip4 foo wild 4242 nc2.out)
	echo 123 | jexec multi_ip4 nc -N 127.0.0.1 4242 # Dropped.
	echo 456 | jexec multi_ip4 nc -N 127.0.0.2 4242
	echo 789 | jexec multi_ip4 nc -N 127.0.0.3 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"456\n" cat nc1.out
        atf_check -o inline:"789\n" cat nc2.out
	# Same test again, but bind in the other order.
	nc2=$(listen4 multi_ip4 foo wild 4242 nc2.out)
	nc1=$(listen4 multi_ip4 foo 127.0.0.2 4242 nc1.out)
	echo 123 | jexec multi_ip4 nc -N 127.0.0.1 4242 # Dropped.
	echo 456 | jexec multi_ip4 nc -N 127.0.0.2 4242
	echo 789 | jexec multi_ip4 nc -N 127.0.0.3 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"456\n" cat nc1.out
        atf_check -o inline:"789\n" cat nc2.out

        # A wildcard socket in the jail is preferred over a non-wildcard socket
        # on the host.
	nc1=$(listen4 multi_ip4 foo wild 4242 nc1.out)
	nc2=$(listen4 multi_ip4 none 127.0.0.2 4242 nc2.out)
	echo 123 | jexec multi_ip4 nc -N 127.0.0.1 4242 # Dropped.
	echo 456 | jexec multi_ip4 nc -N 127.0.0.2 4242
	echo 789 | jexec multi_ip4 nc -N 127.0.0.3 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"456\n789\n" cat nc1.out
	# Same test again, but bind in the other order.
	nc2=$(listen4 multi_ip4 none 127.0.0.2 4242 nc2.out)
	nc1=$(listen4 multi_ip4 foo wild 4242 nc1.out)
	echo 123 | jexec multi_ip4 nc -N 127.0.0.1 4242 # Dropped.
	echo 456 | jexec multi_ip4 nc -N 127.0.0.2 4242
	echo 789 | jexec multi_ip4 nc -N 127.0.0.3 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"456\n789\n" cat nc1.out

	# If two sockets are bound to the same address, the jailed socket is
	# preferred.
	nc1=$(listen4 multi_ip4 foo 127.0.0.2 4242 nc1.out)
	nc2=$(listen4 multi_ip4 none 127.0.0.2 4242 nc2.out)
	echo 123 | jexec multi_ip4 nc -N 127.0.0.1 4242 # Dropped.
	echo 456 | jexec multi_ip4 nc -N 127.0.0.2 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"456\n" cat nc1.out
	atf_check -o empty cat nc2.out
	# Same test again, but bind in the other order.
	nc2=$(listen4 multi_ip4 none 127.0.0.2 4242 nc2.out)
	nc1=$(listen4 multi_ip4 foo 127.0.0.2 4242 nc1.out)
	echo 123 | jexec multi_ip4 nc -N 127.0.0.1 4242 # Dropped.
	echo 456 | jexec multi_ip4 nc -N 127.0.0.2 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"456\n" cat nc1.out
	atf_check -o empty cat nc2.out

	# A jailed socket with a specified address is preferred to a non-jailed
	# wildcard socket.
	nc1=$(listen4 multi_ip4 foo 127.0.0.3 4242 nc1.out)
	nc2=$(listen4 multi_ip4 none wild 4242 nc2.out)
	echo 123 | jexec multi_ip4 nc -N 127.0.0.1 4242
	echo 456 | jexec multi_ip4 nc -N 127.0.0.2 4242
	echo 789 | jexec multi_ip4 nc -N 127.0.0.3 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"789\n" cat nc1.out
	atf_check -o inline:"123\n456\n" cat nc2.out
	# Same test again, but bind in the other order.
	nc2=$(listen4 multi_ip4 none wild 4242 nc2.out)
	nc1=$(listen4 multi_ip4 foo 127.0.0.3 4242 nc1.out)
	echo 123 | jexec multi_ip4 nc -N 127.0.0.1 4242
	echo 456 | jexec multi_ip4 nc -N 127.0.0.2 4242
	echo 789 | jexec multi_ip4 nc -N 127.0.0.3 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"789\n" cat nc1.out
	atf_check -o inline:"123\n456\n" cat nc2.out

	# Make sure that we can reach the jailed socket if nothing in the
	# parent has bound to the same port.
	nc1=$(listen4 multi_ip4 foo wild 4242 nc1.out)
	echo 123 | jexec multi_ip4 nc -N 127.0.0.1 4242 # Dropped.
	echo 456 | jexec multi_ip4 nc -N 127.0.0.2 4242
	echo 789 | jexec multi_ip4 nc -N 127.0.0.3 4242
	stop_listen $nc1
	atf_check -o inline:"456\n789\n" cat nc1.out
}
multi_ip4_cleanup()
{
	jail -r multi_ip4
}

atf_test_case "multi_ip6" "cleanup"
multi_ip6_head()
{
	atf_set descr "Check handling of IPv6 in a jail with multiple addresses"
	atf_set require.user root
}
multi_ip6_body()
{
	local nc1 nc2

	make_parent_jail multi_ip6

	make_classic_jail multi_ip6 foo ip6.addr=fc00::2,fc00::3

        # Jailed non-wildcard sockets are preferred over jailed wildcard
        # sockets.
	nc1=$(listen6 multi_ip6 foo fc00::2 4242 nc1.out)
	nc2=$(listen6 multi_ip6 foo wild 4242 nc2.out)
	echo 123 | jexec multi_ip6 nc -N fc00::1 4242 # Dropped.
	echo 456 | jexec multi_ip6 nc -N fc00::2 4242
	echo 789 | jexec multi_ip6 nc -N fc00::3 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"456\n" cat nc1.out
        atf_check -o inline:"789\n" cat nc2.out
	# Same test again, but bind in the other order.
	nc2=$(listen6 multi_ip6 foo wild 4242 nc2.out)
	nc1=$(listen6 multi_ip6 foo fc00::2 4242 nc1.out)
	echo 123 | jexec multi_ip6 nc -N fc00::1 4242 # Dropped.
	echo 456 | jexec multi_ip6 nc -N fc00::2 4242
	echo 789 | jexec multi_ip6 nc -N fc00::3 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"456\n" cat nc1.out
        atf_check -o inline:"789\n" cat nc2.out

        # A wildcard socket in the jail is preferred over a non-wildcard socket
        # on the host.
	nc1=$(listen6 multi_ip6 foo wild 4242 nc1.out)
	nc2=$(listen6 multi_ip6 none fc00::2 4242 nc2.out)
	echo 123 | jexec multi_ip6 nc -N fc00::1 4242 # Dropped.
	echo 456 | jexec multi_ip6 nc -N fc00::2 4242
	echo 789 | jexec multi_ip6 nc -N fc00::3 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"456\n789\n" cat nc1.out
	# Same test again, but bind in the other order.
	nc2=$(listen6 multi_ip6 none fc00::2 4242 nc2.out)
	nc1=$(listen6 multi_ip6 foo wild 4242 nc1.out)
	echo 123 | jexec multi_ip6 nc -N fc00::1 4242 # Dropped.
	echo 456 | jexec multi_ip6 nc -N fc00::2 4242
	echo 789 | jexec multi_ip6 nc -N fc00::3 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"456\n789\n" cat nc1.out

	# If two sockets are bound to the same address, the jailed socket is
	# preferred.
	nc1=$(listen6 multi_ip6 foo fc00::2 4242 nc1.out)
	nc2=$(listen6 multi_ip6 none fc00::2 4242 nc2.out)
	echo 123 | jexec multi_ip6 nc -N fc00::1 4242 # Dropped.
	echo 456 | jexec multi_ip6 nc -N fc00::2 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"456\n" cat nc1.out
	atf_check -o empty cat nc2.out
	# Same test again, but bind in the other order.
	nc2=$(listen6 multi_ip6 none fc00::2 4242 nc2.out)
	nc1=$(listen6 multi_ip6 foo fc00::2 4242 nc1.out)
	echo 123 | jexec multi_ip6 nc -N fc00::1 4242 # Dropped.
	echo 456 | jexec multi_ip6 nc -N fc00::2 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"456\n" cat nc1.out
	atf_check -o empty cat nc2.out

	# A jailed socket with a specified address is preferred to a non-jailed
	# wildcard socket.
	nc1=$(listen6 multi_ip6 foo fc00::3 4242 nc1.out)
	nc2=$(listen6 multi_ip6 none wild 4242 nc2.out)
	echo 123 | jexec multi_ip6 nc -N fc00::1 4242
	echo 456 | jexec multi_ip6 nc -N fc00::2 4242
	echo 789 | jexec multi_ip6 nc -N fc00::3 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"789\n" cat nc1.out
	atf_check -o inline:"123\n456\n" cat nc2.out
	# Same test again, but bind in the other order.
	nc2=$(listen6 multi_ip6 none wild 4242 nc2.out)
	nc1=$(listen6 multi_ip6 foo fc00::3 4242 nc1.out)
	echo 123 | jexec multi_ip6 nc -N fc00::1 4242
	echo 456 | jexec multi_ip6 nc -N fc00::2 4242
	echo 789 | jexec multi_ip6 nc -N fc00::3 4242
	stop_listen $nc1 $nc2
	atf_check -o inline:"789\n" cat nc1.out
	atf_check -o inline:"123\n456\n" cat nc2.out

	# Make sure that we can reach the jailed socket if nothing in the
	# parent has bound to the same port.
	nc1=$(listen6 multi_ip6 foo wild 4242 nc1.out)
	echo 123 | jexec multi_ip6 nc -N fc00::1 4242 # Dropped.
	echo 456 | jexec multi_ip6 nc -N fc00::2 4242
	echo 789 | jexec multi_ip6 nc -N fc00::3 4242
	stop_listen $nc1
	atf_check -o inline:"456\n789\n" cat nc1.out
}
multi_ip6_cleanup()
{
	jail -r multi_ip6
}

atf_test_case "wild_match_ip4" "cleanup"
wild_match_ip4_head()
{
	atf_set descr "Check handling of IPv4 wild-card addresses"
	atf_set require.user root
}
wild_match_ip4_body()
{
	local nc1 nc2

	make_parent_jail wild_match_ip4

	# The socket with a specified local address gets precedence over
	# a wildcard match.
	nc1=$(listen4 wild_match_ip4 none 127.0.0.1 4242 nc1.out)
	nc2=$(listen4 wild_match_ip4 none wild 4242 nc2.out)
	echo 123 | jexec wild_match_ip4 nc -N 127.0.0.1 4242
	echo 456 | jexec wild_match_ip4 nc -N 127.0.0.2 4242
	atf_check kill $nc1 $nc2
	atf_check -o inline:"123\n" cat nc1.out
	atf_check -o inline:"456\n" cat nc2.out
	# Same test again, but bind in the other order.
	nc2=$(listen4 wild_match_ip4 none wild 4242 nc2.out)
	nc1=$(listen4 wild_match_ip4 none 127.0.0.1 4242 nc1.out)
	echo 123 | jexec wild_match_ip4 nc -N 127.0.0.1 4242
	echo 456 | jexec wild_match_ip4 nc -N 127.0.0.2 4242
	atf_check kill $nc1 $nc2
	atf_check -o inline:"123\n" cat nc1.out
	atf_check -o inline:"456\n" cat nc2.out
}
wild_match_ip4_cleanup()
{
	jail -r wild_match_ip4
}

atf_test_case "wild_match_ip6" "cleanup"
wild_match_ip6_head()
{
	atf_set descr "Check handling of IPv6 wild-card addresses"
	atf_set require.user root
}
wild_match_ip6_body()
{
	local nc1 nc2

	make_parent_jail wild_match_ip6

	# The socket with a specified local address gets precedence over
	# a wildcard match.
	nc1=$(listen6 wild_match_ip6 none fc00::1 4242 nc1.out)
	nc2=$(listen6 wild_match_ip6 none wild 4242 nc2.out)
	echo 123 | jexec wild_match_ip6 nc -N fc00::1 4242
	echo 456 | jexec wild_match_ip6 nc -N fc00::2 4242
	atf_check kill $nc1 $nc2
	atf_check -o inline:"123\n" cat nc1.out
	atf_check -o inline:"456\n" cat nc2.out
	# Same test again, but bind in the other order.
	nc2=$(listen6 wild_match_ip6 none wild 4242 nc2.out)
	nc1=$(listen6 wild_match_ip6 none fc00::1 4242 nc1.out)
	echo 123 | jexec wild_match_ip6 nc -N fc00::1 4242
	echo 456 | jexec wild_match_ip6 nc -N fc00::2 4242
	atf_check kill $nc1 $nc2
	atf_check -o inline:"123\n" cat nc1.out
	atf_check -o inline:"456\n" cat nc2.out
}
wild_match_ip6_cleanup()
{
	jail -r wild_match_ip6
}

atf_init_test_cases()
{
	atf_add_test_case "single_ip4"
	atf_add_test_case "single_ip6"
	atf_add_test_case "multi_ip4"
	atf_add_test_case "multi_ip6"
	atf_add_test_case "wild_match_ip4"
	atf_add_test_case "wild_match_ip6"
}
