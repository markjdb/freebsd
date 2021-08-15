#-
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Copyright (c) 2021 The FreeBSD Foundation
#
# This software was developed by Mark Johnston under sponsorship from
# the FreeBSD Foundation.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the distribution.
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
# Test case ideas:
# - various elements of syslog.conf selectors
# - hostname, program, property-based filters
# - actions: path name, hostname, users (can we implement this?), pipes
#
#

readonly SYSLOGD_PIDFILE=syslogd.pid
readonly SYSLOGD_LOCAL_SOCKET=log
readonly SYSLOGD_LOCAL_PRIVSOCKET=logpriv
readonly SYSLOGD_CONFIG=syslog.conf
readonly SYSLOGD_UDP_PORT=12345

# Start a private syslogd instance.
syslogd_start()
{
    syslogd \
        -b :$SYSLOGD_UDP_PORT \
        -P $(pwd)/$SYSLOGD_PIDFILE \
        -p $(pwd)/$SYSLOGD_LOCAL_SOCKET \
        -S $(pwd)/$SYSLOGD_LOCAL_PRIV_SOCKET \
        -f $(pwd)/$SYSLOGD_CONFIG \
        $@

    while [ ! -S $(pwd)/$SYSLOGD_LOCAL_SOCKET ]; do
        sleep 0.1
    done
}

# Simple logger(1) wrapper.
syslogd_log()
{
    atf_check -s exit:0 -o empty -e empty logger $*
}

# Stop a private syslogd instance.
syslogd_stop()
{
    local pid

    pid=$(cat $SYSLOGD_PIDFILE)
    if ! expr "$pid" : '[1-9][0-9]*' >/dev/null; then
        return
    fi

    kill $pid
    wait $pid

    rm -f $SYSLOGD_PIDFILE $SYSLOGD_LOCAL_SOCKET $SYSLOGD_LOCAL_PRIVSOCKET
}

atf_test_case "basic" "cleanup"
basic_head()
{
    atf_set descr 'Make sure we can log messages using supported transports'
}
basic_body()
{
    cat <<__EOF__ > $SYSLOGD_CONFIG
user.* $(pwd)/basic
__EOF__

    truncate -s 0 basic

    syslogd_start

    syslogd_log -p user.notice -t basic -h $(pwd)/$SYSLOGD_LOCAL_SOCKET \
        "hello, world (unix)"
    atf_check -s exit:0 -o match:'basic: hello, world \(unix\)' cat basic

    # XXXMJ how do we ensure that v4 and v6 are accessible?
    syslogd_log -4 -p user.notice -t basic -h 127.0.0.1 -P $SYSLOGD_UDP_PORT \
        "hello, world (v4)"
    atf_check -s exit:0 -o match:'basic: hello, world \(v4\)' cat basic

    syslogd_log -6 -p user.notice -t basic -h ::1 -P $SYSLOGD_UDP_PORT \
        "hello, world (v6)"
    atf_check -s exit:0 -o match:'basic: hello, world \(v6\)' cat basic
}
basic_cleanup()
{
    syslogd_stop
}

atf_init_test_cases()
{
    atf_add_test_case "basic"
}
