#!/usr/bin/ksh
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2023 Christos Margiolis <christos@FreeBSD.org>
#

script()
{
	kldload dtrace_test
	$dtrace -q -n \
		'kinst::kinst_test_inline:entry,kinst::kinst_test_inline:return' \
		-c "sysctl debug.dtracetest.kinst=1"
	kldunload dtrace_test
}

spin()
{
	while true; do
		ls -la / >/dev/null 2>&1
	done
}

if [ $# != 1 ]; then
	echo expected one argument: '<'dtrace-path'>'
	exit 2
fi

dtrace=$1

spin &
child=$!

script
exit $?
