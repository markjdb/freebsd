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
	loaded="$(kldstat | grep 'dtrace_test')"

	# Don't attempt to load it if it was already loaded.
	test -n "${loaded}" || kldload dtrace_test

	$dtrace -q -n \
		'kinst::kinst_test_fbtconvert:entry,kinst::kinst_test_fbtconvert:return' \
		-c "sysctl debug.dtracetest.kinst=2"

	# If it wasn't loaded by us, don't unload it.
	test -n "${loaded}" || kldunload dtrace_test
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
