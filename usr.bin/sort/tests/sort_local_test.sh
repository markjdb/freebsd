#-
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Copyright (c) 2022 Mark Johnston <markj@FreeBSD.org>
#

atf_test_case utf8stdin
utf8stdin_body()
{
	printf 'l\366st' > a
	printf 'löst\n' > b

	cat a | env LANG=en_US.UTF-8 sort > out 2>&1
	atf_check cmp b out
}

atf_test_case zflag
zflag_body()
{
	printf 'bab\0ab\0' > a

	atf_check -o inline:'ab\0bab\0' sort -z a

	atf_check -o inline:'bab\0ab\0\n' sort a
}

atf_init_test_cases()
{
	atf_add_test_case utf8stdin
	atf_add_test_case zflag
}
