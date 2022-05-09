#-
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Copyright (c) 2022 The FreeBSD Foundation
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

MAKEFS="makefs -t zfs"

. "$(dirname "$0")/makefs_tests_common.sh"

mkpoolname()
{
	echo "makefstest.$(jot -r 1 100000)"
}

atf_test_case file_sizes
file_sizes_body()
{
	local i

	i=1
	while [ $i -lt $((1 << 20)) ]; do
		truncate -s $i ${i}.1
		truncate -s $(($i - 1)) ${i}.2
		truncate -s $(($i + 1)) ${i}.3
		i=$(($i << 1))
	done

	# XXXMJ this creates sparse files, make sure makefs doesn't
	# preserve the sparseness.
        # XXXMJ try with different ashifts
	atf_check -o empty -e empty -s exit:0 \
		$MAKEFS -s 10g -o poolname=$(mkpoolname) ./test.img .

	# XXXMJ mount the pool and verify
}

# Allocate enough dnodes from an object set that the meta dnode needs to use
# indirect blocks.
atf_test_case indirect_dnode_array
indirect_dnode_array_body()
{
	# 512 bytes per dnode, 3*128KB of direct blocks => limit of 768 files.
	for i in $(seq 1 1000); do
		touch $i
	done

	atf_check -o empty -e empty -s exit:0 \
		$MAKEFS -s 10g -o poolname=$(mkpoolname) ./test.img .

	# XXXMJ mount the pool and verify
}

atf_test_case long_file_name
long_file_name_body()
{
	local f1 f2

	# The maximum name length for a microzap entry is 50.
	f1=$(jot -s '' 60 1 1)
	f2=1

	touch $f1 $f2

	atf_check -o not-empty -e empty -s exit:0 \
		$MAKEFS -s 10g -o poolname=$(mkpoolname) ./test.img .

	# XXXMJ mount the pool and verify
}

atf_init_test_cases()
{
	atf_add_test_case file_sizes
	atf_add_test_case indirect_dnode_array
	atf_add_test_case long_file_name

        # XXXMJ tests:
        # - empty directory (empty ZAP handling)
        # - create a snapshot of a filesystem
        # - create a long symlink target
        # - test with different ashifts (at least, 9)
        # - large fat ZAP directory
}
