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
ZFS_POOL_NAME="makefstest$(jot -r 1 100000)"
TEST_ZFS_POOL_NAME="$TMPDIR/poolname"

. "$(dirname "$0")/makefs_tests_common.sh"

common_cleanup()
{
	sync

	zpool destroy "$(cat $TEST_ZFS_POOL_NAME)"
	mdconfig -d -u "$(cat $TEST_MD_DEVICE_FILE)"
}

import_image()
{
	atf_check -e empty -o save:$TEST_MD_DEVICE_FILE -s exit:0 \
	    mdconfig -a -f $TEST_IMAGE
	atf_check -e empty -o empty -s exit:0 \
	    zpool import -R $TEST_MOUNT_DIR $ZFS_POOL_NAME
	echo "$ZFS_POOL_NAME" > $TEST_ZFS_POOL_NAME
}

#
# Test with some default layout defined by the common code.
#
atf_test_case basic cleanup
basic_body()
{
	create_test_inputs

	atf_check -o empty -e empty -s exit:0 \
	    $MAKEFS -s 10g -o poolname=$ZFS_POOL_NAME $TEST_IMAGE $TEST_INPUTS_DIR

	import_image

	check_image_contents
}
basic_cleanup()
{
	common_cleanup
}

# Make sure that we can create and remove an empty directory.
atf_test_case empty_dir cleanup
empty_dir_body()
{
	create_test_dirs

	cd $TEST_INPUTS_DIR
	mkdir dir
	cd -

	atf_check -o empty -e empty -s exit:0 \
	    $MAKEFS -s 10g -o poolname=$ZFS_POOL_NAME $TEST_IMAGE $TEST_INPUTS_DIR

	import_image

	check_image_contents

	atf_check -s exit:0 rmdir ${TEST_MOUNT_DIR}/dir
}
empty_dir_cleanup()
{
	common_cleanup
}

atf_test_case file_sizes cleanup
file_sizes_body()
{
	local i

	create_test_dirs
	cd $TEST_INPUTS_DIR

	i=1
	while [ $i -lt $((1 << 20)) ]; do
		truncate -s $i ${i}.1
		truncate -s $(($i - 1)) ${i}.2
		truncate -s $(($i + 1)) ${i}.3
		i=$(($i << 1))
	done

	cd -

	# XXXMJ this creates sparse files, make sure makefs doesn't
	# preserve the sparseness.
        # XXXMJ try with different ashifts
	atf_check -o empty -e empty -s exit:0 \
	    $MAKEFS -s 10g -o poolname=$ZFS_POOL_NAME $TEST_IMAGE $TEST_INPUTS_DIR

	import_image

	check_image_contents
}
file_sizes_cleanup()
{
	common_cleanup
}

# Allocate enough dnodes from an object set that the meta dnode needs to use
# indirect blocks.
atf_test_case indirect_dnode_array cleanup
indirect_dnode_array_body()
{
	local i

	create_test_dirs
	cd $TEST_INPUTS_DIR
	# 512 bytes per dnode, 3*128KB of direct blocks => limit of 768 files.
        # XXXMJ actual threshold is much lower
	for i in $(seq 1 1000); do
		touch $i
	done
	cd -

	atf_check -o empty -e empty -s exit:0 \
	    $MAKEFS -s 10g -o poolname=$ZFS_POOL_NAME $TEST_IMAGE $TEST_INPUTS_DIR

	import_image

	check_image_contents
}
indirect_dnode_array_cleanup()
{
	common_cleanup
}

#
# Create some files with long names, so as to test fat ZAP handling.
#
atf_test_case long_file_name cleanup
long_file_name_body()
{
	local dir i

	create_test_dirs
	cd $TEST_INPUTS_DIR

	# micro ZAP keys can be at most 50 bytes.
	for i in $(seq 1 60); do
		touch $(jot -s '' $i 1 1)
	done
	dir=$(jot -s '' 61 1 1)
	mkdir $dir
	for i in $(seq 1 60); do
		touch ${dir}/$(jot -s '' $i 1 1)
	done

	cd -

	atf_check -o empty -e empty -s exit:0 \
	    $MAKEFS -s 10g -o poolname=$ZFS_POOL_NAME $TEST_IMAGE $TEST_INPUTS_DIR

	import_image

	check_image_contents

	# Add a directory entry in the hope that OpenZFS might catch a bug
	# in makefs' fat ZAP encoding.
	touch ${TEST_MOUNT_DIR}/foo
}
long_file_name_cleanup()
{
	common_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case basic
        atf_add_test_case empty_dir
	atf_add_test_case file_sizes
	atf_add_test_case indirect_dnode_array
	atf_add_test_case long_file_name

	# XXXMJ tests:
	# - empty filesystem
	# - create a snapshot of a filesystem
	# - create a long symlink target
	# - test with different ashifts (at least, 9), different image sizes
}
