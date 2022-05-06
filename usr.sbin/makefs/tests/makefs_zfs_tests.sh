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
}
