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
	atf_check -o not-empty -e empty -s exit:0 \
		$MAKEFS -s 10g -o poolname=$(mkpoolname) ./test.img .

	# XXXMJ mount the pool and verify
}

atf_init_test_cases()
{
	atf_add_test_case file_sizes
        # XXXMJ add test case for long file names (to verify fat zap handling)

}
