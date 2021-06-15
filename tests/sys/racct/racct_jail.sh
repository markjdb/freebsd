atf_test_case sysv_shm_count cleanup
sysv_shm_count_head()
{
	atf_set "require.user" "root"
}
sysv_shm_count_body()
{
}
sysv_shm_count_cleanup()
{
}

atf_init_test_cases()
{
	atf_add_test_case sysv_shm_count
}
