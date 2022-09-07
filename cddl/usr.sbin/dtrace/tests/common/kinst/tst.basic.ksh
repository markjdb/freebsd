script()
{
	$dtrace -qs <<__EOF__
kinst::vm_fault: {}
kinst::amd64_syscall: {}
kinst::exit1: {}

tick-10s {exit(0);}
__EOF__
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
