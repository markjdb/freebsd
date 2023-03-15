# Copyright (c) 2023 Klara, Inc.

#
# Test basic netmap functionality with software interfaces.
#
# Two netmap applications are used: pkt-gen, and a simplified version of bridge
# which reports the number of packets forwarded in each direction.
#

. $(atf_get_srcdir)/../../common/vnet.subr

PKTGEN=$(atf_get_srcdir)/pkt-gen
NMBRIDGE=$(atf_get_srcdir)/simplebridge
BRIDGEPIDFILE=bridge.pid

# Start a process that forwards packets between two interfaces in netmap mode.
join_interfaces()
{
	local jail ifa ifb outf

	jail=$1
	ifa=$2
	ifb=$3
	outf=$4

	jexec $jail $NMBRIDGE -i $ifa -i $ifb >$outf 2>&1 &
	echo $! > $BRIDGEPIDFILE
	sleep 1 # Let the netmap program initialize itself.
}

# Stop a bridge process previously started by join_interfaces().
unjoin_interfaces()
{
	atf_check pkill -INT -F $BRIDGEPIDFILE
	atf_check rm $BRIDGEPIDFILE
}

# Return the ethernet address of the specified interface.
iface_etheraddr()
{
	local jail iface

	jail=$1
	iface=$2

	jexec $jail ifconfig $iface ether | awk '/ether/{print $2}'
}

#
# Verify that a netmap-enabled if_bridge interface can forward packets between
# interfaces.
#
atf_test_case "bridge_l2_forwarding" "cleanup"
bridge_l2_forwarding_head()
{
	atf_set descr 'Make sure that L2 forwarding works in netmap mode'
	atf_set require.user root
}
bridge_l2_forwarding_body()
{
	vnet_init

	epair_left=$(vnet_mkepair)
	epair_right=$(vnet_mkepair)
	bridge=$(vnet_mkbridge)

	vnet_mkjail bridge ${bridge} ${epair_left}b ${epair_right}b
	vnet_mkjail left ${epair_left}a
	vnet_mkjail right ${epair_right}a

	jexec bridge ifconfig ${epair_left}b up
	jexec bridge ifconfig ${epair_right}b up
	jexec bridge ifconfig ${bridge} up addm ${epair_left}b addm ${epair_right}b

	jexec left ifconfig ${epair_left}a inet 169.254.0.1/16
	jexec right ifconfig ${epair_right}a inet 169.254.0.2/16

	# Let the endpoints communicate without needing to ARP.
	macleft=$(iface_etheraddr left ${epair_left}a)
	jexec right arp -s 169.254.0.1 $macleft
	macright=$(iface_etheraddr right ${epair_right}a)
	jexec left arp -s 169.254.0.2 $macright

	join_interfaces bridge netmap:${bridge} netmap:${bridge}^ pktcount

	# Send five pings from each end to the other.
	atf_check -o ignore jexec left ping -i 0.2 -t 3 -c 5 169.254.0.2
	atf_check -o ignore jexec right ping -i 0.2 -t 3 -c 5 169.254.0.1

	unjoin_interfaces

	# The pings above should generate 10 echo requests and 10 echo replies,
	# so we should have 20 packets arrive on the bridge, and we don't expect
	# to see any packets transmitted from the bridge host.
	atf_check -o match:"[[:space:]]1 pktcount" wc -l pktcount
	atf_check -o inline:'20 0\n' cat pktcount
}
bridge_l2_forwarding_cleanup()
{
	vnet_cleanup
}

#
# Verify that a netmap-enabled if_bridge interface can receive packets locally.
#
atf_test_case "bridge_l3" "cleanup"
bridge_l3_head()
{
	atf_set descr 'Test that a bridge interface can receive packets locally in netmap mode'
	atf_set require.user root
}
bridge_l3_body()
{
	vnet_init

	epair=$(vnet_mkepair)
	bridge=$(vnet_mkbridge)

	vnet_mkjail bridge ${bridge} ${epair}b
	vnet_mkjail host ${epair}a

	jexec bridge ifconfig ${epair}b up
	jexec bridge ifconfig ${bridge} up addm ${epair}b
	jexec bridge ifconfig ${bridge} inet 169.254.0.2/16

	jexec host ifconfig ${epair}a inet 169.254.0.1/16

	machost=$(iface_etheraddr host ${epair}a)
	jexec bridge arp -s 169.254.0.1 $machost
	macbridge=$(iface_etheraddr bridge ${bridge})
	jexec host arp -s 169.254.0.2 $macbridge

	join_interfaces bridge netmap:${bridge} netmap:${bridge}^ pktcount

	# Send five pings from each end to the other.
	atf_check -o ignore jexec host ping -i 0.2 -t 3 -c 5 169.254.0.2
	atf_check -o ignore jexec bridge ping -i 0.2 -t 3 -c 5 169.254.0.1

	unjoin_interfaces

	# The pings above should generate 10 echo requests and 10 echo replies.
	# We should see 10 packets arrive on the bridge, and 10 packets sent via
	# the bridge.
	atf_check -o match:"[[:space:]]1 pktcount" wc -l pktcount
	atf_check -o inline:'10 10\n' cat pktcount
}
bridge_l3_cleanup()
{
	vnet_cleanup
}

#
# Use netmap to transfer packets over an epair.
#
atf_test_case "epair_simple" "cleanup"
epair_simple_head()
{
	atf_set descr 'Test epair interfaces can be used in netmap mode'
	atf_set require.user root
	atf_set timeout 10
}
epair_simple_body()
{
	vnet_init

	epair=$(vnet_mkepair)

	ifconfig ${epair}a up
	ifconfig ${epair}b up

	pkt-gen -i netmap:${epair}a -f rx -n 100000 &
	sleep 1 # Give pkt-gen a chance to start.

	atf_check -o ignore -e ignore pkt-gen -i netmap:${epair}b -f tx -n 100000

	wait
}
epair_simple_cleanup()
{
	vnet_cleanup
}

#
# Verify that pkt-gen can transfer packets over a tunnel.
#
atf_test_case "tun_simple" "cleanup"
tun_simple_head()
{
	atf_set descr 'Test that tun interfaces can be used in netmap mode'
	atf_set require.user root
}
tun_simple_body()
{
	vnet_init

	epair=$(vnet_mkepair)
	tunleft=$(ifconfig tun create)
	tunright=$(ifconfig tun create)

	vnet_mkjail left ${epair}a ${tunleft}
	vnet_mkjail right ${epair}b ${tunright}

	jexec left ifconfig ${epair}a inet 169.254.0.2/16
	jexec right ifconfig ${epair}b inet 169.254.0.3/16

	jexec left nc -u --tun /dev/${tunleft} 169.254.0.3 1234 &
	ncleft=$!
	jexec right nc -u -l --tun /dev/${tunright} 169.254.0.3 1234 &
	ncright=$!

	jexec left ifconfig ${tunleft} inet 169.254.1.2/16 169.254.1.3
	jexec right ifconfig ${tunright} inet 169.254.1.3/16 169.254.1.2

	jexec right pkt-gen -f pong -i netmap:${tunright} -n 100000 &
	sleep 1 # Give pkt-gen a chance to start.

	atf_check -o ignore -e ignore jexec left \
	    pkt-gen -f ping -i netmap:${tunleft} -n 100000

	jexec left kill $ncleft
	jexec right kill $ncright

	wait
}
tun_simple_cleanup()
{
	vnet_cleanup
}

#
# Verify that pkt-gen can transfer packets over a vlan.
#
atf_test_case "vlan_simple" "cleanup"
vlan_simple_head()
{
	atf_set descr 'Test that vlan interfaces can be used in netmap mode'
	atf_set require.user root
}
vlan_simple_body()
{
	vnet_init

	epair=$(vnet_mkepair)
	vlana=$(vnet_mkvlan)
	vlanb=$(vnet_mkvlan)

	ifconfig ${epair}a up
	ifconfig ${vlana} up vlan 42 vlandev ${epair}a

	ifconfig ${epair}b up
	ifconfig ${vlanb} up vlan 42 vlandev ${epair}b

	pkt-gen -i netmap:${vlana} -f rx -n 100000 &
	sleep 1 # Give pkt-gen a chance to start.

	atf_check -o ignore -e ignore pkt-gen -i netmap:${vlanb} -f tx -n 100000

	wait
}
vlan_simple_cleanup()
{
	vnet_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case bridge_l2_forwarding
	atf_add_test_case bridge_l3
	atf_add_test_case epair_simple
	atf_add_test_case tun_simple
	atf_add_test_case vlan_simple
}
