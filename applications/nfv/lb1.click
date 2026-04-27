// Interfaces
define($PORT1 lb1-eth1, $PORT2 lb1-eth2)

// Addresses
// TODO: Change to correct IPs.
define($VIP 10.0.0.43, $LB_MAC 11:11:11:11:11:11, $llm1 10.0.0.40, $llm2 10.0.0.41, $llm3 10.0.0.42)

// TODO: Modify this to the internal address.
AddressInfo(load_balancer_ip $VIP)

Script(print "LB1: Click load balancer on $PORT1 $PORT2")


// Devices
fd1::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)

td1::ToDevice($PORT1, METHOD LINUX)
td2::ToDevice($PORT2, METHOD LINUX)

to_clients::Queue
to_servers::Queue

to_clients -> td1
to_servers -> td2

arpq_clients::ARPQuerier($VIP, $LB_MAC)
arpq_servers::ARPQuerier($VIP, $LB_MAC)

arpq_clients -> to_clients
arpq_servers -> to_servers


// Packet classifiers
c_in::Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)
c_out::Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)

check_from_clients::CheckIPHeader
check_from_servers::CheckIPHeader
fltr::IPFilter(allow dst load_balancer_ip, deny all)

// TODO: Modify this to the internal address.
arp_rest1::ARPResponder($VIP $LB_MAC)
arp_rest2::ARPResponder($VIP $LB_MAC)


// Load-balancing rewrite
// Pattern: SADDR SPORT DADDR DPORT FOUTPUT ROUTPUT.
// Output 0 is towards servers; output 1 is towards clients.
lb_rr::RoundRobinIPMapper(
	- - $llm1 - 0 1,
	- - $llm2 - 0 1,
	- - $llm3 - 0 1
);

lb_rw::IPRewriter(
	lb_rr,
	drop
);


// Client-facing port
fd1 -> c_in
c_in[0] -> ARPPrint("LB1: Incoming ARP Req", TIMESTAMP true) -> arp_rest1 -> to_clients
c_in[1] -> ARPPrint("LB1: ARP Reply", TIMESTAMP true) -> [1]arpq_clients
c_in[2] -> Strip(14) -> check_from_clients -> IPPrint("LB1: client -> VIP", TIMESTAMP true) -> fltr
c_in[3] -> Print("LB1: Other Packet", TIMESTAMP true) -> Discard

fltr[0] -> IPPrint("LB1: allowed to rewrite", TIMESTAMP true) -> [0]lb_rw;
fltr[1] -> Print("LB1: Unallowed Packet", TIMESTAMP true) -> Discard

lb_rw[0] -> IPPrint("LB1: rewritten -> backend", TIMESTAMP true) -> GetIPAddress(16) -> arpq_servers


// Server-facing port
fd2 -> c_out
c_out[0] -> ARPPrint("LB1: Incoming ARP Req (servers)", TIMESTAMP true) -> arp_rest2 -> to_servers
c_out[1] -> ARPPrint("LB1: ARP Reply (servers)", TIMESTAMP true) -> [1]arpq_servers
c_out[2] -> Strip(14) -> check_from_servers -> IPPrint("LB1: backend -> VIP", TIMESTAMP true) -> [1]lb_rw;
c_out[3] -> Print("LB1: Other Packet (servers)", TIMESTAMP true) -> Discard

lb_rw[1] -> IPPrint("LB1: rewritten -> client", TIMESTAMP true) -> GetIPAddress(16) -> arpq_clients


// Lifecycle
DriverManager(
	print "LB1: Router starting",
	pause
)
