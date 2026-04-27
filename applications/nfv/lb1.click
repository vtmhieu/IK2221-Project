// Interfaces
define($PORT1 lb1-eth1, $PORT2 lb1-eth2)

// Addresses
// TODO: Change to correct IPs.
define($VIP 10.0.0.43, $llm1 10.0.0.40, $llm2 10.0.0.41, $llm3 10.0.0.42)

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


// Packet classifiers
c_in::Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)
c_out::Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)

check_from_clients::CheckIPHeader(14)
check_from_servers::CheckIPHeader(14)
fltr::IPFilter(allow dst load_balancer_ip, deny all)

// TODO: Modify this to the internal address.
arp_rest1::ARPResponder($VIP 11:11:11:11:11:11)
arp_rest2::ARPResponder($VIP 11:11:11:11:11:11)


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
c_in[1] -> Print("LB1: ARP Reply", TIMESTAMP true) -> Discard
c_in[2] -> Print("LB1: IP Packet", TIMESTAMP true) -> check_from_clients -> fltr
c_in[3] -> Print("LB1: Other Packet", TIMESTAMP true) -> Discard

fltr[0] -> Print("LB1: Allowed Packet", TIMESTAMP true) -> [0]lb_rw;
fltr[1] -> Print("LB1: Unallowed Packet", TIMESTAMP true) -> Discard

lb_rw[0] -> Print("LB1: Rewritten Packet", TIMESTAMP true) -> to_servers


// Server-facing port
fd2 -> c_out
c_out[0] -> ARPPrint("LB1: Incoming ARP Req (servers)", TIMESTAMP true) -> arp_rest2 -> to_servers
c_out[1] -> Print("LB1: ARP Reply (servers)", TIMESTAMP true) -> Discard
c_out[2] -> Print("LB1: IP Reply Packet", TIMESTAMP true) -> check_from_servers -> [1]lb_rw;
c_out[3] -> Print("LB1: Other Packet (servers)", TIMESTAMP true) -> Discard

lb_rw[1] -> Print("LB1: Rewritten Packet", TIMESTAMP true) -> to_clients


// Lifecycle
DriverManager(
	print "LB1: Router starting",
	pause
)
