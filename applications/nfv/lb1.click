// Interfaces
define($PORT1 lb1-eth1, $PORT2 lb1-eth2)

// Addresses
// TODO: Change to correct IPs.
define($VIP 100.0.0.43, $LB_MAC 11:11:11:11:11:11, $llm1 100.0.0.40, $llm2 100.0.0.41, $llm3 100.0.0.42)

AddressInfo(load_balancer_ip $VIP)

Script(print "LB1: Click load balancer on $PORT1 $PORT2")


// Devices
fd1::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)

td1::ToDevice($PORT1, METHOD LINUX)
td2::ToDevice($PORT2, METHOD LINUX)

// Interface throughput counters required by the report.
cnt_fd1_in::AverageCounter
cnt_fd2_in::AverageCounter
cnt_td1_out::AverageCounter
cnt_td2_out::AverageCounter

to_clients::Queue
to_servers::Queue

to_clients -> cnt_td1_out -> td1
to_servers -> cnt_td2_out -> td2

arpq_clients::ARPQuerier($VIP, $LB_MAC)
arpq_servers::ARPQuerier($VIP, $LB_MAC)

arpq_clients -> to_clients
arpq_servers -> to_servers


// Packet classifiers
c_in::Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)
c_out::Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)

// Split TCP/UDP from ICMP so the rewriters don't drop each other's traffic
ip_class_in  :: IPClassifier(tcp or udp, icmp type echo, -)
ip_class_out :: IPClassifier(tcp or udp, icmp type echo-reply, -)


check_from_clients::CheckIPHeader
check_from_servers::CheckIPHeader
fltr::IPFilter(allow dst load_balancer_ip, deny all)
llm_out::IPClassifier(dst host $llm1, dst host $llm2, dst host $llm3, -)
// icmp classifier for testing and benchmarking purposes
llm_out_icmp::IPClassifier(dst host $llm1, dst host $llm2, dst host $llm3, -)

cnt_cin_arp_req::Counter
cnt_cin_arp_reply::Counter
cnt_cin_ip::Counter
cnt_cin_other_drop::Counter
cnt_allowed_to_rewrite::Counter
cnt_unallowed_drop::Counter

cnt_cout_arp_req::Counter
cnt_cout_arp_reply::Counter
cnt_cout_ip::Counter
cnt_cout_other_drop::Counter

cnt_llm1_requests::Counter
cnt_llm2_requests::Counter
cnt_llm3_requests::Counter
cnt_llm_unknown::Counter

cnt_llm1_icmp::Counter
cnt_llm2_icmp::Counter
cnt_llm3_icmp::Counter
cnt_llm_unknown_icmp::Counter

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

icmp_rw :: ICMPPingRewriter(lb_rr, drop)


// Client-facing port
fd1 -> cnt_fd1_in -> c_in
c_in[0] -> cnt_cin_arp_req -> ARPPrint("LB1: Incoming ARP Req", TIMESTAMP true) -> arp_rest1 -> to_clients
c_in[1] -> cnt_cin_arp_reply -> ARPPrint("LB1: ARP Reply", TIMESTAMP true) -> [1]arpq_clients
c_in[2] -> cnt_cin_ip -> Strip(14) -> check_from_clients -> IPPrint("LB1: client -> VIP", TIMESTAMP true) -> fltr
c_in[3] -> cnt_cin_other_drop -> Print("LB1: Other Packet", TIMESTAMP true) -> Discard

fltr[0] -> cnt_allowed_to_rewrite -> IPPrint("LB1: allowed to rewrite", TIMESTAMP true) -> ip_class_in 
fltr[1] -> cnt_unallowed_drop -> Print("LB1: Unallowed Packet", TIMESTAMP true) -> Discard

// Route to correct rewriter's Input 0
ip_class_in[0] -> [0]lb_rw      // TCP/UDP
ip_class_in[1] -> [0]icmp_rw    // ICMP Pings
ip_class_in[2] -> Discard      // Drop everything else

// load balancer logic for modifying the destination IP's for tcp and UDP
lb_rw[0] -> IPPrint("LB1: rewritten -> backend", TIMESTAMP true) -> llm_out
llm_out[0] -> cnt_llm1_requests -> IPPrint("LB1: request -> llm1", TIMESTAMP true) -> GetIPAddress(16) -> arpq_servers
llm_out[1] -> cnt_llm2_requests -> IPPrint("LB1: request -> llm2", TIMESTAMP true) -> GetIPAddress(16) -> arpq_servers
llm_out[2] -> cnt_llm3_requests -> IPPrint("LB1: request -> llm3", TIMESTAMP true) -> GetIPAddress(16) -> arpq_servers
llm_out[3] -> cnt_llm_unknown -> IPPrint("LB1: request -> unknown backend", TIMESTAMP true) -> GetIPAddress(16) -> arpq_servers

// icmp classifier for testing and benchmarking purposes
icmp_rw[0] -> IPPrint("LB1 ICMP: rewritten -> backend", TIMESTAMP true) -> llm_out_icmp
llm_out_icmp[0] -> cnt_llm1_icmp -> IPPrint("LB1: icmp -> llm1", TIMESTAMP true) -> GetIPAddress(16) -> arpq_servers
llm_out_icmp[1] -> cnt_llm2_icmp -> IPPrint("LB1: icmp -> llm2", TIMESTAMP true) -> GetIPAddress(16) -> arpq_servers
llm_out_icmp[2] -> cnt_llm3_icmp -> IPPrint("LB1: icmp -> llm3", TIMESTAMP true) -> GetIPAddress(16) -> arpq_servers
llm_out_icmp[3] -> cnt_llm_unknown_icmp -> IPPrint("LB1: icmp -> unknown backend", TIMESTAMP true) -> GetIPAddress(16) -> arpq_servers


// Server-facing port
fd2 -> cnt_fd2_in -> c_out
c_out[0] -> cnt_cout_arp_req -> ARPPrint("LB1: Incoming ARP Req (servers)", TIMESTAMP true) -> arp_rest2 -> to_servers
c_out[1] -> cnt_cout_arp_reply -> ARPPrint("LB1: ARP Reply (servers)", TIMESTAMP true) -> [1]arpq_servers
c_out[2] -> cnt_cout_ip -> Strip(14) -> check_from_servers -> IPPrint("LB1: backend -> VIP", TIMESTAMP true) -> ip_class_out
c_out[3] -> cnt_cout_other_drop -> Print("LB1: Other Packet (servers)", TIMESTAMP true) -> Discard



// Route to correct rewriter's Input 1
ip_class_out[0] -> [1]lb_rw     // Return TCP/UDP
ip_class_out[1] -> [1]icmp_rw   // Return ICMP Ping Replies
ip_class_out[2] -> Discard

lb_rw[1] -> IPPrint("LB1: rewritten -> client", TIMESTAMP true) -> GetIPAddress(16) -> arpq_clients
icmp_rw[1] -> IPPrint("LB1 ICMP: rewritten -> client", TIMESTAMP true) -> GetIPAddress(16) -> arpq_clients


// Lifecycle
DriverManager(
	print "LB1: Router starting",
	pause,
	print "LB1 report: interface counters",
	print "LB1 read ${PORT1}: packets=$(cnt_fd1_in.count) rate=$(cnt_fd1_in.rate) pkt/s",
	print "LB1 read ${PORT2}: packets=$(cnt_fd2_in.count) rate=$(cnt_fd2_in.rate) pkt/s",
	print "LB1 wrote ${PORT1}: packets=$(cnt_td1_out.count) rate=$(cnt_td1_out.rate) pkt/s",
	print "LB1 wrote ${PORT2}: packets=$(cnt_td2_out.count) rate=$(cnt_td2_out.rate) pkt/s",
	print "LB1 report: client-facing traffic classes",
	print "LB1 ${PORT1} ARP requests: $(cnt_cin_arp_req.count)",
	print "LB1 ${PORT1} ARP replies: $(cnt_cin_arp_reply.count)",
	print "LB1 ${PORT1} IP packets: $(cnt_cin_ip.count)",
	print "LB1 ${PORT1} other dropped: $(cnt_cin_other_drop.count)",
	print "LB1 ${PORT1} allowed to rewrite: $(cnt_allowed_to_rewrite.count)",
	print "LB1 ${PORT1} unallowed dropped: $(cnt_unallowed_drop.count)",
	print "LB1 report: server-facing traffic classes",
	print "LB1 ${PORT2} ARP requests: $(cnt_cout_arp_req.count)",
	print "LB1 ${PORT2} ARP replies: $(cnt_cout_arp_reply.count)",
	print "LB1 ${PORT2} IP packets: $(cnt_cout_ip.count)",
	print "LB1 ${PORT2} other dropped: $(cnt_cout_other_drop.count)",
	print "LB1 report: backend request distribution",
	print "LB1 requests to llm1 ($llm1): $(cnt_llm1_requests.count)",
	print "LB1 requests to llm2 ($llm2): $(cnt_llm2_requests.count)",
	print "LB1 requests to llm3 ($llm3): $(cnt_llm3_requests.count)",
	print "LB1 requests to unknown backend: $(cnt_llm_unknown.count)",
	print "LB1 icmps to llm1 ($llm1): $(cnt_llm1_icmp.count)",
	print "LB1 icmps to llm2 ($llm2): $(cnt_llm2_icmp.count)",
	print "LB1 icmps to llm3 ($llm3): $(cnt_llm3_icmp.count)",
	print "LB1 icmps to unknown backend: $(cnt_llm_unknown_icmp.count)"
)
