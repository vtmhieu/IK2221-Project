// 2 variables to hold ports names
define($PORT1 napt-eth1, $PORT2 napt-eth2)
//require(library ./forwarder.click)
//Forwarder($PORT1, $PORT2, $VERBOSE)
// Script will run as soon as the router starts
Script(print "Click NAPT on $PORT1 $PORT2")

// IP configuration
AddressInfo(
  IN_ADDR    10.0.0.1/24    1A:1A:1A:1A:1A:1A,
  OUT_ADDR   100.0.0.1/24   2B:2B:2B:2B:2B:2B
)

// Group common elements in a single block. $port is a parameter used just to print
elementclass L2Forwarder {$port|
	input
	->cnt::Counter
        ->Print
	->Queue
	->output
}

// From where to pick packets
fd1::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)

// Add counters
cnt1 :: Counter
cnt2 :: Counter

// Where to send packets
td1::ToDevice($PORT1, METHOD LINUX)
td2::ToDevice($PORT2, METHOD LINUX)

// Add Queues to resolve the push/pull mismatch
q1 :: Queue
q2 :: Queue

// Connect queues to the devices
q1 -> td1
q2 -> td2

// Classifier
// 12/0806 20/0001 = ARP Request
// 12/0806 20/0002 = ARP Reply
// 12/0800 = IP traffic
c1::Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)
c2::Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)

// Split TCP/UDP from ICMP so the rewriters don't drop each other's traffic
ip_class_in  :: IPClassifier(tcp or udp, icmp type echo, -)
ip_class_out :: IPClassifier(tcp or udp, icmp type echo-reply, -)

// ARP Handling
arp_in::ARPResponder(IN_ADDR)
arp_out::ARPResponder(OUT_ADDR)

aq_in::ARPQuerier(IN_ADDR, $PORT1)
aq_out :: ARPQuerier(OUT_ADDR, $PORT2)

// NAT Logic
iprw   :: IPRewriter(pattern OUT_ADDR 1024-65535 - - 0 1, drop)
icmprw :: ICMPPingRewriter(pattern OUT_ADDR 1024-65535 - - 0 1, drop)

// FLOW
// Host -> in -> out
fd1 -> cnt1 -> c1

// 1. ARP Requests (user asking for gateway MAC)
c1[0] -> arp_in -> q1

// 2. ARP Replies (user responding to NAPT's ARP requests)
c1[1] -> [1]aq_in

// 3. IP traffic
c1[2] -> Strip(14) -> CheckIPHeader -> ip_class_in

// Route to correct rewriter's Input 0
ip_class_in[0] -> [0]iprw      // TCP/UDP
ip_class_in[1] -> [0]icmprw    // ICMP Pings
ip_class_in[2] -> Discard      // Drop everything else

// Take translated traffic from Output 0 and send to external zone
iprw[0]   -> aq_out
icmprw[0] -> aq_out

aq_out[0] -> q2
aq_out[1] -> q2

// Drop non-ARP/IP
c1[3] -> Discard


// -------- OUT → USER (IN) --------
fd2 -> cnt2 -> c2

// 1. ARP Requests (external side asking for NAPT MAC)
c2[0] -> arp_out -> q2

// 2. ARP Replies (external side responding to NAPT's ARP requests)
c2[1] -> [1]aq_out

// 3. IP traffic (return path)
c2[2] -> Strip(14) -> CheckIPHeader -> ip_class_out

// Route to correct rewriter's Input 1
ip_class_out[0] -> [1]iprw     // Return TCP/UDP
ip_class_out[1] -> [1]icmprw   // Return ICMP Ping Replies
ip_class_out[2] -> Discard

// Take un-translated return traffic from Output 1 and send to User zone
iprw[1]   -> aq_in
icmprw[1] -> aq_in

aq_in[0] -> q1
aq_in[1] -> q1

// Drop non-ARP/IP
c2[3] -> Discard


// Print something on exit
// DriverManager will listen on router's events
// The pause instruction will wait until the process terminates
// Then the prints will run an Click will exit
DriverManager(
        print "NAPT starting",
        pause,
	print "Packets from ${PORT1}: $(cnt1.count)",
	print "Packets from ${PORT2}: $(cnt2.count)",
)