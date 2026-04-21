// 2 variables to hold ports names
define($PORT1 lb1-eth1, $PORT2 lb1-eth2)

// Script will run as soon as the router starts
Script(print "Click forwarder on $PORT1 $PORT2")

// Group common elements in a single block. $port is a parameter used just to print
elementclass L2Forwarder {$port|
	input
	->cnt::Counter
        ->Print
	->output
}

// From where to pick packets
fd1::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)

// Where to send packets
td1::ToDevice($PORT1, METHOD LINUX)
td2::ToDevice($PORT2, METHOD LINUX)

arp_rest::ARPResponder(10.0.0.0/24 11:11:11:11:11:11)

c::Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)

merger_td1::Queue
merger_td2::Queue

merger_td1->td1
merger_td2->td2

fd1-> c
// c[0]->Print("ARP Request")->Queue->arp_rest->Queue->Print("Sending ARP Reply")->Queue->td1
c[0]->Print("ARP Request")->arp_rest->merger_td1
c[1]->Print("ARP Reply")->merger_td2
c[2]->Print("IP Packet")->merger_td2
c[3]->Print("Other Packet")->Discard

fd2->lf1::L2Forwarder($PORT2)->merger_td1


// Print something on exit
// DriverManager will listen on router's events
// The pause instruction will wait until the process terminates
// Then the prints will run an Click will exit
DriverManager(
        print "Router starting",
        pause,
	print "Packets from ${PORT1}: $(fwd1/cnt.count)",
	print "Packets from ${PORT2}: $(fwd2/cnt.count)",
)
