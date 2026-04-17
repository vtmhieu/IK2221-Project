// 2 variables to hold ports names
define($PORT1 lb1-eth1, $PORT2 lb1-eth2)

// Script will run as soon as the router starts
Script(print "Click forwarder on $PORT1 $PORT2")

// Group common elements in a single block. $port is a parameter used just to print
elementclass L2Forwarder {$port|
	input
	->cnt::Counter
        ->Print
	->Queue
	->output
}

elementclass AssignMACAddress{$ip, $mac|
	input
	->Print("Assigning MAC Address ")
	->ARPResponder($ip $mac) //TODO: Why is this stopping here??
	->Print("Assigned MAC Address")
	->output

}

elementclass PacketClassifier{$port|
	input
	/* ARP 12/0806; 
	Operation Code: 20/0001 (Request), 20/0002 (Reply) 
	*/
	->c::Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)
	c[0]->Print("ARP Request")->am1::AssignMACAddress(10.0.0.50, 11:11:11:11:11:11)->output
	c[1]->Print("ARP Reply")->output
	c[2]->Print("IP Packet")->output	
	c[3]->Print("Other Packet")->Discard
}

// From where to pick packets
fd1::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)

// Where to send packets
td1::ToDevice($PORT1, METHOD LINUX)
td2::ToDevice($PORT2, METHOD LINUX)

pc1::PacketClassifier($PORT1)
pc2::PacketClassifier($PORT2)

// Instantiate 2 forwarders, 1 per directions
fd1->pc1->fwd1::L2Forwarder($PORT1)->td2
fd2->pc2->fwd2::L2Forwarder($PORT2)->td1


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
