// 2 variables to hold port names: eth1<->sw2, eth3<->lb1
define($PORT1 ids-eth1,$PORT2 ids-eth3)

// TO CHECK if a third port for the inspector might be needed

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

// From where to pick packets
fd1::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)

// Counters of throughput/packets in arrival
ac_r_1::AverageCounter
ac_r_2::AverageCounter

// Where to send packets
td_1::ToDevice($PORT1, METHOD LINUX)
td_2::ToDevice($PORT2, METHOD LINUX)

// Counters in exit (throughput/packets)
ac_w_1::AverageCounter
ac_w_2::AverageCounter

// Counters for reporting
cnt_uz_arp::Counter
cnt_uz_icmp::Counter
cnt_uz_tcp_signal::Counter
cnt_uz_http::Counter
cnt_http_post::Counter
cnt_http_put::Counter
cnt_http_bad_method::Counter
cnt_put_safe::Counter
cnt_put_cat_etc_passwd::Counter
cnt_put_cat_var_log::Counter
cnt_put_insert::Counter
cnt_put_update::Counter
cnt_put_delete::Counter
cnt_uz_other_ip::Counter
cnt_uz_drop::Counter

cnt_lb_arp::Counter
cnt_lb_icmp::Counter
cnt_lb_tcp::Counter
cnt_lb_other_ip::Counter
cnt_lb_drop::Counter

// TO CHECK: inspector counters
cnt_insp_rx_drop::Counter

// Instantiate 2 forwarders, 1 per directions
fd1->fwd1::L2Forwarder($PORT1)->td2
fd2->fwd2::L2Forwarder($PORT2)->td1


// TODO: packet inspection

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
