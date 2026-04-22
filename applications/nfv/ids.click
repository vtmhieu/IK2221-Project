// 3 variables to hold port names
// eth1 <-> sw2 (switch as input), eth3 <-> lb1 (lb as output), eth2 <-> inspector for particular messages
define($PORT1 ids-eth1, $PORT2 ids-eth3, $PORT3 ids-eth2)

// Fixed offsets needed to Strip(14) messages:
// + HTTP method starts at byte 40 (assuming no IP/TCP)
// No IP offset as its header starts at 0
define($HTTP_OFF 40)

// Script will run as soon as the router starts
Script(print "Click forwarder on $PORT1 $PORT2")

// Comment and decomment; it was purely a simple debug element 
// $port is a parameter used just to print
//elementclass L2Forwarder {$port|
//	input
//	->cnt::Counter
//        ->Print
//	->Queue
//	->output
//}

// From where to pick packets
fd1::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
// In case replies arrive from the lb
// fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)

// Counters of throughput/packets in arrival
ac_r_1::AverageCounter
ac_r_2::AverageCounter

// Where to send packets
td_2::ToDevice($PORT2, METHOD LINUX)
td_3::ToDevice($PORT3, METHOD LINUX)

// Counters in exit (throughput/packets)
// w1 for the inspector
// w2 for the load balancer
ac_w_1::AverageCounter
ac_w_2::AverageCounter

// Counters for reporting
// uz stands for user zone -> messages arriving from the switch
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

// uz stands for user zone -> messages arriving from the switch
// eth stands for ethernet as exit
// inspect HTTP with a Classifier data structure; messages arriving from the switch
fd1
-> c_uz_eth::Classifier(
	12/0806,   // ARP
	12/0800,   // TOCHECK: is IP version 4 fine?
	-          // everything else
);

// ARP traverses with no filtering 
c_uz_eth[0]
-> cnt_uz_arp
-> ac_w_2
-> td_2;

// IP traffic split
c_uz_eth[1]
-> Strip(14)
-> CheckIPHeader
-> c_uz_ip::IPClassifier(
	icmp,
	tcp dst port 80,
	tcp,
	-  // Everything else
);

// ICMP is under IP and passes with no additional filtering
c_uz_ip[0]
-> cnt_uz_icmp
-> Unstrip(14)
-> ac_w_2
-> td_2;

// HTTP requests are tcp to port 80 : allow only POST/PUT, send all other methods to inspector
c_uz_ip[1]
-> cnt_uz_http
-> c_http_method::Classifier(
	$HTTP_OFF/504f535420,           //POST
	$HTTP_OFF/50555420,             //PUT
	$HTTP_OFF/47455420,             //GET
	$HTTP_OFF/4845414420,           //HEAD
	$HTTP_OFF/4f5054494f4e5320,     //OPTIONS
	$HTTP_OFF/545241434520,         //TRACE
	$HTTP_OFF/44454c45544520,       //DELETE
	$HTTP_OFF/434f4e4e45435420,     //CONNECT
	-                               //other data on port 80
);

// POST is allowed to pass to lb
c_http_method[0]
-> cnt_http_post
-> Unstrip(14)
-> ac_w_2
-> td_2;

// PUT is inspected for command/SQL-injection signatures
c_http_method[1]
-> cnt_http_put
-> search_payload::Search(\r\n\r\n);

// Search handles the packet pointer
// The actual payload begins exactly 4 bytes later, so we use offset 4/
search_payload[0]
-> c_put_payload::Classifier(
	4/636174202f6574632f706173737764, //cat /etc/passwd
	4/636174202f7661722f6c6f672f,     //cat /var/log/
	4/494e53455254,                   //INSERT
	4/555044415445,                   //UPDATE
	4/44454c455445,                   //DELETE
	-								//Everything else
);

// Suspicious payloads of a PUT sent to inspector
c_put_payload[0]
-> cnt_put_cat_etc_passwd
-> Unstrip(14)
-> td_3;

c_put_payload[1]
-> cnt_put_cat_var_log
-> Unstrip(14)
-> td_3;

c_put_payload[2]
-> cnt_put_insert
-> Unstrip(14)
-> td_3;

c_put_payload[3]
-> cnt_put_update
-> Unstrip(14)
-> td_3;

c_put_payload[4]
-> cnt_put_delete
-> Unstrip(14)
-> td_3;

// not malicious PUT goes to lb
c_put_payload[5]
-> cnt_put_safe
-> Unstrip(14)
-> ac_w_2
-> td_2;

// all other HTTP methods go to inspector
c_http_method[2]
-> cnt_http_bad_method
-> Unstrip(14)
-> td_3;

c_http_method[3]
-> cnt_http_bad_method
-> Unstrip(14)
-> td_3;

c_http_method[4]
-> cnt_http_bad_method
-> Unstrip(14)
-> td_3;

c_http_method[5]
-> cnt_http_bad_method
-> Unstrip(14)
-> td_3;

c_http_method[6]
-> cnt_http_bad_method
-> Unstrip(14)
-> td_3;

c_http_method[7]
-> cnt_http_bad_method
-> Unstrip(14)
-> td_3;

// tcp signaling of port 80 pass to lb
c_http_method[8]
-> cnt_uz_tcp_signal
-> Unstrip(14)
-> ac_w_2
-> td_2;

// Non-HTTP TCP signaling must traverse transparently
c_uz_ip[2]
-> cnt_uz_tcp_signal
-> Unstrip(14)
-> ac_w_2
-> td_2;

//let other IP traffic pass
c_uz_ip[3]
-> cnt_uz_other_ip
-> Unstrip(14)
-> ac_w_2
-> td_2;

// Non-ARP/IPv4 frames are dropped
c_uz_eth[2]
-> cnt_uz_drop
-> Discard;

// Print something on exit
// DriverManager will listen on router's events
// The pause instruction will wait until the process terminates
// Then the prints will run an Click will exit
DriverManager(
        print "Router starting",
        pause,
	print "Received from user (ARP): $(cnt_uz_arp.count)",
	print "Received from user (ICMP): $(cnt_uz_icmp.count)",
	print "Received from user (TCP signaling): $(cnt_uz_tcp_signal.count)",
	print "Received from user (HTTP): $(cnt_uz_http.count)",
	print "HTTP POST allowed: $(cnt_http_post.count)",
	print "HTTP PUT observed: $(cnt_http_put.count)",
	print "HTTP bad method to inspector: $(cnt_http_bad_method.count)",
	print "PUT safe to lb1: $(cnt_put_safe.count)",
	print "PUT cat /etc/passwd blocked: $(cnt_put_cat_etc_passwd.count)",
	print "PUT cat /var/log/ blocked: $(cnt_put_cat_var_log.count)",
	print "PUT INSERT blocked: $(cnt_put_insert.count)",
	print "PUT UPDATE blocked: $(cnt_put_update.count)",
	print "PUT DELETE blocked: $(cnt_put_delete.count)",
)
