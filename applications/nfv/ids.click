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
fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)

fd2 -> q_ret::Queue -> td_ret::ToDevice($PORT1, METHOD LINUX)

// Counters of throughput/packets in arrival
ac_r_1::AverageCounter

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
cnt_uz_tcp_signal_80::Counter
cnt_uz_tcp_signal::Counter
cnt_uz_http::Counter
cnt_http_post::Counter
cnt_http_put::Counter
cnt_http_bad_method_get::Counter
cnt_http_bad_method_head::Counter
cnt_http_bad_method_options::Counter
cnt_http_bad_method_trace::Counter
cnt_http_bad_method_delete::Counter
cnt_http_bad_method_connect::Counter
cnt_put_safe::Counter
cnt_put_cat_etc_passwd::Counter
cnt_put_cat_var_log::Counter
cnt_put_insert::Counter
cnt_put_update::Counter
cnt_put_delete::Counter
cnt_uz_other_ip::Counter
cnt_uz_drop::Counter

//Queues to handle counters sending push output and average counter sending pull input
q2 :: Queue
q3 :: Queue

// uz stands for user zone -> messages arriving from the switch
// eth stands for ethernet as exit
// inspect HTTP with a Classifier data structure; messages arriving from the switch
// From where to pick packets
fd1
-> ac_r_1
-> c_uz_eth::Classifier(
	12/0806,
	12/0800,
	-
);

c_uz_eth[0]
-> cnt_uz_arp
-> Print("BRANCH: ARP -> lb1")
-> q2 -> ac_w_2 -> td_2;

c_uz_eth[1]
-> Strip(14)
-> CheckIPHeader
-> c_uz_ip::IPClassifier(
	icmp,
	tcp dst port 80,
	tcp,
	-
);

c_uz_ip[0]
-> cnt_uz_icmp
-> Print("BRANCH: ICMP -> lb1")
-> Unstrip(14)
-> q2 -> ac_w_2 -> td_2;

c_uz_ip[1]
-> cnt_uz_http
-> Print("BRANCH: HTTP tcp port 80")
-> c_http_method::Classifier(
	$HTTP_OFF/504f535420,
	$HTTP_OFF/50555420,
	$HTTP_OFF/47455420,
	$HTTP_OFF/4845414420,
	$HTTP_OFF/4f5054494f4e5320,
	$HTTP_OFF/545241434520,
	$HTTP_OFF/44454c45544520,
	$HTTP_OFF/434f4e4e45435420,
	-
);

c_http_method[0] -> cnt_http_post    -> Print("BRANCH: POST -> lb1")    -> Unstrip(14) -> q2 -> ac_w_2 -> td_2;
c_http_method[1] -> cnt_http_put     -> Print("BRANCH: PUT inspect")    -> search_payload::Search(\r\n\r\n);
c_http_method[2] -> cnt_http_bad_method_get     -> Print("BRANCH: GET -> insp")     -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_http_method[3] -> cnt_http_bad_method_head    -> Print("BRANCH: HEAD -> insp")    -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_http_method[4] -> cnt_http_bad_method_options -> Print("BRANCH: OPTIONS -> insp") -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_http_method[5] -> cnt_http_bad_method_trace   -> Print("BRANCH: TRACE -> insp")   -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_http_method[6] -> cnt_http_bad_method_delete  -> Print("BRANCH: DELETE -> insp")  -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_http_method[7] -> cnt_http_bad_method_connect -> Print("BRANCH: CONNECT -> insp") -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_http_method[8] -> cnt_uz_tcp_signal_80 -> Print("BRANCH: TCP sig port80 -> lb1") -> Unstrip(14) -> q2 -> ac_w_2 -> td_2;

search_payload[0]
-> c_put_payload::Classifier(
	4/636174202f6574632f706173737764,
	4/636174202f7661722f6c6f672f,
	4/494e53455254,
	4/555044415445,
	4/44454c455445,
	-
);

c_put_payload[0] -> cnt_put_cat_etc_passwd -> Print("BRANCH: PUT cat /etc/passwd -> insp") -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_put_payload[1] -> cnt_put_cat_var_log    -> Print("BRANCH: PUT cat /var/log -> insp")    -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_put_payload[2] -> cnt_put_insert         -> Print("BRANCH: PUT INSERT -> insp")          -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_put_payload[3] -> cnt_put_update         -> Print("BRANCH: PUT UPDATE -> insp")          -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_put_payload[4] -> cnt_put_delete         -> Print("BRANCH: PUT DELETE -> insp")          -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_put_payload[5] -> cnt_put_safe           -> Print("BRANCH: PUT safe -> lb1")             -> Unstrip(14) -> q2 -> ac_w_2 -> td_2;

c_uz_ip[2] -> cnt_uz_tcp_signal  -> Print("BRANCH: TCP other -> lb1")   -> Unstrip(14) -> q2 -> ac_w_2 -> td_2;
c_uz_ip[3] -> cnt_uz_other_ip    -> Print("BRANCH: other IP -> lb1")    -> Unstrip(14) -> q2 -> ac_w_2 -> td_2;
c_uz_eth[2] -> cnt_uz_drop       -> Print("BRANCH: non-ARP/IP dropped") -> Discard;

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
