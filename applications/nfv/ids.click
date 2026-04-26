// 3 variables to hold port names
// eth1 <-> sw2 (switch as input), eth3 <-> lb1 (lb as output), eth2 <-> inspector for particular messages
define($PORT1 ids-eth1, $PORT2 ids-eth3, $PORT3 ids-eth2)

// Fixed offsets needed to Strip(14) messages:
// + HTTP method starts at byte 40 (assuming no IP/TCP)
// No IP offset as its header starts at 0
//define($HTTP_OFF 40)

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

// Search elements declared ahead of time for chaining
// Searhc looks through the ENTIRE packet buffer, ignoring TCP header offsets

search_post :: Search("POST ");
search_put  :: Search("PUT ");
search_get  :: Search("GET ");
search_head :: Search("HEAD ");
search_opts :: Search("OPTIONS ");
search_trac :: Search("TRACE ");
search_dele :: Search("DELETE ");
search_conn :: Search("CONNECT ");

// Search for special sequences
put_check_passwd :: Search("cat /etc/passwd");
put_check_log    :: Search("cat /var/log");
put_check_insert :: Search("INSERT");
put_check_update :: Search("UPDATE");
put_check_delete :: Search("DELETE");

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

// I Reassembler to catch payloads split between multiple IP fragments
c_uz_eth[1]
-> Strip(14)
-> CheckIPHeader
-> IPReassembler()
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
-> CheckTCPHeader
-> search_post;

// Cascade of search elements
// Port [0] triggers if the string is found. Port [1] passes the packet along if NOT found.
search_post[0] -> cnt_http_post -> Print("BRANCH: POST -> lb1") -> Unstrip(14) -> q2 -> ac_w_2 -> td_2;
search_post[1] -> search_put;

search_put[0]  -> cnt_http_put -> put_check_passwd;
search_put[1]  -> search_get;

search_get[0]  -> cnt_http_bad_method_get -> Print("BRANCH: GET -> insp") -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
search_get[1]  -> search_head;

search_head[0] -> cnt_http_bad_method_head -> Print("BRANCH: HEAD -> insp") -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
search_head[1] -> search_opts;

search_opts[0] -> cnt_http_bad_method_options -> Print("BRANCH: OPTIONS -> insp") -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
search_opts[1] -> search_trac;

search_trac[0] -> cnt_http_bad_method_trace -> Print("BRANCH: TRACE -> insp") -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
search_trac[1] -> search_dele;

search_dele[0] -> cnt_http_bad_method_delete -> Print("BRANCH: DELETE -> insp") -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
search_dele[1] -> search_conn;

search_conn[0] -> cnt_http_bad_method_connect -> Print("BRANCH: CONNECT -> insp") -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;

// If no HTTP method is found, it's likely TCP signaling
search_conn[1] -> cnt_uz_tcp_signal_80 -> Print("BRANCH: TCP sig port80 -> lb1") -> Unstrip(14) -> q2 -> ac_w_2 -> td_2;

// cascaded payload inspection for PUT -> packets arrive here only if PUT is recognized above

put_check_passwd[0] -> cnt_put_cat_etc_passwd -> Print("BRANCH: PUT cat /etc/passwd -> insp") -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
put_check_passwd[1] -> put_check_log;

put_check_log[0]    -> cnt_put_cat_var_log -> Print("BRANCH: PUT cat /var/log -> insp") -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
put_check_log[1]    -> put_check_insert;

put_check_insert[0] -> cnt_put_insert -> Print("BRANCH: PUT INSERT -> insp") -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
put_check_insert[1] -> put_check_update;

put_check_update[0] -> cnt_put_update -> Print("BRANCH: PUT UPDATE -> insp") -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
put_check_update[1] -> put_check_delete;

put_check_delete[0] -> cnt_put_delete -> Print("BRANCH: PUT DELETE -> insp") -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
// If we reach the end and found none of the bad strings, the PUT is safe.
put_check_delete[1] -> cnt_put_safe -> Print("BRANCH: PUT safe -> lb1") -> Unstrip(14) -> q2 -> ac_w_2 -> td_2;

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
	print "HTTP GET bad method to inspector: $(cnt_http_bad_method_get.count)",
	print "HTTP HEAD bad method to inspector: $(cnt_http_bad_method_head.count)",
	print "HTTP OPTIONS bad method to inspector: $(cnt_http_bad_method_options.count)",
	print "HTTP TRACE bad method to inspector: $(cnt_http_bad_method_trace.count)",
	print "HTTP DELETE bad method to inspector: $(cnt_http_bad_method_delete.count)",
	print "HTTP CONNECT bad method to inspector: $(cnt_http_bad_method_connect.count)",
	print "PUT safe to lb1: $(cnt_put_safe.count)",
	print "PUT cat /etc/passwd blocked: $(cnt_put_cat_etc_passwd.count)",
	print "PUT cat /var/log/ blocked: $(cnt_put_cat_var_log.count)",
	print "PUT INSERT blocked: $(cnt_put_insert.count)",
	print "PUT UPDATE blocked: $(cnt_put_update.count)",
	print "PUT DELETE blocked: $(cnt_put_delete.count)",
)
