define($PORT1 ids-eth1, $PORT2 ids-eth3, $PORT3 ids-eth2)

// HTTP method byte offsets after Ethernet strip (14 bytes removed):
// TCP header 20 bytes (no options):    IP(20) + TCP(20) = offset 40
// TCP header 32 bytes (with timestamps): IP(20) + TCP(32) = offset 52
define($HTTP_OFF_STD 40)
define($HTTP_OFF_OPT 52)

Script(print "Click IDS on $PORT1 $PORT2 $PORT3")

fd1::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)

ac_r_1::AverageCounter
ac_r_2::AverageCounter

td_2::ToDevice($PORT2, METHOD LINUX)
td_3::ToDevice($PORT3, METHOD LINUX)

ac_w_1::AverageCounter
ac_w_2::AverageCounter

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
cnt_put_malformed::Counter
cnt_uz_other_ip::Counter
cnt_uz_drop::Counter

q2 :: Queue
q3 :: Queue

// Return path: lb1 replies go straight back to s2, no inspection needed
fd2 -> ac_r_2 -> Print("IDS --- Response from Load Balancer", TIMESTAMP true) -> q_ret::Queue -> td_ret::ToDevice($PORT1, METHOD LINUX)

fd1
-> ac_r_1
-> c_uz_eth::Classifier(
	12/0806,   // ARP
	12/0800,   // IPv4
	-          // everything else (IPv6 etc.)
);

c_uz_eth[0]
-> cnt_uz_arp
-> Print("IDS ---  BRANCH: ARP -> lb1", TIMESTAMP true)
-> q2 -> ac_w_2 -> td_2;

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
-> Print("IDS ---  BRANCH: ICMP -> lb1", TIMESTAMP true)
-> Unstrip(14)
-> q2 -> ac_w_2 -> td_2;

// HTTP classifier: match methods for the two TCP header sizes seen in tests.
c_uz_ip[1]
-> cnt_uz_http
-> c_http_method::Classifier(
	$HTTP_OFF_STD/504f535420,     // POST  (20-byte TCP header)
	$HTTP_OFF_OPT/504f535420,     // POST  (32-byte TCP header)
	$HTTP_OFF_STD/50555420,       // PUT   (20-byte TCP header)
	$HTTP_OFF_OPT/50555420,       // PUT   (32-byte TCP header)
	$HTTP_OFF_STD/47455420,       // GET   (20-byte TCP header)
	$HTTP_OFF_OPT/47455420,       // GET   (32-byte TCP header)
	$HTTP_OFF_STD/4845414420,     // HEAD  (20-byte TCP header)
	$HTTP_OFF_OPT/4845414420,     // HEAD  (32-byte TCP header)
	$HTTP_OFF_STD/4f5054494f4e5320, // OPTIONS (20-byte TCP header)
	$HTTP_OFF_OPT/4f5054494f4e5320, // OPTIONS (32-byte TCP header)
	$HTTP_OFF_STD/545241434520,   // TRACE (20-byte TCP header)
	$HTTP_OFF_OPT/545241434520,   // TRACE (32-byte TCP header)
	$HTTP_OFF_STD/44454c45544520, // DELETE (20-byte TCP header)
	$HTTP_OFF_OPT/44454c45544520, // DELETE (32-byte TCP header)
	$HTTP_OFF_STD/434f4e4e45435420, // CONNECT (20-byte TCP header)
	$HTTP_OFF_OPT/434f4e4e45435420, // CONNECT (32-byte TCP header)
	-                             // TCP signaling (SYN, ACK, FIN etc.)
);

// POST: allowed through to lb1
c_http_method[0]  -> cnt_http_post -> Print("IDS ---  BRANCH: POST -> lb1", TIMESTAMP true) -> Unstrip(14) -> q2 -> ac_w_2 -> td_2;
c_http_method[1]  -> cnt_http_post -> Print("IDS ---  BRANCH: POST -> lb1", TIMESTAMP true) -> Unstrip(14) -> q2 -> ac_w_2 -> td_2;

// PUT: Search strips through the HTTP header terminator, so payload checks are
// anchored at byte 0 of the HTTP body rather than at a curl-specific offset.
c_http_method[2]  -> cnt_http_put -> s_put_std::Search("\r\n\r\n");
c_http_method[3]  -> cnt_http_put -> s_put_opt::Search("\r\n\r\n");

s_put_std[0] -> c_put_payload_std::Classifier(
	0/636174202f6574632f706173737764, // cat /etc/passwd
	0/636174202f7661722f6c6f672f,     // cat /var/log/
	0/494e53455254,                   // INSERT
	0/555044415445,                   // UPDATE
	0/44454c455445,                   // DELETE
	-                                 // safe PUT
);
s_put_opt[0] -> c_put_payload_opt::Classifier(
	0/636174202f6574632f706173737764, // cat /etc/passwd
	0/636174202f7661722f6c6f672f,     // cat /var/log/
	0/494e53455254,                   // INSERT
	0/555044415445,                   // UPDATE
	0/44454c455445,                   // DELETE
	-                                 // safe PUT
);

// GET, HEAD, OPTIONS, TRACE, DELETE, CONNECT: all go to inspector
c_http_method[4]  -> cnt_http_bad_method_get     -> Print("IDS ---  BRANCH: GET -> insp", TIMESTAMP true)     -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_http_method[5]  -> cnt_http_bad_method_get     -> Print("IDS ---  BRANCH: GET -> insp", TIMESTAMP true)     -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_http_method[6]  -> cnt_http_bad_method_head    -> Print("IDS ---  BRANCH: HEAD -> insp", TIMESTAMP true)    -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_http_method[7]  -> cnt_http_bad_method_head    -> Print("IDS ---  BRANCH: HEAD -> insp", TIMESTAMP true)    -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_http_method[8]  -> cnt_http_bad_method_options -> Print("IDS ---  BRANCH: OPTIONS -> insp", TIMESTAMP true) -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_http_method[9]  -> cnt_http_bad_method_options -> Print("IDS ---  BRANCH: OPTIONS -> insp", TIMESTAMP true) -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_http_method[10] -> cnt_http_bad_method_trace   -> Print("IDS ---  BRANCH: TRACE -> insp", TIMESTAMP true)   -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_http_method[11] -> cnt_http_bad_method_trace   -> Print("IDS ---  BRANCH: TRACE -> insp", TIMESTAMP true)   -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_http_method[12] -> cnt_http_bad_method_delete  -> Print("IDS ---  BRANCH: DELETE -> insp", TIMESTAMP true)  -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_http_method[13] -> cnt_http_bad_method_delete  -> Print("IDS ---  BRANCH: DELETE -> insp", TIMESTAMP true)  -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_http_method[14] -> cnt_http_bad_method_connect -> Print("IDS ---  BRANCH: CONNECT -> insp", TIMESTAMP true) -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_http_method[15] -> cnt_http_bad_method_connect -> Print("IDS ---  BRANCH: CONNECT -> insp", TIMESTAMP true) -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;

// TCP signaling (SYN, ACK, FIN): no HTTP method matched, pass through
c_http_method[16] -> cnt_uz_tcp_signal_80 -> Print("IDS ---  BRANCH: TCP sig port80 -> lb1", TIMESTAMP true) -> Unstrip(14) -> q2 -> ac_w_2 -> td_2;

// PUT payload inspection results.
c_put_payload_std[0] -> cnt_put_cat_etc_passwd -> Print("IDS ---  BRANCH: PUT cat /etc/passwd -> insp", TIMESTAMP true) -> UnstripAnno() -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_put_payload_std[1] -> cnt_put_cat_var_log    -> Print("IDS ---  BRANCH: PUT cat /var/log -> insp", TIMESTAMP true)    -> UnstripAnno() -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_put_payload_std[2] -> cnt_put_insert         -> Print("IDS ---  BRANCH: PUT INSERT -> insp", TIMESTAMP true)          -> UnstripAnno() -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_put_payload_std[3] -> cnt_put_update         -> Print("IDS ---  BRANCH: PUT UPDATE -> insp", TIMESTAMP true)          -> UnstripAnno() -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_put_payload_std[4] -> cnt_put_delete         -> Print("IDS ---  BRANCH: PUT DELETE -> insp", TIMESTAMP true)          -> UnstripAnno() -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_put_payload_std[5] -> cnt_put_safe           -> Print("IDS ---  BRANCH: PUT safe -> lb1", TIMESTAMP true)             -> UnstripAnno() -> Unstrip(14) -> q2 -> ac_w_2 -> td_2;

c_put_payload_opt[0] -> cnt_put_cat_etc_passwd -> Print("IDS ---  BRANCH: PUT cat /etc/passwd -> insp", TIMESTAMP true) -> UnstripAnno() -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_put_payload_opt[1] -> cnt_put_cat_var_log    -> Print("IDS ---  BRANCH: PUT cat /var/log -> insp", TIMESTAMP true)    -> UnstripAnno() -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_put_payload_opt[2] -> cnt_put_insert         -> Print("IDS ---  BRANCH: PUT INSERT -> insp", TIMESTAMP true)          -> UnstripAnno() -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_put_payload_opt[3] -> cnt_put_update         -> Print("IDS ---  BRANCH: PUT UPDATE -> insp", TIMESTAMP true)          -> UnstripAnno() -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_put_payload_opt[4] -> cnt_put_delete         -> Print("IDS ---  BRANCH: PUT DELETE -> insp", TIMESTAMP true)          -> UnstripAnno() -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
c_put_payload_opt[5] -> cnt_put_safe           -> Print("IDS ---  BRANCH: PUT safe -> lb1", TIMESTAMP true)             -> UnstripAnno() -> Unstrip(14) -> q2 -> ac_w_2 -> td_2;

s_put_std[1] -> cnt_put_malformed -> Print("IDS ---  BRANCH: PUT malformed -> insp", TIMESTAMP true) -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;
s_put_opt[1] -> cnt_put_malformed -> Print("IDS ---  BRANCH: PUT malformed -> insp", TIMESTAMP true) -> Unstrip(14) -> q3 -> ac_w_1 -> td_3;

c_uz_ip[2]
-> cnt_uz_tcp_signal
-> Print("IDS ---  BRANCH: TCP other -> lb1", TIMESTAMP true)
-> Unstrip(14)
-> q2 -> ac_w_2 -> td_2;

c_uz_ip[3]
-> cnt_uz_other_ip
-> Print("IDS ---  BRANCH: other IP -> lb1", TIMESTAMP true)
-> Unstrip(14)
-> q2 -> ac_w_2 -> td_2;

c_uz_eth[2]
-> cnt_uz_drop
-> Print("IDS ---  BRANCH: non-ARP/IP dropped", TIMESTAMP true)
-> Discard;

DriverManager(
	print "Router starting",
	pause,
	print "",
	print "=================Aggregate Statistics===============",
	print "",
	print "Total received user packets: $(ac_r_1.count)",
	print "Total user packets dropped by IDS: $(cnt_uz_drop.count)",
	print "Total received load balancer response packets: $(ac_r_2.count)",
	print "",
	print "Total packets sent to insepctor: $(ac_w_1.count)",
	print "Total packets sent to LB: $(ac_w_2.count)",
	print "",
	print "Input Rate (pps): $(ac_r_1.rate)",
	print "Output Rate (pps): $(ac_r_2.rate)",
	print "",
	print "=================Individual Request Type Statistics==============",
	print "Received from user (ARP): $(cnt_uz_arp.count)",
	print "Received from user (ICMP): $(cnt_uz_icmp.count)",
	print "Received from user (TCP signaling): $(cnt_uz_tcp_signal.count)",
	print "Received from user (TCP signaling on port 80): $(cnt_uz_tcp_signal_80.count)",
	print "Received from user (HTTP): $(cnt_uz_http.count)",
	print "HTTP POST allowed: $(cnt_http_post.count)",
	print "HTTP PUT observed: $(cnt_http_put.count)",
	print "HTTP GET bad method to inspector: $(cnt_http_bad_method_get.count)",
	print "HTTP HEAD bad method to inspector: $(cnt_http_bad_method_head.count)",
	print "HTTP OPTIONS bad method to inspector: $(cnt_http_bad_method_options.count)",
	print "HTTP TRACE bad method to inspector: $(cnt_http_bad_method_trace.count)",
	print "HTTP DELETE bad method to inspector: $(cnt_http_bad_method_delete.count)",
	print "HTTP CONNECT bad method to inspector: $(cnt_http_bad_method_connect.count)",
	print "Other IP traffic: $(cnt_uz_other_ip.count)",
	print "PUT safe to lb1: $(cnt_put_safe.count)",
	print "PUT cat /etc/passwd blocked: $(cnt_put_cat_etc_passwd.count)",
	print "PUT cat /var/log/ blocked: $(cnt_put_cat_var_log.count)",
	print "PUT INSERT blocked: $(cnt_put_insert.count)",
	print "PUT UPDATE blocked: $(cnt_put_update.count)",
	print "PUT DELETE blocked: $(cnt_put_delete.count)",
	print "PUT malformed to inspector: $(cnt_put_malformed.count)",
)
