define($PORT1 ids-eth1, $PORT2 ids-eth3, $PORT3 ids-eth2)

Script(print "Click forwarder on $PORT1 $PORT2")

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
cnt_uz_other_ip::Counter
cnt_uz_drop::Counter

q2 :: Queue
q3 :: Queue

search_post :: Search("POST ")
search_put  :: Search("PUT ")
search_get  :: Search("GET ")
search_head :: Search("HEAD ")
search_opts :: Search("OPTIONS ")
search_trac :: Search("TRACE ")
search_dele :: Search("DELETE ")
search_conn :: Search("CONNECT ")

put_check_passwd :: Search("cat /etc/passwd")
put_check_log    :: Search("cat /var/log")
put_check_insert :: Search("INSERT")
put_check_update :: Search("UPDATE")
put_check_delete :: Search("DELETE")

fd2 -> ac_r_2 -> q_ret::Queue -> td_ret::ToDevice($PORT1, METHOD LINUX)

fd1
-> ac_r_1
-> c_uz_eth::Classifier(
	12/0806,
	12/0800,
	-
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

c_uz_ip[1]
-> cnt_uz_http
-> search_post;

search_post[0]
-> cnt_http_post
-> Print("IDS ---  BRANCH: POST -> lb1", TIMESTAMP true)
-> Unstrip(14)
-> q2 -> ac_w_2 -> td_2;

search_post[1]
-> search_put;

search_put[0]
-> cnt_http_put
-> put_check_passwd;

search_put[1]
-> search_get;

search_get[0]
-> cnt_http_bad_method_get
-> Print("IDS ---  BRANCH: GET -> insp", TIMESTAMP true)
-> Unstrip(14)
-> q3 -> ac_w_1 -> td_3;

search_get[1]
-> search_head;

search_head[0]
-> cnt_http_bad_method_head
-> Print("IDS ---  BRANCH: HEAD -> insp", TIMESTAMP true)
-> Unstrip(14)
-> q3 -> ac_w_1 -> td_3;

search_head[1]
-> search_opts;

search_opts[0]
-> cnt_http_bad_method_options
-> Print("IDS ---  BRANCH: OPTIONS -> insp", TIMESTAMP true)
-> Unstrip(14)
-> q3 -> ac_w_1 -> td_3;

search_opts[1]
-> search_trac;

search_trac[0]
-> cnt_http_bad_method_trace
-> Print("IDS ---  BRANCH: TRACE -> insp", TIMESTAMP true)
-> Unstrip(14)
-> q3 -> ac_w_1 -> td_3;

search_trac[1]
-> search_dele;

search_dele[0]
-> cnt_http_bad_method_delete
-> Print("IDS ---  BRANCH: DELETE -> insp", TIMESTAMP true)
-> Unstrip(14)
-> q3 -> ac_w_1 -> td_3;

search_dele[1]
-> search_conn;

search_conn[0]
-> cnt_http_bad_method_connect
-> Print("IDS ---  BRANCH: CONNECT -> insp", TIMESTAMP true)
-> Unstrip(14)
-> q3 -> ac_w_1 -> td_3;

search_conn[1]
-> cnt_uz_tcp_signal_80
-> Print("IDS ---  BRANCH: TCP sig port80 -> lb1", TIMESTAMP true)
-> Unstrip(14)
-> q2 -> ac_w_2 -> td_2;

put_check_passwd[0]
-> cnt_put_cat_etc_passwd
-> Print("IDS ---  BRANCH: PUT cat /etc/passwd -> insp", TIMESTAMP true)
-> Unstrip(14)
-> q3 -> ac_w_1 -> td_3;

put_check_passwd[1]
-> put_check_log;

put_check_log[0]
-> cnt_put_cat_var_log
-> Print("IDS ---  BRANCH: PUT cat /var/log -> insp", TIMESTAMP true)
-> Unstrip(14)
-> q3 -> ac_w_1 -> td_3;

put_check_log[1]
-> put_check_insert;

put_check_insert[0]
-> cnt_put_insert
-> Print("IDS ---  BRANCH: PUT INSERT -> insp", TIMESTAMP true)
-> Unstrip(14)
-> q3 -> ac_w_1 -> td_3;

put_check_insert[1]
-> put_check_update;

put_check_update[0]
-> cnt_put_update
-> Print("IDS ---  BRANCH: PUT UPDATE -> insp", TIMESTAMP true)
-> Unstrip(14)
-> q3 -> ac_w_1 -> td_3;

put_check_update[1]
-> put_check_delete;

put_check_delete[0]
-> cnt_put_delete
-> Print("IDS ---  BRANCH: PUT DELETE -> insp", TIMESTAMP true)
-> Unstrip(14)
-> q3 -> ac_w_1 -> td_3;

put_check_delete[1]
-> cnt_put_safe
-> Print("IDS ---  BRANCH: PUT safe -> lb1", TIMESTAMP true)
-> Unstrip(14)
-> q2 -> ac_w_2 -> td_2;

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
)