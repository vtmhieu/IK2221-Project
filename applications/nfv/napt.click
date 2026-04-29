// Interfaces
define($PORT1 napt-eth1, $PORT2 napt-eth2)

// Script will run as soon as the router starts
Script(print "Click NAPT on $PORT1 $PORT2")

// IP configuration
AddressInfo(
  IN_ADDR    10.0.0.1/24    1A:1A:1A:1A:1A:1A,
  OUT_ADDR   100.0.0.1/24   2B:2B:2B:2B:2B:2B
)

// Device I/O
fd1::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)

td1::ToDevice($PORT1, METHOD LINUX)
td2::ToDevice($PORT2, METHOD LINUX)

// Counters
ac_fd1 :: AverageCounter
ac_fd2 :: AverageCounter
ac_td1 :: AverageCounter
ac_td2 :: AverageCounter

cnt_arp_req_in :: Counter
cnt_arp_rep_in :: Counter
cnt_arp_req_out :: Counter
cnt_arp_rep_out :: Counter
cnt_tcp_udp_in :: Counter
cnt_tcp_udp_out :: Counter
cnt_icmp_in :: Counter
cnt_icmp_out :: Counter

cnt_drop_user_nonip :: Counter
cnt_drop_user_other_ip :: Counter
cnt_drop_ext_nonip :: Counter
cnt_drop_ext_other_ip :: Counter

// Queues
q1 :: Queue
q2 :: Queue

q1 -> Print("NAPT: OUT -> user zone (td1)", MAXLENGTH 64, TIMESTAMP true) -> ac_td1 -> td1
q2 -> Print("NAPT: OUT -> ext zone (td2)", MAXLENGTH 64, TIMESTAMP true) -> ac_td2 -> td2

// Classifiers
c1::Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)
c2::Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -)

ip_class_in  :: IPClassifier(tcp or udp, icmp type echo, -)
ip_class_out :: IPClassifier(tcp or udp, icmp type echo-reply, -)


ip_filter_in :: IPFilter(
  allow dst 10.0.0.1 and icmp type echo,
  allow tcp,
  allow udp,
  allow icmp,
  deny all
)

ip_filter_out :: IPFilter(
  allow dst 100.0.0.1 and icmp type echo,
  allow tcp,
  allow udp,
  allow icmp,
  deny all
)

// ARP Handling
arp_in::ARPResponder(IN_ADDR)
arp_out::ARPResponder(OUT_ADDR)

aq_in::ARPQuerier(IN_ADDR)
aq_out :: ARPQuerier(OUT_ADDR)

// NAT Logic
iprw :: IPRewriter(
  pattern OUT_ADDR 1024-65535 - - 0 1,
  pattern IN_ADDR  - - - 1 0
)

icmprw :: ICMPPingRewriter(
  pattern OUT_ADDR 1024-65535 - - 0 1,
  pattern IN_ADDR  - - - 1 0
)

iprw[2] -> Print("NAPT: TCP/UDP NAT FAILED") -> Discard
icmprw[2] -> Print("NAPT: ICMP NAT FAILED") -> Discard


// ======== USER (IN) → OUT ========
fd1 -> ac_fd1 -> Print("NAPT: raw pkt from user zone", MAXLENGTH 64, TIMESTAMP true) -> c1

c1[0] -> cnt_arp_req_in -> Print("NAPT: ARP REQ from user", MAXLENGTH 64, TIMESTAMP true) -> arp_in -> Print("NAPT: ARP REPLY to user", MAXLENGTH 64, TIMESTAMP true) -> q1
c1[1] -> cnt_arp_rep_in -> Print("NAPT: ARP REPLY from user", MAXLENGTH 64, TIMESTAMP true) -> [1]aq_in
c1[2] -> Print("NAPT: IP from user", MAXLENGTH 64, TIMESTAMP true) -> Strip(14) -> CheckIPHeader -> ip_filter_in
c1[3] -> cnt_drop_user_nonip -> Print("NAPT: non-ARP/IP from user -> DISCARD", MAXLENGTH 64, TIMESTAMP true) -> Discard

// User zone ping interception vs transit forwarding
ip_filter_in[0] -> Print("NAPT: PING to gateway (user zone)") -> ICMPPingResponder() -> [0]aq_in
ip_filter_in[1] -> DecIPTTL -> IPPrint("NAPT: IP stripped from user", TIMESTAMP true) -> ip_class_in

ip_class_in[0] -> cnt_tcp_udp_in -> IPPrint("NAPT: TCP/UDP from user -> iprw[0]", TIMESTAMP true) -> [0]iprw
ip_class_in[1] -> cnt_icmp_in -> IPPrint("NAPT: ICMP echo from user -> icmprw[0]", TIMESTAMP true) -> [0]icmprw
ip_class_in[2] -> cnt_drop_user_other_ip -> IPPrint("NAPT: other IP from user -> DISCARD", TIMESTAMP true) -> Discard

iprw[0]   -> IPPrint("NAPT: iprw[0] translated TCP/UDP -> ext", TIMESTAMP true) -> aq_out
icmprw[0] -> IPPrint("NAPT: icmprw[0] translated ICMP -> ext", TIMESTAMP true) -> aq_out

aq_out[0] -> Print("NAPT: aq_out[0] -> q2", MAXLENGTH 64, TIMESTAMP true) -> q2
aq_out[1] -> Print("NAPT: aq_out[1] ARP query -> q2", MAXLENGTH 64, TIMESTAMP true) -> q2


// ======== OUT → USER (IN) ========
fd2 -> ac_fd2 -> Print("NAPT: raw pkt from ext zone", MAXLENGTH 64, TIMESTAMP true) -> c2

c2[0] -> cnt_arp_req_out -> Print("NAPT: ARP REQ from ext", MAXLENGTH 64, TIMESTAMP true) -> arp_out -> Print("NAPT: ARP REPLY to ext", MAXLENGTH 64, TIMESTAMP true) -> q2
c2[1] -> cnt_arp_rep_out -> Print("NAPT: ARP REPLY from ext", MAXLENGTH 64, TIMESTAMP true) -> [1]aq_out
c2[2] -> Print("NAPT: IP from ext", MAXLENGTH 64, TIMESTAMP true) -> Strip(14) -> CheckIPHeader -> ip_filter_out
c2[3] -> cnt_drop_ext_nonip -> Print("NAPT: non-ARP/IP from ext -> DISCARD", MAXLENGTH 64, TIMESTAMP true) -> Discard

// Ext zone ping interception vs transit forwarding
ip_filter_out[0] -> Print("NAPT: PING to gateway (ext zone)") -> ICMPPingResponder() -> [0]aq_out
ip_filter_out[1] -> DecIPTTL -> IPPrint("NAPT: IP stripped from ext", TIMESTAMP true) -> ip_class_out

ip_class_out[0] -> cnt_tcp_udp_out -> IPPrint("NAPT: return TCP/UDP -> iprw[1]", TIMESTAMP true) -> [1]iprw
ip_class_out[1] -> cnt_icmp_out -> IPPrint("NAPT: return ICMP reply -> icmprw[1]", TIMESTAMP true) -> [1]icmprw
ip_class_out[2] -> cnt_drop_ext_other_ip -> IPPrint("NAPT: other return IP -> DISCARD", TIMESTAMP true) -> Discard

iprw[1]   -> IPPrint("NAPT: iprw[1] un-NAT TCP/UDP -> user", TIMESTAMP true) -> aq_in
icmprw[1] -> IPPrint("NAPT: icmprw[1] un-NAT ICMP -> user", TIMESTAMP true) -> aq_in

aq_in[0] -> Print("NAPT: aq_in[0] -> q1", MAXLENGTH 64, TIMESTAMP true) -> q1
aq_in[1] -> Print("NAPT: aq_in[1] ARP query -> q1", MAXLENGTH 64, TIMESTAMP true) -> q1


// ======== Lifecycle & Reporting ========
DriverManager(
 print "NAPT starting",
 wait,

 print "================ NAPT REPORT ================",

 print "Input rate (user pps): " $(ac_fd1.rate),
 print "Input rate (ext pps): " $(ac_fd2.rate),

 print "Output rate (user pps): " $(ac_td1.rate),
 print "Output rate (ext pps): " $(ac_td2.rate),

 print "Input packets (user): " $(ac_fd1.count),
 print "Input packets (ext): " $(ac_fd2.count),

 print "Output packets (user): " $(ac_td1.count),
 print "Output packets (ext): " $(ac_td2.count),

 print "--- Traffic ---",
 print "ARP req user: " $(cnt_arp_req_in.count),
 print "ARP rep user: " $(cnt_arp_rep_in.count),
 print "ARP req ext: " $(cnt_arp_req_out.count),
 print "ARP rep ext: " $(cnt_arp_rep_out.count),

 print "TCP/UDP out: " $(cnt_tcp_udp_in.count),
 print "TCP/UDP in: " $(cnt_tcp_udp_out.count),

 print "ICMP out: " $(cnt_icmp_in.count),
 print "ICMP in: " $(cnt_icmp_out.count),

 print "--- Drops ---",
 print "User non-IP: " $(cnt_drop_user_nonip.count),
 print "User other IP: " $(cnt_drop_user_other_ip.count),
 print "Ext non-IP: " $(cnt_drop_ext_nonip.count),
 print "Ext other IP: " $(cnt_drop_ext_other_ip.count),

 print "============================================",
 stop
)