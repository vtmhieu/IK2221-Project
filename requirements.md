Load Balancer (lb1): First, the load balancer must read packets from the interface 
and classify the packets into four basic classes. ARP requests, APR replies, IP 
packets, other packets. Upon an ARP request (that targets the virtual IP of the 
corresponding service), an ARP reply must be generated using an ARPResponder 
element per interface. This reply must contain the MAC address of the virtual 
service. Of course, this MAC address will be virtual as well 1, but the hosts should 
be able to generate IP packets after getting back an ARP reply from the load 
balancer. ARP responses must be sent to ARPQuerier elements (one per 
interface). IP packets must be sent to a pipeline of elements that will realize the 
load balancing procedure explained above. There are two directions for the load 
balancer, one towards the servers and another towards the clients. Hence two 
pipelines are required as we explain below. Finally, packets that are neither ARP 
nor IP must be discarded.  
IP pipeline towards the servers: A classifier/filter must be applied to packets coming 
from the external interface, which have destination IPs different from the virtual IP. 
After this classifier, a modification element (i.e., IPRewriter) should work in 
tandem with RoundRobinIPMapper in order to write the correct destination 
addresses (of one server) to the incoming packet.   
IP pipeline towards the clients: The IPRewriter element above should also 
translate the source address of the servers into the virtual addresses that the load 
balancer possesses. That way, the client cannot notice the existence of this “proxy” 
node.  
Any other traffic (not ping to LB and web traffic) is not required to work through the 
Load Balancer. You can safely ignore the cases where the web server instantiates 
connections to other external hosts.  