
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from topology import *
import testing
import time


topos = {'mytopo': (lambda: MyTopo())}


def run_tests(net):
    # You can automate some tests here

    h1 = net.get('h1')
    h2 = net.get('h2')
    s1 = net.get('s1')
    s2 = net.get('s2')
    napt = net.get('napt')
    ids = net.get('ids')
    llm1 = net.get('llm1')


    # Test 1: Ping the Load balancer Virtual IP
    print("Testing ping from h1 to h2:")
    testing.ping(h1, h2, expected=True)
    
    print("Testing ping from h1 to napt:")
    testing.ping(h1, napt, expected=True)
    
    
    print("Testing ping from h1 to ids:")
    testing.ping(h1, ids, expected=True)
    
    print("Testing ping from h1 to llm1:")
    testing.ping(h1, llm1, expected=True)


if __name__ == "__main__":

    # Create topology
    topo = MyTopo()

    ctrl = RemoteController("c0", ip="127.0.0.1", port=6633)

    # Create the network
    net = Mininet(topo=topo,
                  switch=OVSSwitch,
                  controller=ctrl,
                  autoSetMacs=True,
                  autoStaticArp=True,
                  build=True,
                  cleanup=True)

    # Start the network
    net.start()

    print("Waiting 10 seconds for controllers, switches, and CLICK nodes to initialize...")
    time.sleep(10)
    
    startup_services(net)
    run_tests(net)

    # Start the CLI
    CLI(net)

    # You may need some commands before stopping the network! If you don't, leave it empty
    ### COMPLETE THIS PART ###
    
    # We must kill the python web servers we started in the background
    print("--- Cleaning up background services ---")
    for llm_name in ['llm1', 'llm2', 'llm3']:
        server = net.get(llm_name)
        server.cmd('kill %python3')

    net.stop()
