
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from mininet.clean import cleanup
from topology.topology import *
import topology.testing as testing
import subprocess
import time


topos = {'mytopo': (lambda: MyTopo())}


def _reset_logs(paths):
    for path in paths:
        with open(path, "w", encoding="utf-8"):
            pass


def _graceful_stop_click():
    # SIGINT gives Click a chance to exit cleanly and run DriverManager final prints.
    subprocess.run("killall -SIGINT click >/dev/null 2>&1 || true", shell=True, check=False)
    time.sleep(2)


def run_tests(net):
    # You can automate some tests here

    h1 = net.get('h1')
    h2 = net.get('h2')
    s1 = net.get('s1')
    s2 = net.get('s2')
    napt = net.get('napt')
    ids = net.get('ids')
    llm1 = net.get('llm1')
    http_target = llm1


    # Test 1: Ping the Load balancer Virtual IP
    print("Testing ping from h1 to h2:")
    testing.ping(h1, h2, expected=True)
    
    print("Testing ping from h1 to napt:")
    testing.ping(h1, napt, expected=True)
    
    
    print("Testing ping from h1 to ids:")
    testing.ping(h1, ids, expected=True)
    
    print("Testing ping from h1 to llm1:")
    testing.ping(h1, llm1, expected=True)

    # Test 2: Test HTTP POST request
    print("Testing HTTP POST request from h1 to llm1 (through IDS path):")
    testing.curl(h1, http_target, method="POST", payload="test=data")

    # Test 3: Test HTTP PUT request
    print("Testing HTTP PUT request from h1 to llm1 (through IDS path):")
    testing.curl(h1, http_target, method="PUT", payload="test=data")

    # Test 4: Test HTTP GET request
    print("Testing HTTP GET request from h1 to llm1 (through IDS path):")
    testing.curl(h1, http_target, method="GET")

    # Test 5: Test HTTP DELETE request
    print("Testing HTTP DELETE request from h1 to llm1 (through IDS path):")
    testing.curl(h1, http_target, method="DELETE")

    # Test 6: Test HTTP OPTIONS request
    print("Testing HTTP OPTIONS request from h1 to llm1 (through IDS path):")
    testing.curl(h1, http_target, method="OPTIONS")

    # Test 7: Test HTTP TRACE request
    print("Testing HTTP TRACE request from h1 to llm1 (through IDS path):")
    testing.curl(h1, http_target, method="TRACE")

    # Test 8: Test HTTP CONNECT request
    print("Testing HTTP CONNECT request from h1 to llm1 (through IDS path):")
    testing.curl(h1, http_target, method="CONNECT")

    # Test 9: Test HTTP PUT with malicious payload
    print("Testing HTTP PUT with malicious payload from h1 to llm1 (through IDS path):")
    testing.curl(h1, http_target, method="PUT", payload="cat /etc/passwd")

    # Test 10: Test HTTP PUT with safe payload
    print("Testing HTTP PUT with safe payload from h1 to llm1 (through IDS path):")
    testing.curl(h1, http_target, method="PUT", payload="safe=data")

    print("Testing HTTP PUT with unsafe INSERT from h1 to llm1 (through IDS path):")
    testing.curl(h1, http_target, method="PUT", payload="INSERT")

    print("Testing HTTP PUT with unsafe UPDATE from h1 to llm1 (through IDS path):")
    testing.curl(h1, http_target, method="PUT", payload="UPDATE")

    print("Testing HTTP PUT with unsafe DELETE from h1 to llm1 (through IDS path):")
    testing.curl(h1, http_target, method="PUT", payload="DELETE")

    print("Testing HTTP PUT with unsafe payload from h1 to llm1 (through IDS path):")
    testing.curl(h1, http_target, method="PUT", payload="cat /var/log/")


if __name__ == "__main__":

    # Extra safety cleanup: remove stale mininet links/nodes before creating a new topology.
    cleanup()

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
    
    try:
        startup_services(net)
        run_tests(net)
    finally:
        print("--- Requesting graceful CLICK shutdown ---")
        _graceful_stop_click()

        # Always stop background services and the topology after tests.
        print("--- Cleaning up background services ---")
        for llm_name in ['llm1', 'llm2', 'llm3']:
            server = net.get(llm_name)
            server.cmd('pkill -f "python3 -m http.server 80" || true')

        net.stop()
        cleanup()
