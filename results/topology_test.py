
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


def _reset_terminal_output():
    subprocess.run("stty sane 2>/dev/null || true", shell=True, check=False)
    subprocess.run("stty onlcr 2>/dev/null || true", shell=True, check=False)


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
    _reset_terminal_output()

    h1 = net.get('h1')
    h2 = net.get('h2')
    napt = net.get('napt')
    ids = net.get('ids')
    lb_vip = "100.0.0.45"
    http_target = lb_vip
    results = []

    def record(name, passed):
        results.append((name, passed))
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {name}")


    # Test 1: Ping the Load balancer Virtual IP
    record("ping h1 -> h2", testing.ping(h1, h2, expected=True))
    
    record("ping h1 -> napt", testing.ping(h1, napt, expected=True))
    
    
    # record("ping h1 -> ids", testing.ping(h1, ids, expected=True))
    
    record("ping h1 -> load balancer VIP", testing.ping(h1, lb_vip, expected=True))

    # Test 2: Test HTTP POST request
    record(
        "HTTP POST allowed through IDS to VIP",
        testing.curl(h1, http_target, method="POST", payload="test=data"),
    )

    # Test 3: Test HTTP PUT request
    record(
        "HTTP PUT allowed through IDS to VIP",
        testing.curl(h1, http_target, method="PUT", payload="test=data"),
    )

    # Test 4: Test HTTP GET request
    record(
        "HTTP GET blocked/diverted by IDS",
        testing.curl(h1, http_target, method="GET", expected=False),
    )

    # Test 5: Test HTTP DELETE request
    record(
        "HTTP DELETE blocked/diverted by IDS",
        testing.curl(h1, http_target, method="DELETE", expected=False),
    )

    # Test 6: Test HTTP OPTIONS request
    record(
        "HTTP OPTIONS blocked/diverted by IDS",
        testing.curl(h1, http_target, method="OPTIONS", expected=False),
    )

    # Test 7: Test HTTP TRACE request
    record(
        "HTTP TRACE blocked/diverted by IDS",
        testing.curl(h1, http_target, method="TRACE", expected=False),
    )

    # Test 8: Test HTTP CONNECT request
    record(
        "HTTP CONNECT blocked/diverted by IDS",
        testing.curl(h1, http_target, method="CONNECT", expected=False),
    )

    # Test 9: Test HTTP PUT with malicious payload
    record(
        "HTTP PUT cat /etc/passwd blocked/diverted by IDS",
        testing.curl(h1, http_target, method="PUT", payload="cat /etc/passwd", expected=False),
    )

    # Test 10: Test HTTP PUT with safe payload
    record(
        "HTTP PUT safe payload allowed through IDS to VIP",
        testing.curl(h1, http_target, method="PUT", payload="safe=data"),
    )
    #Tests 11-14: Test HTTP PUT with various malicious payloads
    record(
        "HTTP PUT INSERT blocked/diverted by IDS",
        testing.curl(h1, http_target, method="PUT", payload="INSERT", expected=False),
    )

    record(
        "HTTP PUT UPDATE blocked/diverted by IDS",
        testing.curl(h1, http_target, method="PUT", payload="UPDATE", expected=False),
    )

    record(
        "HTTP PUT DELETE blocked/diverted by IDS",
        testing.curl(h1, http_target, method="PUT", payload="DELETE", expected=False),
    )

    record(
        "HTTP PUT cat /var/log/ blocked/diverted by IDS",
        testing.curl(h1, http_target, method="PUT", payload="cat /var/log/", expected=False),
    )

    #Tests 15-20: Duplicate some above tests from h2

    record(
        "HTTP POST allowed through IDS to VIP",
        testing.curl(h2, http_target, method="POST", payload="test=data"),
    )

    record(
        "HTTP PUT allowed through IDS to VIP",
        testing.curl(h2, http_target, method="PUT", payload="test=data"),
    )

    record(
        "HTTP GET blocked/diverted by IDS",
        testing.curl(h2, http_target, method="GET", expected=False),
    )

    record(
        "HTTP DELETE blocked/diverted by IDS",
        testing.curl(h2, http_target, method="DELETE", expected=False),
    )

    record(
        "HTTP HEAD blocked/diverted by IDS",
        testing.curl(h2, http_target, method="HEAD", expected=False),
    )

    record(
        "HTTP PUT safe payload allowed through IDS to VIP",
        testing.curl(h2, http_target, method="PUT", payload="safe=data"),
    )

    record(
        "HTTP PUT INSERT blocked/diverted by IDS",
        testing.curl(h2, http_target, method="PUT", payload="INSERT", expected=False),
    )
    

    passed_count = sum(1 for _, passed in results if passed)
    failed = [(name, passed) for name, passed in results if not passed]

    print("")
    print("================= TEST RECAP =================")
    for name, passed in results:
        status = "PASS" if passed else "FAIL"
        print(f"{status}: {name}")
    print("----------------------------------------------")
    print(f"Passed: {passed_count}/{len(results)}")
    print(f"Failed: {len(failed)}/{len(results)}")
    print("==============================================")

    return not failed


if __name__ == "__main__":

    # Extra safety cleanup: remove stale mininet links/nodes before creating a new topology.
    cleanup()
    _reset_terminal_output()

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
    _reset_terminal_output()

    print("Waiting 10 seconds for controllers, switches, and CLICK nodes to initialize...")
    time.sleep(10)
    
    tests_passed = False
    try:
        startup_services(net)
        tests_passed = run_tests(net)
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

    if not tests_passed:
        raise SystemExit(1)
