
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
from results.phase_1_report import write_phase_1_report


topos = {'mytopo': (lambda: MyTopo())}


def _reset_logs(paths):
    for path in paths:
        with open(path, "w", encoding="utf-8"):
            pass


def _graceful_stop_click():
    # SIGINT gives Click a chance to exit cleanly and run DriverManager final prints.
    subprocess.run("killall -SIGINT click >/dev/null 2>&1 || true", shell=True, check=False)
    time.sleep(2)


def _read_ids_report(path):
    stats = {}
    with open(path, "r", encoding="utf-8") as report:
        for line in report:
            if ":" not in line:
                continue
            label, value = line.split(":", 1)
            label = label.strip()
            value = value.strip()
            if not value:
                continue
            try:
                stats[label] = int(value)
            except ValueError:
                continue
    return stats


def _check_ids_report(path):
    stats = _read_ids_report(path)

    total_user = stats.get("Total received user packets", 0)
    sent_inspector = stats.get("Total packets sent to insepctor", 0)
    sent_lb = stats.get("Total packets sent to LB", 0)

    received_arp = stats.get("Received from user (ARP)", 0)
    received_icmp = stats.get("Received from user (ICMP)", 0)
    received_http = stats.get("Received from user (HTTP)", 0)

    tcp_80 = stats.get("Received from user (TCP signaling on port 80)", 0)
    http_put = stats.get("HTTP PUT observed", 0)
    http_get_bad = stats.get("HTTP GET bad method to inspector", 0)
    http_head_bad = stats.get("HTTP HEAD bad method to inspector", 0)
    http_options_bad = stats.get("HTTP OPTIONS bad method to inspector", 0)
    http_trace_bad = stats.get("HTTP TRACE bad method to inspector", 0)
    http_delete_bad = stats.get("HTTP DELETE bad method to inspector", 0)
    http_connect_bad = stats.get("HTTP CONNECT bad method to inspector", 0)

    put_safe = stats.get("PUT safe to lb1", 0)
    put_passwd = stats.get("PUT cat /etc/passwd blocked", 0)
    put_varlog = stats.get("PUT cat /var/log/ blocked", 0)
    put_insert = stats.get("PUT INSERT blocked", 0)
    put_update = stats.get("PUT UPDATE blocked", 0)
    put_delete = stats.get("PUT DELETE blocked", 0)

    checks = [
        (
            "sent_inspector + sent_lb == total_received_user",
            (sent_inspector + sent_lb) == total_user,
        ),
        (
            "arp + icmp + http == total_received_user",
            (received_arp + received_icmp + received_http) == total_user,
        ),
        (
            "http_put + bad_methods + tcp_80 == received_http",
            (
                http_put
                + http_get_bad
                + http_head_bad
                + http_options_bad
                + http_trace_bad
                + http_delete_bad
                + http_connect_bad
                + tcp_80
            )
            == received_http,
        ),
        (
            "http_put == sum(put breakdown)",
            (put_safe + put_passwd + put_varlog + put_insert + put_update + put_delete)
            == http_put,
        ),
    ]

    print("--- IDS report consistency checks ---")
    for label, result in checks:
        print(f"{label}: {result}")


def run_tests(net):
    h1 = net.get('h1')
    h2 = net.get('h2')
    s1 = net.get('s1')
    s2 = net.get('s2')
    napt = net.get('napt')
    ids = net.get('ids')
    llm1 = net.get('llm1')
    http_target = llm1

    sequence = [
        ("curl", "GET", None),
        ("curl", "POST", "test=data"),
        ("ping", h1, h2),
        ("curl", "PUT", "safe=data"),
        ("curl", "DELETE", None),
        ("curl", "OPTIONS", None),
        ("ping", h1, napt),
        ("curl", "TRACE", None),
        ("curl", "CONNECT", None),
        ("curl", "PUT", "cat /etc/passwd"),
        ("curl", "POST", "alpha=1&beta=2"),
        ("curl", "PUT", "INSERT"),
        ("ping", h1, ids),
        ("curl", "PUT", "UPDATE"),
        ("curl", "PUT", "DELETE"),
        ("curl", "PUT", "cat /var/log/"),
        ("curl", "GET", None),
        ("curl", "POST", "name=test"),
        ("ping", h1, llm1),
        ("curl", "PUT", "payload=xyz"),
    ]

    print("Running 2-minute repeating sequence of curls/pings...")
    start_time = time.monotonic()
    index = 0
    while time.monotonic() - start_time < 120:
        action = sequence[index]
        if action[0] == "ping":
            src, dst = action[1], action[2]
            print(f"Ping {src.name} -> {dst.name}:")
            testing.ping(src, dst, expected=True)
        else:
            method, payload = action[1], action[2]
            if payload is None:
                print(f"Curl {method} {http_target.name}:")
                testing.curl(h1, http_target, method=method)
            else:
                print(f"Curl {method} {http_target.name} payload={payload}:")
                testing.curl(h1, http_target, method=method, payload=payload)

        index = (index + 1) % len(sequence)

    _check_ids_report("/home/ik2221/IK2221-Project/results/ids.report")


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

    write_phase_1_report()
