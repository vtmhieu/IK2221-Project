# IK2221 – Network Function Virtualization (Phase 1)

## Project Goal
The goal of this assignment is to gain hands-on experience with Network Functions Virtualization (NFV) by building a Mininet-based network that supports:
- A load balancer for LLM inferencing services.
- A Network Address and Port Translator (NAPT).
- An Intrusion Detection System (IDS).
- Packet capture and reporting for evaluation.

## Team Requirements
- Teams must consist of **5 students**.
- **NEW 2025:** Final project evaluation is **individual**.
- Every team member must be able to explain their own contribution and the whole project.
- Every team member must be present during the project discussion.

## Topology Overview
The project uses a Mininet topology with two zones:

### 1. User Zone (UZ)
Contains:
- `h1`, `h2`: End-user hosts.
- `sw1`: Layer 2 switch.
- `napt`: Network Address and Port Translator.

### 2. Inferencing Zone (IZ)
Contains:
- `sw2`: Core switch.
- `ids`: Intrusion Detection System.
- `lb1`: Load balancer.
- `sw3`: Switch connecting the load balancer to servers.
- `llm1`, `llm2`, `llm3`: Inferencing servers.
- `insp`: Inspector server.

## Naming and IP Rules
- You must strictly follow the naming convention shown in Figure 1.
- Switch names must be sequential:
  - `sw1`, `sw2`, `sw3`, etc.
- The object name in code must match the assigned device name.
- Sequential switch naming must produce human-friendly DPIDs.
- You must use the IP configuration from the figure.

### Required IPs
- `h1`: `10.0.0.50/24`
- `h2`: `10.0.0.51/24`
- `napt` user-side interface: `10.0.0.1/24`
- `napt` inferencing-side interface: `100.0.0.1/24`
- `insp`: `100.0.0.30/24`
- `llm1`: `100.0.0.40/24`
- `llm2`: `100.0.0.41/24`
- `llm3`: `100.0.0.42/24`
- Virtual service IP: `100.0.0.45/24`
- Load balancer service port: `80`

## Functional Requirements

### 1. NAPT
The NAPT must:
- Translate private IPs from the user zone to public IPs on outbound traffic.
- Translate public IPs back to private IPs on inbound traffic.
- Handle:
  - ARP properly.
  - TCP translation using `IPRewriter`.
  - ICMP echo request/reply using `ICMPPingRewriter`.
- Convert traffic between `10.0.0.0/24` and `100.0.0.0/24`.
- Support ping traffic to the virtual service.

### 2. Load Balancer (`lb1`)
The load balancer must provide:
- A virtual HTTP/TCP service at `100.0.0.45:80`.
- Round-robin forwarding to `llm1`, `llm2`, and `llm3`.
- Source translation so clients only see the virtual service IP.
- ARP replies for the virtual service IP.
- ICMP response support so users can ping the virtual IP.
- Blocking of all traffic not related to the required service.

#### Load Balancer behavior
- For ARP requests targeting the virtual IP:
  - Respond with a virtual MAC address.
- For IP traffic:
  - Forward requests to one of the inference servers using round-robin logic.
  - Rewrite destination IP to the selected server.
  - Rewrite source IP back to `100.0.0.45` on return traffic.
- Ignore irrelevant traffic.

### 3. IDS (`ids`)
The IDS must:
- Act as a transparent sniffer/forwarder.
- Allow ARP, ICMP, and TCP signaling to pass through.
- Inspect only HTTP traffic.

#### HTTP method filtering
The IDS must allow only:
- `POST`
- `PUT`

It must block and redirect all other HTTP methods to the inspector server.

#### Payload inspection
For HTTP `PUT` requests, inspect the beginning of the payload for:
- `cat /etc/passwd`
- `cat /var/log/`
- `INSERT`
- `UPDATE`
- `DELETE`

If a suspicious pattern is found:
- Redirect the packet to `insp`.

### 4. Inspector Server (`insp`)
The inspector:
- Is a passive Mininet host.
- Requires no active services.
- Must capture traffic on its interface.
- Must dump captured packets to a PCAP file for IDS verification.

## Click Implementation Requirements
The following modules must be implemented in **Click**:
- `lb1`
- `ids`
- `napt`

### General Click rules
- Capture packets from the corresponding Mininet switch interfaces.
- Use `FromDevice` with `SNIFFER false`.
- Use `AverageCounter` after each `FromDevice` and before each `ToDevice`.
- Use `Counter` to count packets by traffic class where classification is required.
- Use `DriverManager` to print counters into report files when the module terminates.

### Load balancer Click specifics
- Classify packets into:
  - ARP requests
  - ARP replies
  - IP packets
  - Other packets
- Use `ARPResponder` for ARP requests.
- Use `ARPQuerier` for ARP responses.
- Use `IPRewriter` with `RoundRobinIPMapper` for destination rewriting.
- Perform source rewriting for return traffic.

### IDS Click specifics
- Use `IPClassifier` to identify HTTP traffic.
- Use `Classifier` to inspect HTTP methods at the correct header offset.
- Use `Search` only to jump to the HTTP payload, not to search for malicious keywords.
- Redirect suspicious traffic to the inspector.

### NAPT Click specifics
- Handle ARP frames correctly.
- Use `IPRewriter` for TCP.
- Use `ICMPPingRewriter` for ICMP.
- Support both traffic directions between:
  - `10.0.0.0/24`
  - `100.0.0.0/24`

## Testing Requirements
You must provide automated tests that:
- Stress the full application.
- Verify behavior automatically.
- Do not rely on manual checking.

### Required testing tools
You may use:
- `ping`
- `iperf`
- `netcat`
- `wget`
- `curl`
- Python/Scapy

### Required test outputs
- Each Click module must generate a report file named:
  - `lb1.report`
  - `ids.report`
  - `napt.report`
- The report must include:
  - Input/output packet rates
  - Total packets read/written
  - Class-specific counters
  - Dropped packets

## Deliverables
You must submit a folder named:

```text
ik2221-assign-phase1-team<Number>
```

For example:
```text
ik2221-assign-phase1-team1
```

### Required structure
```text
ik2221-assign-phase1-team<Number>/
├── MEMBERS
├── Makefile
├── topology/
│   └── topology files
├── application/
│   └── controllers/
├── nfv/
│   └── Click modules
└── results/
    └── automated tests
```

### Submission rules
- Keep topology and application code in separate subfolders.
- Do not include garbage files.
- Follow the exact naming scheme.
- The project may fail automatic testing if files are misplaced.

## Makefile Rules
Your main `Makefile` must include:
- `topo`: start the topology.
- `app`: start the application/controller.
- `clean`: clean the system.
- `test`: run `topo`, `app`, and the tester script automatically.

## Report File
Before submission, create:
- `phase_1_report`

This file must contain redirected stdout/stderr from running:
- `make test`

It must be generated automatically by your scripts.

## Evaluation
### Grading breakdown
- NFV applications design and implementation: **40/100**
  - Load balancer: **10/100**
  - NAPT: **10/100**
  - IDS: **10/100**
  - Design quality: **5/100**
  - HTTP server setup and request generation: included in design
- Tests: **5/100**

### Phase weight
- Phase 1 counts for **40% of the final assignment grade**.

## Deadline
- Submission deadline: **2026-04-29 at 17:00**
- Check Canvas for the definitive deadline.

## VM and Environment
You must use the provided course VM for development and testing.

### Access
- Username: `ik2221`
- Password: `ik2221`

### Example SSH access
```bash
ssh -p 2222 ik2221@localhost
```

### macOS VM run example
```bash
qemu-system-x86_64 -smp 4 -m 4G -drive file=ik2221.qcow2,format=qcow2 -netdev user,id=net0,hostfwd=tcp::2222-:22 -device e1000,netdev=net0 -vga virtio -display default -usb -device usb-tablet
```

## Start-up Instructions
1. Run `make app` to start the controller.
2. Run `make topo` to start Mininet.
3. Use the Mininet CLI to test connectivity.
4. Use tools like `tcpdump` or Wireshark for debugging.

## Important Notes
- All assignments will be checked with a plagiarism tool.
- Large penalties apply for plagiarism.
- You may be given a zero if the submission structure is not correct or manual fixes are needed for testing.