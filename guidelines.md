# IK2221 Phase 1 — Target Project Structure and Architecture Guide

This document describes the **target structure** that the project should achieve so that another coding agent can understand the architecture, folder layout, implementation boundaries, runtime flow, and acceptance criteria without needing to reverse-engineer the assignment brief. The project is a Mininet-based NFV system built around POX, OpenFlow learning switches, and Click-based virtual network functions implementing a NAPT, an IDS, and a load balancer in front of three lightweight HTTP servers.[file:1]

The assignment requires a topology with a **User Zone** and an **Inferencing Zone**, strict node naming and IP conventions, Click implementations for `napt`, `ids`, and `lb1`, automated tests, generated report files, and a submission package that follows an exact folder and Makefile layout.[file:1]

## System objective

The system must emulate a small virtualized network where two users in a private subnet access a virtual HTTP service exposed at `100.0.0.45:80`, while the infrastructure transparently performs address translation, malicious HTTP filtering, and round-robin load balancing across three backend inference servers.[file:1]

From a software-architecture perspective, the project is not just “a topology plus some scripts.” It is a coordinated NFV pipeline in which Mininet instantiates the nodes and links, POX boots and coordinates the application logic, Open vSwitch provides L2 switch behavior for `sw1`, `sw2`, and `sw3`, and Click modules implement the packet-processing logic for `napt`, `ids`, and `lb1` after these nodes register with the controller.[file:1]

## Desired mental model

An agent working on this repository should think in terms of **four layers** that must fit together cleanly.[file:1]

1. **Topology layer**: defines Mininet nodes, links, interfaces, IPs, default routes, startup behavior, and naming conventions.[file:1]
2. **Controller layer**: starts POX, handles switch registration, and launches the proper Click program for each NFV node through the provided controller framework.[file:1]
3. **NFV layer**: implements packet processing in Click for `napt`, `ids`, and `lb1`, replacing the skeleton forwarding-only behavior with actual translation, inspection, and balancing logic.[file:1]
4. **Validation layer**: runs automated tests, captures expected outputs, and generates `.report` files and a global `phase_1_report` from `make test`.[file:1]

A clean solution keeps each layer separate and makes the interfaces between them obvious. The topology should instantiate the world, the controller should orchestrate the runtime, the Click modules should own packet behavior, and the tests should verify the full system automatically.[file:1]

## Network architecture

The network is divided into two zones. The **User Zone (UZ)** contains `h1`, `h2`, and `sw1`, with both user hosts placed behind the `napt` function so their private addresses remain hidden from the outside world.[file:1]

The **Inferencing Zone (IZ)** contains `sw2`, `ids`, `lb1`, `sw3`, the passive inspector host `insp`, and the three backend servers `llm1`, `llm2`, and `llm3`.[file:1]

### User Zone

The user-side subnet is the private network `10.0.0.0/24`. Host `h1` must use `10.0.0.50/24`, host `h2` must use `10.0.0.51/24`, and the user-facing interface of `napt` must use `10.0.0.1/24` so that both hosts can use it as the default gateway.[file:1]

`sw1` is a regular OpenFlow L2 learning switch. It should not contain custom NFV logic; its role is connectivity between the hosts and the edge NFV device.[file:1]

### Inferencing Zone

The inferencing-side network uses `100.0.0.0/24`. The inferencing-side interface of `napt` must use `100.0.0.1/24`, the inspector host `insp` must use `100.0.0.30/24`, and the backend servers must be `llm1=100.0.0.40/24`, `llm2=100.0.0.41/24`, and `llm3=100.0.0.42/24`.[file:1]

The load-balanced virtual service IP is `100.0.0.45/24` on TCP port 80, and this is not a real host interface but a virtual service endpoint owned logically by `lb1`.[file:1]

### Traffic path

The intended traffic path is: user host -> `sw1` -> `napt` -> `sw2` -> `ids` -> `lb1` -> `sw3` -> one of `llm1/llm2/llm3`, with suspicious HTTP traffic diverted from `ids` to `insp` instead of continuing to the load balancer.[file:1]

The architecture matters because the project requirements are sequential: `napt` must translate private users into the public inferencing subnet, `ids` must inspect HTTP semantics before requests reach the virtual service, and `lb1` must expose one stable public service while hiding the backend server identities from clients.[file:1]

## Naming constraints

The naming constraints are part of the required structure, not style suggestions. The project description explicitly requires the code to follow the device names from the figure and to create switches sequentially as `sw1`, `sw2`, `sw3`, and so on, so that Mininet/OpenFlow produce human-friendly DPIDs and the controller can distinguish devices reliably.[file:1]

That means the topology code should keep object names, switch names, and host names aligned with the assignment notation. A future agent should avoid renaming these nodes for convenience because that can break controller assumptions, test scripts, or debugging expectations.[file:1]

## Functional decomposition

A good target structure assigns one clear responsibility to each main component. That separation makes the project easier to test and easier for another agent to modify safely.[file:1]

### `napt` responsibility

`napt` is the edge translator between the user private subnet and the inferencing subnet. It must apply Source NAPT for outbound traffic and Destination NAPT for inbound traffic so that external nodes never see the private `10.0.0.x` addresses of `h1` and `h2`.[file:1]

The assignment requires `napt` to handle ARP correctly and to perform address/port translation for TCP using `IPRewriter` and for ICMP echo request/reply using `ICMPPingRewriter`.[file:1]

From a design standpoint, `napt` should be treated as a bidirectional packet-rewrite appliance with two interfaces and clear inside/outside roles. The logic should not leak policy concerns from IDS or balancing concerns from the load balancer into this module.[file:1]

### `ids` responsibility

`ids` is an inline transparent HTTP inspector. It has no assigned IP and acts as a sniffer/forwarder that allows ARP, ICMP requests/responses, and TCP signaling to pass transparently while selectively analyzing HTTP requests.[file:1]

Its first duty is HTTP method enforcement: only `POST` and `PUT` requests may proceed to `lb1`, while other methods such as `GET`, `HEAD`, `OPTIONS`, `TRACE`, `DELETE`, or `CONNECT` must be diverted to `insp`.[file:1]

Its second duty is payload inspection for HTTP `PUT` requests. The beginning of the payload must be checked for the suspicious patterns `cat /etc/passwd`, `cat /var/log/`, `INSERT`, `UPDATE`, and `DELETE`, and matching traffic must be redirected to the inspector.[file:1]

The important architectural point is that `ids` is a policy gate before the service. It is not responsible for serving packets, not responsible for NAT, and not responsible for backend selection.[file:1]

### `lb1` responsibility

`lb1` owns the virtual service `100.0.0.45:80`. When a request arrives for this virtual IP, `lb1` must select one of the three backend servers in round-robin order, rewrite the destination accordingly, and forward the packet toward `sw3`.[file:1]

On the return path, `lb1` must rewrite the source of backend responses so the client sees the virtual service IP rather than the real server address. This hides the presence of the backend cluster and makes the system behave like a single service endpoint.[file:1]

`lb1` must also answer ARP requests targeting the virtual service IP using a virtual MAC and must generate ICMP responses so users can successfully ping the virtual IP.[file:1]

### `insp` responsibility

`insp` is passive. It does not provide application services to the rest of the topology and exists primarily as a sink for suspicious traffic plus a packet-capture endpoint that writes evidence to PCAP.[file:1]

The system should ensure the link from `ids` to `insp` is always active and that packet capture is configured, for example using `tcpdump`, even though the PCAP itself does not need to be submitted.[file:1]

### `sw1`, `sw2`, `sw3` responsibility

These three switches are ordinary OpenFlow v1.0 L2 learning switches implemented with POX/Open vSwitch according to the skeleton. They should remain simple forwarding devices and not become a place for custom NFV behavior that belongs in Click modules.[file:1]

A future agent should preserve that boundary. If a behavior is required because of packet semantics or service policy, it probably belongs in `napt`, `ids`, or `lb1`, not in ad hoc switch rules beyond the normal controller-driven L2 behavior.[file:1]

## Runtime architecture

At runtime, Mininet creates the topology and the hosts, switches, and NFV nodes. POX starts separately through `make app`, and when the relevant NFV nodes register, the controller launches the corresponding Click programs using the provided framework and `subprocess.Popen()` behavior described in the project brief.[file:1]

This implies a useful implementation rule: **do not tightly couple Click startup logic to arbitrary shell scripts** if the skeleton already expects startup through the controller. The stable design is for the topology to boot the nodes, the controller to observe them, and the controller to start the appropriate Click modules for each NFV element.[file:1]

## Recommended repository structure

The assignment mandates an exact submission structure. The final package must be a folder named `ik2221-assign-phase1-team<Number>` containing a `MEMBERS` file, a top-level `Makefile`, a `topology` directory, an `application` directory, an `nfv` directory, and a `results` directory.[file:1]

A practical internal structure that stays consistent with the required layout is shown below.[file:1]

```text
ik2221-assign-phase1-team<Number>/
├── MEMBERS
├── Makefile
├── phase_1_report
├── topology/
│   ├── Makefile
│   ├── topology.py
│   ├── topology_test.py
│   └── __init__.py            # optional, only if useful
├── application/
│   ├── Makefile
│   └── controllers/
│       ├── baseController.py
│       ├── main controller module(s)
│       └── helper modules
├── nfv/
│   ├── lb1.click
│   ├── ids.click
│   ├── napt.click
│   └── optional helper config/data files
└── results/
    ├── test scripts
    ├── generated .report files after test run
    └── optional captured outputs/log summaries
```

This layout preserves the professor’s required packaging while giving an implementation agent a clean map of where each concern lives.[file:1]

## Folder-by-folder intent

### `MEMBERS`

This file is part of the required submission format and must contain the name and email of each team member.[file:1]

For an agent, this file is not operational logic. It should be treated as submission metadata and not as a place for runtime settings or documentation.[file:1]

### Top-level `Makefile`

The main `Makefile` is part of the grading interface. It must provide the rules `topo`, `app`, `clean`, and `test`, where `test` launches the topology, controller, and tester script to produce a summary of test results.[file:1]

This Makefile should act as the system entry point. Another agent should assume that teaching assistants and automated graders will interact with the repository almost entirely through these targets, so correctness and robustness here matter as much as the internal code.[file:1]

### `topology/`

This directory should contain the Mininet topology implementation and the topology-aware test scaffolding. It should define all nodes, links, IPs, default routes, and startup behavior required for the environment to function correctly.[file:1]

The assignment mentions a provided `topology_test.py` skeleton for test execution, and the topology layer is also expected to support cleanup through `make clean`.[file:1]

The target design is for this folder to answer questions like:
- What nodes exist?
- How are they connected?
- What are their interface addresses?
- What should start automatically when Mininet comes up?
- How are default routes configured for `h1` and `h2`?[file:1]

### `application/controllers/`

This directory should contain the POX controller sources. It is the coordination layer that reacts to registration events and launches the Click modules for the NFV nodes according to the skeleton controller design.[file:1]

The controller should not re-implement the packet-processing logic already assigned to Click. Its job is orchestration, OpenFlow switch handling for the regular switches, and clean startup/shutdown integration.[file:1]

### `nfv/`

This directory is the heart of the NFV logic. It must contain the Click modules for `napt`, `ids`, and `lb1`, replacing the skeleton’s simple forwarding behavior with the required data-plane functionality.[file:1]

A useful internal convention is to treat each Click file as a self-contained network appliance with explicit inputs, outputs, classification stages, and counters. Another agent should be able to open one file and understand what packet classes it handles, what it rewrites, what it drops, and what counters it emits.[file:1]

### `results/`

This directory should contain the automated tests that stress the whole application and any artifacts generated by those tests, especially the `.report` outputs required for each Click network function.[file:1]

It should be thought of as the reproducibility and evidence folder. If someone wants proof that the topology, policy, and packet-processing logic work correctly, this is where they should look first.[file:1]

## Internal architecture expectations

Another agent should aim for a structure where each major requirement maps to one obvious code location.[file:1]

| Requirement | Preferred ownership |
|---|---|
| Node creation, links, IPs, default routes | `topology/` [file:1] |
| POX startup and NFV module launch | `application/controllers/` [file:1] |
| NAPT translation logic | `nfv/napt.click` [file:1] |
| IDS HTTP method and payload inspection | `nfv/ids.click` [file:1] |
| Virtual service ARP, ICMP, and round-robin balancing | `nfv/lb1.click` [file:1] |
| End-to-end verification and reporting | `results/` plus top-level `Makefile` [file:1] |

This mapping is important because it prevents a common failure mode: spreading one requirement across multiple unrelated files without a clear owner.[file:1]

## Topology design targets

The topology should instantiate the exact assignment nodes and should preserve the logical ordering of NFV functions in the path. A strong implementation makes the data path obvious from the topology code rather than relying on hidden assumptions in controller logic.[file:1]

At a minimum, the topology should ensure that `h1` and `h2` can route through `10.0.0.1`, that servers and the inspector are reachable in the `100.0.0.0/24` subnet, and that the NFV nodes are placed in-line where the packet path naturally enforces NAPT first, IDS second, and load balancing third.[file:1]

The hosts and servers only need assigned IP address, subnet mask, and default gateway, while the actual service on `llm1`, `llm2`, and `llm3` can be lightweight Python HTTP servers serving the same 3–5 test pages rather than any real LLM inference stack.[file:1]

## Load balancer structure target

The load balancer module should be organized around **packet classes and traffic direction**. The brief explicitly expects classification into ARP requests, ARP replies, IP packets, and other packets, with non-ARP/non-IP traffic discarded.[file:1]

A clean internal layout for `lb1.click` is:
- ingress from each interface;
- counters near `FromDevice` and `ToDevice`;
- ARP handling branch for virtual IP resolution;
- IP branch split by direction;
- external-to-server rewrite path using `RoundRobinIPMapper` and `IPRewriter`;
- server-to-client rewrite path restoring the virtual service IP;
- discard branch for unsupported traffic.[file:1]

The agent should preserve the idea that the LB is both a service facade and a translator. It is not simply choosing a backend; it is also hiding backend identity consistently in both directions.[file:1]

## IDS structure target

The IDS module should be organized as a transparent forwarder with a selective HTTP analysis branch. The key design challenge is accurate parsing boundaries: method matching must happen in the correct HTTP header position, and payload keyword matching must inspect the first bytes after the HTTP header rather than searching arbitrarily through the entire packet.[file:1]

The brief explicitly notes that `Search` should be used to advance to the payload boundary, while actual malicious-pattern matching should rely on `Classifier` and the hexadecimal values of the target patterns rather than using `Search` inefficiently for the keywords themselves.[file:1]

A good mental model for `ids.click` is:
- fast-pass path for ARP, ICMP, and TCP signaling;
- HTTP-identification path via `IPClassifier`;
- method-based split allowing only `POST` and `PUT` to continue;
- payload-inspection branch for `PUT` traffic;
- redirect-to-inspector output for suspicious or disallowed requests.[file:1]

## NAPT structure target

The NAPT module should be implemented as a bidirectional translator with one inside-facing and one outside-facing interface. It must process ARP appropriately and maintain translation behavior for both TCP and ICMP echo traffic.[file:1]

A strong design for `napt.click` separates:
- inbound-from-user traffic;
- inbound-from-inferencing-zone traffic;
- ARP handling;
- TCP rewrite path through `IPRewriter`;
- ICMP echo rewrite path through `ICMPPingRewriter`;
- device I/O counters before and after packet handling.[file:1]

The most important structural principle is to keep subnet translation consistent: inside users are `10.0.0.0/24`, outside-facing translated traffic is `100.0.0.0/24`, and the boundary IPs are `10.0.0.1` and `100.0.0.1`.[file:1]

## Testing architecture target

The tests must be **automated** and should verify behavior programmatically rather than telling a human what to look for. The project description is explicit that grading will use the staff’s own test script too, so implementation should cover scenarios comprehensively rather than overfitting to a narrow demo.[file:1]

A mature target structure includes tests for at least the following behaviors:[file:1]
- basic connectivity and routing where appropriate;
- successful ping from the user zone to the virtual service IP through the LB-generated ICMP handling;
- successful HTTP access to `100.0.0.45:80` with only allowed methods;
- round-robin backend distribution across `llm1`, `llm2`, and `llm3`;
- rejection or diversion of disallowed HTTP methods;
- diversion of suspicious `PUT` payloads to the inspector path;
- generation of `.report` files for `lb1`, `ids`, and `napt`.[file:1]

The agent should design tests not only around “does traffic pass?” but also around “does traffic go to the correct destination, get dropped when required, and leave evidence in counters or captures?” because the assignment grades both NFV functionality and testing quality.[file:1]

## Reporting requirements

Each Click module must generate a report file named after the function, such as `lb1.report`, after the automated tests have stressed the application and the modules terminate. These files should include packet read/write counts, observed throughput via `AverageCounter`, and class-level counts via `Counter` where classification exists.[file:1]

In addition, the repository must include a `phase_1_report` file containing the redirected stdout and stderr from `make test`, and this file must be generated automatically by the scripts rather than edited manually.[file:1]

This means the reporting path is part of the architecture. It is not an afterthought; the runtime must shut down cleanly enough for Click `DriverManager` outputs and the overall test transcript to be produced deterministically.[file:1]

## Submission structure target

The final deliverable must be a tarball of the folder `ik2221-assign-phase1-team<Number>` and uploaded before the stated deadline. The brief warns that incorrect structure, misplaced Makefiles, or too much need for manual fixing can lead to failure in automatic testing or even a zero mark.[file:1]

For an implementation agent, this means submission compatibility is a first-class requirement. A technically good solution with the wrong file layout is still structurally wrong for this course.[file:1]

## What another agent should preserve

An agent extending this repository should preserve the following invariants because they are structural requirements, not optional engineering choices:[file:1]

- Node names and switch sequencing must match the assignment notation.[file:1]
- The private user subnet must remain behind `napt`.[file:1]
- The service must remain exposed as the virtual IP `100.0.0.45:80`.[file:1]
- `ids` must remain inline before `lb1` so filtering occurs before balancing.[file:1]
- `lb1` must hide the backend identities from clients through rewriting.[file:1]
- `insp` must remain passive and receive suspicious traffic.[file:1]
- Switches `sw1`–`sw3` should remain regular L2 learning switches under POX/Open vSwitch.[file:1]
- `napt`, `ids`, and `lb1` must remain implemented in Click.[file:1]
- Tests and report generation must remain automated and invokable through `make test`.[file:1]

## Common implementation mistakes to avoid

The project brief implies several failure modes that another agent should actively avoid.[file:1]

- Do not change the required node naming and IP convention casually, because controller logic, grading scripts, and debugging assumptions depend on it.[file:1]
- Do not move required Makefiles or required folders away from the submission layout expected by the graders.[file:1]
- Do not push NFV logic into ad hoc switch commands or manual Open vSwitch rule injection, because switch control is meant to happen through the Python controller and the NFV logic is meant to live in Click.[file:1]
- Do not rely on manual validation; tests must assert outcomes automatically.[file:1]
- Do not forget `SNIFFER false` in `FromDevice`, because duplicate packets in the Linux stack can create confusing behavior.[file:1]
- Do not implement IDS keyword detection as a broad substring search over the whole packet when the assignment specifically asks for matching the first bytes of the HTTP payload after moving the pointer correctly.[file:1]

## Practical handoff guidance

If this project is handed to another coding agent, the agent should start by locating or creating the required top-level folders and ensuring that the main `Makefile` exposes `topo`, `app`, `clean`, and `test`. Next, it should verify that the topology reflects the required node names, IPs, and routes before touching NFV logic, because broken topology assumptions will invalidate debugging everywhere else.[file:1]

After topology validation, the agent should confirm that the controller launches the Click modules for `napt`, `ids`, and `lb1` in the expected way. Only then should it implement or refine the Click pipelines module by module, starting with `napt`, then `ids`, then `lb1`, and finally tightening the automated tests and report generation.[file:1]

## Acceptance checklist

The project structure can be considered aligned with the target when all of the following are true:[file:1]

- The repository matches the required submission layout with `MEMBERS`, top-level `Makefile`, `topology/`, `application/`, `nfv/`, and `results/`.[file:1]
- The topology uses the required host, switch, and NFV names and the required IP addressing plan.[file:1]
- `sw1`, `sw2`, and `sw3` behave as standard POX/OpenFlow learning switches.[file:1]
- `napt` translates between `10.0.0.0/24` and `100.0.0.0/24` for TCP and ICMP echo traffic.[file:1]
- `ids` transparently forwards non-HTTP-supporting traffic as required and filters HTTP methods so only `POST` and `PUT` proceed.[file:1]
- `ids` diverts suspicious `PUT` payloads containing the specified patterns to `insp`.[file:1]
- `lb1` owns the virtual IP `100.0.0.45`, answers ARP for it, answers pings to it, and distributes web traffic to `llm1`, `llm2`, and `llm3` in round-robin fashion.[file:1]
- Client-visible traffic uses the virtual service identity rather than exposing backend server IPs.[file:1]
- Automated tests verify behavior without manual inspection.[file:1]
- `lb1.report`, `ids.report`, `napt.report`, and `phase_1_report` are generated through the normal test flow.[file:1]

## Closing note

The most useful way to understand this project is as a **structured NFV pipeline with strict packaging requirements**. Another agent should preserve the topology and submission contract exactly, keep orchestration in POX, keep packet semantics in Click, and treat automation and reporting as part of the required architecture rather than supplementary tooling.[file:1]
