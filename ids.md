# IK2221 Phase 1 — IDS Implementation Guide

This document explains in detail what must be implemented for the **IDS section** of the IK2221 Phase 1 project. It is written as a handoff document for a coding agent or teammate who needs to understand the exact role of the IDS, the expected packet-processing behavior, the Click design boundaries, the required traffic classifications, and how the IDS should be tested and reported.[file:1]

The short version is that the IDS is an inline Click-based network function placed in the inferencing path before the load balancer. It must transparently forward normal non-HTTP-supporting traffic, inspect incoming HTTP requests, allow only `POST` and `PUT`, redirect disallowed HTTP methods to the inspector host, and also redirect suspicious `PUT` payloads containing specific code-injection patterns to the inspector host instead of the load balancer.[file:1]

## IDS role in the topology

In the project topology, the IDS sits in the inferencing zone between `sw2` and `lb1`, with a side path to the passive inspector server `insp`. Its job is to inspect incoming traffic before it reaches the load balancer and to divert suspicious traffic for inspection while allowing acceptable traffic to continue toward the virtual service path.[file:1]

This means the IDS is not a general firewall for the whole topology and not a replacement for the load balancer or NAPT. It is a specialized, inline HTTP inspection function whose decisions affect whether requests proceed to `lb1` or are pushed to `insp`.[file:1]

## Required behavior at a high level

The project description defines the IDS as a Click module attached to the interfaces of the Mininet switch `ids`, and it explicitly states that the module has **no IP address** and should therefore act as a forwarder/sniffer rather than as a host-level endpoint.[file:1]

At a high level, the IDS must do five things correctly:[file:1]

- Capture packets from the interfaces of the Mininet `ids` node.[file:1]
- Forward ARP, ICMP ping requests/responses, and TCP signaling transparently.[file:1]
- Inspect only HTTP traffic by first classifying IP packets appropriately.[file:1]
- Allow only HTTP `POST` and `PUT` requests to continue to `lb1`.[file:1]
- Redirect disallowed methods and suspicious `PUT` payloads to `insp`.[file:1]

A correct implementation is therefore a **transparent forwarding pipeline with selective HTTP branching**, not a default-drop middlebox for every packet type.[file:1]

## What the IDS is not supposed to do

Understanding the non-goals is just as important as understanding the goals. The IDS does not own the virtual service IP, does not perform round-robin balancing, and does not handle source/destination address translation between private and public subnets; those responsibilities belong to `lb1` and `napt` respectively.[file:1]

The IDS also does not need to expose services or communicate with other nodes as a conventional host, because the brief states that it has no assigned IP and acts only as a forwarding inspection point.[file:1]

## Placement and packet direction

The practical packet direction for traffic of interest is user host -> `sw1` -> `napt` -> `sw2` -> `ids` -> `lb1` -> `sw3` -> backend server, with suspicious requests diverted from `ids` to `insp` instead of continuing to `lb1`.[file:1]

The IDS is therefore inspecting **requests on the way into the service**, not ordinary server responses flowing back to the client. The assignment even warns not to overthink the attack surface and explicitly says the relevant attacks are plain HTTP requests, while TCP responses from the servers should pass without additional filtering.[file:1]

## Click implementation requirement

The assignment explicitly requires that `ids` be implemented in **Click**, not in POX controller code and not in ad hoc Linux forwarding logic. The provided skeleton already contains a pre-implemented version that only forwards traffic, and your task is to replace that forwarding-only behavior with the required IDS logic.[file:1]

The POX controller is expected only to start the Click module when the Mininet node registers, using the base controller structure and a subprocess-based startup flow. The packet-processing intelligence belongs inside the Click graph itself.[file:1]

## Core functional requirements

The IDS logic can be broken into three major behaviors: transparent forwarding, HTTP method filtering, and HTTP payload inspection.[file:1]

### 1. Transparent forwarding

The IDS must allow the following traffic classes to traverse transparently:[file:1]

- ARP frames.[file:1]
- ICMP ping requests and responses.[file:1]
- TCP signaling traffic.[file:1]

This means those packets should not be sent to the inspector merely because they are non-HTTP or because they are not relevant to the application-layer policy. The IDS is expected to stay out of the way for this traffic.[file:1]

### 2. HTTP method filtering

For HTTP traffic, the IDS must inspect the HTTP method and only allow **`POST`** and **`PUT`** to proceed toward the load balancer. Any other HTTP method must be redirected to the inspector server.[file:1]

The brief explicitly lists `GET`, `HEAD`, `OPTIONS`, `TRACE`, `PUT`, `DELETE`, and `CONNECT` as relevant methods in the explanation, and the implementation requirement is clear: only `POST` and `PUT` are allowed.[file:1]

This implies that at least the following should be considered **disallowed** and sent to `insp` when detected in HTTP requests:[file:1]

- `GET` [file:1]
- `HEAD` [file:1]
- `OPTIONS` [file:1]
- `TRACE` [file:1]
- `DELETE` [file:1]
- `CONNECT` [file:1]

### 3. Suspicious payload detection for `PUT`

For HTTP `PUT` requests, the IDS must additionally inspect the beginning of the HTTP payload and redirect the packet to the inspector if the first bytes after the HTTP header match one of the specified dangerous patterns.[file:1]

The required suspicious patterns are:[file:1]

- `cat /etc/passwd` [file:1]
- `cat /var/log/` [file:1]
- `INSERT` [file:1]
- `UPDATE` [file:1]
- `DELETE` [file:1]

These are treated as indicators of Linux command injection or SQL-style injection attempts in the assignment brief.[file:1]

## Precise interpretation of the HTTP requirement

One of the most important implementation details is that the IDS should not treat all TCP packets as HTTP and should not scan arbitrarily for words anywhere in packet payloads. The brief specifically says to classify IP packets using `IPClassifier` so that only HTTP traffic is matched for this analysis.[file:1]

That means a good design first isolates the relevant packet subset and only then performs the more specific checks. In practice, the IDS needs a staged classifier design: first identify traffic that should always pass through, then identify HTTP traffic, then inspect HTTP method, and finally inspect the payload of allowed `PUT` requests.[file:1]

## Required Click elements and how they are meant to be used

The assignment does not give a complete final Click graph, but it does explicitly mention several elements that should guide the design.[file:1]

### `FromDevice`

The IDS captures packets from the interfaces of the Mininet switch `ids`, so the graph will start from one or more `FromDevice` elements attached to the relevant interfaces. The project notes also warn that `FromDevice` copies packets by default, so you must use `SNIFFER false` to destroy the original packet and avoid duplicate traffic through the Linux stack.[file:1]

### `IPClassifier`

The brief explicitly says to use `IPClassifier` to only match HTTP traffic. This is an early classification stage that should separate HTTP-relevant IP packets from everything else that should continue transparently without deep inspection.[file:1]

### `Classifier`

The IDS must use a `Classifier` element to inspect the HTTP method by matching the correct bytes in the header and to detect the payload keywords using hexadecimal values at the appropriate offset.[file:1]

The wording in the assignment matters here: the implementation must identify the **exact location** of the HTTP method field in the header space and classify the hexadecimal representation of the methods rather than using an imprecise textual search over the packet.[file:1]

### `Search`

The brief says `Search` is useful for advancing the packet payload pointer to the first byte of the HTTP payload after the HTTP header. It explicitly says **not** to use `Search` to find the malicious keywords themselves, because that would be inefficient and would search for the pattern at any byte position instead of checking the first bytes of the payload.[file:1]

This is a strong hint about the intended architecture: use `Search` for structural navigation to the payload boundary, then use `Classifier` for exact prefix matching at the new offset.[file:1]

### `ToDevice`

The IDS must have outputs that send packets either onward in the normal path toward `lb1` or sideways toward the inspector host `insp`. Those final forwarding actions should terminate at the relevant `ToDevice` elements.[file:1]

### `AverageCounter` and `Counter`

For testing and deliverables, the project requires `AverageCounter` elements right after each `FromDevice` and right before each `ToDevice` to measure packets read, packets written, and throughput. It also requires `Counter` elements for traffic classes when the module performs classification, which the IDS clearly does.[file:1]

## Logical pipeline the IDS should implement

A solid implementation can be understood as a multi-stage pipeline.[file:1]

### Stage 1: interface capture and base counters

Packets arrive from the IDS-facing interfaces through `FromDevice(..., SNIFFER false)`. Immediately after capture, the implementation should place `AverageCounter` elements so the module can report packet input statistics later.[file:1]

### Stage 2: transparent-pass traffic separation

At an early stage, the module should separate traffic that must pass transparently without deep HTTP inspection. This includes ARP frames, ICMP echo request/reply traffic, and TCP signaling that should not be blocked or diverted simply because it is not an HTTP request body carrying application data.[file:1]

The reason for separating this early is architectural clarity: the IDS is supposed to be mostly invisible for ordinary forwarding while only becoming opinionated on HTTP request content.[file:1]

### Stage 3: HTTP identification

Among IP packets, the IDS must identify the traffic that should be treated as HTTP. The project brief explicitly instructs the use of `IPClassifier` for this purpose.[file:1]

This stage should feed only candidate HTTP requests into the method-analysis logic, while other packets continue through the transparent path.[file:1]

### Stage 4: method analysis

Once HTTP traffic is isolated, the next stage must inspect the beginning of the HTTP request line and determine which method is being used. The implementation must allow only `POST` and `PUT` to continue toward the load balancer and must send all other methods to the inspector.[file:1]

This means there should be at least three logical branches here: allowed `POST`, allowed `PUT`, and disallowed/unknown method.[file:1]

### Stage 5: payload analysis for `PUT`

`POST` can continue toward `lb1` after the method check because the assignment only requires deep payload inspection for `PUT`. `PUT`, however, must go through an additional step that moves the pointer to the first byte of the HTTP payload and then checks whether the payload begins with one of the listed suspicious patterns.[file:1]

If one of those patterns matches, the packet must be redirected to `insp`. If not, the `PUT` request may continue toward `lb1`.[file:1]

### Stage 6: output counters and forwarding

Before packets leave the IDS, `AverageCounter` elements should be placed right before the `ToDevice` elements so the module can report output statistics and throughput. `Counter` elements should also be placed on important branches so that the final report indicates how many packets fell into each relevant traffic class, including suspicious, allowed, transparent, and dropped classes where appropriate.[file:1]

## A useful classification model

Another agent implementing the IDS will benefit from defining explicit internal traffic classes. The project does not give exact names, but this is a practical structure consistent with the assignment:[file:1]

| Traffic class | Required action |
|---|---|
| ARP | Forward transparently [file:1] |
| ICMP echo request/response | Forward transparently [file:1] |
| TCP signaling / non-inspected support traffic | Forward transparently [file:1] |
| HTTP `POST` | Forward to `lb1` [file:1] |
| HTTP `PUT` with safe prefix | Forward to `lb1` [file:1] |
| HTTP `PUT` with suspicious prefix | Redirect to `insp` [file:1] |
| HTTP method other than `POST` or `PUT` | Redirect to `insp` [file:1] |
| Unhandled/invalid traffic | Usually drop or classify explicitly depending on design [file:1] |

This table is not an extra assignment requirement by itself, but it is a very good internal design contract because it maps every relevant packet type to one obvious outcome.[file:1]

## Important nuance about HTTP responses

The project brief explicitly says not to overthink the attack surface and notes that the relevant cases are plain HTTP requests with specific payloads and methods, while TCP responses from the servers should pass without additional filtering. That means the IDS should not accidentally break normal server-to-client responses by trying to parse them as if they were client-originated HTTP request lines.[file:1]

In practice, the IDS should be careful to apply method and payload checks only to request-direction traffic that actually matches the expected HTTP request structure.[file:1]

## Inspector behavior and output path

When the IDS detects a disallowed method or suspicious `PUT` payload, the packet must be redirected to the inspector server `insp` for further inspection. The project states that `insp` is a passive host and that the link between IDS and inspector should always be on so suspicious packets can be pushed there.[file:1]

The inspector host must capture traffic on its interface, for example using `tcpdump`, and dump the traffic to a PCAP file. The PCAP does not need to be submitted, but the capture mechanism must be in place because it is part of the proof that the IDS behavior is correct.[file:1]

## Reporting obligations for the IDS

The IDS is one of the Click-based network functions, so it must participate in the assignment’s reporting framework. The project requires `AverageCounter` right after each `FromDevice` and right before each `ToDevice`, and it requires `Counter` for classified traffic classes.[file:1]

After the automated tests finish and the Click module terminates, the IDS should print its collected counters to a designated file named `ids.report` using `DriverManager` or the equivalent report-triggering mechanism described in the brief.[file:1]

The report should make it possible to see at least how many packets entered the module, how many left, and how many were observed in the relevant classes such as allowed HTTP methods, suspicious HTTP traffic, transparent traffic, and any dropped class that exists in the design.[file:1]

## Testing expectations for the IDS

The assignment requires tests to be automated and to verify outcomes rather than simply describing what a human should look at. For the IDS specifically, tests should prove both the positive path and the rejection/diversion path.[file:1]

A robust IDS test suite should include at least the following scenarios:[file:1]

- A request using `POST` that reaches the service path successfully.[file:1]
- A request using `PUT` with a benign payload that reaches the service path successfully.[file:1]
- A request using a disallowed method such as `GET` or `DELETE` that is redirected to the inspector.[file:1]
- A `PUT` request whose payload starts with `cat /etc/passwd` and is redirected to the inspector.[file:1]
- A `PUT` request whose payload starts with `cat /var/log/` and is redirected to the inspector.[file:1]
- A `PUT` request whose payload starts with `INSERT`, `UPDATE`, or `DELETE` and is redirected to the inspector.[file:1]
- Verification that suspicious traffic appears in the inspector’s PCAP capture path.[file:1]

The project specifically recommends traffic-generation tools such as `ping`, `iperf`, `netcat`, `wget`, `curl`, and Python/Scapy, and it directly mentions generating HTTP messages containing the special patterns to validate the IDS behavior.[file:1]

## Suggested testing strategy

A very practical strategy is to use `curl` for method tests and a scripted client for exact payload-prefix tests. The reason is that the IDS rules are sensitive to both the HTTP method and the very first bytes after the header, so you want reproducible control over the request line and body content.[file:1]

For example, a good test plan would separate cases into method-only tests and payload-prefix tests. First verify that `POST` and `PUT` pass while `GET` and other methods are diverted, then verify that suspicious `PUT` payloads are diverted even though the method itself is allowed.[file:1]

## Architectural boundaries another agent should preserve

If another coding agent takes over the IDS work, it should preserve the following boundaries because they are strongly implied or explicitly required by the assignment:[file:1]

- The IDS remains implemented in Click.[file:1]
- The IDS remains inline before the load balancer.[file:1]
- The IDS has no assigned IP and behaves as a forwarding/sniffing middlebox.[file:1]
- Transparent traffic classes are not broken by over-aggressive filtering.[file:1]
- Only `POST` and `PUT` are allowed as HTTP methods.[file:1]
- Only `PUT` undergoes the specified payload-prefix inspection.[file:1]
- Suspicious and disallowed traffic is redirected to `insp`, not silently accepted.[file:1]
- The inspector capture path stays enabled.[file:1]
- Counters and report generation remain part of the final implementation.[file:1]

## Common implementation mistakes to avoid

Several mistakes are easy to make in the IDS section and would likely lead to incorrect behavior even if the module appears partially functional.[file:1]

- Treating the IDS as an IP host instead of a transparent forwarding Click appliance.[file:1]
- Filtering all TCP traffic instead of isolating HTTP request traffic first.[file:1]
- Forgetting that ARP, ICMP ping traffic, and TCP signaling must traverse transparently.[file:1]
- Allowing `GET` because it is common in web traffic, even though the assignment explicitly permits only `POST` and `PUT`.[file:1]
- Scanning for malicious keywords anywhere in the packet instead of checking the very first bytes of the HTTP payload after the header boundary.[file:1]
- Using `Search` to search for the malicious strings directly, contrary to the project guidance.[file:1]
- Forgetting `SNIFFER false` on `FromDevice`, which can cause duplicate packet behavior in the Linux stack.[file:1]
- Failing to generate `ids.report` with counters after tests complete.[file:1]
- Building only manual demos instead of automated assertions that graders can run through `make test`.[file:1]

## Implementation checklist

The IDS section can be considered complete when all of the following are true:[file:1]

- `ids` is implemented as a Click module and launched through the existing controller flow.[file:1]
- The module captures traffic from the `ids` Mininet interfaces using `FromDevice(..., SNIFFER false)` or the equivalent required behavior.[file:1]
- ARP frames pass transparently.[file:1]
- ICMP ping requests and responses pass transparently.[file:1]
- TCP signaling passes transparently.[file:1]
- HTTP traffic is isolated using `IPClassifier`.[file:1]
- HTTP methods are identified using `Classifier` at the correct header location.[file:1]
- Only `POST` and `PUT` are forwarded to `lb1`.[file:1]
- All other HTTP methods are redirected to `insp`.[file:1]
- For `PUT`, the payload pointer is advanced to the first byte after the HTTP header using `Search` or equivalent structural navigation as described in the brief.[file:1]
- The first payload bytes are checked against `cat /etc/passwd`, `cat /var/log/`, `INSERT`, `UPDATE`, and `DELETE` using `Classifier` and hexadecimal matching.[file:1]
- Matching suspicious `PUT` requests are redirected to `insp`.[file:1]
- Safe `PUT` requests continue to `lb1`.[file:1]
- `AverageCounter` and `Counter` elements are placed so reporting is available.[file:1]
- `ids.report` is generated after automated tests finish.[file:1]
- The inspector host captures suspicious traffic into PCAP as proof of correct redirection.[file:1]

## Final design summary

The IDS implementation is best understood as a **transparent HTTP-aware inspection bridge**. Most traffic should flow through it normally, but HTTP requests must be screened so that only `POST` and benign `PUT` traffic reaches the load balancer, while dangerous methods and suspicious `PUT` payloads are diverted to the inspector.[file:1]

A strong solution keeps that behavior explicit in the Click graph, with clear traffic classes, correct use of `IPClassifier`, `Classifier`, and `Search`, proper output routing to either `lb1` or `insp`, and automated tests plus reporting artifacts that prove the IDS works as required.[file:1]
