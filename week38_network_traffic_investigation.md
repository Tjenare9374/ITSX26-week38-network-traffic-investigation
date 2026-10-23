# Week 38 – Network Traffic Investigation

## Scope and evidence note

This report analyzes the supplied file `U3.1-plattnat.pcap`. Findings below are based on packet-level inspection of that file. The capture does **not** establish how it was created, which physical/logical interface was used, or whether it represents a live environment or a prepared teaching capture. Those details are therefore not guessed.

The IP addresses are private RFC 1918 addresses from the supplied capture. No public IP address appears in the captured IPv4 packets. The capture contains no personal names or payloads that I have copied into this report beyond short technical examples needed to explain the finding.

## A. Environment and method

- **Evidence file:** `U3.1-plattnat.pcap`
- **File size:** 98,222 bytes
- **Capture format:** classic PCAP, Ethernet link type
- **Packets analyzed:** 712
- **Observed packet timestamps:** 2026-10-14 18:06:20.177366 to 18:14:26.116079 UTC
- **Analysis method:** packet-level inspection of Ethernet, IPv4, UDP, TCP, DNS and application payloads; TCP flows grouped by endpoint addresses and ports.
- **Capture source:** supplied PCAP file. The original capture method and source environment were not included in the evidence available for this analysis.
- **Interface / host OS / capture command:** not determinable from the PCAP alone.
- **Sanitization:** the original PCAP is kept separate from the report. The report uses internal IP addresses and only short payload excerpts relevant to the analysis. No raw packet dump is reproduced.

A PCAP timestamp range describes the timestamps recorded in the file; it does not independently prove when or where the capture was made. The timestamp timezone is interpreted as UTC for reporting.

## B. Packet path and network context

### Observed address and service roles

| Address | Role suggested by observed traffic | Evidence |
|---|---|---|
| `10.40.1.2` | DNS resolver | Receives UDP/53 queries and returns A records |
| `10.40.1.10` | Web/portal endpoint | DNS maps `portal.uppdragsgivaren.se` to this address; accepts TCP/443 and communicates with the application on TCP/8080 |
| `10.40.1.20` | Application endpoint | Receives HTTP requests on TCP/8080 and initiates database connections to TCP/5432 |
| `10.40.1.30` | Database endpoint | Accepts TCP/5432; receives queries from the application and one direct client connection |
| `10.40.1.40` | Log collection endpoint, likely | Accepts TCP/6514 traffic; the port is commonly used for syslog over TLS, but the service identity is inferred from port and traffic pattern |
| `10.40.2.21`, `.22`, `.23`, `.34`, `.57` | Client-side addresses | Query DNS and/or initiate service connections |

These are traffic-based role inferences, not verified asset inventory. The capture shows the following application paths:

1. Client (`10.40.2.x`) → DNS resolver (`10.40.1.2:53`) → A record for `portal.uppdragsgivaren.se` (`10.40.1.10`).
2. Client (`10.40.2.x`) ↔ portal endpoint (`10.40.1.10:443`) over TLS-like traffic.
3. Portal endpoint (`10.40.1.10`) → application endpoint (`10.40.1.20:8080`) using readable HTTP.
4. Application endpoint (`10.40.1.20`) → database endpoint (`10.40.1.30:5432`) using readable PostgreSQL-style query messages.
5. Database endpoint (`10.40.1.30`) → log endpoint (`10.40.1.40:6514`) using TLS-like traffic.

### What can and cannot be established

- All 712 captured packets are IPv4 over Ethernet.
- All observed addresses are private IPv4 addresses.
- No public IP address is present, so this capture does not show an Internet-facing leg.
- No ICMP packets are present.
- No explicit gateway or next-hop exchange can be identified from the packet contents. A default route cannot be reliably inferred from this PCAP alone.
- NAT/PAT is not demonstrated: the capture does not show a private/public address translation pair. NAT may exist elsewhere, outside the captured point.
- A firewall decision cannot be directly observed from these packets. Successful connections show that traffic passed the observation point, but do not identify the rule or device that allowed it.

## C. Protocol inventory

| Protocol / service | Evidence in capture | Assessment |
|---|---|---|
| DNS | 32 UDP packets, 16 query/response pairs on port 53 | Present. All observed queries ask for an A record for `portal.uppdragsgivaren.se`; each response returns `10.40.1.10` with TTL 300. |
| ICMP | 0 packets | Not observed. This does not prove ICMP is disabled elsewhere. |
| TCP | 680 packets, 68 distinct TCP conversations | Present. Each observed conversation follows a SYN, SYN/ACK, ACK opening sequence and ends with FIN-based closure in the captured flow patterns. |
| HTTP | Readable HTTP requests/responses on TCP/8080 | Present and unencrypted in the capture. |
| TLS / HTTPS-like traffic | TLS record/handshake-looking bytes on TCP/443 and TCP/6514 | Present. Application contents are not readable from the captured payloads. The capture alone does not verify certificate trust or full TLS configuration. |
| PostgreSQL-style database protocol | Readable query messages on TCP/5432 | Present. SQL text is exposed in plaintext in the observed traffic. |
| SSH | TCP/22 conversations | Present by port and TCP behavior. The application payload does not expose readable SSH session content. |

Packet counts are for this file only and should not be interpreted as long-term traffic rates.

## D. Detailed flow analysis

### Flow 1 – HTTP request from portal to application

**Packet references:** 13–22, especially packets 16 and 18.

- **Client side:** `10.40.1.10:45705`
- **Server side:** `10.40.1.20:8080`
- **Protocol:** TCP carrying HTTP
- **Observed sequence:**
  - Packet 13: TCP SYN from `10.40.1.10:45705` to `10.40.1.20:8080`.
  - Packet 14: SYN/ACK from the application endpoint.
  - Packet 15: ACK completes the TCP three-way handshake.
  - Packet 16: readable request `GET /api/orders?kund=bad HTTP/1.1`, with `Host: app`.
  - Packet 18: readable response `HTTP/1.1 200 OK` and JSON body `{"status": "elev"}`.
  - Packets 21–22: FIN-based connection closure and final acknowledgement.
- **Expected behavior:** a TCP connection is established, an HTTP request is sent, and the server returns an HTTP response.
- **Observed behavior:** the handshake and closure complete; the request and response are visible in plaintext. The server returns status 200.
- **Security significance:** the URI query value and response body are readable to anyone able to capture this traffic. If the endpoint carries sensitive order/customer information or authorization-related state, plaintext HTTP exposes it to network observers. The value `kund=bad` and response value `elev` are observations only; the capture does not establish what those strings mean or prove privilege escalation.
- **Anomalies/limits:** no TCP reset is present in this flow. A status code of 200 alone does not prove the application performed the correct authorization check.

A second ordinary example appears at packets 48 and 50: `GET /api/orders?kund=klot` followed by `HTTP/1.1 200 OK` with `{"status": "saffran"}`. This reinforces that application data is visible in the capture.

### Flow 2 – Direct client access to the database

**Packet references:** 223–232, especially packets 223–228.

- **Client side:** `10.40.2.34:41603`
- **Server side:** `10.40.1.30:5432`
- **Protocol:** TCP carrying PostgreSQL-style query messages
- **Observed sequence:**
  - Packet 223: client sends SYN to the database server on TCP/5432.
  - Packet 224: database server replies SYN/ACK.
  - Packet 225: client ACK completes the handshake.
  - Packet 226: client sends a readable query message containing `SELECT * FROM kunder; -- rulle hage`.
  - Packet 228: database endpoint sends a response payload.
  - Packets 230–232: FIN-based connection closure and final acknowledgement.
- **Expected behavior:** in a segmented application architecture, database access should normally be restricted to approved application/service identities and hosts, unless a documented operational requirement permits direct client access.
- **Observed behavior:** a client-side address in `10.40.2.0/24` opens a direct TCP connection to the database endpoint and sends a query. The query text is visible in plaintext. The capture shows a response payload but does not provide enough context to establish what records, if any, were returned.
- **Security significance:** this is the clearest network segmentation concern in the capture. Direct client-to-database connectivity may bypass the application tier, its authorization checks, and application logging. The query uses `SELECT *`, which can request every column in the `kunder` table; the capture does not prove that the requester was unauthorized or that data was successfully disclosed.
- **Anomalies/limits:** the connection completes and closes normally; no TCP reset is observed. A successful TCP connection does not by itself establish database authentication success or the identity/privileges of the database user.

### Additional database exposure – application-to-database traffic

Packets 23–32, 55–64 and multiple later flows show `10.40.1.20` connecting to `10.40.1.30:5432`. Packet 26, for example, contains the query text `SELECT id, namn FROM kunder WHERE ort = 'krabba';`. This is consistent with an application server querying a database, but the query text is readable in the capture. The direct client flow at packet 226 differs because its source is `10.40.2.34`, rather than the application endpoint `10.40.1.20`.

### TCP behavior and limitations

The file contains 68 TCP conversations. The observed conversations follow the same basic opening and closing pattern: SYN, SYN/ACK, ACK, data/ACK exchange where applicable, and FIN-based closure. No TCP RST flags were observed. This does not rule out application-layer errors, authorization failures, packet loss outside this capture point, or issues occurring before/after the recorded time.

## E. HTTP compared with TLS/HTTPS

### HTTP on TCP/8080

The capture exposes the request path, query value, Host header, response status and response body as readable text. For example, packet 16 contains `GET /api/orders?kund=bad HTTP/1.1`, and packet 18 contains a 200 response and JSON text.

**Troubleshooting value:** plaintext makes request routing, parameters, status codes and response bodies easy to inspect.

**Confidentiality risk:** a network observer with access to this segment can read the application data. HTTP does not provide transport encryption or cryptographic integrity.

### TLS-like traffic on TCP/443 and TCP/6514

The payloads begin with byte patterns consistent with TLS records, but the application content is not readable as plaintext in this capture.

**Troubleshooting value:** packet timing, source/destination, ports, TCP setup/teardown, TLS record sizes and visible handshake metadata can still help troubleshoot connectivity. Full interpretation may require TLS-aware dissection and, where legally and operationally appropriate, session keys.

**Confidentiality benefit:** TLS is designed to protect application data in transit and detect tampering when correctly configured. This capture alone cannot prove certificate validation, strong cipher selection, correct hostname verification, or the absence of TLS weaknesses.

The comparison is not that HTTPS hides all metadata: addresses, ports, packet sizes, timing and some handshake metadata remain observable. DNS is also visible here because the DNS queries are ordinary UDP/53 requests, not encrypted DNS.

## F. Firewall and hardening recommendations

### Rule example based on the observed direct database flow

**Observed flow:** `10.40.2.34:41603 → 10.40.1.30:5432`, packets 223–232.

Recommended policy, subject to the actual business requirements:

1. Deny new inbound connections to database TCP/5432 from client networks such as `10.40.2.0/24`.
2. Permit TCP/5432 only from the explicitly approved application host(s), such as `10.40.1.20`, and only if this matches the documented design.
3. Restrict database host firewall rules as well as network firewall/ACL rules; do not rely on network location alone.
4. Log denied database connection attempts and alert on client-subnet attempts to reach TCP/5432.
5. Validate the rule with an approved test and review the resulting firewall logs. No firewall configuration was changed as part of this analysis.

### HTTP hardening

- Replace HTTP between the portal and application with authenticated TLS/mTLS where feasible, or protect the service with an equivalently strong, documented control.
- Avoid sending sensitive customer/order values in query strings where practical; URLs can appear in logs and monitoring systems.
- Ensure server-side authorization checks are enforced independently of the client-supplied `kund` value.
- Use parameterized database queries and least-privilege database accounts; do not assume that a readable query alone proves SQL injection.

### Listening service versus permitted traffic

A process listening on TCP/5432 or TCP/8080 is not the same thing as a firewall permitting access to it. This PCAP shows successful traffic between the listed endpoints at the capture point. It does not identify the listening-process configuration or the firewall rule that permitted the flow. Confirm these separately on the relevant hosts and network controls.

## G. CIA triad and evidence quality

### Confidentiality

- DNS queries reveal the requested hostname.
- HTTP on TCP/8080 exposes request paths, query values and response bodies.
- PostgreSQL-style query text on TCP/5432 is readable, including the direct client query at packet 226.
- TLS-like traffic is not readable as application plaintext in the capture.

### Integrity and traceability

- TCP provides sequence numbers, acknowledgements and connection-state evidence, but this PCAP does not prove the integrity of the application’s stored data.
- The original file can be identified by SHA-256: `226de555a97dafb860b79e1ed5672c3432f120da3e51783f92a1c5e2fe06c7f8`.
- Keep the original PCAP unchanged, record the hash, preserve packet references, and store sanitized report excerpts separately.
- The capture does not independently prove the identity of the operator or the completeness of the collection process.

### Availability

- The observed TCP flows establish connections and close normally; no TCP resets were observed.
- This is a short capture of approximately 8 minutes and 6 seconds. It cannot establish service availability outside that interval or rule out resource exhaustion, intermittent failure, or attacks not represented in the file.

### Evidence limitations

- Capture source, capture interface, collection method, host operating system and capture filters are unknown.
- No ICMP, IPv6, public-address traffic, explicit gateway activity or firewall logs are present in this file.
- Application meaning and user authorization cannot be inferred from short payload values alone.
- Packet observations support the existence of a direct client-to-database connection; they do not, by themselves, prove malicious intent or confirmed data exfiltration.

## H. Conclusion and next steps

The strongest finding is that `10.40.2.34` connects directly to `10.40.1.30:5432` and sends a readable database query in packet 226. This suggests a possible segmentation or access-control weakness if client networks are not intended to access the database directly. The second clear weakness is plaintext HTTP between `10.40.1.10` and `10.40.1.20` on TCP/8080, which exposes request parameters and response content to network observers.

Prioritized next steps:

1. Verify the intended network architecture and whether `10.40.2.0/24` should ever access database TCP/5432.
2. Review firewall/ACL and database access logs around the capture timestamps; identify the account and authorization context for the connection in packets 223–232.
3. Restrict database access to approved application/service hosts, with explicit deny rules for client networks.
4. Encrypt the portal-to-application path and review whether sensitive data belongs in URL query strings.
5. Confirm database least privilege, parameterized query use, and application-side authorization.
6. Collect the network diagram, firewall logs, database audit logs and service configuration to validate the hypotheses.

No conclusion is made that a breach occurred. The PCAP provides evidence of exposed plaintext and direct network reachability, but not proof of successful unauthorized data access or exfiltration.

AI-use declaration

AI was used to a limited extent as a support tool, mainly to help organize parts of the report and clarify a few protocol-level concepts. The packet evidence and technical conclusions were checked against the supplied PCAP, and interpretations that cannot be proven directly from the packets are identified as inferences. The analysis and final wording should be reviewed to ensure they accurately reflect my own understanding of the evidence.