# Evidence README – Week 38 Network Traffic Investigation

## Evidence item

- **File:** `U3.1-plattnat.pcap`
- **Format:** classic PCAP, Ethernet
- **Size:** 98,222 bytes
- **Packets:** 712
- **SHA-256:** `226de555a97dafb860b79e1ed5672c3432f120da3e51783f92a1c5e2fe06c7f8`

## Source and environment

The file was supplied for analysis. The original capture source, capture operator, host operating system, capture interface, capture command and capture filter are not documented in the available evidence. Do not fill these fields from assumptions.

- **Recorded packet timestamp range:** 2026-10-14 18:06:20.177366–18:14:26.116079 UTC
- **Analysis date:** 2026-10-23
- **Analysis method:** packet-level parsing of Ethernet/IPv4, UDP, TCP, DNS and application payloads.
- **Raw PCAP handling:** retain the original file locally and unchanged unless the instructor explicitly authorizes uploading it.

## Sanitization and report excerpts

The report contains private RFC 1918 addresses and limited protocol payload excerpts needed to substantiate findings. It does not include a full packet dump or attach the raw PCAP. The report identifies packet numbers so that the findings can be reproduced against the original local file.

## Key evidence references

- **DNS:** packets 1–2 show `portal.uppdragsgivaren.se` resolving to `10.40.1.10`; the same query/response pattern appears 16 times.
- **HTTP plaintext:** packets 13–22; packet 16 contains a GET request to `/api/orders?kund=bad`, and packet 18 contains an HTTP 200 response with a readable JSON body.
- **Application-to-database traffic:** packets 23–32; packet 26 contains a readable SQL query from `10.40.1.20` to `10.40.1.30:5432`.
- **Direct client-to-database traffic:** packets 223–232; packet 226 contains `SELECT * FROM kunder; -- rulle hage` from `10.40.2.34` to `10.40.1.30:5432`.
- **TLS-like traffic:** examples include client/portal traffic on TCP/443 and log-endpoint traffic on TCP/6514.

## Limitations

- A PCAP alone does not establish the physical environment or the identity of the capture operator.
- The capture does not include ICMP, IPv6, public IP traffic, explicit firewall logs or the network diagram.
- A readable query or completed TCP connection does not by itself prove unauthorized access or data exfiltration.
- Packet timestamps are taken from the file; the reported timezone is interpreted as UTC.
