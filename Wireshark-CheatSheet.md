# Wireshark & Network Analysis Cheat Sheet
**Absolute Beginner → Practicing Analyst | SOC / Blue Team Reference**

This guide explains common protocols, default ports, security-relevant patterns, and Wireshark display filters from basic to advanced. A matching packet is an investigation lead—not proof of an attack. Correlate endpoints, both traffic directions, timestamps, packet sequences, host logs, and application context.

## 1. How to investigate a PCAP

1. Define scope: PCAP source, timeframe, packet count, and capture limitations.
2. Establish context: **Statistics → Protocol Hierarchy, Endpoints, Conversations**.
3. Ask a focused question, then filter.
4. Inspect representative connections and surrounding packets. Use **Follow TCP Stream** or **Follow UDP Stream** when useful.
5. Correlate observations, consider benign explanations, then document evidence, interpretation, confidence, and limitations.

### Capture filters vs display filters

| Filter type | When used | Example | Effect |
|---|---|---|---|
| Capture filter | Before/during capture | `host 192.0.2.10` | Controls which packets are recorded; BPF/libpcap syntax |
| Display filter | After capture | `ip.addr == 192.0.2.10` | Shows matching packets without deleting others |

The filters in this guide are **display filters** unless explicitly marked as capture filters.

## 2. Filter syntax fundamentals

| Goal | Display filter | Meaning |
|---|---|---|
| Source IPv4 | `ip.src == 192.0.2.10` | Packets from the source |
| Destination IPv4 | `ip.dst == 192.0.2.20` | Packets to the destination |
| Either direction | `ip.addr == 192.0.2.10` | Source or destination matches |
| AND | `ip.src == 192.0.2.10 && tcp` | Both conditions match |
| OR | `dns || http` | Either condition matches |
| NOT | `!(arp)` | Excludes ARP |
| Port | `tcp.port == 443` | TCP source or destination port 443 |
| TCP or UDP port | `tcp.port == 53 || udp.port == 53` | Port 53 on TCP or UDP |
| Initial SYN | `tcp.flags.syn == 1 && tcp.flags.ack == 0` | SYN set, ACK not set |
| Frame number | `frame.number == 123` | Frame 123 |

Common operators: `==`, `!=`, `>`, `<`, `>=`, `<=`, `&&`, `||`, `!`. Use Wireshark autocomplete and the Display Filter Reference when a field is rejected. Do not confuse capture-filter syntax with display-filter syntax.

## 3. Network basics

| Term | Meaning | Investigation value |
|---|---|---|
| IP address | Logical address of a network interface | Identifies communicating endpoints |
| MAC address | Link-layer address on a local segment | Helps correlate local Ethernet traffic |
| Port | Application/service endpoint for TCP/UDP | Helps identify likely service |
| Client/server | Request initiator and service provider | Helps establish direction; roles can vary |
| TCP | Reliable, connection-oriented transport | Handshakes, ACKs, retransmissions, termination |
| UDP | Connectionless transport | DNS, DHCP, NTP, QUIC and other services |
| Payload | Data carried by a packet | May be readable, encrypted, compressed, or absent |
| Retransmission | Data sent again when delivery/ACK is uncertain | May indicate loss, delay, capture gaps, or other issues |
| RST | Abruptly resets a TCP connection | Can be normal rejection or application/network behaviour |
| Beaconing | Repeated communication, often at intervals | May be normal check-ins or possible C2 |
| Exfiltration | Unauthorised data transfer out of an environment | Needs evidence of data movement and context |

### Private IPv4 ranges (RFC 1918)

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`

An address outside these ranges is not automatically malicious or necessarily public-reachable. Consider VPNs, NAT, IPv6, lab networks, and capture location.

## 4. Protocol overview

Ports shown are common defaults, not proof of protocol identity. Verify packet dissection and context.

| Protocol | Basic meaning / use | Common port(s) | Possible security patterns to investigate |
|---|---|---|---|
| ARP | Maps IPv4 addresses to local MAC addresses | None | ARP spoofing/poisoning, unusual reply patterns |
| IPv4 / IPv6 | Addresses and routes packets | N/A | Spoofing indicators, unexpected paths/volume |
| ICMP | Network diagnostics and control messages | No TCP/UDP port | Reconnaissance, tunnelling, floods |
| TCP | Reliable connection-oriented transport | N/A | SYN scans/floods, connection exhaustion |
| UDP | Connectionless transport | N/A | UDP scans, reflection/amplification patterns |
| DNS | Resolves names and DNS records | TCP/UDP 53 | DNS tunnelling, DGA-like queries, NXDOMAIN spikes |
| DHCPv4 | Assigns client IP configuration | UDP 67 server / 68 client | Rogue DHCP, starvation, unexpected DNS/gateway |
| HTTP | Web request/response, usually unencrypted | TCP 80 commonly | Exploit requests, suspicious downloads, clear-text credentials, C2-like repetition |
| HTTPS | HTTP protected by TLS | TCP 443 commonly | Suspicious destinations; payload is usually encrypted |
| TLS | Encrypts/authenticates application sessions | Often TCP 443; other ports exist | Suspicious certificates/metadata, obsolete versions; encrypted payload limits |
| QUIC / HTTP/3 | Modern transport over UDP; HTTP/3 uses QUIC | UDP 443 commonly | Unexpected destinations/volume; encrypted content |
| SSH | Secure remote shell/file transfer | TCP 22 | Brute-force attempts, unexpected remote access/tunnelling |
| Telnet | Remote terminal without built-in encryption | TCP 23 | Clear-text credentials, unauthorised access |
| FTP | File transfer; separate data channel may be used | TCP 21 control; data varies | Clear-text credentials/data, unusual transfers |
| SMTP | Sends email | TCP 25; submission 587; implicit TLS 465 | Spam, unusual outbound mail, data leakage |
| POP3 / IMAP | Retrieves/manages email | 110/995; 143/993 | Credential exposure on unencrypted sessions |
| SMB/SMB2 | Windows file sharing and related operations | TCP 445 commonly | Lateral movement, suspicious share/file access, ransomware-related activity |
| NetBIOS | Legacy Windows naming/session services | UDP 137/138; TCP 139 | Discovery, spoofing, unexpected legacy traffic |
| Kerberos | Ticket-based authentication, often Active Directory | TCP/UDP 88 | Password guessing, Kerberoasting-related patterns, unusual authentication |
| LDAP / LDAPS | Directory access and queries | TCP/UDP 389; TCP 636 LDAPS | Directory enumeration, insecure binds |
| NTP | Synchronises system clocks | UDP 123 | Reflection/amplification, unexpected time sources |
| SNMP | Network-device monitoring/management | UDP 161 queries; 162 traps | Exposed community strings, unauthorised queries |
| RDP | Remote desktop | TCP/UDP 3389 commonly | Brute force, unexpected remote access |
| Syslog | Transports device/application logs | UDP 514 commonly; other transports exist | Unexpected sources, unusual/missing log volume |
| DCE/RPC | Remote procedure calls, common in Windows | TCP 135 plus dynamic ports often | Remote service discovery, lateral movement |
| WebSocket | Persistent bidirectional application channel | Often 80/443 via HTTP(S) | Unexpected persistent sessions; possible C2 |
| MQTT | Lightweight messaging, often IoT | TCP 1883; TLS often 8883 | Unauthorised broker access, unusual topic traffic |
| SIP / RTP | Voice/video signalling and media | SIP 5060/5061; RTP varies | Unauthorised calls, flooding patterns |

**Important:** A port number is only a convention. Applications can use non-standard ports, and malicious activity can use legitimate protocols.

## 5. Protocol display filters

### Ethernet, ARP and IP

| Goal | Filter | Follow-up |
|---|---|---|
| ARP packets | `arp` | Inspect sender/target IP and MAC |
| ARP requests | `arp.opcode == 1` | Check repeated unanswered requests |
| ARP replies | `arp.opcode == 2` | Check whether IP-to-MAC mappings are consistent |
| IPv4 | `ip` | Inspect endpoints, TTL, fragmentation |
| IPv6 | `ipv6` | Inspect IPv6 endpoints and neighbour discovery |
| Host in either direction | `ip.addr == 192.0.2.10` | Review both directions and conversations |
| Subnet | `ip.addr == 192.0.2.0/24` | Review traffic involving that subnet |
| Low TTL | `ip.ttl <= 5` | Context only; low TTL is not proof of an attack |
| IPv4 fragments | `ip.flags.mf == 1 || ip.frag_offset > 0` | Check reassembly and capture quality |

### ICMP

| Goal | Filter | Follow-up |
|---|---|---|
| ICMPv4 | `icmp` | Inspect type/code, endpoints, rate |
| Echo requests | `icmp.type == 8` | Check source, target, frequency |
| Echo replies | `icmp.type == 0` | Match requests and replies |
| Destination unreachable | `icmp.type == 3` | Inspect code and related flow |
| Time exceeded | `icmp.type == 11` | May be traceroute or routing behaviour |
| ICMP involving host | `icmp && ip.addr == 192.0.2.10` | Correlate with other traffic |

ICMPv6 uses `icmpv6` and different message-type values; do not reuse ICMPv4 type numbers without checking.

### TCP

| Goal | Filter | Follow-up |
|---|---|---|
| All TCP | `tcp` | Establish baseline with Conversations/Endpoints |
| TCP port 443 | `tcp.port == 443` | Confirm TLS/application dissection |
| Initial SYNs | `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Count sources, destinations, ports and timing |
| SYN/ACK replies | `tcp.flags.syn == 1 && tcp.flags.ack == 1` | Compare with initial SYNs |
| TCP resets | `tcp.flags.reset == 1` | Inspect direction and prior connection state |
| FIN packets | `tcp.flags.fin == 1` | Check normal termination sequence |
| Retransmissions | `tcp.analysis.retransmission` | Inspect sequence/ACK and both directions |
| Fast retransmissions | `tcp.analysis.fast_retransmission` | Check preceding duplicate ACKs |
| Spurious retransmissions | `tcp.analysis.spurious_retransmission` | Verify capture/context; this is Wireshark's classification |
| Duplicate ACKs | `tcp.analysis.duplicate_ack` | Inspect ACK number and missing sequence range |
| Out-of-order segments | `tcp.analysis.out_of_order` | Consider reordering or capture artefacts |
| Zero window | `tcp.analysis.zero_window` | Investigate receiver backpressure |
| Window update | `tcp.analysis.window_update` | Check whether transfer resumes |
| One stream | `tcp.stream == 0` | Replace `0` with the actual stream index |
| Host's TCP traffic | `ip.addr == 192.0.2.10 && tcp` | Correlate both directions |
| TCP payload | `tcp.len > 0` | Identify data-bearing segments, not necessarily readable data |

**TCP caution:** SYNs, RSTs and retransmissions are not inherently malicious. A scan hypothesis becomes stronger when one source probes many ports/hosts in a short interval and the response pattern supports it. Confirm with asset context and approved scanning records.

### UDP and DHCP

| Goal | Filter | Follow-up |
|---|---|---|
| All UDP | `udp` | Review UDP conversations |
| UDP port 53 | `udp.port == 53` | Confirm DNS dissection |
| Large UDP length | `udp.length > 1200` | Identify application; size alone is not suspicious |
| DHCP/BOOTP | `bootp` | Inspect Discover/Offer/Request/ACK sequence |
| Discover | `bootp.option.dhcp == 1` | Inspect client and broadcast behaviour |
| Offer | `bootp.option.dhcp == 2` | Identify offering server |
| Request | `bootp.option.dhcp == 3` | Inspect requested IP and server identifier |
| ACK | `bootp.option.dhcp == 5` | Inspect assigned address and options |

DHCP field names can vary by Wireshark version. If `bootp` is rejected, search autocomplete for `dhcp` and inspect the protocol tree. DHCPv6 is separate.

### DNS

| Goal | Filter | Follow-up |
|---|---|---|
| All DNS | `dns` | Review query/response ratio and endpoints |
| Queries | `dns.flags.response == 0` | Inspect names and query types |
| Responses | `dns.flags.response == 1` | Inspect answers, response code, TTL |
| Non-zero response code | `dns.flags.rcode != 0` | Determine exact error and frequency |
| NXDOMAIN | `dns.flags.rcode == 3` | Check repeated names and software behaviour |
| A records | `dns.qry.type == 1` | IPv4 lookups |
| AAAA records | `dns.qry.type == 28` | IPv6 lookups |
| TXT queries | `dns.qry.type == 16` | Check context; TXT is also common for legitimate services |
| Exact queried name | `dns.qry.name == "example.com"` | Identify client and answer |
| Long query name | `dns.qry.name.len > 50` | Inspect uniqueness, label structure, frequency |
| DNS over TCP | `dns && tcp` | Check large/truncated responses or fallback |
| DNS involving host | `dns && ip.addr == 192.0.2.10` | Correlate query with later connections |

Possible patterns include DNS tunnelling, DGA-like lookups, fast-flux-like answer changes, and query spikes. Long names, TXT queries, or NXDOMAIN alone do not prove malicious activity.

### HTTP

| Goal | Filter | Follow-up |
|---|---|---|
| HTTP traffic | `http` | Review request/response sequence |
| Requests | `http.request` | Inspect client, method, host, URI |
| Responses | `http.response` | Inspect status, server, content type |
| GET requests | `http.request.method == "GET"` | Check requested resources |
| POST requests | `http.request.method == "POST"` | Inspect visible body only when captured and authorised |
| Error responses | `http.response.code >= 400` | Distinguish 4xx from 5xx |
| Redirects | `http.response.code >= 300 && http.response.code < 400` | Check `Location` and follow-up request |
| Host header | `http.host == "example.com"` | Correlate IP, URI and response |
| User-Agent exists | `http.user_agent` | User-Agent can be spoofed |
| URI contains text | `http.request.uri contains "login"` | Review full request context |
| One TCP stream | `tcp.stream == 5` | Replace index; use Follow TCP Stream |

A `200 OK` only means the HTTP request received a successful status. It does not establish that the activity is safe.

### TLS, HTTPS and QUIC

| Goal | Filter | Follow-up |
|---|---|---|
| TLS-dissected packets | `tls` | Review handshakes and metadata |
| ClientHello | `tls.handshake.type == 1` | Inspect SNI if visible and offered parameters |
| ServerHello | `tls.handshake.type == 2` | Inspect negotiated parameters |
| Certificate message | `tls.handshake.type == 11` | Inspect subject, issuer, validity; verify separately |
| Visible SNI | `tls.handshake.extensions_server_name` | May be absent or hidden by ECH |
| TLS alerts | `tls.record.content_type == 21` | Inspect alert details and surrounding handshake |
| TCP port 443 | `tcp.port == 443` | Confirm TLS; port alone does not prove HTTPS |
| QUIC | `quic` | Review UDP-based encrypted session metadata |
| UDP port 443 | `udp.port == 443` | Confirm whether traffic is QUIC or another service |

Encrypted application data is not normally readable. Visible metadata and a valid certificate do not prove the application activity is benign.

### Remote access, email and file sharing

| Protocol | Filter | Follow-up |
|---|---|---|
| SSH | `ssh` | Inspect banners, frequency and duration |
| SSH default port | `tcp.port == 22` | Confirm SSH dissection |
| FTP | `ftp || ftp-data` | Inspect commands and data connections |
| FTP login commands | `ftp.request.command == "USER" || ftp.request.command == "PASS"` | Treat any exposed credentials as sensitive |
| SMTP | `smtp` | Inspect sender/recipient metadata where visible |
| POP3 | `pop` | Check unencrypted authentication exposure |
| IMAP | `imap` | Inspect mailbox operations and encryption |
| SMB/SMB2 | `smb || smb2` | Inspect share names, operations, status codes |
| SMB2 create/open | `smb2.cmd == 5` | Inspect file path and context; validate field in your version |
| SMB2 write | `smb2.cmd == 9` | Review write activity and direction |
| SMB2 non-zero status | `smb2.nt_status != 0` | Determine whether the status is expected |
| Kerberos | `kerberos` | Inspect message types and principals |
| Kerberos AS-REQ | `kerberos.msg_type == 10` | Correlate with responses and auth logs |
| Kerberos AS-REP | `kerberos.msg_type == 11` | A response alone does not establish compromise |
| LDAP | `ldap` | Inspect bind/search operations and volume |
| NetBIOS name service | `nbns` | Review names and source hosts |
| DCE/RPC | `dcerpc` | Inspect RPC sequence and endpoint mapper context |
| RDP | `rdp` | Network metadata alone may not establish authentication success |

### Other protocols

| Protocol | Filter | Useful questions |
|---|---|---|
| NTP | `ntp` | Is the time source expected? Is volume unusual? |
| SNMP | `snmp` | Are devices queried by authorised management hosts? |
| SIP | `sip` | Are registrations/calls expected? |
| RTP | `rtp` | Are media flows and timing plausible? |
| MQTT | `mqtt` | Which broker, client ID and topics are involved? |
| Syslog | `syslog` | Are sources and message volumes expected? |
| ICMPv6 | `icmpv6` | Review neighbour discovery and router advertisements |
| Wi-Fi frames | `wlan` | Only useful when the capture contains relevant 802.11 frames |

## 6. Security investigation playbooks

These are triage starting points, not automatic detections.

### A. Possible TCP port scan

```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Narrow to one source:

```wireshark
ip.src == 192.0.2.10 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Ask: Is one source contacting many destination ports/hosts in a short period? Which responses are SYN/ACK, RST, or absent? Is the activity authorised? Does the capture include both directions?

### B. Possible repeated outbound beaconing

```wireshark
ip.src == 192.0.2.10 && (tcp || udp)
```

Use **Statistics → Conversations**, then inspect timestamps for regular intervals. Ask whether the destination is expected, whether timing is consistent, and whether endpoint/process telemetry identifies the application. A Wireshark filter alone cannot prove C2.

### C. Possible unusual DNS activity

```wireshark
dns.flags.response == 0
```

Narrow the review:

```wireshark
dns.qry.type == 16 || dns.qry.name.len > 50
```

Ask whether one host produces many unique, long or high-entropy-looking subdomains, at an unusual rate, to an unexpected domain. Corroborate before alleging tunnelling.

### D. Possible suspicious HTTP activity

```wireshark
http.request
```

```wireshark
http.request.method == "POST"
```

Review host, URI, User-Agent, response, timing and visible body. Repeated requests can be normal application polling; `200 OK` is not a security verdict.

### E. TCP reliability / capture issue

```wireshark
tcp.analysis.retransmission || tcp.analysis.duplicate_ack || tcp.flags.reset == 1
```

Check direction, sequence/ACK numbers, preceding packets, whether many flows are affected, and whether capture loss/asymmetric visibility is possible.

### F. Possible SMB lateral movement

```wireshark
smb || smb2
```

Check client, server, share, file operations and whether the source is expected to access the share. Correlate with Windows authentication, process and file-access logs.

### G. Possible data transfer / exfiltration

Start with **Statistics → Conversations**, sort by bytes, then inspect relevant flows:

```wireshark
ip.addr == 192.0.2.10
```

Ask what direction carried data, which application was used, whether the destination is expected, and whether there is evidence the data was sensitive and transferred without authorisation. High volume alone is not proof of exfiltration.

## 7. Statistics and analysis tools

| Wireshark feature | Use |
|---|---|
| Protocol Hierarchy | Understand which protocols dominate the capture |
| Endpoints | Find hosts and compare traffic volume |
| Conversations | Identify high-volume or unusual communication pairs |
| I/O Graphs | Visualise traffic volume and spikes over time |
| Expert Information | Find warnings and TCP analysis annotations; leads, not verdicts |
| Follow TCP/UDP Stream | Understand a conversation in context |
| Flow Graph | Reconstruct packet sequence between endpoints |
| Name Resolution | Display available names; validate them rather than assuming they are authoritative |

## 8. Professional investigation report template

```text
Investigation ID / Title:
Analyst / Date:
Wireshark version:
PCAP name / source:
Objective / Scenario:
Scope and timeframe:

Executive summary:
Key questions:
Methodology:
Display filters used:
Evidence (frame, timestamp, IPs, ports, protocol):
Observations (what the packets show):
Interpretation (what they may mean):
Alternative explanations:
Assessment / verdict:
Confidence and rationale:
Recommended next steps:
Limitations:
Lessons learned:
References:
```

**Observation vs interpretation vs verdict**
- Observation: “The host sent SYN packets to 14 destination ports within two seconds.”
- Interpretation: “The pattern may be consistent with port scanning.”
- Verdict: “Suspicious pending validation against authorised scanning and other evidence.”

This is an illustrative example, not a claim about your capture.

## 9. Common mistakes

1. Calling every retransmission, reset, failed DNS query or unusual port malicious.
2. Inspecting every packet manually instead of prioritising with statistics.
3. Assuming a port number proves the application protocol.
4. Looking at only one direction of a connection.
5. Ignoring capture loss, missing packets, truncation or asymmetric visibility.
6. Inferring encrypted payload content from TLS metadata.
7. Calling the entire PCAP benign based on one benign connection.
8. Using a field name without checking autocomplete/documentation.
9. Publishing captures that contain credentials, personal information or unauthorised traffic.

## 10. Quick filter starter pack

```wireshark
ip.addr == 192.0.2.10
dns
dns.flags.response == 0
http.request
tls
tls.handshake.type == 1
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.flags.reset == 1
tcp.analysis.retransmission || tcp.analysis.duplicate_ack
ip.addr == 192.0.2.10 && tcp
tcp.port == 53 || udp.port == 53
smb || smb2
kerberos
icmp
frame.number == 123
```

Replace example IPs, ports, stream indexes and frame numbers with values from your capture. If Wireshark rejects a field, use autocomplete and verify it in the reference for your installed version.

## 11. Official references

- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [Wireshark Capture Filter Reference](https://www.wireshark.org/docs/man-pages/pcap-filter.html)
- [Wireshark Wiki](https://wiki.wireshark.org/)

Corroborate network evidence with endpoint telemetry, authentication logs, DNS logs, firewall/proxy logs, threat intelligence and approved asset/service inventories where available.

---
**Scope:** This is a learning aid, not a complete protocol specification or an automatic detection rule set. Validate filters against your Wireshark version and capture. Only analyse traffic you are authorised to inspect.
