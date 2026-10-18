# Wireshark SOC Investigations

A practical portfolio of network-traffic investigations conducted with **Wireshark**, focused on protocol analysis, TCP behaviour, reconnaissance patterns, and evidence-based security assessment.

> **Portfolio note:** These are learning investigations, not claims of professional incident-response experience. Findings and verdicts are limited to the traffic and evidence documented in each report.

## Repository Overview

This repository contains investigation reports, supporting screenshots, a reusable Wireshark filter cheat sheet, and links to the packet captures used during analysis.

### Investigation Index
## Investigation Index

| ID | Investigation | Focus | Report |
|---|---|---|---|
| [INV-001](01-Basics/INV-001-DNS/) | DNS Investigation | DNS requests, responses, and name resolution | [Open folder](01-Basics/INV-001-DNS.odt/) |
| [INV-002](01-Basics/INV-002-ICMP/) | ICMP Investigation | ICMP traffic and connectivity behaviour | [Open folder](01-Basics/INV-002-ICMP.odt/) |
| [INV-003](01-Basics/INV-003-TCP/) | TCP Investigation | TCP headers, flags, handshakes, and connection behaviour | [Open folder](01-Basics/INV-003-TCP.odt/) |
| [INV-004](01-Basics/INV-004-UDP/) | UDP Investigation | UDP traffic and connectionless communication | [Open folder](01-Basics/INV-004-UDP.odt/) |
| [INV-005](02-Protocols/INV-005-DHCP/) | DHCP Investigation | DHCP discovery and address assignment | [Open folder](02-Protocols/INV-005-DHCP.odt/) |
| [INV-006](02-Protocols/INV-006-HTTP/) | HTTP + TCP Stream Investigation | HTTP requests/responses, user agents, and stream analysis | [Open folder](02-Protocols/INV-006-HTTP.odt/) |
| [INV-007](02-Protocols/INV-007-TLS/) | TLS + Network Anomaly Investigation | TLS negotiation, certificates, metadata, and encryption limits | [Open folder](02-Protocols/INV-007-TLS.odt/) |
| [INV-008](03-network-analysis/INV-008-TCP-Problems/) | TCP Anomalies | Retransmissions, resets, Kerberos exchanges, and evidence limits | [Open folder](03-network-analysis/INV-008-TCP-Problems.odt/) |
| [INV-009](03-network-analysis/INV-009-Port-Scanning/) | Port Scanning Investigation | SYN probes, destination ports, and response patterns | [Open folder](03-network-analysis/INV-009-Port-Scanning.odt/) |
| [INV-010](04-Security-investigations/INV-010-Security-Incident/) | Full SOC Investigation | Capture overview, SMB2 activity, downloads, and suspicious NetSupport-like communication | [Open folder](04-Security-investigations/INV-010-Security-Incident.odt/) |

**INV-005 — DHCP** is reserved in the structure, but no DHCP report was included in the files reviewed for this repository setup. Add its link once the report exists.

## Repository Structure

```text
wireshark-soc-investigations/
├── README.md
├── 01-Basics/
│   ├── INV-001-DNS/
│   ├── INV-002-ICMP/
│   ├── INV-003-TCP/
│   └── INV-004-UDP/
├── 02-Protocols/
│   ├── INV-005-DHCP/
│   ├── INV-006-HTTP/
│   └── INV-007-TLS/
├── 03-Network-Analysis/
│   ├── INV-008-TCP-Problems/
│   └── INV-009-Port-Scan/
├── 04-Security-Investigations/
│   └── INV-010-Security-Incident/
├── pcaps/
├── screenshots/
└── Wireshark-CheatSheet.md
```

## Investigation Workflow

The reports use a repeatable, evidence-led workflow:

1. **Define scope** — identify the capture, timeframe, and investigation questions.
2. **Establish context** — review capture statistics, Protocol Hierarchy, Endpoints, and Conversations.
3. **Filter and prioritise** — use display filters to narrow relevant traffic.
4. **Inspect representative connections** — review packet sequences and streams rather than relying on isolated packets.
5. **Correlate evidence** — connect IPs, ports, protocols, timestamps, flags, and application-layer details where visible.
6. **Assess alternatives** — consider normal software behaviour, capture loss, retransmissions, encryption, and visibility limitations.
7. **Document conclusions** — distinguish observations from interpretation and limit verdicts to available evidence.

## Tools and Skills

- **Wireshark** — packet inspection, display filters, protocol dissection, and stream analysis.
- **TCP/IP analysis** — addressing, ports, handshakes, connection termination, retransmissions, and resets.
- **Application protocols** — DNS, HTTP, TLS, SMB2, Kerberos, and related traffic where present in the captures.
- **SOC investigation practice** — scoping, evidence correlation, timeline construction, uncertainty assessment, and report writing.

Only list tools and techniques actually used in a given investigation report.

## Evidence and Reporting Principles

- A retransmission, TCP reset, unusual port, or repeated request is **not proof of malicious activity by itself**.
- Encrypted TLS payloads limit what can be concluded from packet contents; visible metadata does not reveal the full application exchange.
- A benign finding for one connection does not establish that the entire capture is benign.
- Each assessment should state its scope, supporting evidence, uncertainty, and relevant limitations.
- Do not publish credentials, personal information, private organizational traffic, or captures you are not authorised to redistribute.

## PCAP Sources and Data Handling

The `pcaps/` directory is intended for captures that are explicitly licensed or authorised for redistribution. If a capture cannot be redistributed, keep it out of the repository and add a link to its original source in the relevant investigation folder instead.

Suggested per-investigation source note:

```text
PCAP source: [name and original URL]
Redistribution: [permitted / not permitted / not verified]
SHA-256: [optional hash for integrity verification]
```

Do not claim a source licence or redistribution permission unless you have verified it.

## Screenshots

Store only screenshots that help a reader reproduce or understand a finding. Use clear filenames, for example:

- `INV-006-http-request.png`
- `INV-008-tcp-retransmissions.png`
- `INV-009-syn-scan-responses.png`
- `INV-010-smb2-session.png`

Avoid screenshots that expose credentials, personal data, or unrelated traffic. Reference relevant images from the corresponding report using relative Markdown links.

## Wireshark Filter Cheat Sheet

See [Wireshark-CheatSheet.md](Wireshark-CheatSheet.md) for commonly used display filters, what they show, and practical investigation notes.

## Report Folder Convention

Each investigation folder should ideally contain:

```text
INV-XXX-Topic/
├── report.md       # Preferred Markdown report, or the original report file
├── screenshots/    # Only if screenshots are specific to this investigation
└── README.md       # Optional short summary, PCAP source, and reproduction notes
```

Keep original `.odt` reports if you want to preserve the original document. For easier review on GitHub, consider also exporting or converting each final report to Markdown or PDF. Use accurate, relative links and update the index when adding reports.

## Scope and Disclaimer

This repository is for educational and portfolio purposes. Analyses are based on the specified training captures and the evidence documented in the reports. They do not establish that a host or capture is completely safe or compromised beyond the stated scope. Only analyse traffic you are authorised to inspect.

---

*Last updated: October 2026*
