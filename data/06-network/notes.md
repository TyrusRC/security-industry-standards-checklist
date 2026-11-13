# NET sheet notes (data/06-network)

Counts: 98 tests in 18 files. Organised by NIST SP 800-115 technique: PLAN (planning), REV (review techniques), DISC (discovery and port or service identification), VULN (vulnerability scanning and validation), PEN (penetration test), CRED (default credentials, password policy, cracking), SOC (social engineering), WIFI (wireless), plus topic files SEG, TLS, DNS, MAIL, SVC, MITM, DOS, LOG, ADM, BKP.

## Sources read
sources/extra/nist800-115.txt (chapters 3, 4, 5, 6, appendix tool list), sources/pci_dss/PCI-DSS-v4_0_1.md (requirements 1, 2, 4, 6, 8, 10, 11, 12), sources/nist80053/NIST_SP-800-53_rev5_catalog.json (control text), cheat sheets: Network_Segmentation, Denial_of_Service, Transport_Layer_Security, Logging, Infrastructure_as_Code_Security, Password_Storage, Attack_Surface_Analysis, Virtual_Patching, Vulnerable_Dependency_Management, Subdomain_Takeover_Prevention, Docker_Security, Secrets_Management; WSTG INFO-01, INFO-04, CONF-01, CONF-04, CONF-05; OWASP Top 10 2025 A02 and A09.

## Missing on disk (not cited, not invented)
- CIS Benchmarks (no `level` field set, no `cis` refs).
- PTES.
- NSA/CISA network infrastructure security guide.
- RFCs and vendor guides for SPF, DKIM, DMARC, DNSSEC, SNMP, SSH, IPsec/IKE, DHCP snooping, 802.1X. The tests for these use only principle text found in 800-53, PCI DSS, the cheat sheets and WSTG. Detailed pass values (for example DMARC policy level, SSH algorithm lists) are left to the organization standard.
- A dedicated DNS, SSH or email cheat sheet (none in CheatSheetSeries on disk).
- MITRE ATT&CK Enterprise full text: only sources/attack/ics-attack.json and mobile-attack.json exist. Enterprise IDs were checked against catalog/attack.json (ID and title only). The refs map each test to the technique title; no technique description was read.

## Open issues
- Overlap candidates with other sheets: NET-SVC-007 (container daemon API) may duplicate a future K8S or CLD test. NET-SEG-008 and NET-SEG-010 touch cloud and IaC.
- WEB tests reused through `see`: TLS (WEB-TLS-001/002/003/004), subdomain takeover (WEB-CONF-011), logging (WEB-LOG-003/007/013/014), web password policy (WEB-PWD-001), default accounts (WEB-AUTHN-001), dependencies (WEB-DEP-001), host and port enumeration (WEB-INFO-004).
- SNMP, SMB, LDAP, NTP, DHCP and name-resolution tests rest on short source text (PCI 2.3.1, 800-115 NetBIOS and tool list, DoS cheat sheet amplification note, ATT&CK titles). Tool hints in `example` come from common practice and are not from the source files.
- Control texts in 800-53 are templates with parameters; the organization must set the values.
