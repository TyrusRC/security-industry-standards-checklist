# Gap plan: topics still missing from the checklist (2026-11-12)

Method. The tables of contents of three public pentest wikis (HackTricks, HackTricks Cloud, Pentest Book) in
`sources/ref_titles/` were used **only as a topic index**. No wiki text is copied or paraphrased. Each candidate
topic was grepped against an index of all 1,559 tests (id, title, objective, steps, refs). A topic counts as a gap
only when it is a testable control or weakness class, the nearest existing tests were read by id, and a primary
source exists. Cloud, Kubernetes and Linux hardening were skipped: other agents own them (`gap2-*` files).

Coverage context: every ASVS 5 id (345), every MASWE id (78) and 119 of 120 WSTG ids are already referenced.
So the remaining gaps sit **outside the OWASP verification standards**. They fall into three groups:
Windows/Active Directory (no tests), network infrastructure protocols, and web/mobile topics from cheat sheets
or MASTG pages that no test cites.

## Rules for the writers

- The schema requires `sources_read` to list files under `sources/`. A vendor URL or RFC is **not** a
  `sources_read` entry. Fetch each URL a test depends on **before** writing it, into the batch's own folder:
  `sources/extra/gap3-A/`, `sources/extra/gap3-B/` or `sources/extra/gap3-C/`. Log fetches and decisions in the
  batch's own notes file (`data/01-web/notes-gap3-A.md`, `data/06-network/notes-gap3-B.md`,
  `data/06-network/notes-gap3-C.md`). Never edit a shared file such as `guide/sources-fetch-B.md`. Put the URL in
  `refs.other` too. If the writer has no web tool, the caller fetches the pre-fetch list below first.
- A new category means a new file. Use `data/<sheet>/gap3-<cat>.yaml` and the prefixes below. **Do not** add
  ids to existing prefixes (NET-MAIL, NET-SVC, NET-WIFI, WEB-XSLEAK and so on), because another file holds those
  numbers. None of the prefixes below exists (checked against all ids on 2026-11-12, including `gap2-*`).
- Before each test, read the nearest-id tests named in the table. Follow the merge rule in `guide/schema.md`:
  if the control is already there, add a ref and write no new test.

## (a) Gap topics, ranked by value for an auditor

Est = estimated number of tests. Batch sizes: A = 31, B = 30, C = 26. Rank is global across all batches (1 = highest value).

### Batch A: web and mobile (writes only to `data/01-web/gap3-*.yaml` and `data/03-mobile/gap3-*.yaml`)

| Rank | # | Topic | Sheet / category / file | Why it is a gap (nearest existing ids) | Primary source to read | Est |
|---|---|---|---|---|---|---|
| 4 | A1 | Production configuration of server-side frameworks (debug off, secret key handling, allowed hosts, deploy self-checks, default permission and throttle classes, mass-assignment guards, php.ini) | WEB / FWK / `01-web/gap3-fwk.yaml` | Only generic tests exist: WEB-CONF-002 (default/debug functions) and WEB-ERR-002. None of the 8 framework cheat sheets is cited by any test | CheatSheetSeries/cheatsheets: `Django_Security`, `Django_REST_Framework`, `FastAPI_Security`, `Laravel`, `Ruby_on_Rails`, `Symfony`, `PHP_Configuration`, `Bean_Validation` | 8 |
| 10 | A2 | JavaScript server runtimes and SSR meta-frameworks (server actions treated as public endpoints, auth not only in middleware, cache scoping per audience, data passed to the client, request size limits, event-loop blocking) | WEB / NODE / `01-web/gap3-node.yaml` | No test covers server actions, SSR cache scoping or event-loop DoS. Nearest: WEB-AUTHZ-009, WEB-CACHE-002, API-RES-* | `Nextjs_Security_Cheat_Sheet.md`, `Nodejs_Security_Cheat_Sheet.md` | 5 |
| 13 | A3 | Cookie theft detection and device-bound sessions (binding to device, IP/UA anomaly checks, DBSC) | WEB / DBSC / `01-web/gap3-dbsc.yaml` | WEB-SESS-001..030 cover cookie attributes and lifetime, but not detecting a stolen cookie that is replayed from another device. Cheat sheet not cited | `Cookie_Theft_Mitigation_Cheat_Sheet.md`; W3C WICG Device Bound Session Credentials draft | 3 |
| 19 | A4 | Cross-site leak defenses as controls (Fetch Metadata resource-isolation policy, framing protection, CORP, cache partition awareness, SameSite) | WEB / ISO / `01-web/gap3-iso.yaml` | Only one black-box test, WEB-XSLEAK-001. WEB-CLIENT-014 covers COOP only. No test checks that a server-side isolation policy exists | `XS_Leaks_Cheat_Sheet.md`; W3C Fetch Metadata Request Headers spec | 4 |
| 14 | A5 | DNS rebinding: server-side fetch time-of-check/time-of-use, and browser-to-local or internal HTTP services (Host allow-list, auth on localhost services) | WEB / REBIND / `01-web/gap3-rebind.yaml` | No test uses the word "rebind". API-SSRF-002/004/005 test address filters but not resolve-then-connect. LLM-MCP-005 touches Host checks for MCP only | `Webhook_Security_Cheat_Sheet.md` (line ~122), `sources/capec/capec_latest.xml` (CAPEC-275); WICG Private Network Access draft | 3 |
| 25 | A6 | Service worker and web worker security (scope, `Service-Worker-Allowed`, worker script origin, cached authenticated responses, removal at logout) | WEB / SW / `01-web/gap3-sw.yaml` | No test mentions service or web workers. WEB-CLIENT-006 covers storage only | `HTML5_Security_Cheat_Sheet.md` (Service Workers, Web Workers); W3C Service Workers spec | 2 |
| 24 | A7 | HTTP/2 and HTTP/3 protocol-level DoS limits (stream resets, CONTINUATION frames, concurrent stream caps) | WEB / H2 / `01-web/gap3-h2.yaml` | WEB-HTTP-005 covers connection-specific headers. NET-DOS-002 covers slow HTTP/1 only | RFC 9113 §10.5; RFC 9114 §10.5 (fetch; the on-disk DoS cheat sheet has no HTTP/2 content) | 2 |
| 23 | A8 | Cross-platform mobile frameworks (Flutter TLS and pinning behavior, React Native bundle secrets and OTA update integrity, Cordova/Capacitor plugin and allow-list config) | MOB / XPLAT / `03-mobile/gap3-xplat.yaml` | No test names any framework. MASTG has about 25 Flutter and 14 React Native pages. Nearest: MOB-NETWORK-*, MOB-CODE-009 | `sources/repos/mastg/knowledge/android/MASVS-NETWORK/MASTG-KNOW-0015.md`, `.../ios/MASVS-NETWORK/MASTG-KNOW-0072.md`, `.../android/MASVS-CODE/MASTG-KNOW-0004.md`, `tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0403.md` | 3 |
| 26 | A9 | Android task affinity and launch-mode hijacking | MOB / TASK / `03-mobile/gap3-task.yaml` | 0 hits for taskAffinity. MOB-UI-005 covers overlays and MOB-IPC-* covers intents, but not task stacks | `mastg/Document/0x05a-Platform-Overview.md` (one line, so thin); https://developer.android.com/privacy-and-security/risks/strandhogg (fetch first) | 1 |

### Batch B: Windows and Active Directory (writes only to `data/06-network/gap3-{ad,adcs,win,wrmt}.yaml`)

| Rank | # | Topic | Sheet / category / file | Why it is a gap (nearest existing ids) | Primary source to read | Est |
|---|---|---|---|---|---|---|
| 1 | B1 | NTLM relay hardening: SMB signing required, LDAP signing plus channel binding, EPA on HTTP auth endpoints, NTLMv1/LM off | NET / WIN / `06-network/gap3-win.yaml` | NET-SVC-001 checks SMB exposure. NET-SVC-004 checks anonymous and clear-text binds. NET-SVC-012 (Linux agent) covers Samba. No Windows signing or relay controls | `sources/repos/SecurityBenchmarks/Secure Compute Baselines/AzureSecurityCenter_BaselineRules_Windows_Linux_V4.xlsx` (sheet BaselineWindows2016: SMB sign, LDAP client signing, LAN Manager, NTLM SSP); learn.microsoft.com/windows-server/storage/file-server/smb-signing; learn.microsoft.com/windows-server/identity/ad-ds/ldap-signing; CAPEC-644 | 4 |
| 2 | B2 | AD CS certificate template and CA misconfiguration (requester-supplied SAN, any-purpose EKU, enrollment-agent templates, template ACLs, SAN edit flag on CA, NTLM on web enrollment) | NET / ADCS / `06-network/gap3-adcs.yaml` | 0 hits. A domain takeover path that a checklist can verify | learn.microsoft.com/defender-for-identity/security-posture-assessments/certificates; learn.microsoft.com/windows-server/identity/ad-cs/secure-delegate-audit-certification-authority | 4 |
| 3 | B3 | Privileged groups and admin tiering (membership of built-in admin groups, Protected Users, "sensitive and cannot be delegated", admin logon limits, authentication policy silos) | NET / AD / `06-network/gap3-ad.yaml` | NIST-AC-004 reviews privileged roles generically. No directory-specific test | learn.microsoft.com/windows-server/security/credentials-protection-and-management/protected-users-security-group; .../windows-server/security/windows-authentication/how-to-configure-protected-accounts; xlsx user-rights rows | 3 |
| 6 | B4 | Kerberos account hygiene (service accounts with SPNs use gMSA or long random passwords, pre-authentication required, AES only and no RC4/DES, krbtgt rotation) | NET / AD / `06-network/gap3-ad.yaml` | 0 hits for SPN or pre-auth. NET-CRED-004 cracks hashes generically | `sources/capec/capec_latest.xml` (CAPEC-509, 652); learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-service-accounts | 3 |
| 7 | B5 | Credential theft protection on Windows hosts (LSA protection, Credential Guard, WDigest off, cached-logon count, Remote Credential Guard) | NET / WIN / `06-network/gap3-win.yaml` | DESK-DATA-003 checks one app's memory, not OS credential stores | xlsx ("Disallow Digest authentication", LSA rows); learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection; learn.microsoft.com/windows/security/identity-protection/credential-guard/configure; CAPEC-645 | 3 |
| 8 | B6 | Kerberos delegation settings (no unconstrained delegation outside DCs, constrained and resource-based delegation reviewed, sensitive accounts excluded) | NET / AD / `06-network/gap3-ad.yaml` | The 3 "delegation" hits are LLM or NIST access-sharing tests | learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview (verify and fetch); Protected Users page above | 2 |
| 9 | B7 | Unique local administrator passwords (Windows LAPS: deployed, rotation, who can read) | NET / AD / `06-network/gap3-ad.yaml` | NET-CRED-001/005 cover default and hard-coded passwords. Shared local admin passwords are not tested | learn.microsoft.com/windows-server/identity/laps/laps-overview; xlsx "Accounts:" rows | 2 |
| 15 | B8 | Dangerous directory permissions (replication rights held only by DCs, write rights on privileged objects or GPOs, AdminSDHolder) | NET / AD / `06-network/gap3-ad.yaml` | No test. NIST-AC-004/005 are generic | Defender for Identity security posture assessment pages (learn.microsoft.com/defender-for-identity/security-posture-assessments/; verify the page and fetch); `nist80053` AC-6 | 2 |
| 11 | B9 | Windows remote management exposure (WinRM Basic auth off and HTTPS only, RDP with NLA, "deny network logon" for local accounts, remote UAC token filtering) | NET / WRMT / `06-network/gap3-wrmt.yaml` | NET-SVC-002 covers RDP/VNC internet exposure. NET-ADM-001 covers the admin access path. Host-side settings are not tested | xlsx (rows "Allow Basic authentication", Remote Desktop, user-rights "Deny access to this computer from the network", UAC rows) | 3 |
| 20 | B10 | Application and script control on Windows servers and admin hosts (App Control/AppLocker in enforce mode, PowerShell logging and constrained language) | NET / WIN / `06-network/gap3-win.yaml` | NET-SVC-017 (Linux agent) covers fapolicyd and USBGuard on Linux only. NIST-SI-005 covers anti-malware | `nist80053` CM-7(2)/(5); learn.microsoft.com/windows/security/application-security/application-control/ (verify and fetch) | 2 |
| 16 | B11 | Windows local privilege-escalation configuration (writable service binaries and service registry keys, AlwaysInstallElevated, writable autorun and scheduled-task paths, SeImpersonate held by user-reachable services) | NET / WIN / `06-network/gap3-win.yaml` | DESK-CONF-002 and DESK-AUTHZ-001 cover one desktop app's own install, not host-wide | `sources/cwe/cwec_latest.xml.zip` (CWE-732, CWE-276, CWE-428); xlsx UAC rows; learn.microsoft.com/windows/win32/msi/alwaysinstallelevated; Azure Windows baseline CCE-37490-0 (learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows). Service ACL part rests on CWE only (thin) | 2 |

### Batch C: network infrastructure and AI business flows (writes only to `data/06-network/gap3-{l2,v6,rte,smtp,wlan,expo,voip}.yaml` and `data/07-llm/gap3-*.yaml`)

| Rank | # | Topic | Sheet / category / file | Why it is a gap (nearest existing ids) | Primary source to read | Est |
|---|---|---|---|---|---|---|
| 5 | C1 | Mail transport security beyond SPF/DKIM/DMARC (MTA-STS and TLS-RPT published and valid, DANE where DNSSEC exists, no open relay from outside, VRFY/EXPN off, strict end-of-data handling) | NET / SMTP / `gap3-smtp.yaml` | NET-MAIL-001 covers SPF/DKIM/DMARC only. NET-SVC-014 (Linux agent) covers Postfix host config. External, domain-level checks are missing | RFC 8461, RFC 8460, RFC 7672, RFC 5321 §3.3/§4.1.1 (fetch into sources/extra); `nist80053` SC-8 | 4 |
| 12 | C2 | Switch access-port hardening and port-based access control (trunk negotiation off, unused ports disabled, native VLAN not used for users, 802.1X/MAB on wired ports) | NET / L2 / `gap3-l2.yaml` | NET-MITM-001..003 cover ARP, MAC flood and DHCP. NET-DISC-003 detects rogue devices but does not test NAC. VLAN hopping is not tested | `Network_Segmentation_Cheat_Sheet.md`; `nist80053` IA-3, SC-7; `sources/pci_dss/PCI-DSS-v4_0_1.md` (req. 1); IEEE 802.1X-2020 (name only) | 4 |
| 17 | C4 | IPv6 first-hop security on access networks (RA Guard, DHCPv6 guard, rogue RA detection, firewall rules for IPv6 that match IPv4) | NET / V6 / `gap3-v6.yaml` | NET-MITM-003 covers DHCPv4 only. NET-KERN-002 (Linux agent) covers host sysctl, not the network | RFC 6105, RFC 7113, RFC 7610, RFC 9099 (fetch); `nist80053` (IPv6 mentions) | 3 |
| 21 | C5 | Routing and gateway-redundancy protocol authentication (OSPF/BGP/EIGRP auth, passive interfaces, BGP GTSM or TCP-AO, prefix filters, HSRP/VRRP auth) | NET / RTE / `gap3-rte.yaml` | NET-SEG-006 checks spoofed source addresses only | RFC 7454, RFC 5082, RFC 5925, RFC 5709 (fetch); `sources/capec/capec_latest.xml` (CAPEC-584) | 3 |
| 22 | C6 | Wi-Fi client-side and management-frame controls (802.1X supplicants validate the server certificate, Protected Management Frames, guest client isolation, WPS off) | NET / WLAN / `gap3-wlan.yaml` | NET-WIFI-002 checks AP auth and encryption. Evil-twin resistance of clients and PMF are not tested | `nist80053` AC-18; `sources/pci_dss/PCI-DSS-v4_0_1.md` (2.3, 11.2); IEEE 802.11-2020 (PMF, formerly 802.11w) and the Wi-Fi Alliance WPA3 specification (fetch). `nist800-115.txt` §4.4 covers wireless scanning only | 3 |
| 18 | C7 | Exposed debug and remote-execution protocols (Java debug wire, JMX/RMI, X11, distcc, AJP, FastCGI reachable over the network) | NET / EXPO / `gap3-expo.yaml` | NET-SVC-006 covers DB listeners and NET-SVC-007 covers the container API. NET-DISC-008 is generic. These protocols give code execution without credentials | `sources/cwe/cwec_latest.xml.zip` (CWE-306, CWE-489); `nist80053` CM-7 | 2 |
| 27 | C8 | Payments started by AI agents (agent identity before screening, sanctions/AML screening of payee and operator, signed audit trail, spend authority) | LLM / PAY / `07-llm/gap3-pay.yaml` | LLM-DOS-003 and LLM-MCP-010 cover spend caps, LLM-AGENCY-004 covers approvals. No AML or payee-screening test. Cheat sheet not cited | `AML_Sanctions_AI_Agent_Payments_Cheat_Sheet.md` (single source, so flag as thin) | 3 |
| 29 | C9 | AI in advertising systems (consent gate on AI decisions, corpus protection, outcome-event integrity) | LLM / ADS / `07-llm/gap3-ads.yaml` | PRIV-CONSENT-001 and MOB-PRIV-007 cover ad consent, not AI ad pipelines. Cheat sheet not cited | `AI-Powered_Advertising_Systems_Security_Cheat_Sheet.md` | 2 |
| 28 | C10 | VoIP signalling and media protection (SIP over TLS, SRTP, registration auth and rate limits, toll-fraud limits) | NET / VOIP / `gap3-voip.yaml` | 0 hits | RFC 3261 §26, RFC 3711 (fetch); `sources/extra/nist800-115.txt` (VoIP mentions) | 2 |

Total: 29 topics (A 9, B 11, C 9), about 87 tests.

### Pre-fetch lists (exact URLs; the caller fetches them if the writer has no web tool)

- **A:** https://developer.android.com/privacy-and-security/risks/strandhogg ; https://www.rfc-editor.org/rfc/rfc9113 ;
  https://www.rfc-editor.org/rfc/rfc9114 ; https://w3c.github.io/ServiceWorker/ ; https://w3c.github.io/webappsec-fetch-metadata/ ;
  https://wicg.github.io/private-network-access/ ; https://w3c.github.io/webappsec-dbsc/
- **B:** https://learn.microsoft.com/windows-server/storage/file-server/smb-signing ;
  https://learn.microsoft.com/windows-server/identity/ad-ds/ldap-signing ;
  https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server ;
  https://learn.microsoft.com/defender-for-identity/security-posture-assessments/certificates ;
  https://learn.microsoft.com/windows-server/identity/ad-cs/secure-delegate-audit-certification-authority ;
  https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/protected-users-security-group ;
  https://learn.microsoft.com/windows-server/security/windows-authentication/how-to-configure-protected-accounts ;
  https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-service-accounts ;
  https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection ;
  https://learn.microsoft.com/windows/security/identity-protection/credential-guard/configure ;
  https://learn.microsoft.com/windows-server/identity/laps/laps-overview ;
  https://learn.microsoft.com/windows/win32/msi/alwaysinstallelevated ;
  https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows .
  Not yet verified (search first): Kerberos constrained delegation overview, App Control for Business overview,
  Defender for Identity posture pages for delegation and sensitive groups.
- **C:** RFC 8461, 8460, 7672, 5321, 6105, 7113, 7610, 9099, 7454, 5082, 5925, 5709, 3261, 3711
  (https://www.rfc-editor.org/rfc/rfcNNNN.txt); IEEE 802.11-2020 summary and the Wi-Fi Alliance WPA3 specification.

**Top 5 by auditor value:** B1 NTLM relay hardening, B2 AD CS templates, B3 privileged groups and tiering,
A1 framework production configuration, C1 mail transport (MTA-STS/DANE/open relay).

## (b) Topics rejected on purpose

Rejected classes (named in our words, not the wiki titles):

1. **Pages for a single product, CMS or appliance** (CMS platforms, wiki/ticket tools, specific gateways, backup
   consoles, hypervisor consoles). The controls they show are already generic tests: WEB-CONF-002/003/007 and
   NET-VULN-004/007.
2. **Exploit chains for one CVE or one language trick** (LFI-to-RCE variants, specific deserialization gadgets,
   print-spooler and coercion CVEs, logging-library JNDI). The weakness classes are covered: WEB-INJ-013,
   WEB-INJ-025, WEB-DESER-001, WEB-VAL-003.
3. **SQL dialect pages for each DBMS.** WEB-INJ-002 already tests each backend.
4. **Tool tutorials and cheat sheets** (proxies, injection automators, instrumentation frameworks, scanners,
   RF tools). These are not controls.
5. **Offensive tradecraft and post-exploitation** (reverse shells, C2, tunneling, AV/EDR evasion, ticket
   forging, token-abuse tools, persistence, anti-forensics, offensive OPSEC/anonymity). The defensive side is
   covered by batch B (B1–B11).
6. **Binary exploitation, reversing, crypto/stego puzzles, CTF write-ups.** DESK-CODE-004 and MOB-CODE-005
   cover compiler hardening flags.
7. **Forensics and malware analysis.** This is incident-response work, not a pass/fail control. Process tests
   exist: PRIV-BREACH-*, IOT-MGMT-002.
8. **Already covered, so no new test** (keyword grep gave false zeros):
   - broadcast name poisoning (NET-MITM-004)
   - cross-site script inclusion (WEB-CLIENT-007)
   - cookie prefixes and tossing (WEB-SESS-009)
   - oversized cookies (WEB-CLIENT-010)
   - agent-to-agent protocols (LLM-AGENT-007/020/021)
   - exposed inference servers (LLM-SUPPLY-009)
   - identity propagation (API-MSVC-003/004; only add `Identity_Propagation_Patterns` and
     `Authentication_Patterns` as refs)
   - subdomain takeover (WEB-CONF-011)
   - browser extensions (WEB-EXT-001..003)
   - archive path traversal (WEB-FILE-004)
   - debug, actuator and API-doc endpoints (WEB-CONF-002/003, API-GQL-010)
   - source-control exposure (WEB-CONF-005)
   - reverse tabnabbing (WEB-CLIENT-008)
   - request smuggling (WEB-HTTP-004)
   - Secure Boot (NET-OS-008)
   - CI platform hardening (CICD-*)
   - lookalike domains (NET-DNS-003, WEB-IDM-*)
9. **Cloud, Kubernetes, Linux and SaaS-tenant topics.** Other agents own these. SaaS identity-provider tenant
   hardening (admin MFA, third-party OAuth app consent) should go to the cloud agent. If the cloud agent does not
   take it, it belongs in a later batch.

## (c) Needs source (no usable primary source on disk; do not write until one is fetched)

- **Out-of-band management controllers (BMC/IPMI)**: removed from batch C. NIST 800-53 on disk mentions only
  out-of-band *authentication*. Fetch the NSA/CISA 2023 joint BMC hardening guidance (confirm the exact title and
  URL first) or vendor iLO/iDRAC hardening guides. Nearest test: NET-ADM-006. Estimate: 3 tests, category NET-OOB.

- **OT/ICS assessment**: `sources/attack/ics-attack.json` is an attack taxonomy only. Fetch NIST SP 800-82r3
  (or use IEC 62443, which is not freely available).
- **Network printers and multifunction devices** (stored jobs, saved LDAP/SMTP credentials, raw print ports): no
  standard on disk. NIST SP 800-53 is too generic. A candidate is the NIST/NIAP Protection Profile for Hardcopy
  Devices.
- **macOS endpoint hardening** (Gatekeeper, SIP, FileVault, TCC): fetch the Apple Platform Security guide or the
  macOS Security Compliance Project.
- **Smart contracts and wallet-signing flows**: fetch the EEA EthTrust Security Levels spec.
- **Physical access badges and RFID cloning**: there is no control standard on disk.
- **Account pre-hijacking at registration**: the only source is academic (USENIX Security 2022). Nearest test:
  WEB-IDM-002.
- **Client-side path traversal** (user input in front-end fetch paths): there is no OWASP sheet or WSTG section.
  The only fit is the generic CWE-22.
- **C-based toolchain hardening at build time**: the `C-Based_Toolchain_Hardening` sheet is on disk. Decide
  first whether it belongs in CICD or DESK, because DESK-CODE-004 already checks the output binary.

## Quality risks (checks a reviewer should run on the existing 1,559 tests)

1. **Thin sources.** 245 tests have exactly one `sources_read` entry. Some whole categories are 100%
   single-source: all PCI-* categories (AUTH, LOG, KEY, DATA, SWDEV, CHG, ACC), NIST-AU, NIST-SI, WEB-ZTA,
   WEB-LEGACY, WEB-THREAT, WEB-VDP, LLM-EVID and LLM-CODING. Check that the steps follow from that one file.
2. **Mapping that is too complete.** All 345 ASVS ids and all 78 MASWE ids are referenced. Sample about 30
   (ASVS L3 and MASWE privacy ids) and confirm that the test steps verify the requirement, not just a similar
   title.
3. **ATT&CK refs checked against titles only.** `catalog/attack.json` holds only id/title/chapter. Enterprise
   STIX is not on disk (only `mobile-attack.json` and `ics-attack.json`). Check that the 126 `refs.attack`
   values are correct.
4. **PCI catalog truncation and a stale note.** `guide/sources-fetch-B.md` still says the PCI catalog is blocked
   with 0 items. It now has 309 items, with titles cut to 14 words. Check a sample of the 144 PCI refs against
   the full text in `sources/pci_dss/PCI-DSS-v4_0_1.md`.
5. **Likely duplicates under the merge rule:**
   - WEB-INJ-018 and WEB-HTTP-004 (request smuggling)
   - WEB-INJ-025 and WEB-DESER-001 (deserialization)
   - WEB-CLIENT-004, WEB-HTTP-009 and API-WS-001..004 (WebSockets)
   - WEB-AUTHZ-007 and WEB-INJ-022 (mass assignment)
   - WEB-CONF-013 and WEB-CACHE-002 (path confusion)
   - WEB-AUTHZ-015 and WEB-INJ-013 (traversal and inclusion)
   - NET-MAIL-001 and NET-SVC-014 (mail)
6. **Categories with one test**: WEB-DESER, WEB-PQC, WEB-WASM, WEB-ELEV, WEB-PAY, NET-MAIL, NIST-CM, PCI-CFG,
   PCI-RISK. Several 2-test categories also come from earlier gap runs (WEB-ABUSE, BOT, CACHE, DB, EMAIL, MFE).
   Decide for each whether to merge it into a parent category or grow it.
7. **Cheat sheets that no test cites**, although tests exist on the same topic: `Access_Control`,
   `Transport_Layer_Protection`, `TLS_Cipher_String`, `Injection_Prevention`, `Injection_Prevention_in_Java`.
   WEB-AUTHZ-* and WEB-TLS-* may rest on thinner sources than are available.
8. **Parallel-writer collisions.** NET-SVC now spans `svc.yaml` and `gap2-svc.yaml`. After the cloud, K8s and
   Linux agents and the three batches above finish, run `tools/validate.py` and check that ids are unique and
   that no file holds two categories.
