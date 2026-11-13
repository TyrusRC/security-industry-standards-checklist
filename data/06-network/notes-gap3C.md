# Gap batch C notes (network and AI business flows)

Date: 2026-11-12. Wi-Fi topic C6 (gap3-wlan) is postponed by the user: nothing written.

| Topic | File | Tests | Sources read |
|---|---|---|---|
| C1 SMTP | gap3-smtp.yaml | NET-SMTP-001..006 | RFC 8461, 8460, 7672, 5321 (sections 3.5, 4.1.1.3, 4.1.1.4, 7.3, 7.9); NIST 800-53 catalog |
| C2 L2 | gap3-l2.yaml | NET-L2-001..004 | Network_Segmentation cheat sheet, NIST IA-3/SC-7, PCI DSS 1.4.1 |
| C4 IPv6 | gap3-v6.yaml | NET-V6-001..003 | RFC 6105, 7113, 7610, 9099 |
| C5 routing | gap3-rte.yaml | NET-RTE-001..003 | RFC 7454, 5082, 5925, 5709, 9099 2.5.2, CAPEC-584 |
| C7 exposure | gap3-expo.yaml | NET-EXPO-001..003 | CWE-306, CWE-489 (cwec zip), NIST CM-7 |
| C10 VoIP | gap3-voip.yaml | NET-VOIP-001..003 | RFC 3261 section 26, RFC 3711 section 9 |
| C8 payments | 07-llm/gap3-pay.yaml | LLM-PAY-001..005 | AML_Sanctions_AI_Agent_Payments cheat sheet (single source, thin) |
| C9 ads | 07-llm/gap3-ads.yaml | LLM-ADS-001..003 | AI-Powered_Advertising_Systems cheat sheet (single source) |

Total: 26 tests.

## Gaps and skipped parts
- C2: no source covers trunk negotiation, native VLAN or 802.1X/MAB details. The Network_Segmentation cheat sheet only shows VLAN zones, and IEEE 802.1X is not in sources/. The steps use common vendor practice; the example column holds Cisco-style commands. Treat the L2 tests as thin.
- C4: the RFC 9099 firewall text is in section 3.1 (not 2.x).
- C5: no source for EIGRP, HSRP or VRRP authentication, so nothing is written for them. RFC 7454 does not require TCP-AO or MD5 (it says "NOT REQUIRED"), so the test states it as a recommendation.
- C7: no vendor documents for JDWP, distcc, AJP or FastCGI are in sources/. The tests use the CWE and CM-7 basis and tool hints only.
- C10: the plan source RFC 3261 has no toll-fraud rules, so no toll-fraud test. nist800-115.txt only names SIP tools (BackTrack) and gives no VoIP control, so it is not cited in tests.
- C8/C9: single source each; every note field says so. OFAC and GDPR legal duties are not tested; the tests check technical controls only.
- No cheat-sheet id was cited unless the file was read. NET-SMTP tests carry no cheat-sheet ref.
- Pointer tests (`see`): NET-MITM-003, NET-SEG-006, NET-DISC-003, NET-DISC-008, NET-SVC-014, LLM-AGENT-007/009, LLM-AGENCY-004, LLM-DOS-003, LLM-MCP-010, PRIV-CONSENT-001, LLM-POISON-001, LLM-RAG-001.
