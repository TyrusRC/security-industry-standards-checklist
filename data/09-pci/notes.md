# PCI DSS v4.0.1 notes (sheet PCI)

Source: sources/pci_dss/PCI-DSS-v4_0_1.md. Catalog: catalog/pci_dss.json (179 items with "software": true).
Mapping file: data/mappings/pci.json (all 179 software items are keys).

## Counts
- 179 software items. 128 have at least one test. 51 have none (see below).
- 80 new tests in data/09-pci (cfg, trans, data, key, swdev, chg, acc, auth, log, scan, risk).
- 43 items are covered by existing tests only. 85 items have a new PCI test (many also have existing tests).
- Of the 51 empty items: 31 are section headers, 14 are x.1.1 and x.1.2 policy and role items, 6 are listed below.

## Decisions
- Mapping rule: a test is mapped only when its steps check the control in the requirement. Existing refs.pci_dss values from the NET sheet were kept. Non-software ids in those refs (1.x, 11.2.1, 11.5.x, 12.5.2, 12.6.x, 12.10.5) are not in the mapping file because they are out of scope.
- Several existing tests use ASVS limits that differ from PCI DSS (WEB-PWD-001: 8 characters, WEB-PWD-008: no composition rule, WEB-PWD-010: no forced rotation). They are NOT mapped to 8.3.6 or 8.3.9. New tests PCI-AUTH-009 and PCI-AUTH-011 hold the PCI values (12 characters with letters and digits, 90 days or dynamic analysis).
- WEB-AUTHN-002 and API-AUTHN-003 are mapped to 8.3.4 as partial cover. PCI-AUTH-008 adds the exact limits (10 attempts, 30 minutes).
- WEB-SESS-019 is partial for 8.2.8 (no 15 minute value). PCI-AUTH-007 adds the value.
- WEB-DATA-007 and WEB-DATA-013 are partial for 3.4.1 and 3.5.1. The PCI-DATA tests add PAN, BIN and last four digits, SAD and key rules.
- 6.2.4 is mapped to a set of representative attack-class tests (injection, XSS, CSRF, crypto, business logic, access control). PCI-SWDEV-004 checks the documented methods.
- 6.3.3 (one month for critical patches) is covered by NET-VULN-004 and others. No new test was written (merge rule).
- 2.2.5 is covered by NET-DISC-008 and NET-ADM-002. 2.3.1 and 2.3.2 are covered by NET-WIFI-002 and NET-WIFI-003. No new tests (merge rule).
- 8.3.10 and 8.3.10.1 (service provider only) share one test, PCI-AUTH-012. 11.3.1.3 and 11.3.2.1 share PCI-SCAN-001. 3.6.1.2 and 3.7.3 share PCI-KEY-003. 7.2.5 and 7.2.5.1 share PCI-ACC-003. 10.4.2 and 10.4.2.1 share PCI-LOG-010.
- Existing NET-LOG-001 (10.4.1) and NET-LOG-003 (10.5.1) cover network devices only. PCI-LOG-008 and PCI-LOG-012 cover all in-scope systems.
- Most new tests are Manual or Config Review because the control is a process or a configuration. Test cards and test PANs only. Never use live PANs.

## Items with no test
- Section headers (no own control): 2.1, 2.2, 2.3, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 4.1, 4.2, 6.1, 6.2, 6.3, 6.4, 6.5, 7.1, 7.3, 8.2, 8.3, 8.4, 8.5, 8.6, 10.1 to 10.7. Their child items carry the tests.
- Policy and role items (documents only, not software tests): 2.1.1, 2.1.2, 3.1.1, 3.1.2, 4.1.1, 4.1.2, 6.1.1, 6.1.2, 7.1.1, 7.1.2, 8.1.1, 8.1.2, 10.1.1, 10.1.2.
- 3.3.3: applies to issuers only. Needs issuer business justification review. Not written.
- 3.7.8: key custodian acknowledgement forms. Organisational, no technical check.
- 6.2.2: developer training at least every 12 months. Organisational (training records).
- 8.3.8: documented guidance to users on authentication. Organisational (communication).
- 11.4.6: segmentation penetration test every six months for service providers. Segmentation is out of scope for this sheet.
- 11.4.7: multi-tenant service providers support external penetration tests of customers. Organisational.

## Out of scope
- Physical, wireless-only rogue AP, network segmentation and firewall items (Req 1, 9, 11.2, 11.5, 12 except 12.3.1) are not software. Segmentation rules are covered in the NET sheet.
- 4.2.1.2 (wireless best practices) is mapped to NET-WIFI-002. 4.2.1 is mapped to the WEB-TLS tests and others.
