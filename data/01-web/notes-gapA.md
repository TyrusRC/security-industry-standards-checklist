# Gap-fill notes, group A

## DevGuide web app checklist (10 pages)
Each item was compared with existing test titles and steps. Most items are covered by existing tests.

| Page | Covered by existing tests | New tests | Skipped (reason) |
|---|---|---|---|
| 01-secure-by-default | CONF-002/003/005/006/007/008/010, INFO-002/003, FILE-*, CRYPTO-018, SECRET-001, ARCH-003, ZTA-004, K8S/CLD tests | none | Change control and dev/prod isolation: process items, covered in sheet PCI/CICD (PCI-CHG, CICD-*) |
| 02-frameworks-libraries | DEP-001..007, CICD-TPS-003 | WEB-MFE-002 (remote code loading) | Technology cheat sheet list: pointers only |
| 03-secure-database-access | INJ-001/004/005, ARCH-003, CRYPTO-018 | WEB-DB-001, WEB-DB-002 | "Close connection early", "use stored procedures": design advice without a pass/fail test |
| 04-encode-escape-data | XSS-004, INJ-014, HTTP-001, VAL-008 | none | none |
| 05-validate-inputs | VAL-*, FILE-*, INJ-025, DEP-006, CLIENT-001, IDOR-004 | WEB-DESER-001 (deserialization isolation and logging), WEB-XMLSEC-002, WEB-PAY-001 | none |
| 06-digital-identity | AUTHN-*, PWD-*, MFA-*, SESS-*, AUTHN-013 (last sign-in), SESS-026 | WEB-PWD-023 (password reuse), WEB-CSRF-001..005 (item SM 22), WEB-EMAIL-001/002, WEB-PASSKEY-* | Periodic session ID renewal and renewal at HTTP to HTTPS change: not in ASVS 5, low value |
| 07-access-controls | AUTHZ-*, IDOR-*, BIZ-009, ZTA-*, API-BFLA-*, API-BOLA-* | WEB-PDP-001..004, WEB-ELEV-001 | "Do not hard code roles", "segregate privileged logic": code review items (WEB-CODEREV-002) |
| 08-protect-data | CRYPTO-*, DATA-*, TLS-*, HDR-001, SECRET-*, CLIENT-013 | WEB-PQC-001 | Memory management (non-executable stacks, free memory): native code only, partly VAL-005/007, CRYPTO-017 |
| 09-logging-monitoring | LOG-001..014, AUTHN-025 | none | none |
| 10-handle-errors-exceptions | ERR-001..005, LOG-010 | none | "Free memory on errors": native code only |

## New tests per cheat sheet
- Authorization_Patterns, Authorization_Decisions_And_Output_Handling, Authorization_Policy_And_Data_Distribution, Authorization_Regression_Testing, Authorization_Testing_Automation: new WEB-PDP-001..004 (data/01-web/gap-pdp.yaml); mapped to API-MSVC-001, WEB-ZTA-005, WEB-AUTHZ-010/011/017.
- Authentication_Patterns, Identity_Propagation_Patterns: mapped only (API-MSVC-001/003/004, WEB-CONF-015, WEB-AUTHZ-011/014, WEB-OAUTH-006, WEB-JWT-006/007). Reason: existing tests already test the controls.
- Multi_Tenant_Security: new WEB-TENANT-001..006; mapped to WEB-AUTHZ-012, API-BOLA-006, API-MSVC-002.
- Passkey_Security: new WEB-PASSKEY-001..004.
- Cookie_Theft_Mitigation: mapped only (WEB-ZTA-002, WEB-AUTHZ-008, WEB-SESS-008, WEB-AUTHN-013).
- Cross-Site_Request_Forgery_Prevention: new WEB-CSRF-001..005. WEB-SESS-030 already existed as a basic CSRF test and is mapped; the new tests cover origin and Fetch Metadata checks, token binding, double-submit cookies, login CSRF and client-side CSRF.
- Injection_Prevention: mapped only (INJ-001/004/006/012/014, XSS-004, VAL-012).
- XML_Security: new WEB-XMLSEC-001..003; mapped to INJ-007/008, API-SOAP-001/002, DESK-INJ-003.
- XSS_Filter_Evasion: mapped only (XSS-001/002/003/004/010). The sheet is a payload list; no new control.
- Web_Frontend_Security: mapped only (XSS-003/006/009, CLIENT-005/006/018).
- Micro_Frontend_Security: new WEB-MFE-001/002.
- XS_Leaks: new WEB-XSLEAK-001; mapped to CLIENT-003/005/009/014/021.
- Web_Cache_Security: new WEB-CACHE-001/002; mapped to CONF-013, DATA-003/006/011, INJ-019.
- Bot_Management_and_Anti-Automation: new WEB-BOT-001/002; mapped to AUTHN-002/003/004, BIZ-009/010/011.
- Webhook_Security: new WEB-WEBHOOK-001..004; mapped to API-SSRF-003 (publisher SSRF) and API-CONS-005.
- Database_Security: new WEB-DB-001/002; mapped to NET-SVC-006, NET-SEG-002, WEB-ARCH-003, DESK-COMM-005, CLD-CFG-004, NET-BKP-002.
- Browser_Extension_Vulnerabilities: new WEB-EXT-001..003 (a few topics, such as XSS and CSP, are merged into these).
- Post_Quantum_Cryptography: new WEB-PQC-001; mapped to WEB-CRYPTO-002/004 (inventory, agility).
- Third_Party_Payment_Gateway_Integration: new WEB-PAY-001; mapped to BIZ-012/014, API-CONS-005.
- Email_Validation_and_Verification: new WEB-EMAIL-001/002; mapped to IDM-004, PWD-017/018, AUTHN-014/015, SESS-025.
- Access_Control, Transport_Layer_Protection, TLS_Cipher_String: skipped. The files are deprecated stubs without controls (they point to Authorization and Transport Layer Security cheat sheets).

## Open points
- WEB-SESS-030 and WEB-CSRF-001 share the cross-site request theme. SESS-030 is the generic WSTG-SESS-05 test; CSRF-001..005 each check a separate control.
- Mapping file: data/mappings/cheatsheet-A.json (25 cheat sheets).
