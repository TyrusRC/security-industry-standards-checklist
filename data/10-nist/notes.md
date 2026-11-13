# Notes for the NIST sheet (data/10-nist)

Sources read: sources/nist80053/NIST_SP-800-53_rev5_catalog.json (statement and guidance parts of each mapped control), sources/extra/nist-800-63b.html (SP 800-63B-4, for the lockout, timeout and authenticator tests), sources/extra/nist-ai-rmf.txt (AI RMF 1.0), catalog/nist_ssdf.json (SSDF 1.1 ids and titles).

## Result
- Families in scope: AC, AU, IA, SC, SI, SA, CM. The catalog lists 651 non-withdrawn controls in these families.
- In scope (a security test on a software system can check the control): 239. Skipped: 412.
- Mapped to at least one existing test: 223. Covered only by a new test of this sheet: 16. Left without any test: 0.
- New tests: 29 (AC 12, AU 4, IA 2, SC 3, SI 5, SA 2, CM 1). They add a test id to 81 controls in data/mappings/nist.json.
- Mapping file: data/mappings/nist.json, key nist_800_53, one key per in-scope control. `python3 tools/check_mappings.py` gives 0 errors.

## Decisions
- A test is mapped only when its title and steps check the same thing as the control text. Many existing tests carry an older nist_800_53 ref list in their own YAML. These refs were used as a start and were re-read. Tests with wide scope (for example SC-7, SC-5, AC-3, AC-6) are listed on the base control and on the enhancements that they really check.
- The control text of each in-scope control was read in the OSCAL file. Organisation-defined parameters are not fixed here. The test steps say "the policy sets" the value.
- The PCI sheet (data/09-pci) had no tests when this work was done. No PCI test is mapped. Run this mapping again when the PCI sheet exists.
- Merge rule: a control that an existing test already checks got no second test. New tests exist only where no existing test checked the control, or only part of it. Their ids are added to the mapping.
- New tests have the sheet NIST and use the test types Config Review and Manual. Ids in refs were checked by tools/validate.py.
- AI RMF and SSDF have no key in the schema refs. Their mapping is given below as plain text only.

## Skipped (not tested by software security tests)
- All X-1 policy and procedure controls: AC-1, AU-1, IA-1, SC-1, SI-1, SA-1, CM-1. Reason: policy documents.
- Organisational, personnel or physical controls: AC-3(3) mandatory access control model, AC-16 and AC-16(x) attribute models, AC-18 wireless, AC-19 mobile device management, AC-20 external systems, AC-21 information sharing, AC-25 reference monitor, AU-10(x) chain of custody, AU-13 and AU-14 and AU-16 cross-organisation, CM-2(7) travel, CM-9 plan, CM-10 licence tracking, IA-4(4) and IA-4(5) and IA-4(6), IA-5(8) multiple systems, IA-5(12) and IA-5(17) biometrics, IA-5(15) GSA products, IA-5(16) in-person, IA-12(1) to IA-12(6) identity proofing process steps, IA-2(12) and IA-8(1) PIV, SA-2 resources, SA-4 acquisition (except SA-4(9)), SA-5 documentation, SA-8 other principles, SA-16 training, SA-17 design documents, SA-20, SA-21 screening, SA-23, SA-24, SC-7(25) to SC-7(27) national security, SC-40 wireless link, SC-48 sensor relocation, SC-51 hardware, SI-5 advisories, SI-8 spam, SI-13 to SI-14 component failover, SI-18 to SI-23 privacy and tainting, SI-19 de-identification.
- Hardware or physical separation items: AC-6(4), SC-3(1), SC-4(2), SC-7(14), SC-31, SC-32, SC-34, SC-39(1), SC-49, SC-50, SI-7(9), SI-7(10).
- Controls for classified, cross-domain or high-assurance guard systems: AC-4(1) to AC-4(32) except AC-4 and AC-4(21), AC-3(15), SC-46.
- Further enhancement skips: reasons are the same (organisation process, no software test). Every enhancement not listed in data/mappings/nist.json is out of scope for this reason.

## In-scope controls with a weak (partial) mapping
Each control has at least one test. These controls are checked in a narrow way, or only through tests of other sheets. Add tests here if an assessor needs more depth.
| Control | Why partial |
|---|---|
| AU-5(1), AU-5(2), AU-12(3), AC-3(4), AC-3(10), AC-8, AC-11(1), AC-12(2), AC-12(3), SI-2(6), SI-4(10), SI-7(8), SI-10(1), SA-11(9), SA-15(2), CM-4 | Only the new NIST tests check them. No other sheet has a test. |
| AC-11 | Only desktop and mobile tests exist, plus NIST-AC-009. Web apps use session timeouts (AC-12). |
| AC-2(6), AC-2(11) | Dynamic privilege and usage conditions: checked only through contextual access tests. |
| SC-12(1) | Key loss recovery: one existing test and NIST-SC-001. |
| SC-7(8), SC-7(4) | Proxy and managed interface: few tests. |
| IA-4(1), IA-7, IA-12 | One or two existing tests each. IA-12 identity proofing steps are skipped. |
| SI-6 | Function self-test: tests of other sheets are release gates only. NIST-SI-004 adds the check. |
| AU-7, AU-7(1), AU-12(2) | Log format and search: one existing test and NIST-AU-004. |
| CM-3(6), CM-12, CM-12(1) | Cryptography under configuration control and data location: broad tests only. |

## AI RMF 1.0 to LLM tests
AI RMF items are listed only when a test in data/07-llm checks the item. Organisational items (for example GOVERN 1.1, GOVERN 2.x, GOVERN 3.x, MAP 1.x, MAP 5.x) have no test.
| AI RMF item | Topic | LLM tests |
|---|---|---|
| GOVERN 1.6 | Inventory of AI systems | LLM-SUPPLY-007, LLM-AGENCY-001 |
| GOVERN 1.7 | Decommission and phase out | LLM-RAG-012, LLM-GOV-004 |
| GOVERN 4.3 | Testing, incident identification and information sharing | LLM-GOV-006, LLM-GOV-005, LLM-MODEL-007 |
| GOVERN 6.1 | Risks of third-party software and data | LLM-SUPPLY-008, LLM-SUPPLY-013, LLM-DATA-013 |
| GOVERN 6.2 | Contingency for third-party failures | LLM-DOS-011, LLM-AGENT-011 |
| MAP 2.2 | Knowledge limits and use of output | LLM-MISINFO-002, LLM-MISINFO-007 |
| MAP 3.5 | Human oversight processes | LLM-AGENCY-004, LLM-AGENCY-005, LLM-AGENT-027 |
| MAP 4.1 | Legal risks of components, data and software | LLM-SUPPLY-007, LLM-SUPPLY-008 |
| MAP 4.2 | Internal risk controls of AI components | LLM-AGENCY-006, LLM-AGENT-023, LLM-PINJ-012 |
| MEASURE 1.3 | Independent expert assessment | LLM-GOV-006, LLM-PINJ-016, LLM-SUPPLY-013 |
| MEASURE 2.4 | Monitoring of behaviour in production | LLM-OUTPUT-011, LLM-AGENCY-014, LLM-AGENT-029 |
| MEASURE 2.5 | Validity and reliability | LLM-MODEL-004, LLM-MISINFO-002, LLM-MISINFO-005 |
| MEASURE 2.6 | Safety risk evaluation | LLM-MISINFO-010, LLM-MODEL-005, LLM-AGENCY-004 |
| MEASURE 2.7 | Security and resilience | LLM-PINJ-001, LLM-PINJ-007, LLM-PINJ-008, LLM-PINJ-015, LLM-MODEL-001, LLM-POISON-001, LLM-POISON-003, LLM-SYSPROMPT-001, LLM-DOS-001, LLM-AGENT-012 |
| MEASURE 2.8 | Transparency and accountability | LLM-RAG-013, LLM-AGENT-026, LLM-MISINFO-008 |
| MEASURE 2.9 | Explanation and interpretation of output | LLM-MISINFO-008, LLM-MISINFO-004 |
| MEASURE 2.10 | Privacy risk of the AI system | LLM-DATA-001, LLM-DATA-002, LLM-DATA-003, LLM-DATA-004, LLM-MODEL-002, LLM-MODEL-003 |
| MEASURE 2.11 | Fairness and bias | LLM-MISINFO-009, LLM-GOV-001 |
| MEASURE 3.1 | Tracking of identified risks over time | LLM-POISON-005, LLM-GOV-006 |
| MEASURE 4.1 | Measurement connected to deployment context | LLM-MODEL-007, LLM-RAG-018 |
| MANAGE 1.3 | Responses to high priority risks | LLM-AGENCY-004, LLM-AGENT-030, LLM-GOV-005 |
| MANAGE 2.2 | Mechanisms to sustain value and supersede systems | LLM-AGENT-011, LLM-AGENCY-015 |
| MANAGE 2.3 | Response to unknown risks | LLM-AGENT-030, LLM-AGENCY-007, LLM-GOV-005 |
| MANAGE 2.4 | Disengage or deactivate AI that behaves wrongly | LLM-AGENCY-015, LLM-AGENT-030, LLM-AGENT-011 |
| MANAGE 3.1 | Risks of third-party resources are monitored | LLM-SUPPLY-001, LLM-SUPPLY-003, LLM-SUPPLY-009, LLM-MCP-009 |
| MANAGE 3.2 | Pre-trained models are monitored | LLM-SUPPLY-002, LLM-SUPPLY-004, LLM-SUPPLY-005, LLM-POISON-006, LLM-POISON-007 |
| MANAGE 4.1 | Post-deployment monitoring and incident handling | LLM-OUTPUT-011, LLM-DATA-005, LLM-MCP-010, LLM-GOV-005, LLM-DOS-013 |
| MANAGE 4.3 | Incidents and errors are communicated | LLM-GOV-005, LLM-AGENT-026 |

## SSDF 1.1 to CI/CD and related tests
| SSDF item | Topic | Tests |
|---|---|---|
| PO.3.2 | Secure operation of toolchain | CICD-CFG-001, CICD-CFG-002, CICD-CFG-003, CICD-CFG-005, CICD-IAM-003 |
| PO.3.3 | Tools produce evidence artifacts | CICD-LOG-002, CICD-LOG-003, CICD-ART-003, CICD-ART-004, CICD-ART-009 |
| PO.4.2 | Gather and protect check information | CICD-LOG-005, CICD-LOG-007, CICD-ART-009, CICD-VULN-001 |
| PO.5.1 | Separate and protect environments | CICD-CFG-009, CICD-PBAC-003, CICD-PBAC-006, CICD-FLOW-008 |
| PO.5.2 | Harden development endpoints | CICD-CFG-008, CICD-CRED-002, CICD-PBAC-001 |
| PS.1.1 | Protect code from unauthorized access and change | CICD-FLOW-001, CICD-FLOW-002, CICD-FLOW-003, CICD-ART-001, CICD-IAM-001, CICD-CFG-006, CICD-ART-007 |
| PS.2.1 | Integrity verification information for acquirers | CICD-ART-002, CICD-ART-003, CICD-ART-004, CICD-ART-006, LLM-SUPPLY-003 |
| PS.3.1 | Archive and protect each release | CICD-ART-005, CICD-ART-007, CICD-ART-009, CICD-CFG-011 |
| PS.3.2 | Provenance data for components | CICD-ART-003, CICD-ART-004, LLM-SUPPLY-007 |
| PW.1.1 | Risk modelling | API-MSVC-005, NET-REV-001 |
| PW.2.1 | Design review | API-MSVC-005, WEB-ARCH-001 |
| PW.4.4 | Verify acquired third-party components | CICD-DEP-001, CICD-DEP-002, CICD-DEP-003, CICD-DEP-004, CICD-DEP-008, CICD-TPS-003, CICD-DEP-007, CICD-VULN-001 |
| PW.5.1 | Secure coding practices | CICD-VULN-006, CICD-PPE-006, WEB-VAL-012, OWASP injection tests in the WEB sheet |
| PW.6.1 | Compiler and build tool security features | MOB-CODE-005, DESK-CODE-004, CICD-DEP-003, CICD-DEP-009 |
| PW.7.1 | Decide on code review or analysis | CICD-FLOW-001, CICD-PPE-002, LLM-OUTPUT-008 |
| PW.7.2 | Do the code review and analysis | CICD-VULN-006, CICD-VULN-005, CICD-CRED-001, CICD-CRED-002 |
| PW.8.2 | Scope, design and run executable code tests | CICD-VULN-001, CICD-VULN-002, API-REST-002, API-BOLA-008, NIST-SA-002 |
| PW.9.1 | Secure baseline | CICD-CFG-003, WEB-CONF-001, K8S-CMP-001, API-CONF-009 |
| PW.9.2 | Secure defaults | CICD-IAM-004, WEB-CONF-002, IOT-DEF-001 |
| RV.1.1 | Gather vulnerability information | CICD-VULN-003, WEB-DEP-003, CLD-SUP-004 |
| RV.1.2 | Review, analyze and test to confirm vulnerabilities | CICD-VULN-001, CICD-VULN-002, CICD-VULN-003, NET-VULN-001 |
| RV.2.1 | Analyze each vulnerability for risk | NET-VULN-002, NET-VULN-003, CICD-VULN-004 |
| RV.2.2 | Plan and implement risk responses | CICD-VULN-004, NET-VULN-005, NET-VULN-006, WEB-DEP-001 |
| RV.3.1 to RV.3.4 | Root cause analysis | No test. NIST-SA-001 checks the flaw tracking that these items need. |
| PO.1, PO.2, PO.3.1, PO.4.1, PW.1.2, PW.1.3, PW.4.1, PW.4.2, PW.6.2, PW.8.1, RV.1.3, PO.2.x | Requirements, roles, training and policy | No test. Organisational items. |

Read the AI RMF and SSDF tables as pointers. The test text is the authority. Check the table again when tests are added or renamed.
