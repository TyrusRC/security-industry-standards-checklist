# Gap-fill notes, group B (cheat sheets)

Mapping file: data/mappings/cheatsheet-B.json. Mapped tests were read (steps) before mapping.

| Cheat sheet | Mapped | New tests |
|---|---|---|
| GitHub_Actions_Security | 15 existing CICD tests | CICD-PPE-009, PPE-010, PPE-011, VULN-007, TPS-007, ART-010, PBAC-009, CRED-012, CRED-013 |
| Workload_Identity_Federation | CICD-CRED-007 | CICD-CRED-014 to CRED-017, IAM-009, LOG-008 |
| Secure_Coding_with_AI | 15 existing LLM and CICD tests | LLM-CODING-001 to 008; CICD-PPE-010 also cites it |
| Verifying_Third_Party_Agent_Execution_Evidence | none (LLM-AGENT-026 is close but covers own logs) | LLM-EVID-001 to 007 |
| NodeJS_Docker | 7 existing K8S and CICD tests | K8S-DKR-007, DKR-008, DKR-009 |
| Secure_Code_Review | 5 existing tests | WEB-CODEREV-001 to 003 |
| Threat_Modeling | none | WEB-THREAT-001 to 004 |
| Abuse_Case (historical, archive statement) | none | WEB-ABUSE-001, 002 |
| Vulnerability_Disclosure | none | WEB-VDP-001 to 004 |
| Zero_Trust_Architecture | 9 existing tests | WEB-ZTA-001 to 006 |
| Legacy_Application_Management | NET-VULN-007, WEB-DEP-003 | WEB-LEGACY-001 to 005 |

Not covered, add on request: Django_*, FastAPI_*, Laravel, Symfony, Ruby_on_Rails, Nodejs_Security, Nextjs_Security, PHP_Configuration, JAAS, C-Based_Toolchain_Hardening, Bean_Validation, Injection_Prevention_in_Java, Security_Terminology, AI-Powered_Advertising_Systems_Security, AML_Sanctions_AI_Agent_Payments.

Known small gaps not written as tests: curated shared workflows (GitHub Actions), repository rulesets that require workflows, ownership of copied files in Node.js images (COPY --chown), CI agent action logging details (Secure_Coding_with_AI section 11), multi-agent propagation (covered by LLM-AGENT-004 and LLM-PINJ-018 only in part).
Other agents own the mapping rows for the shared cheat sheets (for example Docker_Security, Secrets_Management); this file adds only group B ids.
