# CLD sheet notes
- Scope: cloud-native security, provider-neutral. IDs CLD-<CAT>-NNN. Categories: CFG, IAM, NET, SEC, SRV (serverless), INJ (cloud event injection), LOG, AST (assets), QTA (quotas), SUP (images, registries, patching), IAC.
- Sources used: OWASP Cloud-Native Application Security Top 10 (index page), OWASP cheat sheets Secure Cloud Architecture, Serverless/FaaS, Secrets Management, Infrastructure as Code, Network Segmentation, Microservices Security, Logging, Software Supply Chain, Vulnerable Dependency Management, Denial of Service, SSRF, Docker, Kubernetes.
- The CNAS-1 to CNAS-10 detail pages in the repository contain only "TBD". The tests map to the example lists in sources/top10s/cnas_index.md.
- The CIS Benchmarks and the NSA/CISA Kubernetes Hardening Guide are not on disk. They are not used and not cited.
- Ownership: pipeline controls are in the CICD sheet (see links). Pod, node and cluster controls are in the K8S sheet. Generic injection and SSRF are in WEB and API; CLD-INJ tests cover cloud event sources only. CLD-NET-004 (metadata service settings) and CLD-CFG-001 (storage exposure) overlap in part with API-SSRF-007 and WEB-CONF-012 and point to them with `see`. They check the account-wide configuration.
- Commands for AWS, Azure and GCP are hints for the `example` column. Check flags against the CLI version in use. Tools such as prowler, ScoutSuite (scout), checkov, trivy and gitleaks are not part of the sources.
- MITRE ATT&CK IDs were taken from catalog/attack.json. T1562.x IDs are not in the catalog; T1685.002 is used for cloud log tampering.
