# K8S sheet notes
- Scope: containers and Kubernetes. IDs K8S-<CAT>-NNN. Categories: WRK (workload), RBAC, SEC (secrets), POL (policy), NET, EXP (exposed components), CMP (cluster components), AUTH, LAT (cluster to cloud), LOG, IMG (images and registry), DKR (Docker host).
- Sources used: OWASP Kubernetes Top Ten 2025 pages K01-K10, OWASP Cloud-Native Application Security Top 10 (index), and the OWASP cheat sheets Kubernetes, Docker, Secrets Management, Logging, Microservices, Network Segmentation, Software Supply Chain, Vulnerable Dependency Management, Denial of Service, SSRF, IaC.
- The CIS Benchmarks and the NSA/CISA Kubernetes Hardening Guide are not on disk. They are not used and not cited. Tool names such as kube-bench, docker-bench-security and kubescape are hints only; their check IDs are not used.
- The CNAS-1 to CNAS-10 detail pages in the repository contain only "TBD". The tests map to the example lists in sources/top10s/cnas_index.md.
- Ownership: pipeline controls (signing, provenance, build scans, pinned base images, secrets in layers) are in the CICD sheet and are linked with `see`. Instance-level IAM, buckets and IMDS settings are in the CLD sheet. Generic injection is in WEB and API.
- MITRE ATT&CK IDs were taken from catalog/attack.json. T1562.x IDs are not in the catalog; T1685.002 is used for cloud log tampering.
- Example commands are hints and must be checked against the tool version in use. Do not run tests with a "Do not run on production" precondition on production.
