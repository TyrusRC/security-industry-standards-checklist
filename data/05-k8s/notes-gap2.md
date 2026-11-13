# K8S sheet, gap2 extension
This note supersedes the line in notes.md that says NSA/CISA and Kubescape ids are not used. The gap2 files cite both.

Files: gap2-cmp, rbac, wrk, net, exp, pol, img, log, sec, lat (56 tests: CMP-007..023, RBAC-010..017, WRK-012..023, NET-007..010, EXP-007..008, POL-006..008, IMG-007..009, LOG-008..011, SEC-009..010, LAT-006).
Sources: NSA/CISA Hardening Guide 1.2 (read in full), regolibrary controls (description and remediation of every cited control), Kubernetes docs (security-checklist, api-server-bypass-risks, application-security-checklist, multi-tenancy, securing-a-cluster, rbac-good-practices, secrets-good-practices, pod-security-admission, linux-kernel-security-constraints headings and key sections).

## Themes and new tests
- Control plane files and PKI: CMP-007, 008, 009
- Control plane flags and TLS: CMP-010 to 017
- Add-on CVEs, static pods, runtime socket, feature gates, integrations, unused components: CMP-018 to 023
- RBAC rights (exec, workload create, delete, PV/CSR/token/webhook, system:masters, workload takeover, CoreDNS, review): RBAC-010 to 017
- Workload settings (hostPath, hostPort/HostProcess, SSH/sudo, noexec, requests, hygiene, CronJob, volumes, dangling objects, Agent Sandbox, placement, seccomp audit): WRK-012 to 023
- Network (TLS on ingress, zones, tenant policy selectors, Gateway API) and exposure (private nodes, control plane firewall): NET-007..010, EXP-007..008
- Policy (namespaces, PSA exemptions, tenant isolation): POL-006..008
- Images (pull policy and digests, fail-closed signatures, scan gate): IMG-007..009
- Logging (audit retention, all layers, attack alerts, auto response): LOG-008..011
- Secrets (etcd disposal and swap, KMS key): SEC-009..010; cloud credential mounts: LAT-006

## Coverage
Kubescape: all 294 controls are in a test (refs.tool_check) or in data/mappings/tool-k8s.json. Prowler kubernetes: all 92 checks. The mapping file links controls to existing tests only where their steps check the item.
tools/check_mappings.py now reads the key tool_check (catalog/checks.json).

## NSA/CISA sections used
Threat model (as basis), Pod security (non-root, immutable, secure images, PSA, service account tokens, hardening environments), Network separation (Namespaces, Network policies, Resource policies, Control plane hardening, Etcd, Kubeconfig Files, Worker node segmentation, Encryption, Secrets, cloud infrastructure), Authentication and authorization, Audit Logging and Threat Detection, Upgrading. Items already covered by existing tests (rootless engine, service mesh, LimitRange and ResourceQuota, TLS log transport, log buffering) have no new test.

## Skipped
- Hygiene-only controls with no security effect are folded into WRK-017 and WRK-020 at Info or Low severity.
- Cloud-vendor steps of EKS, AKS and GKE controls (ECR, ACR, GAR, IAM authenticator) are mapped to IMG-005, AUTH-001, LAT-002 and EXP-001; no vendor-specific test was written.
- Alpha-state items and API Priority and Fairness: not read in detail in the sources, so no test.
