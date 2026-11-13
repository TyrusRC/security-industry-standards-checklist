# CICD sheet notes

Files: flow, iam, dep, vuln, ppe, pbac, cred, cfg, tps, art, log (92 tests, IDs CICD-<CAT>-NNN).

Sources used (all opened from disk): the ten CICD-SEC pages, A03:2025, A08:2025, and the cheat sheets CI_CD_Security, Software_Supply_Chain_Security, Dependency_Graph_SBOM, NPM_Security, Secrets_Management, Vulnerable_Dependency_Management, Virtual_Patching, Infrastructure_as_Code_Security, Docker_Security (image and secret parts). SSDF ids come from sources/nist_ssdf/ssdf.txt and are in refs.other as "SSDF x.y.z".

Not on disk, not cited as sources: SLSA spec, CycloneDX spec, SPDX spec, OWASP SCVS, Sigstore docs. The words SLSA, CycloneDX and cosign appear only because the cheat sheets name them. Tool names in examples are hints, not citations.

Catalog-only refs: ATT&CK, CWE, CAPEC and NIST 800-53 ids were checked by grep in catalog/*.json. Their texts were not read from sources/. The mapping to each test is the author's judgment.

Not read in full: Third_Party_Javascript_Management (web-level, not cited), the Docker rules not about images, Secrets_Management sections 4-7. Parts of Vulnerable_Dependency_Management (Cases 4-5) and Virtual_Patching (after the method outline) were skimmed.

Pointers (see): WEB-DEP-001..005 (dependency confusion, SBOM, integrity, remediation times), WEB-SECRET-001/002. No ASVS ids are in refs; V15.1.2 and V15.2.4 live in the web tests.

Out of scope here: A08 firmware update signing (IOT sheet), serialization integrity (WEB-DEP-006), Kubernetes admission control (K8S sheet).

Open issues: ATT&CK for T1195 has no direct pipeline test mapping beyond sub-techniques used. Example commands use placeholder names (ORG, REPO) and are not run.
