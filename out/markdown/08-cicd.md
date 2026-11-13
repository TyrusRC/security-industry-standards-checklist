# CICD security test cases

107 tests. Tick the box when the test passes.


## ART

- [ ] **CICD-ART-001** Check that signed commits are required on protected branches  
  *Severity if fail:* Medium | *Type:* Config Review, Automated  
  *Objective:* Finds branches that accept commits from unknown authors.  
  *Steps:*
  1. Read the branch rules for signed commits.
  2. List recent commits on the protected branch.
  3. Look at the signature status of each.
  4. Make sure unsigned commits cannot reach the branch.
  *Example:* `gh api repos/ORG/REPO/branches/main/protection/required_signatures; git log --show-signature -n 20; git log --format='%H %G?' -n 50`  
  *Expected:* Protected branches require signed commits from known keys. Unsigned commits are rejected.  
  *Refs:* owasp_top10: A03:2025, A08:2025; cicd_top10: CICD-SEC-9; cheatsheet: CI_CD_Security_Cheat_Sheet; cwe: CWE-345; capec: CAPEC-443; attack: T1195.002; nist_800_53: SI-7, CM-14

- [ ] **CICD-ART-002** Check signing of build artifacts and verification before deploy  
  *Severity if fail:* High | *Type:* Config Review, Automated  
  *Objective:* Finds artifacts that deploy without a check of who built them.  
  *Steps:*
  1. Find the signing step in the release pipeline.
  2. Make sure signing uses the identity of the CI workflow.
  3. Find the verification step before deploy or install.
  4. Try to deploy an unsigned test artifact to a test environment.
  *Example:* `cosign sign IMAGE@sha256:DIGEST; cosign verify --certificate-identity-regexp '^https://github.com/ORG/REPO/' --certificate-oidc-issuer https://token.actions.githubusercontent.com IMAGE@sha256:DIGEST`  
  *Expected:* The pipeline signs every release artifact. The deploy step checks the signature, the signer identity and the digest, and rejects unsigned artifacts.  
  *Refs:* owasp_top10: A03:2025, A08:2025; cicd_top10: CICD-SEC-9, CICD-SEC-1; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet, Docker_Security_Cheat_Sheet, NPM_Security_Cheat_Sheet, CI_CD_Security_Cheat_Sheet; cwe: CWE-494, CWE-345; capec: CAPEC-206; attack: T1195.002, T1554; nist_800_53: SI-7, CM-14, SR-11; other: SSDF PS.2.1

- [ ] **CICD-ART-003** Check build provenance and its verification  
  *Severity if fail:* High | *Type:* Config Review, Automated  
  *Objective:* Finds artifacts with no verifiable record of where, when and how they were built.  
  *Steps:*
  1. Find the provenance step in the build platform.
  2. Make sure the build platform creates it, not a developer machine.
  3. Check the provenance for one release: builder, source repository and build parameters.
  4. Make sure the deploy policy rejects missing or unexpected provenance.
  *Example:* `gh attestation verify ARTIFACT --repo ORG/REPO; cosign verify-attestation --type slsaprovenance IMAGE@sha256:DIGEST --certificate-identity-regexp ... --certificate-oidc-issuer ...`  
  *Expected:* Each release has provenance from the build platform. The deploy policy checks builder identity, source and digest. Missing evidence is rejected.  
  *Refs:* owasp_top10: A03:2025, A08:2025; cicd_top10: CICD-SEC-9; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet, Dependency_Graph_SBOM_Cheat_Sheet, Docker_Security_Cheat_Sheet; cwe: CWE-345; attack: T1195.002; nist_800_53: SR-4; other: SSDF PS.3.2

- [ ] **CICD-ART-004** Check the SBOM for each release and its link to the artifact  
  *Severity if fail:* Medium | *Type:* Config Review, Automated  
  *Objective:* Finds releases with no SBOM, or an SBOM that nobody can tie to the shipped artifact.  
  *Steps:*
  1. Find the SBOM step in the release pipeline.
  2. Generate an SBOM from the final artifact and compare it with the published one.
  3. Make sure the SBOM lists transitive dependencies, hashes and generator data.
  4. Make sure a signed attestation binds the SBOM to the artifact digest.
  *Example:* `syft IMAGE@sha256:DIGEST -o cyclonedx-json > sbom.json; cosign verify-attestation --type cyclonedx IMAGE@sha256:DIGEST --certificate-identity-regexp ... --certificate-oidc-issuer ...`  
  *Expected:* Each release has a valid SBOM that matches the final artifact. A signed attestation binds the SBOM to the artifact digest.  
  *Refs:* owasp_top10: A03:2025; cicd_top10: CICD-SEC-9; cheatsheet: Dependency_Graph_SBOM_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet, Docker_Security_Cheat_Sheet, NPM_Security_Cheat_Sheet; cwe: CWE-1357; nist_800_53: SR-4, CM-8; other: SSDF PS.3.2  
  *See:* WEB-DEP-002

- [ ] **CICD-ART-005** Check that one built artifact is promoted unchanged through environments  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds pipelines that rebuild per environment, so the tested artifact is not the shipped one.  
  *Steps:*
  1. Follow one release from test to production.
  2. Compare the artifact digest in each environment.
  3. Make sure deployments refer to the digest, not a mutable tag.
  4. Make sure the build is immutable and does not rerun for production.
  *Example:* `docker buildx imagetools inspect IMAGE:TAG; kubectl get deploy NAME -o jsonpath='{.spec.template.spec.containers[*].image}'`  
  *Expected:* The same digest runs in every environment. Deployments use digests. Production does not trigger a new build.  
  *Refs:* owasp_top10: A03:2025, A08:2025; cicd_top10: CICD-SEC-9, CICD-SEC-1; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet, Docker_Security_Cheat_Sheet; cwe: CWE-345; capec: CAPEC-678; attack: T1195.002; nist_800_53: SI-7

- [ ] **CICD-ART-006** Check hash or signature checks for downloaded scripts and tools  
  *Severity if fail:* High | *Type:* Code Review, Automated  
  *Objective:* Finds build steps that download and run code without a check against a published hash.  
  *Steps:*
  1. Search pipeline files and Dockerfiles for curl or wget piped to a shell and for downloaded binaries.
  2. For each, find the check of a hash or signature.
  3. Make sure the expected hash comes from a trusted source.
  4. Make sure a changed download fails the build.
  *Example:* `grep -rnE 'curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|curl -[a-zA-Z]*O' .github Dockerfile* scripts/; sha256sum -c tool.sha256`  
  *Expected:* No downloaded script runs without a hash or signature check. A changed file makes the build fail.  
  *Refs:* owasp_top10: A03:2025, A08:2025; cicd_top10: CICD-SEC-9, CICD-SEC-3; cheatsheet: CI_CD_Security_Cheat_Sheet, Docker_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-494, CWE-829; attack: T1195.002, T1105; nist_800_53: SI-7; other: SSDF PW.4.4  
  *See:* WEB-DEP-005

- [ ] **CICD-ART-007** Check write controls and immutability of the artifact repository  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds registries where people can overwrite released artifacts or tags.  
  *Steps:*
  1. List the accounts that can write to the release repositories.
  2. Make sure only the CI service account can publish releases.
  3. Try to overwrite an existing release tag on a test repository.
  4. Make sure retention rules keep released artifacts.
  *Example:* `gh api orgs/ORG/packages/container/NAME --jq .visibility; skopeo inspect docker://REGISTRY/NAME:TAG; jf rt curl /api/repositories/REPO`  
  *Expected:* Only the CI service account can publish. Released tags and versions cannot change. Retention rules keep release artifacts.  
  *Refs:* owasp_top10: A03:2025, A08:2025; cicd_top10: CICD-SEC-9, CICD-SEC-1; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet, NPM_Security_Cheat_Sheet; cwe: CWE-345, CWE-284; attack: T1195.002; nist_800_53: AC-6, SI-7; other: SSDF PS.3.1

- [ ] **CICD-ART-008** Review protection of signing keys and signing identity  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds signing keys that unreviewed jobs or many people can use.  
  *Steps:*
  1. List the signing keys and certificates and where they are stored.
  2. Make sure they are in a KMS or HSM, or that signing uses short-lived keyless identity.
  3. Make sure jobs that run unreviewed code cannot use them.
  4. Make sure key use is logged and has an alert.
  *Example:* `cosign verify --certificate-identity ID --certificate-oidc-issuer ISSUER IMAGE; aws kms get-key-policy --key-id KEY --policy-name default`  
  *Expected:* Signing keys are in hardened storage, or signing uses short-lived identity. Only reviewed release jobs can sign. Each use is logged.  
  *Refs:* owasp_top10: A03:2025, A08:2025; cicd_top10: CICD-SEC-9, CICD-SEC-6; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet, CI_CD_Security_Cheat_Sheet; cwe: CWE-522; capec: CAPEC-68, CAPEC-673; nist_800_53: CM-14, SC-12; other: SSDF PS.2.1

- [ ] **CICD-ART-009** Check retention of release evidence  
  *Severity if fail:* Low | *Type:* Manual, Config Review  
  *Objective:* Finds releases for which the SBOM, signatures and provenance are lost.  
  *Steps:*
  1. Pick one release from the last year.
  2. Find its SBOM, signatures, provenance and build logs.
  3. Make sure the original files are stored with the release.
  4. Make sure write access to the store is limited.
  *Example:* `oras discover IMAGE@sha256:DIGEST; cosign tree IMAGE@sha256:DIGEST`  
  *Expected:* The original SBOM, signed evidence and provenance exist for each release. Write access to the store is limited.  
  *Refs:* owasp_top10: A03:2025; cicd_top10: CICD-SEC-9; cheatsheet: Dependency_Graph_SBOM_Cheat_Sheet; cwe: CWE-353; nist_800_53: SR-4; other: SSDF PS.3.1, SSDF PS.3.2


## CFG

- [ ] **CICD-CFG-001** Check the inventory, owners and patch level of CI/CD systems  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds unknown or outdated CI/CD servers, runners and plugins.  
  *Steps:*
  1. List all SCM, CI, registry and runner systems, including self-managed instances.
  2. Record the owner and the version of each.
  3. Compare each version with the vendor security advisories.
  4. Include build tools and plugins in the check.
  *Example:* `curl -s https://JENKINS/pluginManager/api/json?depth=1 | jq '.plugins[]|{shortName,version}'; trivy image RUNNER_IMAGE; nmap -sV -p 80,443,8080 CIDR`  
  *Expected:* Every CI/CD system has an owner and a version record. Systems and plugins have all available security patches, or access is restricted.  
  *Refs:* cicd_top10: CICD-SEC-7, CICD-SEC-10; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-1104, CWE-1395; attack: T1072; nist_800_53: CM-8, RA-5; other: SSDF PO.3.2

- [ ] **CICD-CFG-002** Check network exposure and transport security of CI/CD systems  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds CI/CD systems open to the internet or using weak transport between systems.  
  *Steps:*
  1. Scan the CI/CD host addresses from outside the corporate network, with approval.
  2. Make sure management interfaces are not exposed.
  3. Check the TLS version between the SCM and the CI system.
  4. Make sure access is limited by IP or VPN where possible.
  *Example:* `nmap -Pn -p 22,80,443,8080,50000 CI_HOST; testssl.sh --protocols CI_HOST:443`  
  *Expected:* CI/CD systems are not open to the internet without need. Connections use TLS 1.2 or higher. Access is limited by network rules.  
  *Refs:* cicd_top10: CICD-SEC-7; cheatsheet: CI_CD_Security_Cheat_Sheet; cwe: CWE-284; nist_800_53: SC-7, SC-8

- [ ] **CICD-CFG-003** Review CI/CD settings against hardening guides and default values  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds platform settings that stay at an insecure default.  
  *Steps:*
  1. Get the hardening baseline, such as the CIS Benchmark, for each platform.
  2. Read the security settings of each platform.
  3. Find default accounts, default passwords and open defaults.
  4. Document and fix each difference.
  *Example:* `legitify analyze --namespace ORG; gh api orgs/ORG --jq '{two_factor_requirement_enabled,default_repository_permission,members_can_create_public_repositories}'`  
  *Expected:* No default account or default password exists. Settings match the baseline. Each exception has an owner and a reason.  
  *Refs:* cicd_top10: CICD-SEC-7; cheatsheet: CI_CD_Security_Cheat_Sheet; cwe: CWE-1188, CWE-1269; attack: T1078.001; nist_800_53: CM-6, CM-2; other: SSDF PO.3.2, SSDF PW.9.1

- [ ] **CICD-CFG-004** Check debug and shell access to execution nodes  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds users who can open a shell on a build node and read secrets from memory.  
  *Steps:*
  1. List the users with SSH, debug or console access to runners.
  2. Check for CI features that open a session in a running job.
  3. Make sure access is limited, approved and logged.
  4. Make sure such access is not on nodes that hold production secrets.
  *Example:* `gh api repos/ORG/REPO/actions/runners; grep -E 'AllowUsers|AllowGroups' /etc/ssh/sshd_config; last -n 20  # on the runner`  
  *Expected:* Only a small approved group can open a session on a build node. Access is logged. Nodes with production secrets have no debug access.  
  *Refs:* cicd_top10: CICD-SEC-7, CICD-SEC-5; cheatsheet: CI_CD_Security_Cheat_Sheet; cwe: CWE-250, CWE-269; attack: T1078; nist_800_53: AC-6, AU-12

- [ ] **CICD-CFG-005** Check that self-hosted CI services run without host administrator rights  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds CI services that run as root or administrator on the host.  
  *Steps:*
  1. Find the account that runs each CI controller and agent service.
  2. Make sure it is not root or administrator.
  3. Look at sudo rules and group memberships of this account.
  4. Make sure the host is dedicated to the CI role.
  *Example:* `ps -o user,cmd -C java,Runner.Listener; sudo -l -U ci-runner; id ci-runner`  
  *Expected:* CI services run as dedicated unprivileged accounts. The accounts have no general sudo rights.  
  *Refs:* cicd_top10: CICD-SEC-7; cheatsheet: CI_CD_Security_Cheat_Sheet; cwe: CWE-250; nist_800_53: AC-6, CM-7

- [ ] **CICD-CFG-006** Check repository fork and visibility restrictions  
  *Severity if fail:* Medium | *Type:* Config Review, Automated  
  *Objective:* Finds repositories that users can fork out or make public by mistake.  
  *Steps:*
  1. Read the organization settings for forking private repositories.
  2. Read who may change repository visibility to public.
  3. List private repositories that have forks.
  4. Make sure these actions are limited to a small group.
  *Example:* `gh api orgs/ORG --jq '{members_can_fork_private_repositories,members_can_create_public_repositories}'; gh api repos/ORG/REPO/forks --jq 'length'`  
  *Expected:* Users cannot fork private repositories or change visibility to public without approval.  
  *Refs:* cicd_top10: CICD-SEC-7, CICD-SEC-2; cheatsheet: CI_CD_Security_Cheat_Sheet; cwe: CWE-284; nist_800_53: AC-3

- [ ] **CICD-CFG-007** Review change management for CI/CD settings  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds changes to pipeline and platform settings that nobody tracks.  
  *Steps:*
  1. Read the change process for CI/CD settings, SBOM tools, registries and integrations.
  2. Pick five recent setting changes from the audit log.
  3. Find the approval and ticket for each change.
  4. Make sure a review of all settings runs on a schedule.
  *Example:* `gh api orgs/ORG/audit-log?phrase=action:repo.update_actions_settings --paginate; gh api orgs/ORG/audit-log?phrase=action:org.update_actions_settings`  
  *Expected:* Every setting change maps to an approved request. A scheduled review checks all security settings.  
  *Refs:* cicd_top10: CICD-SEC-7; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-1269; nist_800_53: CM-3, CM-5; other: SSDF PO.3.2

- [ ] **CICD-CFG-008** Check hardening of developer workstations and IDE extensions  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds developer machines and extensions that can steal credentials or inject code.  
  *Steps:*
  1. Read the endpoint policy for developer machines: patches, MFA and monitoring.
  2. List the IDE extensions that developers use.
  3. Make sure extensions come from an approved list.
  4. Make sure a restricted mode is the default for unknown projects.
  *Example:* `code --list-extensions --show-versions; osquery: SELECT name,version FROM vscode_extensions;`  
  *Expected:* Developer machines are patched and monitored. Only approved IDE extensions are installed. Unknown projects open in restricted mode.  
  *Refs:* cicd_top10: CICD-SEC-7; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet, NPM_Security_Cheat_Sheet; cwe: CWE-1357; capec: CAPEC-698, CAPEC-670; attack: T1195.001; other: SSDF PO.5.2

- [ ] **CICD-CFG-009** Check separation of development, build and production environments  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds environments that share accounts, networks or data with production.  
  *Steps:*
  1. List the development, test, build and production environments.
  2. Check for shared accounts, networks and credentials between them.
  3. Make sure the build environment cannot be reached from developer workstations without control.
  4. Make sure production data is not in lower environments.
  *Example:* `aws organizations list-accounts; kubectl config get-contexts; terraform state list | grep -i env`  
  *Expected:* Each environment has its own accounts, network rules and credentials. Build systems are separate from production.  
  *Refs:* owasp_top10: A08:2025; cicd_top10: CICD-SEC-7, CICD-SEC-5; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet, CI_CD_Security_Cheat_Sheet; cwe: CWE-284; nist_800_53: SC-7; other: SSDF PO.5.1

- [ ] **CICD-CFG-010** Check that infrastructure code is the only way to change infrastructure  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds infrastructure that people change by hand and that no review covers.  
  *Steps:*
  1. Find the repository for each infrastructure area.
  2. Make sure changes need a pull request and review.
  3. Look for resources without code or tags.
  4. Make sure immutable deployment replaces changed resources.
  *Example:* `terraform plan -detailed-exitcode; aws resourcegroupstaggingapi get-resources --query 'ResourceTagMappingList[?Tags==`[]`].ResourceARN'`  
  *Expected:* All infrastructure comes from reviewed code. Untagged or unmanaged resources are found and removed or adopted.  
  *Refs:* cicd_top10: CICD-SEC-1, CICD-SEC-7; cheatsheet: Infrastructure_as_Code_Security_Cheat_Sheet; cwe: CWE-1269; nist_800_53: CM-2, CM-3

- [ ] **CICD-CFG-011** Test restore of the source code repositories from backup  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds repositories that cannot be restored after loss or destruction.  
  *Steps:*
  1. Find the backup plan for the SCM and the artifact registry.
  2. Restore one repository into a test location.
  3. Compare the restored refs and commit hashes with the source.
  4. Make sure backup access is limited and logged.
  *Example:* `git clone --mirror https://git.example.org/ORG/REPO.git && git -C REPO.git fsck --full; git ls-remote ORIGIN | sha256sum`  
  *Expected:* A backup exists and restores into a complete copy with the same commit hashes. Access to backups is limited.  
  *Refs:* cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-693; nist_800_53: CP-9


## CRED

- [ ] **CICD-CRED-001** Scan the full repository history for secrets  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds credentials in current files and in old commits that stay readable to all repository users.  
  *Steps:*
  1. Clone the repository with its full history, including all branches and tags.
  2. Run two secret scanners on the full history.
  3. Compare the results and remove false positives.
  4. For each real finding, make sure the secret is revoked and rotated.
  *Example:* `gitleaks detect --redact -v; trufflehog git file://. --only-verified; git log --all --oneline | wc -l`  
  *Expected:* The history holds no active secrets. Each past finding has a record of revocation and rotation.  
  *Refs:* cicd_top10: CICD-SEC-6; cheatsheet: Secrets_Management_Cheat_Sheet, CI_CD_Security_Cheat_Sheet, Infrastructure_as_Code_Security_Cheat_Sheet; cwe: CWE-798; attack: T1552.001; nist_800_53: IA-5  
  *See:* WEB-SECRET-001

- [ ] **CICD-CRED-002** Check that push protection and pre-commit scanning block new secrets  
  *Severity if fail:* Medium | *Type:* Config Review, Automated  
  *Objective:* Finds repositories where a developer can push a new secret without a warning.  
  *Steps:*
  1. Read the secret scanning and push protection settings of the organization and repository.
  2. Make sure a pre-commit or IDE check runs on developer machines.
  3. On a test repository, commit a fake token with a known test format.
  4. Make sure the push is blocked or flagged.
  *Example:* `gh api repos/ORG/REPO --jq .security_and_analysis; pre-commit run gitleaks --all-files; gitleaks protect --staged`  
  *Expected:* Push protection and pre-commit checks are on. A fake test token is blocked or flagged before it reaches the shared branch.  
  *Refs:* cicd_top10: CICD-SEC-6; cheatsheet: Secrets_Management_Cheat_Sheet, CI_CD_Security_Cheat_Sheet; cwe: CWE-798; attack: T1552.001; other: SSDF PW.7.1

- [ ] **CICD-CRED-003** Look for hard-coded credentials in pipeline and infrastructure files  
  *Severity if fail:* High | *Type:* Code Review, Automated  
  *Objective:* Finds passwords and keys in CI files, scripts, IaC and deployment manifests.  
  *Steps:*
  1. List the CI files, build scripts, IaC and deployment manifests.
  2. Search them for passwords, keys, tokens and connection strings.
  3. Look for credentials in default values of pipeline variables.
  4. Make sure each credential comes from the secret store.
  *Example:* `gitleaks detect --no-git -s .github/ ; semgrep scan --config p/secrets .; trivy config --scanners secret .`  
  *Expected:* No file in the repository holds a credential. All pipelines read secrets from the secret store at run time.  
  *Refs:* cicd_top10: CICD-SEC-6; cheatsheet: CI_CD_Security_Cheat_Sheet, Infrastructure_as_Code_Security_Cheat_Sheet, Secrets_Management_Cheat_Sheet; cwe: CWE-798; attack: T1552.001  
  *See:* WEB-SECRET-001

- [ ] **CICD-CRED-004** Check build logs for exposed secrets and masking  
  *Severity if fail:* High | *Type:* Config Review, Automated  
  *Objective:* Finds secrets printed in console output and shipped to log systems.  
  *Steps:*
  1. Download the logs of recent builds, including failed and debug builds.
  2. Scan the logs for secrets.
  3. Make sure the platform masks secret values in logs.
  4. Make sure debug and trace mode is off for builds with secrets.
  *Example:* `gh run list --limit 50 --json databaseId --jq '.[].databaseId' | xargs -I{} gh run view {} --log > logs.txt; gitleaks detect --no-git -s logs.txt`  
  *Expected:* Build logs hold no secret values. Masking is on. Debug mode is off for jobs with secrets.  
  *Refs:* cicd_top10: CICD-SEC-6; cheatsheet: CI_CD_Security_Cheat_Sheet, Secrets_Management_Cheat_Sheet; cwe: CWE-532; attack: T1552.001; nist_800_53: AU-3

- [ ] **CICD-CRED-005** Check container image layers and build arguments for secrets  
  *Severity if fail:* High | *Type:* Config Review, Automated  
  *Objective:* Finds images where a secret from the build stays in a layer, a build argument or an environment value.  
  *Steps:*
  1. Search the Dockerfiles for ARG, ENV and COPY that handle credentials.
  2. Make sure the build uses secret mounts.
  3. Scan the final image and all its layers for secrets.
  4. Look at the image history for credential values.
  *Example:* `trivy image --scanners secret IMAGE@sha256:DIGEST; docker history --no-trunc IMAGE; hadolint Dockerfile; trufflehog docker --image IMAGE`  
  *Expected:* Images hold no secrets in any layer. Builds pass credentials only through secret mounts that are not saved in the image.  
  *Refs:* cicd_top10: CICD-SEC-6; cheatsheet: Docker_Security_Cheat_Sheet, Secrets_Management_Cheat_Sheet; cwe: CWE-798, CWE-522; attack: T1552.001, T1525

- [ ] **CICD-CRED-006** Check built packages and charts for included secrets  
  *Severity if fail:* High | *Type:* Config Review, Automated  
  *Objective:* Finds packages, binaries and charts that contain credentials or environment files.  
  *Steps:*
  1. List the package types that the pipeline publishes.
  2. Create the package without publishing it and list its files.
  3. Scan the package contents for secrets and environment files.
  4. Make sure an allowlist, such as the files property, controls the contents.
  *Example:* `npm publish --dry-run; npm pack && tar -tzf *.tgz; trufflehog filesystem ./package; helm package CHART && gitleaks detect --no-git -s CHART`  
  *Expected:* Published packages hold only the intended files and no secrets. An allowlist controls the package contents.  
  *Refs:* cicd_top10: CICD-SEC-6; cheatsheet: NPM_Security_Cheat_Sheet, Secrets_Management_Cheat_Sheet; cwe: CWE-798; attack: T1552.001

- [ ] **CICD-CRED-007** Check that pipelines use short-lived federated credentials  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds static cloud keys and long-lived tokens stored in CI variables.  
  *Steps:*
  1. List the secrets in the CI platform and mark the cloud keys and long-lived tokens.
  2. Find pipelines that use OIDC federation to get temporary credentials.
  3. Read the trust policy and make sure it limits repository, branch and environment.
  4. Replace static keys on a test pipeline and remove the old key.
  *Example:* `aws iam get-role --role-name ROLE --query Role.AssumeRolePolicyDocument; gh api repos/ORG/REPO/actions/secrets --jq '.secrets[].name'`  
  *Expected:* Pipelines get temporary credentials through OIDC. The trust policy names the exact repository, branch or environment. No static cloud key is stored.  
  *Refs:* cicd_top10: CICD-SEC-6, CICD-SEC-5; cheatsheet: Secrets_Management_Cheat_Sheet, CI_CD_Security_Cheat_Sheet; cwe: CWE-798, CWE-522; attack: T1552.001, T1078.004; nist_800_53: IA-5

- [ ] **CICD-CRED-008** Review rotation and expiry of pipeline credentials  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds deploy keys and tokens that stay valid for years.  
  *Steps:*
  1. List deploy keys, tokens, service account keys and registry credentials that pipelines use.
  2. Record the creation date and the expiry date of each.
  3. Compare the age with the rotation policy.
  4. Make sure rotation runs without a long outage.
  *Example:* `gh api repos/ORG/REPO/keys --jq '.[]|{title,created_at}'; aws iam list-access-keys --user-name USER; gh api repos/ORG/REPO/actions/secrets --jq '.secrets[]|{name,updated_at}'`  
  *Expected:* Each credential has an owner, an expiry date and a rotation date within policy. Rotation is automated or tested.  
  *Refs:* cicd_top10: CICD-SEC-6; cheatsheet: Secrets_Management_Cheat_Sheet; cwe: CWE-798; nist_800_53: IA-5  
  *See:* WEB-SECRET-002

- [ ] **CICD-CRED-009** Check that credentials work only under set conditions  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds stolen pipeline credentials that work from any network or identity.  
  *Steps:*
  1. List the credentials that pipelines use to reach cloud and registry services.
  2. Read the conditions on each, such as source address or identity.
  3. From a host outside the allowed range, use a test credential on a test resource.
  4. Make sure the request is denied.
  *Example:* `aws iam get-user-policy --user-name USER --policy-name POLICY; npm token list`  
  *Expected:* Credentials are limited to source addresses or identities of the pipeline. A request from outside is denied and logged.  
  *Refs:* cicd_top10: CICD-SEC-6; cheatsheet: Secrets_Management_Cheat_Sheet, NPM_Security_Cheat_Sheet, CI_CD_Security_Cheat_Sheet; cwe: CWE-522; attack: T1528; nist_800_53: IA-5

- [ ] **CICD-CRED-010** Review the secret inventory, access and exposure response plan  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds secrets without an owner and teams that cannot revoke an exposed secret quickly.  
  *Steps:*
  1. Get the list of secrets stored in CI tools, with purpose and owner.
  2. Look at who can view or change the stored secrets.
  3. Make sure forks and copied jobs do not copy secrets.
  4. Run a tabletop test of revoke, rotate and delete for one exposed test secret.
  *Example:* `gh api orgs/ORG/actions/secrets --jq '.secrets[]|{name,visibility}'; gh api repos/ORG/REPO/collaborators --jq '.[]|select(.permissions.admin)|.login'`  
  *Expected:* Every stored secret has a purpose and an owner. Access is reviewed. The team revokes and rotates an exposed secret within the policy time.  
  *Refs:* cicd_top10: CICD-SEC-6; cheatsheet: Secrets_Management_Cheat_Sheet; cwe: CWE-798; nist_800_53: IA-5  
  *See:* WEB-SECRET-002

- [ ] **CICD-CRED-011** Check that application runtime secrets do not pass through the pipeline  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds production secrets that the pipeline holds when the service could read them itself.  
  *Steps:*
  1. List the production application secrets that the pipeline stores or injects.
  2. Find which of them the application could get from a secret manager at run time.
  3. Read the platform identity that the deployed service uses.
  4. Remove the secrets that the pipeline does not need.
  *Example:* `kubectl get sa,rolebinding -n NS; aws secretsmanager list-secrets --query 'SecretList[].Name'; grep -rn 'secrets\.' .github/workflows/deploy*.yml`  
  *Expected:* The pipeline deploys with a platform identity. The deployed service reads its own secrets from the secret manager at run time.  
  *Refs:* cicd_top10: CICD-SEC-6, CICD-SEC-5; cheatsheet: Secrets_Management_Cheat_Sheet; cwe: CWE-522; nist_800_53: AC-6  
  *See:* WEB-SECRET-001


## DEP

- [ ] **CICD-DEP-001** Check that build clients pull packages only through the internal proxy  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds build jobs and workstations that fetch packages directly from public registries.  
  *Steps:*
  1. List the package managers that the pipeline uses.
  2. Read the registry setting of each package manager in the repository and on the runner.
  3. Make sure each setting points to the internal proxy or repository.
  4. Block direct internet access for the runner on a test job and run the build.
  *Example:* `npm config get registry; pip config list; mvn help:effective-settings | grep -i mirror; cat .npmrc pip.conf .yarnrc.yml`  
  *Expected:* All package managers resolve through the internal proxy. The build fails when the proxy is not reachable. Direct registry access is blocked.  
  *Refs:* owasp_top10: A03:2025, A08:2025; cicd_top10: CICD-SEC-3; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet, NPM_Security_Cheat_Sheet, CI_CD_Security_Cheat_Sheet; cwe: CWE-829, CWE-427; capec: CAPEC-538; attack: T1195.001; nist_800_53: SR-3; other: SSDF PW.4.1  
  *See:* WEB-DEP-004

- [ ] **CICD-DEP-002** Check for dependency confusion on internal package names  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds internal package names that a public registry can supply instead.  
  *Steps:*
  1. List the names of internal packages from the manifests and the internal registry.
  2. Look up each name on the matching public registry.
  3. Make sure private packages use the organization scope or namespace.
  4. Make sure clients fetch the scope only from the internal registry.
  *Example:* `npm view @org/internal-lib; pip download --no-deps internal-lib --index-url https://pypi.org/simple 2>&1 | tail -2; grep -n '@org:registry' .npmrc`  
  *Expected:* Public registries have no package with an internal name, or the name is reserved. Scoped packages come only from the internal registry.  
  *Refs:* owasp_top10: A03:2025; cicd_top10: CICD-SEC-3; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet, CI_CD_Security_Cheat_Sheet, NPM_Security_Cheat_Sheet; cwe: CWE-427, CWE-829; capec: CAPEC-538; attack: T1195.001  
  *See:* WEB-DEP-004

- [ ] **CICD-DEP-003** Make sure the pipeline installs exactly the locked dependency versions  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds builds that resolve dependencies again and pull versions that nobody reviewed.  
  *Steps:*
  1. Make sure a lockfile exists for each package manager and is in the repository.
  2. Find the install command in the pipeline.
  3. Make sure the command stops when the manifest and lockfile differ.
  4. Change a version in the manifest only, on a test branch, and run the pipeline.
  *Example:* `npm ci; yarn install --frozen-lockfile; pip install --require-hashes -r requirements.txt; mvn -B dependency:resolve`  
  *Expected:* The pipeline uses frozen lockfile installs. A build fails when the manifest and the lockfile do not match.  
  *Refs:* owasp_top10: A03:2025; cicd_top10: CICD-SEC-3; cheatsheet: NPM_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet, CI_CD_Security_Cheat_Sheet; cwe: CWE-1357, CWE-829; attack: T1195.001; other: SSDF PW.4.1  
  *See:* WEB-DEP-002

- [ ] **CICD-DEP-004** Check checksum and signature verification of pulled packages  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds package installs that do not compare hashes or signatures with known good values.  
  *Steps:*
  1. Read the lockfiles for integrity hashes of each package.
  2. Make sure the pipeline does not turn off hash or signature checks.
  3. Change one hash in a lockfile copy on a test branch.
  4. Run the build and look at the result.
  *Example:* `grep -c integrity package-lock.json; pip install --require-hashes -r requirements.txt; npm audit signatures`  
  *Expected:* Every package has a hash in the lockfile. The build fails when a hash or signature does not match.  
  *Refs:* owasp_top10: A03:2025, A08:2025; cicd_top10: CICD-SEC-3, CICD-SEC-9; cheatsheet: CI_CD_Security_Cheat_Sheet, NPM_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-494, CWE-353; attack: T1195.001; nist_800_53: SI-7; other: SSDF PW.4.4  
  *See:* WEB-DEP-005

- [ ] **CICD-DEP-005** Check that package install scripts run without access to secrets  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds installs where lifecycle scripts of third-party packages can read pipeline secrets.  
  *Steps:*
  1. Find the install step of each pipeline and the secrets that are in scope there.
  2. Make sure lifecycle scripts are off or limited to an allowlist.
  3. Make sure the install step runs in a job without secrets and without write tokens.
  4. Look at the environment of the install step.
  *Example:* `npm config get ignore-scripts; grep -rn 'ignore-scripts' .npmrc .github/ ; npm ci --ignore-scripts`  
  *Expected:* Install scripts are off, or only allowlisted packages run them. The install step has no access to secrets or deploy tokens.  
  *Refs:* owasp_top10: A03:2025; cicd_top10: CICD-SEC-3, CICD-SEC-5; cheatsheet: NPM_Security_Cheat_Sheet, CI_CD_Security_Cheat_Sheet; cwe: CWE-829, CWE-250; capec: CAPEC-538; attack: T1195.001, T1552.001

- [ ] **CICD-DEP-006** Make sure the repository contains its package manager configuration  
  *Severity if fail:* Medium | *Type:* Code Review  
  *Objective:* Finds projects that depend on the insecure default configuration of a client.  
  *Steps:*
  1. Look for .npmrc, pip.conf, settings.xml or the same file for each package manager in the repository.
  2. Read the registry, scope and integrity settings in these files.
  3. Make sure the file does not point to a public mirror that you do not control.
  4. Make sure no credentials are in the file.
  *Example:* `git ls-files | grep -E '(^|/)(\.npmrc|pip\.conf|settings\.xml|\.yarnrc\.yml|nuget\.config)$'; gitleaks detect --no-git -s .npmrc`  
  *Expected:* Each project holds its own package manager configuration with the internal registry and scopes. The files hold no credentials.  
  *Refs:* owasp_top10: A03:2025; cicd_top10: CICD-SEC-3; cheatsheet: NPM_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-427, CWE-798; attack: T1195.001

- [ ] **CICD-DEP-007** Check new dependency names for typosquatting and slopsquatting  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds newly added packages whose names copy popular packages or names an AI tool made up.  
  *Steps:*
  1. List the dependencies added in the last release.
  2. Compare each name with the intended package name.
  3. Look at the age, download count, maintainers and repository link of each new package.
  4. Make sure each new package passed a documented review.
  *Example:* `npm view PACKAGE time.created maintainers repository.url dist.tarball; git diff HEAD~50 -- package.json`  
  *Expected:* Each new dependency has the intended name, a known maintainer and a review record. No package name is unknown or very new without a reason.  
  *Refs:* owasp_top10: A03:2025; cicd_top10: CICD-SEC-3; cheatsheet: NPM_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-1357; capec: CAPEC-538; attack: T1195.001; other: SSDF PW.4.1

- [ ] **CICD-DEP-008** Find dependencies that come from outside the registry  
  *Severity if fail:* Medium | *Type:* Code Review  
  *Objective:* Finds git URL, tarball and local path dependencies that skip registry controls.  
  *Steps:*
  1. Search the manifests and lockfiles for git URLs, tarball URLs and file or link paths.
  2. Check where each source resolves.
  3. Make sure each source is pinned to a commit hash or checksum.
  4. Make sure each source has an owner and a review record.
  *Example:* `grep -nE '"(git\+|https?://|file:|link:)' package.json package-lock.json; grep -nE '^(-e )?git\+|@ https?://' requirements*.txt`  
  *Expected:* No dependency comes from an unpinned URL or path. Each exception is pinned, reviewed and has an owner.  
  *Refs:* owasp_top10: A03:2025, A08:2025; cicd_top10: CICD-SEC-3; cheatsheet: NPM_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-829, CWE-494; attack: T1195.001; other: SSDF PW.4.4

- [ ] **CICD-DEP-009** Check that base images and tool versions are pinned  
  *Severity if fail:* Medium | *Type:* Code Review, Automated  
  *Objective:* Finds floating tags such as latest that change the build without a reviewed change.  
  *Steps:*
  1. Search Dockerfiles, pipeline files and install scripts for latest tags and open version ranges.
  2. Make sure base images are pinned by digest or exact version.
  3. Make sure OS package and tool versions are pinned.
  4. Make sure an update process changes pinned versions in a reviewed pull request.
  *Example:* `hadolint Dockerfile; grep -rnE 'FROM .*(:latest|[^@:]$)' Dockerfile*; grep -rn 'latest' .github/workflows`  
  *Expected:* No build input uses a floating tag. Pinned versions change only through reviewed pull requests.  
  *Refs:* owasp_top10: A03:2025; cicd_top10: CICD-SEC-3; cheatsheet: Docker_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet, CI_CD_Security_Cheat_Sheet; cwe: CWE-1357, CWE-829; attack: T1195.002; other: SSDF PW.4.1


## FLOW

- [ ] **CICD-FLOW-001** Check branch protection on every production branch  
  *Severity if fail:* High | *Type:* Config Review, Automated  
  *Objective:* Finds production branches where one account can push or merge code without review.  
  *Steps:*
  1. List the branches that build, release or deploy to production.
  2. Read the branch protection rules or rulesets for each branch.
  3. Make sure pull requests and at least one approving review are required.
  4. Make sure administrators and bots are not on a bypass list.
  5. Make sure force pushes and branch deletion are blocked.
  *Example:* `gh api repos/ORG/REPO/branches/main/protection; gh api repos/ORG/REPO/rulesets; scorecard --repo=github.com/ORG/REPO --checks=Branch-Protection,Code-Review`  
  *Expected:* Every production branch requires a reviewed pull request. No user, team or app can bypass the rule. Force pushes are blocked.  
  *Refs:* owasp_top10: A08:2025; cicd_top10: CICD-SEC-1; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-284, CWE-693; capec: CAPEC-443; attack: T1195.002; nist_800_53: CM-3, CM-5; other: SSDF PS.1.1

- [ ] **CICD-FLOW-002** Check that unreviewed pushers cannot trigger deployment pipelines  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds accounts that may push unreviewed code and also start a deployment.  
  *Steps:*
  1. List the users, teams and apps that may push to a protected branch without review.
  2. List the users and apps that may start or approve the deployment pipelines of the same repository.
  3. Compare the two lists.
  4. Look at any account that appears in both lists.
  *Example:* `gh api repos/ORG/REPO/branches/main/protection/restrictions; gh api repos/ORG/REPO/collaborators --jq '.[]|{login,permissions}'`  
  *Expected:* No account that may push unreviewed code can also trigger or approve a production deployment pipeline.  
  *Refs:* cicd_top10: CICD-SEC-1; cheatsheet: CI_CD_Security_Cheat_Sheet; cwe: CWE-269; nist_800_53: AC-5, AC-6

- [ ] **CICD-FLOW-003** Review auto-merge rules for bypass and third-party code  
  *Severity if fail:* High | *Type:* Code Review, Config Review  
  *Objective:* Finds auto-merge rules that can merge unreviewed code into a protected branch.  
  *Steps:*
  1. List all auto-merge rules and bots in the SCM and the CI.
  2. Read the code and conditions of each rule.
  3. Check that the rule applies to the smallest possible set of files and users.
  4. Make sure the rule does not import third-party code.
  5. Make sure the rule cannot be bypassed with a crafted change.
  *Example:* `gh api repos/ORG/REPO --jq .allow_auto_merge; grep -rn 'auto-merge\|automerge\|dependabot' .github/`  
  *Expected:* Auto-merge is off, or it applies to minimal contexts. The rule code is reviewed, has no third-party code and cannot be bypassed.  
  *Refs:* cicd_top10: CICD-SEC-1; cheatsheet: CI_CD_Security_Cheat_Sheet; cwe: CWE-693; attack: T1195.002

- [ ] **CICD-FLOW-004** Check approval gates before production deployment  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds production deployments that start without a second person approving them.  
  *Steps:*
  1. List the pipelines and jobs that deploy to production.
  2. Read the environment or stage protection settings of each job.
  3. Make sure a person other than the author must approve the deployment.
  4. Try to start the production job from a branch that has no approval, on a test copy.
  *Example:* `gh api repos/ORG/REPO/environments/production --jq '.protection_rules'; glab api projects/ID/protected_environments`  
  *Expected:* A production deployment needs approval from a required reviewer who is not the author. No account can skip the approval gate.  
  *Refs:* owasp_top10: A08:2025; cicd_top10: CICD-SEC-1; cheatsheet: CI_CD_Security_Cheat_Sheet; cwe: CWE-284; nist_800_53: CM-3

- [ ] **CICD-FLOW-005** Make sure only artifacts from the CI service account reach deployment  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds deploy stages that accept artifacts uploaded by people or other accounts.  
  *Steps:*
  1. Find the artifact repositories that the deploy stage reads from.
  2. List the accounts that can upload to these repositories.
  3. Upload a test artifact with a personal account to a non-production path.
  4. Make sure the deploy stage rejects the test artifact.
  *Example:* `cosign verify --certificate-identity-regexp '^https://github.com/ORG/REPO/.github/workflows/release.yml@' --certificate-oidc-issuer https://token.actions.githubusercontent.com IMAGE@sha256:DIGEST`  
  *Expected:* The deploy stage accepts only artifacts that the approved CI identity created. Artifacts from other accounts need a second review.  
  *Refs:* owasp_top10: A08:2025; cicd_top10: CICD-SEC-1, CICD-SEC-9; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-345; capec: CAPEC-446; attack: T1195.002; nist_800_53: SR-11; other: SSDF PS.2.1

- [ ] **CICD-FLOW-006** Look for drift between production and its CI/CD origin  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds production changes that did not come from the reviewed pipeline.  
  *Steps:*
  1. Pick the code, images and infrastructure that run in production.
  2. Compare their digests or state with the last pipeline build.
  3. Look for resources that no signed template or pipeline created.
  4. Make sure each difference has a ticket and a fix.
  *Example:* `terraform plan -detailed-exitcode; kubectl diff -f manifests/; aws lambda get-function --function-name NAME --query Configuration.CodeSha256`  
  *Expected:* Production matches its pipeline origin. Detected drift is reported and corrected. Unmanaged resources are removed or brought under code.  
  *Refs:* cicd_top10: CICD-SEC-1, CICD-SEC-9; cheatsheet: Infrastructure_as_Code_Security_Cheat_Sheet, CI_CD_Security_Cheat_Sheet; cwe: CWE-1269; nist_800_53: CM-3, CM-6

- [ ] **CICD-FLOW-007** Check separation of duties from code change to production  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds paths where one person can write code and promote it to production alone.  
  *Steps:*
  1. Draw the path from commit to production for one service.
  2. Mark each step where a second person must approve.
  3. Look for steps that one account can complete alone, such as self-approval or a direct deploy.
  4. Make sure the author of a change cannot approve it.
  *Example:* `gh api repos/ORG/REPO/branches/main/protection --jq '.required_pull_request_reviews'  # look at require_last_push_approval and dismiss_stale_reviews`  
  *Expected:* No single account can write code and promote it to production. Self-approval is blocked at each gate.  
  *Refs:* owasp_top10: A08:2025; cicd_top10: CICD-SEC-1; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet, CI_CD_Security_Cheat_Sheet; cwe: CWE-269; nist_800_53: AC-5; other: SSDF PS.1.1

- [ ] **CICD-FLOW-008** Check direct write access to production outside the pipeline  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds people and tools that can change production code or infrastructure without a pipeline run.  
  *Steps:*
  1. List the roles with write access to production cloud accounts and clusters.
  2. Look at the audit log for changes made outside the pipeline in the last 90 days.
  3. Make sure a break-glass process with approval and logging exists for such access.
  4. Make sure the process raises an alert when someone uses it.
  *Example:* `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionCode; kubectl auth can-i --list --as=USER`  
  *Expected:* Production changes come only from the pipeline identity. Direct access needs approval, is logged and raises an alert.  
  *Refs:* cicd_top10: CICD-SEC-1; cheatsheet: CI_CD_Security_Cheat_Sheet, Infrastructure_as_Code_Security_Cheat_Sheet; cwe: CWE-284; attack: T1078; nist_800_53: AC-6, CM-5

- [ ] **CICD-FLOW-009** Check staged rollout of new releases  
  *Severity if fail:* Low | *Type:* Manual, Config Review  
  *Objective:* Finds deployments that reach all systems at once, so one bad release hits everything.  
  *Steps:*
  1. Read the deployment configuration of one production service.
  2. Make sure the release goes first to a canary or small group.
  3. Make sure a health check or approval gates the next stage.
  4. Make sure the pipeline can stop and roll back the release.
  *Example:* `kubectl rollout status deploy/NAME; argocd app get NAME; grep -rn 'canary\|strategy' deploy/`  
  *Expected:* New releases roll out in stages with a gate between stages. The pipeline can stop and roll back a release.  
  *Refs:* cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-1357


## ART

- [ ] **CICD-ART-010** Check that release workflows do not restore or save caches  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds cache poisoning that gives an attacker code in a release or access to production secrets.  
  *Steps:*
  1. List the workflows that build, release or publish packages.
  2. Look for cache steps and for built-in cache options in setup actions.
  3. Make sure release and publish workflows use no cache.
  4. Make sure workflows that share a cache with a release workflow cannot be started by untrusted users.
  *Example:* `grep -rnE 'actions/cache|cache:' .github/workflows; zizmor --pedantic .github/workflows/  # cache-poisoning rule`  
  *Expected:* Release and publish workflows do not use any cache. Untrusted workflows cannot write to a cache that a release workflow reads.  
  *Refs:* cicd_top10: CICD-SEC-9, CICD-SEC-4; cheatsheet: GitHub_Actions_Security_Cheat_Sheet; cwe: CWE-345; attack: T1195.002


## CRED

- [ ] **CICD-CRED-012** Check that reusable workflows do not use secrets inherit  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds called workflows that receive secrets they do not need.  
  *Steps:*
  1. Search the workflows for secrets: inherit on jobs that call reusable workflows.
  2. Make sure the caller passes only the secrets that the called workflow needs.
  3. Look at the environment that the called workflow selects. Note that its secrets can override passed secrets.
  4. Make sure secrets are set at step level or in an environment, not at job level.
  *Example:* `grep -rn 'secrets: inherit' .github/workflows; zizmor .github/workflows/`  
  *Expected:* No workflow uses secrets: inherit. Each secret is passed by name and limited to the step or environment that needs it.  
  *Refs:* cicd_top10: CICD-SEC-6, CICD-SEC-5; cheatsheet: GitHub_Actions_Security_Cheat_Sheet, Secrets_Management_Cheat_Sheet; cwe: CWE-522, CWE-250

- [ ] **CICD-CRED-013** Check that actions/checkout does not persist credentials  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds workflows that leave Git credentials in the workspace for later steps to steal.  
  *Steps:*
  1. Search the workflows for each use of actions/checkout.
  2. Make sure persist-credentials is false unless a later step needs Git write access.
  3. For each exception, make sure a later step really uses the stored credential.
  *Example:* `grep -rn -A4 'actions/checkout' .github/workflows | grep persist-credentials; zizmor .github/workflows/  # artipacked rule`  
  *Expected:* Each checkout step sets persist-credentials to false. Exceptions have a documented Git operation that needs the credential.  
  *Refs:* cicd_top10: CICD-SEC-6; cheatsheet: GitHub_Actions_Security_Cheat_Sheet; cwe: CWE-522

- [ ] **CICD-CRED-014** Check the trust policy of workload identity federation  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds trust policies that admit other tenants, repositories or branches.  
  *Steps:*
  1. Read the trust policy of each federated cloud role or identity.
  2. Make sure the policy names the exact issuer, the expected audience and the allowed subject.
  3. Make sure the policy limits the organization, repository and deployment context. Prefer immutable identifiers over names.
  4. Make sure the policy has no wildcard that admits all repositories or all job contexts.
  5. Make sure the cloud provider can enforce each claim that the policy uses.
  *Example:* `aws iam get-role --role-name ROLE --query Role.AssumeRolePolicyDocument; gcloud iam workload-identity-pools providers describe PROVIDER --workload-identity-pool=POOL --location=global`  
  *Expected:* Trust policies name the exact issuer, audience and subject. They limit repository, branch or environment and have no broad wildcard.  
  *Refs:* cicd_top10: CICD-SEC-5, CICD-SEC-2; cheatsheet: Workload_Identity_Federation_Cheat_Sheet, GitHub_Actions_Security_Cheat_Sheet; cwe: CWE-863, CWE-284; attack: T1078.004

- [ ] **CICD-CRED-015** Test that unauthorized jobs cannot get federated credentials  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds trust policies that look strict but admit repositories, branches or jobs that must not deploy.  
  *Steps:*
  1. Run a job from an unauthorized test repository. Try to exchange the OIDC token for cloud credentials.
  2. Run a job from an unauthorized branch of the trusted repository. Try the same exchange.
  3. Run the authorized job. Try to read a resource outside its assigned permissions.
  4. Repeat these tests after each change to the trust policy.
  *Example:* `aws sts assume-role-with-web-identity --role-arn ROLE --role-session-name t --web-identity-token "$OIDC_TOKEN"  # test jobs only`  
  *Expected:* Unauthorized repositories, branches and job contexts get no credentials. The authorized job cannot reach resources outside its permissions.  
  *Refs:* cicd_top10: CICD-SEC-5, CICD-SEC-2; cheatsheet: Workload_Identity_Federation_Cheat_Sheet; cwe: CWE-863; attack: T1078.004

- [ ] **CICD-CRED-016** Check OIDC token permission, credential lifetime and removal of old keys  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds jobs that can request tokens without need, long credential lifetimes and static keys that still work.  
  *Steps:*
  1. Search the workflows for id-token: write.
  2. Make sure only the jobs that need cloud access have the permission, at job level.
  3. Read the lifetime of the issued credentials. Make sure it is the shortest the job needs.
  4. Make sure logs, artifacts and caches do not hold the OIDC token or issued credentials.
  5. Make sure the static keys that federation replaced are revoked and removed from the pipelines.
  *Example:* `grep -rn 'id-token' .github/workflows; aws iam get-role --role-name ROLE --query Role.MaxSessionDuration; aws iam list-access-keys --user-name USER`  
  *Expected:* Only jobs with cloud access can request tokens. Credential lifetime is short. Replaced static keys no longer work.  
  *Refs:* cicd_top10: CICD-SEC-6; cheatsheet: Workload_Identity_Federation_Cheat_Sheet; cwe: CWE-522, CWE-532

- [ ] **CICD-CRED-017** Check that a compromised job stops getting credentials quickly  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds missing procedures to stop credential issuance and to end sessions that exist already.  
  *Steps:*
  1. Read the incident procedure for a compromised pipeline job.
  2. Make sure the procedure lists how to stop new credential issuance.
  3. Make sure the procedure lists how to revoke or restrict sessions that exist already.
  4. Note that removal of the trust relationship alone does not end existing sessions.
  5. Run the procedure on a test role and make sure the old session stops.
  *Example:* `aws iam put-role-policy --role-name TESTROLE --policy-name RevokeOlderSessions --policy-document file://deny-before-time.json  # test role only`  
  *Expected:* The team can stop new credentials and end existing sessions of a federated identity within the target time.  
  *Refs:* cicd_top10: CICD-SEC-6; cheatsheet: Workload_Identity_Federation_Cheat_Sheet, GitHub_Actions_Security_Cheat_Sheet


## IAM

- [ ] **CICD-IAM-009** Check that federated deployment roles are separate and cannot change federation  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds deployment roles with administrative rights that let a compromised job change its own trust.  
  *Steps:*
  1. List the federated identities and their permissions policies.
  2. Make sure production and non-production use different identities and trust rules.
  3. Make sure each role has only the cloud operations and resources that the deployment needs.
  4. Make sure deployment roles cannot change federation settings or permissions.
  *Example:* `aws iam list-attached-role-policies --role-name ROLE; aws iam simulate-principal-policy --policy-source-arn ARN --action-names iam:UpdateAssumeRolePolicy iam:AttachRolePolicy`  
  *Expected:* Each federated role has least privilege and separate production and test identities. Deployment roles cannot change trust or permissions.  
  *Refs:* cicd_top10: CICD-SEC-5, CICD-SEC-2; cheatsheet: Workload_Identity_Federation_Cheat_Sheet; cwe: CWE-250, CWE-732; nist_800_53: AC-6


## LOG

- [ ] **CICD-LOG-008** Check that token exchange and role use trace to pipeline runs  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds federated access that the team cannot trace to a pipeline run.  
  *Steps:*
  1. Make sure cloud audit events for token exchange and role use are on.
  2. Run a test deployment. Find its token exchange event in the cloud log.
  3. Look at the identity fields that the event records.
  4. Make sure the team can link the event to the CI/CD run record.
  *Example:* `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRoleWithWebIdentity`  
  *Expected:* Each token exchange and role use is logged. The log lets the team find the pipeline run that made it.  
  *Refs:* cicd_top10: CICD-SEC-10; cheatsheet: Workload_Identity_Federation_Cheat_Sheet; nist_800_53: AU-2, AU-12


## PBAC

- [ ] **CICD-PBAC-009** Check runner groups and labels that separate high and low privilege runners  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds runners with high privileges that any repository or workflow can use.  
  *Steps:*
  1. List the runner groups and the repositories that can use each group.
  2. Make sure runners that build images or reach restricted networks are in separate groups.
  3. Make sure the groups are limited to the repositories that need them.
  4. Make sure public repositories do not use self-hosted runners, or that the runners are ephemeral.
  *Example:* `gh api orgs/ORG/actions/runner-groups --jq '.runner_groups[]|{name,visibility,allows_public_repositories}'`  
  *Expected:* High-privilege runner groups are available only to named repositories. Low-privilege jobs run on separate runners.  
  *Refs:* cicd_top10: CICD-SEC-5; cheatsheet: GitHub_Actions_Security_Cheat_Sheet; cwe: CWE-250


## PPE

- [ ] **CICD-PPE-009** Check the workflow_run and issue_comment triggers for privilege escalation  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds privileged workflows that an attacker can start or steer through another workflow or a comment.  
  *Steps:*
  1. List the workflows that use the workflow_run or issue_comment trigger.
  2. Make sure each one checks that the triggering actor is a trusted member.
  3. Make sure workflow_run jobs do not use artifacts from the triggering run without a check.
  4. Make sure a comment trigger accepts only a full commit SHA and checks out only that SHA.
  5. Make sure workflow chains use workflow_call with reusable workflows.
  *Example:* `grep -rnE 'workflow_run|issue_comment' .github/workflows; zizmor --pedantic .github/workflows/; actionlint`  
  *Expected:* No privileged workflow runs on the output or comment of an untrusted actor. Comment triggers check the actor and a fixed commit SHA.  
  *Refs:* cicd_top10: CICD-SEC-4; cheatsheet: GitHub_Actions_Security_Cheat_Sheet; cwe: CWE-94, CWE-345; attack: T1059

- [ ] **CICD-PPE-010** Check that workflow AI assistants have minimal tools and no write access  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds workflows where prompt injection through issues or pull requests gives an attacker secrets or write access.  
  *Steps:*
  1. List the workflows that run an AI assistant to review pull requests or triage issues.
  2. List the triggers, the secrets and the GITHUB_TOKEN permissions of each workflow.
  3. Make sure untrusted users cannot start a workflow that has secrets or a token with write permission.
  4. Make sure the assistant has only the tools and actions that the task needs.
  5. Open a test issue with a harmless injected instruction. Make sure the assistant does not follow it.
  *Example:* `grep -rniE 'claude|copilot|gemini|openai|llm' .github/workflows; zizmor .github/workflows/`  
  *Expected:* An AI assistant that reads untrusted input has no secrets and no write token. Its tool list is limited to the task.  
  *Refs:* cicd_top10: CICD-SEC-4; cheatsheet: GitHub_Actions_Security_Cheat_Sheet, Secure_Coding_with_AI_Cheat_Sheet; cwe: CWE-77

- [ ] **CICD-PPE-011** Check that all external contributors need approval before workflows run  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds repositories where a trusted first pull request lets later malicious pull requests run without approval.  
  *Steps:*
  1. Read the setting for fork pull request workflows in the repository and organization.
  2. Make sure the setting is Require approval for all external contributors.
  3. Make sure the first-time contributors option alone is not in use.
  4. Open a test pull request from a fork that was merged before. Make sure the workflow waits for approval.
  *Example:* `gh api repos/ORG/REPO/actions/permissions/fork-pr-contributor-approval`  
  *Expected:* Every workflow run from an external contributor waits for manual approval by a maintainer.  
  *Refs:* cicd_top10: CICD-SEC-4; cheatsheet: GitHub_Actions_Security_Cheat_Sheet; cwe: CWE-284


## TPS

- [ ] **CICD-TPS-007** Check actions for impostor commits and a delay before updates  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds pinned actions whose commit comes from a fork and update tools that adopt new releases at once.  
  *Steps:*
  1. List each third-party action and reusable workflow with its pinned commit hash.
  2. Make sure each commit belongs to the named organization and repository.
  3. Read the Dependabot or Renovate configuration for actions.
  4. Make sure the configuration has a delay between a release and its adoption.
  *Example:* `zizmor --pedantic .github/workflows/  # impostor-commit rule; cat .github/dependabot.yml  # cooldown`  
  *Expected:* Each pinned commit exists in the named repository. Automatic updates wait a defined number of days before they adopt a release.  
  *Refs:* cicd_top10: CICD-SEC-3, CICD-SEC-8; cheatsheet: GitHub_Actions_Security_Cheat_Sheet; cwe: CWE-829, CWE-494; attack: T1195.002


## VULN

- [ ] **CICD-VULN-007** Check that workflow files are scanned and the scan blocks merges  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds workflow vulnerabilities that nobody detects because no tool scans the workflow files.  
  *Steps:*
  1. Look for CodeQL with the actions language or for zizmor in the repository settings or workflows.
  2. Make sure the scan runs on each pull request and is a required status check.
  3. Make sure the scan blocks a merge for high and critical findings.
  4. Make sure a scheduled full scan runs and that the team tracks each finding to closure.
  *Example:* `gh api repos/ORG/REPO/code-scanning/default-setup; gh api repos/ORG/REPO/rulesets; zizmor --pedantic .github/workflows/`  
  *Expected:* Workflow files are scanned on each pull request and on a schedule. High and critical findings block the merge.  
  *Refs:* cicd_top10: CICD-SEC-4, CICD-SEC-7; cheatsheet: GitHub_Actions_Security_Cheat_Sheet; cwe: CWE-94


## IAM

- [ ] **CICD-IAM-001** Review identities and permissions across the CI/CD systems  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds overly permissive human and programmatic identities in the SCM, CI and registries.  
  *Steps:*
  1. List all human and programmatic identities in the SCM, CI, registry and deployment tools.
  2. Record the identity provider and the permission level of each identity.
  3. Compare the granted permissions with the permissions in use.
  4. Find identities with organization-wide write or admin rights.
  5. Create a ticket to remove unused permissions.
  *Example:* `legitify analyze --namespace ORG; gh api orgs/ORG/members --jq '.[].login'; gh api orgs/ORG/outside_collaborators`  
  *Expected:* Every identity is mapped to an owner and an identity provider. Each identity holds only the permissions it uses, on the repositories it needs.  
  *Refs:* cicd_top10: CICD-SEC-2; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-269, CWE-250; attack: T1078; nist_800_53: AC-2, AC-6; other: SSDF PS.1.1

- [ ] **CICD-IAM-002** Find stale human and service accounts and tokens  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds unused accounts and tokens that still give access to CI/CD systems.  
  *Steps:*
  1. Get the policy period after which an inactive identity must be disabled.
  2. List the last activity date of each user, service account and token.
  3. Find identities that exceed the period.
  4. Make sure former employees and contractors have no active account in any CI/CD system.
  *Example:* `gh api orgs/ORG/audit-log?phrase=actor:USER; gh api /orgs/ORG/personal-access-tokens --jq '.[]|{owner:.owner.login,last_used:.token_last_used_at}'`  
  *Expected:* A defined inactivity period exists. No identity exceeds it. Accounts of people who left are removed from all CI/CD systems.  
  *Refs:* cicd_top10: CICD-SEC-2; cheatsheet: CI_CD_Security_Cheat_Sheet; cwe: CWE-269; attack: T1078; nist_800_53: AC-2

- [ ] **CICD-IAM-003** Check central IdP login, no local accounts and enforced MFA  
  *Severity if fail:* High | *Type:* Config Review, Automated  
  *Objective:* Finds local accounts and logins without MFA on CI/CD platforms.  
  *Steps:*
  1. Read the authentication settings of the SCM, CI and registry.
  2. Make sure login uses the central IdP with SSO.
  3. List local accounts that do not use the IdP.
  4. Make sure MFA is required for all users and for admins.
  *Example:* `gh api orgs/ORG --jq .two_factor_requirement_enabled; gh api orgs/ORG/members?filter=2fa_disabled; curl -s https://JENKINS/securityRealm/`  
  *Expected:* All users log in through the central IdP with MFA. Local accounts do not exist, or each one is documented and disabled when unused.  
  *Refs:* cicd_top10: CICD-SEC-2; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-1390, CWE-306; attack: T1078.003; nist_800_53: IA-2, AC-2

- [ ] **CICD-IAM-004** Make sure self-registration and base permissions are off  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds CI/CD platforms where anyone with a valid email can register and get access.  
  *Steps:*
  1. Open the sign-up page of the self-managed SCM or CI from an unauthenticated browser.
  2. Try to start a registration with an address from the company domain, on a test system.
  3. Read the default permission level for new users and for large groups.
  4. Make sure the default permission is none.
  *Example:* `curl -sI https://git.example.org/users/sign_up; glab api application/settings | jq '.signup_enabled,.default_project_creation'`  
  *Expected:* Self-registration is off or needs admin approval. New users and large groups start with no permission.  
  *Refs:* cicd_top10: CICD-SEC-2; cheatsheet: CI_CD_Security_Cheat_Sheet; cwe: CWE-1188, CWE-284; attack: T1078.001; nist_800_53: AC-2

- [ ] **CICD-IAM-005** Check that only organization email domains are allowed  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds accounts that use personal or external email addresses on CI/CD platforms.  
  *Steps:*
  1. List the email address of each user in the SCM, CI and registry.
  2. Find addresses outside domains that the organization owns.
  3. Check for a domain restriction in the platform settings.
  4. Make sure each non-organization account has a documented reason and an owner.
  *Example:* `gh api orgs/ORG/members --paginate --jq '.[].login' | xargs -I{} gh api users/{} --jq '.email'; glab api application/settings | jq .domain_allowlist`  
  *Expected:* Only addresses from domains that the organization manages can hold accounts. Exceptions are documented and reviewed.  
  *Refs:* cicd_top10: CICD-SEC-2; cheatsheet: CI_CD_Security_Cheat_Sheet; cwe: CWE-284; nist_800_53: AC-2

- [ ] **CICD-IAM-006** Review external collaborators and their access expiry  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds external collaborators with permanent or excessive access to repositories and pipelines.  
  *Steps:*
  1. List external collaborators and outside contractors on all CI/CD systems.
  2. Look at the permission level and the repositories of each one.
  3. Make sure each access has an expiry date and an internal sponsor.
  4. Make sure access ends when the work is done.
  *Example:* `gh api orgs/ORG/outside_collaborators --paginate; gh api repos/ORG/REPO/invitations`  
  *Expected:* External collaborators have least privilege on named repositories only. Each access has an expiry date and an internal owner.  
  *Refs:* cicd_top10: CICD-SEC-2; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-269; attack: T1199; nist_800_53: AC-2, AC-6

- [ ] **CICD-IAM-007** Check for shared accounts and shared service credentials  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds accounts or credentials that several people or systems share.  
  *Steps:*
  1. List service accounts and the systems that use each one.
  2. Find accounts that more than one person or more than one pipeline uses.
  3. Look at the audit log for one account that logs in from several locations.
  4. Make sure each context has its own account with its own permissions.
  *Example:* `gh api orgs/ORG/audit-log --jq '.[]|select(.actor=="SERVICE_ACCOUNT")|.actor_ip' | sort -u`  
  *Expected:* Each person and each pipeline context has its own identity. No credential is shared between people, between systems, or between people and systems.  
  *Refs:* cicd_top10: CICD-SEC-2, CICD-SEC-6; cheatsheet: CI_CD_Security_Cheat_Sheet, Secrets_Management_Cheat_Sheet; cwe: CWE-522; attack: T1078; nist_800_53: IA-2, AC-6

- [ ] **CICD-IAM-008** Check package publishing accounts for 2FA and trusted publishing  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds package publishing accounts and tokens that an attacker can use to push malicious versions.  
  *Steps:*
  1. List the accounts and tokens that can publish packages for your organization.
  2. Make sure 2FA is on for each publisher account.
  3. Make sure CI publishing uses trusted publishing with OIDC where the registry supports it.
  4. Make sure remaining tokens are granular, short-lived and not committed.
  *Example:* `npm token list; npm profile get; npm access list collaborators PACKAGE`  
  *Expected:* Publishing needs 2FA or trusted publishing. Tokens are granular, scoped to named packages and expire soon.  
  *Refs:* cicd_top10: CICD-SEC-2, CICD-SEC-6; cheatsheet: NPM_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-522; capec: CAPEC-538; attack: T1195.001, T1528; nist_800_53: IA-2, IA-5


## LOG

- [ ] **CICD-LOG-001** Build an inventory of all CI/CD systems and instances  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds CI/CD systems that nobody monitors, such as self-managed servers run by one team.  
  *Steps:*
  1. List the SCM, CI, registry, package manager, CD and orchestration systems.
  2. Search the network and cloud for additional instances of each.
  3. Record the owner and the log status of each instance.
  4. Add unknown instances to the inventory.
  *Example:* `nmap -p 8080,443 -sV --script http-title CIDR; aws ec2 describe-instances --filters Name=tag:role,Values=ci; shodan-style search of own domains`  
  *Expected:* The inventory covers every CI/CD instance. Each has an owner and a log status.  
  *Refs:* cicd_top10: CICD-SEC-10, CICD-SEC-7; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-778; nist_800_53: CM-8

- [ ] **CICD-LOG-002** Check that audit logs are on for human and programmatic access  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds systems that do not log logins, permission changes and token use.  
  *Steps:*
  1. For each CI/CD system, read the audit log settings.
  2. Make sure logs cover user creation, login, permission changes and token creation.
  3. Make sure logs cover access by apps, service accounts and tokens.
  4. Run a test change and look for it in the log.
  *Example:* `gh api orgs/ORG/audit-log?per_page=5; curl -s https://JENKINS/manage/log/; glab api audit_events`  
  *Expected:* Audit logging is on in each system. A test change appears in the log with the actor, time and source.  
  *Refs:* cicd_top10: CICD-SEC-10; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet, Secrets_Management_Cheat_Sheet; cwe: CWE-778; attack: T1078; nist_800_53: AU-2, AU-12

- [ ] **CICD-LOG-003** Check that pipeline events go to a central log system  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds push, build and upload events that stay in local systems where an attacker can erase them.  
  *Steps:*
  1. List the events that matter: pushes, builds, artifact uploads, deployments.
  2. Find the log forwarder or export setting for each system.
  3. Search the SIEM for a test push, build and upload.
  4. Make sure events from different systems can be matched.
  *Example:* `gh api orgs/ORG/audit-log/streams; logger -p auth.info 'cicd-test'; SIEM search: source=ci AND repo=TEST`  
  *Expected:* Audit and application events of all CI/CD systems arrive in the central log system within the set delay.  
  *Refs:* cicd_top10: CICD-SEC-10; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-778; capec: CAPEC-571; attack: T1195.002; nist_800_53: AU-6, AU-12

- [ ] **CICD-LOG-004** Test alerts for attacks on the CI/CD pipeline  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds attacks on the pipeline that raise no alert.  
  *Steps:*
  1. List the alert rules for CI/CD, such as branch protection changes, new tokens and workflow file changes.
  2. On a test repository, change a branch protection rule and create a test token.
  3. Wait for the alert time and look for the alerts.
  4. Add rules for the events that raised no alert.
  *Example:* `gh api -X DELETE repos/ORG/TEST/branches/main/protection  # test repository only; SIEM search for action:protected_branch.destroy`  
  *Expected:* Alerts exist for changes to protection rules, new tokens, new workflows, odd secret reads and odd outbound traffic. A test change raises an alert.  
  *Refs:* cicd_top10: CICD-SEC-10; cheatsheet: CI_CD_Security_Cheat_Sheet, Secrets_Management_Cheat_Sheet; cwe: CWE-778; attack: T1195.002; nist_800_53: AU-6, SI-4

- [ ] **CICD-LOG-005** Check log content, format and retention  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds logs that hold secrets, cannot be parsed or are kept too short for an investigation.  
  *Steps:*
  1. Read the log policy for CI/CD systems.
  2. Make sure logs use a parsable format such as JSON or syslog.
  3. Search logs for secrets and personal data.
  4. Make sure the retention period fits investigation and legal needs.
  *Example:* `gitleaks detect --no-git -s exported-audit-log.json; jq . exported-audit-log.json | head`  
  *Expected:* Logs are parsable, hold no secrets and are kept for the set period. Audit logs cannot be changed by pipeline users.  
  *Refs:* cicd_top10: CICD-SEC-10, CICD-SEC-6; cheatsheet: CI_CD_Security_Cheat_Sheet, Secrets_Management_Cheat_Sheet; cwe: CWE-532, CWE-778; nist_800_53: AU-11, AU-9

- [ ] **CICD-LOG-006** Check that secret manager requests trace back to the pipeline run  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds secret reads that cannot be tied to the user, commit or job that caused them.  
  *Steps:*
  1. Run a test pipeline that reads one test secret.
  2. Find the read event in the secret manager log.
  3. Make sure the event holds the workflow identity, repository, branch or run.
  4. Make sure unusual reads raise an alert.
  *Example:* `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue; vault audit list`  
  *Expected:* Each secret read shows which pipeline run, commit or user caused it. Unusual reads raise an alert.  
  *Refs:* cicd_top10: CICD-SEC-10, CICD-SEC-6; cheatsheet: Secrets_Management_Cheat_Sheet; cwe: CWE-778; nist_800_53: AU-3, AU-12

- [ ] **CICD-LOG-007** Check tamper evidence of build records  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds build logs and records that an attacker with build access could change without trace.  
  *Steps:*
  1. Find where build logs and records are stored.
  2. List the accounts that can change or delete them.
  3. Make sure a copy goes to write-once or separate storage.
  4. Try to change a test record and look for the change event.
  *Example:* `aws s3api get-bucket-versioning --bucket LOGS; aws s3api get-object-lock-configuration --bucket LOGS`  
  *Expected:* Build logs are tamper-evident. Pipeline users cannot change or delete them. Changes raise an event.  
  *Refs:* owasp_top10: A08:2025; cicd_top10: CICD-SEC-10, CICD-SEC-9; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-778; capec: CAPEC-81, CAPEC-93; attack: T1195.002; nist_800_53: AU-9, SR-9


## PBAC

- [ ] **CICD-PBAC-001** Check that secrets are scoped to the pipeline, step and environment  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds secrets that every pipeline or every branch can read.  
  *Steps:*
  1. List the secrets at organization, repository and environment level.
  2. Find secrets that all repositories or all branches can read.
  3. Compare each secret with the pipelines that use it.
  4. Make sure production secrets are only in protected environments.
  *Example:* `gh api orgs/ORG/actions/secrets --jq '.secrets[]|{name,visibility}'; gh api repos/ORG/REPO/environments --jq '.environments[].name'; glab api projects/ID/variables`  
  *Expected:* Each secret is available only to the pipelines and steps that need it. Production secrets need a protected branch or environment.  
  *Refs:* cicd_top10: CICD-SEC-5, CICD-SEC-6; cheatsheet: CI_CD_Security_Cheat_Sheet, Secrets_Management_Cheat_Sheet; cwe: CWE-269, CWE-522; attack: T1552.001; nist_800_53: AC-6; other: SSDF PS.1.1

- [ ] **CICD-PBAC-002** Check the default permissions of the job token  
  *Severity if fail:* High | *Type:* Config Review, Automated  
  *Objective:* Finds pipeline tokens that have write access to code or packages by default.  
  *Steps:*
  1. Read the default token permission of the organization and the repository.
  2. Make sure the default is read-only.
  3. Look at each workflow for a permissions block.
  4. Make sure each write permission is granted only to the job that needs it.
  *Example:* `gh api repos/ORG/REPO/actions/permissions/workflow; zizmor .github/workflows/ ; grep -rn 'permissions:' -A4 .github/workflows`  
  *Expected:* The default token is read-only. Each job lists the exact permissions it needs. Write access is granted per job.  
  *Refs:* cicd_top10: CICD-SEC-5; cheatsheet: CI_CD_Security_Cheat_Sheet; cwe: CWE-250, CWE-269; attack: T1528; nist_800_53: AC-6

- [ ] **CICD-PBAC-003** Check runner isolation and clean state after each job  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds shared build nodes that keep files, caches or credentials between jobs.  
  *Steps:*
  1. List the runners and the pipelines that use each one.
  2. Make sure pipelines with different sensitivity do not share a node.
  3. Make sure each job runs on an ephemeral node or a clean container.
  4. Run two jobs one after the other on a test runner and look for left-over files.
  *Example:* `gh api repos/ORG/REPO/actions/runners --jq '.runners[]|{name,labels}'; ls -la "$RUNNER_TEMP" ~/.cache  # in a test job`  
  *Expected:* Nodes are ephemeral or reset after each job. Pipelines with different sensitivity never share a node, cache or workspace.  
  *Refs:* cicd_top10: CICD-SEC-5; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-284; capec: CAPEC-678; attack: T1195.002; other: SSDF PO.5.1

- [ ] **CICD-PBAC-004** Check the OS rights of the job and the container  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds jobs that run as root, in privileged containers or with access to the Docker socket.  
  *Steps:*
  1. Read the runner service account and its OS permissions.
  2. Look for the privileged flag, host mounts and added capabilities in job containers.
  3. Look for a mount of the Docker socket in the job.
  4. Make sure jobs run as a non-root user.
  *Example:* `ps -o user= -C Runner.Listener; grep -rnE 'privileged|docker.sock|cap_add|--cap-add' .github/ docker-compose*.yml; docker inspect --format '{{.HostConfig.Privileged}}' CONTAINER`  
  *Expected:* Jobs run as an unprivileged user. Job containers are not privileged and have no Docker socket or broad host mount.  
  *Refs:* cicd_top10: CICD-SEC-5, CICD-SEC-7; cheatsheet: CI_CD_Security_Cheat_Sheet, Docker_Security_Cheat_Sheet; cwe: CWE-250; attack: T1525; nist_800_53: AC-6, CM-6

- [ ] **CICD-PBAC-005** Test outbound network access from build nodes  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds build nodes that can send data to any host on the internet.  
  *Steps:*
  1. Read the egress rules for the build network.
  2. Start a test job that connects to a harmless external host that is not on the allowlist.
  3. Look at the result of the connection.
  4. Make sure the allowlist holds only the registries and services that the build needs.
  *Example:* `curl -sS -m 5 -o /dev/null -w '%{http_code}\n' https://example.org  # in a test job`  
  *Expected:* Build nodes can reach only allowlisted hosts. The test connection to an unlisted host fails and the event is logged.  
  *Refs:* cicd_top10: CICD-SEC-5; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet, CI_CD_Security_Cheat_Sheet; cwe: CWE-693; attack: T1195.002; nist_800_53: SC-7; other: SSDF PO.5.1

- [ ] **CICD-PBAC-006** Check network segmentation and metadata service access from jobs  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds jobs that can reach internal systems or the cloud instance identity service.  
  *Steps:*
  1. List the internal networks and services that the runner network can reach.
  2. Compare the list with the resources the pipelines need.
  3. From a test job, try to reach the cloud metadata address and an unrelated internal host.
  4. Make sure the instance metadata service needs a session token or is blocked.
  *Example:* `curl -sS -m 3 -o /dev/null -w '%{http_code}\n' http://169.254.169.254/latest/meta-data/  # in a test job; nmap -Pn -p 22,443 INTERNAL_HOST`  
  *Expected:* Runners reach only the systems that the pipelines need. Jobs cannot read the metadata service without a protected session token.  
  *Refs:* cicd_top10: CICD-SEC-5, CICD-SEC-7; cheatsheet: CI_CD_Security_Cheat_Sheet; cwe: CWE-284; attack: T1552.005; nist_800_53: SC-7

- [ ] **CICD-PBAC-007** Check what controller access pipeline jobs have  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds jobs that can read other jobs, run on the CI controller or change CI settings.  
  *Steps:*
  1. Make sure no job runs on the CI controller node.
  2. Read the permissions of the job identity on the CI platform.
  3. From a test job, try to list other projects, credentials and nodes.
  4. Make sure the request fails.
  *Example:* `curl -s -u JOBTOKEN: https://JENKINS/api/json?tree=jobs[name]; gh api repos/OTHER_ORG/OTHER_REPO/actions/secrets  # with the job token`  
  *Expected:* Jobs run on separate nodes. The job identity cannot list other projects, read stored credentials or change CI settings.  
  *Refs:* cicd_top10: CICD-SEC-5; cheatsheet: CI_CD_Security_Cheat_Sheet; cwe: CWE-269; attack: T1072; nist_800_53: AC-6

- [ ] **CICD-PBAC-008** Check that third-party build steps run in a scoped context  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds third-party actions, plugins and scripts that run with the full rights of the job.  
  *Steps:*
  1. List the third-party actions, plugins, orbs and downloaded scripts that jobs use.
  2. Find the jobs where they run together with secrets or write tokens.
  3. Move the step to a job without secrets on a test branch.
  4. Make sure the step still works with its limited rights.
  *Example:* `grep -rnE 'uses: [^./]' .github/workflows | grep -v '@[0-9a-f]\{40\}'; zizmor .github/workflows/`  
  *Expected:* Third-party steps run in jobs with minimal secrets, a read-only token and limited egress. They do not share a job with deploy credentials.  
  *Refs:* cicd_top10: CICD-SEC-5, CICD-SEC-8; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-829, CWE-250; attack: T1195.002


## PPE

- [ ] **CICD-PPE-001** Test direct poisoned pipeline execution from an unreviewed branch  
  *Severity if fail:* Critical | *Type:* Manual, Config Review  
  *Objective:* Finds pipelines where a changed CI file on an unreviewed branch runs with secrets.  
  *Steps:*
  1. List the events that start each pipeline, such as push and pull request.
  2. Make sure the pipeline for a push to an unprotected branch has no secrets and no deploy rights.
  3. Push a harmless change to a CI file on a test branch that prints a marker text.
  4. Look at the run and make sure no secret or protected environment was available.
  *Example:* `zizmor .github/workflows/; actionlint; gh api repos/ORG/REPO/actions/secrets; echo CANARY-OK in a test workflow`  
  *Expected:* A changed CI file on an unreviewed branch or pull request runs without secrets, without deploy rights and without protected environments.  
  *Refs:* owasp_top10: A08:2025; cicd_top10: CICD-SEC-4; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-94, CWE-77; capec: CAPEC-445; attack: T1195.002, T1072; other: SSDF PS.1.1

- [ ] **CICD-PPE-002** Check that CI configuration files need review before they run  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds CI definitions that a user can change without a second person reviewing them.  
  *Steps:*
  1. Find where the CI configuration file is stored.
  2. Make sure a named owner must review changes to it, or that it comes from a protected source.
  3. Read the CODEOWNERS file for the workflow and pipeline paths.
  4. Make sure branch protection requires the code owner review.
  *Example:* `cat .github/CODEOWNERS | grep -E 'workflows|Jenkinsfile|\.gitlab-ci'; gh api repos/ORG/REPO/branches/main/protection --jq .required_pull_request_reviews.require_code_owner_reviews`  
  *Expected:* CI configuration changes need code owner review. Or the pipeline reads its definition from a protected branch or a separate protected repository.  
  *Refs:* owasp_top10: A08:2025; cicd_top10: CICD-SEC-4; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-284; capec: CAPEC-445; attack: T1195.002, T1072; nist_800_53: CM-3, CM-5

- [ ] **CICD-PPE-003** Test indirect poisoned pipeline execution through referenced files  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds jobs that run repository files, such as Makefile, scripts and test code, with secrets.  
  *Steps:*
  1. List the files that the pipeline runs, such as Makefile, scripts, test code and linter configuration.
  2. Find the jobs that run these files together with secrets.
  3. Change a referenced script on a test branch to print a marker text.
  4. Make sure the changed file runs without secrets until a reviewer approves it.
  *Example:* `grep -rnE 'make |bash |sh |python |npm run' .github/workflows Jenkinsfile; grep -rn 'secrets\.' .github/workflows`  
  *Expected:* Jobs with secrets run only reviewed files. Unreviewed files run in a job without secrets, or the secret step does not run repository scripts.  
  *Refs:* owasp_top10: A08:2025; cicd_top10: CICD-SEC-4; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-94; capec: CAPEC-445; attack: T1195.002, T1072

- [ ] **CICD-PPE-004** Test public poisoned pipeline execution from forks  
  *Severity if fail:* Critical | *Type:* Config Review, Automated  
  *Objective:* Finds public repositories that run code from anonymous contributors with secrets or write tokens.  
  *Steps:*
  1. List the workflows that run on pull requests from forks.
  2. Make sure forks do not receive secrets and get a read-only token.
  3. Look for pull_request_target or similar triggers that check out and run fork code.
  4. Make sure first-time contributors need manual approval before a run.
  *Example:* `zizmor --pedantic .github/workflows/; gh api repos/ORG/REPO/actions/permissions/fork-pr-contributor-approval; grep -rn 'pull_request_target' .github/workflows`  
  *Expected:* Fork pull requests run without secrets and with a read-only token. Triggers with write rights never run fork code. Outside contributors need approval.  
  *Refs:* owasp_top10: A08:2025; cicd_top10: CICD-SEC-4; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-94, CWE-250; capec: CAPEC-445; attack: T1195.002, T1072

- [ ] **CICD-PPE-005** Check that public repository pipelines do not share runners with private ones  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds public project builds that run on the same CI instance or runner as private projects.  
  *Steps:*
  1. List the runners and the CI instances for public and private repositories.
  2. Find runners that serve both.
  3. Look for shared caches, volumes and credentials between them.
  4. Make sure public builds use separate ephemeral runners.
  *Example:* `gh api orgs/ORG/actions/runner-groups --jq '.runner_groups[]|{name,visibility,allows_public_repositories}'`  
  *Expected:* Public and private pipelines use separate runners, caches and credentials. Runners for public builds are ephemeral.  
  *Refs:* owasp_top10: A08:2025; cicd_top10: CICD-SEC-4; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-284; attack: T1195.002, T1072

- [ ] **CICD-PPE-006** Test CI steps for injection from untrusted context values  
  *Severity if fail:* High | *Type:* Code Review, Automated  
  *Objective:* Finds steps that put names of branches, pull request titles or commit messages into shell commands.  
  *Steps:*
  1. Search the pipeline files for context values that enter run steps, such as titles, branch names and issue text.
  2. Make sure the values pass through environment variables, not direct text insertion.
  3. Open a test pull request with a title that holds a harmless command substitution marker.
  4. Look at the run log and make sure the marker is printed as plain text.
  *Example:* `zizmor --format plain .github/workflows/ | grep -i injection; actionlint -shellcheck=; grep -rn '\${{ github.event' .github/workflows`  
  *Expected:* Untrusted values never go into shell code. The marker text appears in the log as plain text.  
  *Refs:* owasp_top10: A08:2025; cicd_top10: CICD-SEC-4; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-77, CWE-94; attack: T1195.002, T1072

- [ ] **CICD-PPE-007** Check user-controlled build parameters  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds build parameters that let a user change how the build runs, for example scripts or URLs.  
  *Steps:*
  1. List the manual triggers and the input parameters of each pipeline.
  2. Find parameters that set commands, URLs, branches or script paths.
  3. Make sure only authorized users can start these triggers.
  4. Remove the parameters that are not needed.
  *Example:* `grep -rn 'workflow_dispatch\|parameters {' -A8 .github/workflows Jenkinsfile`  
  *Expected:* Build parameters are few. They accept only validated values and do not set commands or script locations. Only authorized users can start the build.  
  *Refs:* owasp_top10: A08:2025; cicd_top10: CICD-SEC-4; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-77; attack: T1195.002, T1072

- [ ] **CICD-PPE-008** Make sure pipeline definitions and build scripts are in version control  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds pipeline settings that exist only in the CI user interface with no history or review.  
  *Steps:*
  1. List the pipelines and jobs in the CI system.
  2. Find jobs whose definition is only in the CI user interface.
  3. Make sure each pipeline definition and build script is in a repository.
  4. Make sure the audit log shows who changed a job setting.
  *Example:* `curl -s https://JENKINS/api/json?tree=jobs[name,_class]; gh api repos/ORG/REPO/contents/.github/workflows`  
  *Expected:* Every pipeline definition and build script is in version control with review and history. No job exists only in the user interface.  
  *Refs:* owasp_top10: A08:2025; cicd_top10: CICD-SEC-4; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-1269; attack: T1195.002, T1072; nist_800_53: CM-3, CM-2; other: SSDF PS.1.1


## TPS

- [ ] **CICD-TPS-001** List all third-party integrations in the SCM and CI  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds integrations that nobody approved, such as apps, OAuth apps, tokens, SSH keys and webhooks.  
  *Steps:*
  1. List GitHub or GitLab apps, OAuth apps, personal tokens, deploy keys and webhooks.
  2. Record the owner, the method and the permission level of each.
  3. Find integrations without an approval record.
  4. Check that webhook targets belong to known vendors and use a secret.
  *Example:* `gh api orgs/ORG/installations; gh api orgs/ORG/hooks; gh api repos/ORG/REPO/keys; gh api repos/ORG/REPO/hooks`  
  *Expected:* Every integration has an approval record, an owner and a known permission level. No unknown app, key or webhook exists.  
  *Refs:* owasp_top10: A03:2025; cicd_top10: CICD-SEC-8; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-829; attack: T1199; nist_800_53: SR-3, CM-8; other: SSDF PW.4.1

- [ ] **CICD-TPS-002** Compare granted and used permissions of third-party integrations  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds integrations with more access than they use.  
  *Steps:*
  1. For each integration, read the permissions it holds and the repositories it can reach.
  2. Look at the audit log for the permissions it used in the last 90 days.
  3. Mark unused and excess permissions.
  4. Reduce the access to the used set.
  *Example:* `gh api orgs/ORG/installations --jq '.installations[]|{app_slug,permissions,repository_selection}'`  
  *Expected:* Each integration holds only the permissions it uses, on the repositories it needs. Excess permissions are removed.  
  *Refs:* owasp_top10: A03:2025; cicd_top10: CICD-SEC-8, CICD-SEC-2; cheatsheet: CI_CD_Security_Cheat_Sheet; cwe: CWE-269; attack: T1199; nist_800_53: AC-6

- [ ] **CICD-TPS-003** Check that third-party actions and plugins are approved and pinned  
  *Severity if fail:* High | *Type:* Config Review, Automated  
  *Objective:* Finds build steps that load unreviewed third-party code that can change without notice.  
  *Steps:*
  1. Read the allowed actions policy of the organization.
  2. List each action, plugin or orb in the pipelines.
  3. Make sure each is on an approved list.
  4. Make sure each is pinned to a full commit hash or a fixed version.
  *Example:* `gh api orgs/ORG/actions/permissions --jq .allowed_actions; zizmor --pedantic .github/workflows/; pinact run --check`  
  *Expected:* Only approved third-party steps are allowed. Each one is pinned to a commit hash or a fixed version, and the pin changes only through review.  
  *Refs:* owasp_top10: A03:2025, A08:2025; cicd_top10: CICD-SEC-8, CICD-SEC-3; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-829, CWE-1357; capec: CAPEC-446; attack: T1195.002; nist_800_53: SR-3; other: SSDF PW.4.1

- [ ] **CICD-TPS-004** Check who can install plugins and add integrations  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds users who can extend the CI/CD platform without vetting.  
  *Steps:*
  1. List the roles that can install plugins, apps and integrations.
  2. Make sure the group is small.
  3. Read the vetting steps for a new plugin: vendor history, upkeep and needed settings.
  4. Look at the last three additions and find their approval record.
  *Example:* `curl -s https://JENKINS/role-strategy/strategy/getAllRoles; gh api orgs/ORG --jq .members_can_install_apps`  
  *Expected:* Only a small group can add plugins and integrations. Each addition has a vetting record and enters configuration management.  
  *Refs:* owasp_top10: A03:2025; cicd_top10: CICD-SEC-8; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-284; nist_800_53: CM-5, CM-7; other: SSDF PW.4.1

- [ ] **CICD-TPS-005** Check assessment of third-party suppliers and components  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds suppliers and open-source components that entered the chain without a risk review.  
  *Steps:*
  1. Pick five recent new suppliers or components.
  2. Look for a record of security history, upkeep and vulnerability handling.
  3. Make sure the review matches the criticality of the component.
  4. Make sure the process names who approves.
  *Example:* `scorecard --repo=github.com/OWNER/PROJECT; osv-scanner --lockfile=package-lock.json`  
  *Expected:* Each supplier and component has a review record. High-risk items get a deeper review and a named approver.  
  *Refs:* owasp_top10: A03:2025; cicd_top10: CICD-SEC-8, CICD-SEC-3; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-1357, CWE-1104; other: SSDF PW.4.1, SSDF PW.4.4, SSDF PO.1.3

- [ ] **CICD-TPS-006** Review removal of unused integrations  
  *Severity if fail:* Low | *Type:* Manual, Config Review  
  *Objective:* Finds integrations, apps and webhooks that stay active after the need ended.  
  *Steps:*
  1. List integrations and their last activity date.
  2. Find integrations with no activity in the policy period.
  3. Make sure there is a periodic review with named owners.
  4. Remove one unused test integration and check the process.
  *Example:* `gh api orgs/ORG/installations --jq '.installations[]|{app_slug,updated_at}'; gh api orgs/ORG/audit-log?phrase=action:integration_installation`  
  *Expected:* A scheduled review removes unused integrations. No integration is idle longer than the policy period.  
  *Refs:* owasp_top10: A03:2025; cicd_top10: CICD-SEC-8; cheatsheet: CI_CD_Security_Cheat_Sheet; cwe: CWE-284; nist_800_53: CM-8


## VULN

- [ ] **CICD-VULN-001** Check the dependency vulnerability scan gate in the pipeline  
  *Severity if fail:* High | *Type:* Config Review, Automated  
  *Objective:* Finds pipelines that build and ship components with known vulnerabilities without a gate.  
  *Steps:*
  1. Find the SCA or vulnerability scan step in the pipeline.
  2. Make sure it scans direct and transitive dependencies.
  3. Make sure the step fails the build above the defined severity.
  4. Add a known vulnerable test dependency on a test branch and run the pipeline.
  *Example:* `trivy fs --scanners vuln --severity HIGH,CRITICAL --exit-code 1 .; grype dir:. --fail-on high; osv-scanner -r .`  
  *Expected:* The pipeline scans all dependencies on every build. The build fails when a finding exceeds the allowed severity.  
  *Refs:* owasp_top10: A03:2025; cheatsheet: Vulnerable_Dependency_Management_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet, NPM_Security_Cheat_Sheet, CI_CD_Security_Cheat_Sheet; cwe: CWE-1395; nist_800_53: RA-5; other: SSDF PW.4.4, SSDF RV.1.1  
  *See:* WEB-DEP-001, WEB-DEP-003

- [ ] **CICD-VULN-002** Check scanning of the final build output and container images  
  *Severity if fail:* High | *Type:* Config Review, Automated  
  *Objective:* Finds images and binaries that contain vulnerable or unauthorized components after the build.  
  *Steps:*
  1. Find the image or binary that the pipeline publishes.
  2. Scan the final output, not only the source.
  3. Make sure the scan covers OS packages and bundled libraries.
  4. Lint the Dockerfile for a USER directive and pinned base images.
  *Example:* `trivy image --severity HIGH,CRITICAL IMAGE@sha256:DIGEST; grype IMAGE@sha256:DIGEST; hadolint Dockerfile`  
  *Expected:* The pipeline scans the final image or binary before release. Findings above the limit block the release.  
  *Refs:* owasp_top10: A03:2025; cheatsheet: Docker_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet, CI_CD_Security_Cheat_Sheet; cwe: CWE-1395; nist_800_53: RA-5; other: SSDF PW.4.4

- [ ] **CICD-VULN-003** Check ongoing monitoring of deployed releases for new advisories  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds released software that nobody re-checks when a new advisory appears.  
  *Steps:*
  1. Find where the release SBOMs are stored and how they map to deployed systems.
  2. Make sure a job scans these SBOMs again on a schedule.
  3. Look for alert subscriptions to advisory sources for the components in use.
  4. Check that a new finding creates a ticket with an owner.
  *Example:* `grype sbom:sbom.cdx.json --fail-on high; osv-scanner --sbom=sbom.cdx.json; dependency-track API: GET /api/v1/finding/project/UUID`  
  *Expected:* Deployed releases are re-checked against advisories on a schedule. New findings create a ticket with an owner and a due date.  
  *Refs:* owasp_top10: A03:2025; cheatsheet: Dependency_Graph_SBOM_Cheat_Sheet, Vulnerable_Dependency_Management_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-1395, CWE-1104; nist_800_53: RA-5; other: SSDF RV.1.1

- [ ] **CICD-VULN-004** Review temporary mitigations and virtual patches for vulnerable components  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds vulnerabilities that stay open behind a mitigation that nobody tests or removes.  
  *Steps:*
  1. List the vulnerable components that have a temporary mitigation, wrapper or virtual patch.
  2. Make sure each one links to a CVE, an owner and an end date.
  3. Test the mitigation with alternate inputs on a test system.
  4. Make sure the scanner suppression covers only that CVE.
  *Example:* `grep -rn 'ignore\|suppress' .trivyignore .grype.yaml dependency-check-suppressions.xml; git log --since=180.days -- .trivyignore`  
  *Expected:* Each mitigation has a CVE, an owner and an end date. Tests show it blocks alternate inputs. A suppression covers only its CVE.  
  *Refs:* owasp_top10: A03:2025; cheatsheet: Virtual_Patching_Cheat_Sheet, Vulnerable_Dependency_Management_Cheat_Sheet; cwe: CWE-1395, CWE-1329; other: SSDF RV.2.2

- [ ] **CICD-VULN-005** Check that the pipeline scans infrastructure as code  
  *Severity if fail:* Medium | *Type:* Config Review, Automated  
  *Objective:* Finds infrastructure code that reaches production without a misconfiguration scan.  
  *Steps:*
  1. Find the IaC repositories and the pipeline steps that apply them.
  2. Make sure a static IaC scan runs on each pull request.
  3. Make sure the scan fails the change above the defined severity.
  4. Make sure IaC changes follow the same review rules as application code.
  *Example:* `trivy config --severity HIGH,CRITICAL --exit-code 1 .; checkov -d . --quiet; tflint`  
  *Expected:* A static IaC scan runs on every change and blocks serious findings. IaC changes need pull request review.  
  *Refs:* owasp_top10: A03:2025; cheatsheet: Infrastructure_as_Code_Security_Cheat_Sheet, CI_CD_Security_Cheat_Sheet; cwe: CWE-1188; nist_800_53: CM-6, SA-15; other: SSDF PW.7.1

- [ ] **CICD-VULN-006** Check static code analysis and secret scan steps in the pipeline  
  *Severity if fail:* Medium | *Type:* Config Review, Automated  
  *Objective:* Finds pipelines that build custom code without any automated code analysis.  
  *Steps:*
  1. Find the SAST and secret scan steps in the pipeline.
  2. Make sure they run on every pull request and on the default branch.
  3. Make sure the findings block the merge above the defined severity.
  4. Make sure the rules and tools are updated on a schedule.
  *Example:* `semgrep scan --config auto --error --severity ERROR .; gitleaks detect --redact`  
  *Expected:* Static analysis and secret scan run on each pull request. Serious findings block the merge. Rules are kept current.  
  *Refs:* owasp_top10: A03:2025; cheatsheet: CI_CD_Security_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-693; nist_800_53: SA-15; other: SSDF PW.7.1
