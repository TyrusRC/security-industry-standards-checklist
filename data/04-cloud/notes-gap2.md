# CLD gap2 notes

Method: all 996 Prowler aws/azure/gcp checks in catalog/checks.json were grouped into control themes with a regex assigner (first match wins). One provider-neutral test per theme; all covered ids are in refs.tool_check. MCSB v1 control ids (from Microsoft_cloud_security_benchmark_v1.xlsx) are in refs.other. Prowler metadata files (Risk, Remediation) of two checks per theme are in sources_read. Commands in `example` are hints; check flags against the CLI version in use.

## New tests (67)

| ID | Theme (title) | Prowler checks | MCSB |
|---|---|---|---|
| CLD-CFG-007 | Check organization guardrails: SCPs, policy enforcement, tags and delegated admins | 8 | GS-2, PV-2, AM-2 |
| CLD-CFG-008 | Check that posture services run in every region | 6 | PV-2, GS-5 |
| CLD-CFG-009 | Check storage ACLs, uniform access, access points and bucket names | 6 | DP-8, IM-1 |
| CLD-CFG-010 | Check that managed data and AI services use private endpoints | 19 | NS-2, NS-1 |
| CLD-CFG-011 | Check network isolation of AI, notebook and virtual desktop workloads | 11 | NS-2, NS-1 |
| CLD-CFG-012 | Check that managed Kubernetes API endpoints and nodes are private | 7 | NS-2, PV-3 |
| CLD-CFG-013 | Check customer-managed keys for sensitive data stores | 13 | DP-5, DP-4 |
| CLD-CFG-014 | Check encryption settings of analytics, workflow, AI and backup services | 25 | DP-5, DP-4 |
| CLD-CFG-015 | Check TLS on database, cache, search, stream and replication connections | 18 | DP-3, NS-8 |
| CLD-CFG-016 | Check secure transfer, TLS version and SMB settings of storage | 6 | DP-3, NS-8 |
| CLD-CFG-017 | Check TLS listeners, ciphers and origin traffic on load balancers and CDNs | 18 | DP-3, NS-8 |
| CLD-CFG-018 | Check TLS, HTTPS redirect, client certificates and FTP on app services | 8 | DP-3, NS-8 |
| CLD-CFG-019 | Check certificate expiry, key algorithms and removal of expired certificates | 7 | DP-7 |
| CLD-CFG-020 | Check post-quantum and FIPS TLS policies on long-lived data paths | 5 | DP-3 |
| CLD-CFG-021 | Find snapshots, images and backups shared publicly or cross-account | 7 | DP-8, BR-2 |
| CLD-CFG-022 | Check that backup plans cover all data stores and VMs | 14 | BR-1, BR-3 |
| CLD-CFG-023 | Check automated backups and point-in-time recovery of databases | 18 | BR-1, BR-4 |
| CLD-CFG-024 | Check deletion protection on databases, clusters and load balancers | 10 | BR-2 |
| CLD-CFG-025 | Check versioning, soft delete, object lock and retention of stored data | 14 | BR-2, BR-1 |
| CLD-CFG-026 | Check multi-zone and failover setup of managed data services | 20 | BR-1 |
| CLD-CFG-027 | Check zone spread, health checks and autoscaling of compute and network paths | 27 | BR-1 |
| CLD-CFG-028 | Check database engine settings: ports, minor upgrades and event alerts | 17 | PV-1, PV-2 |
| CLD-CFG-029 | Check risky database flags on managed MySQL and SQL Server instances | 9 | PV-1, PV-2 |
| CLD-CFG-030 | Check session time limits of managed virtual desktops | 3 | PV-3 |
| CLD-IAC-005 | Check stack termination protection and toolkit bootstrap version | 2 | DS-6, PV-1 |
| CLD-IAM-007 | Check that the root account has no keys and a hardware MFA | 5 | PA-1, IM-6, PA-5 |
| CLD-IAM-008 | Check MFA enforcement for console users, admins and management APIs | 11 | IM-6, IM-1 |
| CLD-IAM-009 | Check password policy and temporary credential lifetime | 13 | IM-6 |
| CLD-IAM-010 | Find old, unused and duplicate access keys and credentials | 15 | IM-3, PA-3, IM-8 |
| CLD-IAM-011 | Check API keys for restrictions, age and a better method | 9 | IM-3, IM-8 |
| CLD-IAM-012 | Find administrator rights on users, groups, roles and service accounts | 14 | PA-7, PA-1, PA-2 |
| CLD-IAM-013 | Find policies that allow privilege escalation | 14 | PA-7 |
| CLD-IAM-014 | Check separation of duties for key, service account and role admins | 6 | PA-1, PA-7 |
| CLD-IAM-015 | Check role trust, confused deputy protection and external access findings | 10 | IM-3, PA-4 |
| CLD-IAM-016 | Check resource policies of queues, topics, buses and shared resources | 11 | NS-2, DP-8 |
| CLD-IAM-017 | Check security contacts, support roles and incident setup for each account | 16 | IR-2, PA-8, IR-3 |
| CLD-IAM-018 | Check tenant settings for guests, app consent and user creation rights | 9 | IM-1, PA-3 |
| CLD-IAM-019 | Check customer identity pools and directory sign-in settings | 12 | IM-6, IM-9 |
| CLD-IAM-020 | Check that workloads use their own attached identity and not default accounts | 11 | IM-3 |
| CLD-IAM-021 | Check database and data service authentication and default admin names | 14 | IM-1, IM-3 |
| CLD-IAM-022 | Check that shared keys and local accounts are off | 8 | IM-1, IM-3 |
| CLD-LOG-006 | Check that threat detection runs in all regions under a central admin | 4 | LT-1, LT-5 |
| CLD-LOG-007 | Check threat detection protection plans for storage, containers, functions and databases | 8 | LT-1 |
| CLD-LOG-008 | Check that cloud workload protection plans are on for each resource type | 16 | LT-1, LT-2 |
| CLD-LOG-009 | Check agents, endpoint protection and alert routing of the workload protection service | 5 | ES-1, PV-5 |
| CLD-LOG-010 | Check sensitive data discovery on object storage | 2 | DP-1, DP-2 |
| CLD-LOG-011 | Check audit log detection for enumeration, privilege escalation and LLM abuse | 5 | LT-2, LT-3 |
| CLD-LOG-012 | Check access and execution logs of APIs, functions, workflows and build jobs | 14 | LT-3 |
| CLD-LOG-013 | Check audit and query logs of databases, search domains and brokers | 25 | LT-3 |
| CLD-LOG-014 | Check control plane, container and cluster logs | 8 | LT-3, LT-1 |
| CLD-LOG-015 | Check storage access logs and object change notifications | 3 | LT-3 |
| CLD-LOG-016 | Check detailed monitoring metrics for hosts and brokers | 2 | LT-3 |
| CLD-LOG-017 | Check invocation logs and diagnostic logs of AI services | 6 | LT-3 |
| CLD-NET-007 | Check CDN origin access, dangling origins and edge settings | 5 | NS-2, NS-6 |
| CLD-NET-008 | Check security group hygiene, peering, transit and VPC routing paths | 10 | NS-7, NS-1 |
| CLD-NET-009 | Check network firewall coverage and flow visibility for each VPC | 6 | NS-3, NS-4 |
| CLD-NET-010 | Check DNSSEC, domain transfer lock and mail domain signing | 6 | NS-10 |
| CLD-NET-011 | Find dangling DNS records that allow subdomain takeover | 1 | NS-10, AM-3 |
| CLD-NET-012 | Check managed admin access to VMs and block serial ports | 7 | PA-2, PA-6, NS-8 |
| CLD-NET-013 | Check VM boot integrity, confidential computing and enclave host exposure | 7 | PV-3, PV-4 |
| CLD-NET-014 | Check root and terminal access on managed notebooks | 5 | PA-7, PV-3 |
| CLD-SEC-006 | Check KMS key use, deletion state, multi-region keys and enclave attestation | 9 | DP-6, DP-8 |
| CLD-SRV-007 | Check function dead letter queues and cross-account layers | 2 | PV-3 |
| CLD-SRV-008 | Check client certificates and cache encryption on API gateways | 2 | NS-2, IM-4 |
| CLD-SRV-009 | Check container task definitions for privilege, host sharing and root file system | 4 | PV-3 |
| CLD-SUP-005 | Check image tag immutability and lifecycle rules in registries | 2 | DS-2, AM-3 |
| CLD-SUP-006 | Check database vulnerability assessment scans and reports | 4 | PV-5, PV-6 |

## Checks mapped to existing tests (data/mappings/tool-cloud.json, 328 checks)

A check is mapped only when the steps of the existing test cover the control.
- CLD-CFG-001: 14 checks (mapping only)
- CLD-CFG-002: 22 checks (mapping only)
- CLD-CFG-003: 46 checks (mapping only)
- CLD-CFG-004: 24 checks (mapping only)
- CLD-LOG-001: 12 checks (mapping only)
- CLD-LOG-002: 12 checks (mapping only)
- CLD-LOG-003: 14 checks (mapping only)
- CLD-LOG-004: 37 checks (mapping only)
- CLD-SEC-001: 7 checks (mapping only)
- CLD-SEC-002: 23 checks (mapping only)
- CLD-SEC-003: 8 checks (mapping only)
- CLD-SEC-004: 5 checks (mapping only)
- CLD-NET-002: 14 checks (mapping only)
- CLD-NET-001: 3 checks (mapping only)
- CLD-NET-004: 5 checks (mapping only)
- CLD-NET-006: 20 checks (mapping only)
- CLD-SUP-001: 3 checks (mapping only)
- CLD-SUP-002: 4 checks (mapping only)
- CLD-SUP-004: 15 checks (mapping only)
- CLD-SUP-003: 19 checks (mapping only)
- CLD-SRV-002: 8 checks (mapping only)
- CLD-SRV-003: 3 checks (mapping only)
- CLD-AST-001: 2 checks (mapping only)
- CLD-AST-003: 8 checks (mapping only)

## Skipped checks (24)

- LLM guardrail, prompt and model-governance checks (bedrock guardrails, prompt management, sagemaker clarify/monitor/registry/SSO/prod variants, azure prompt shield): belong to the LLM sheet.
- Pipeline checks (codebuild, codepipeline, codeartifact): belong to the CICD sheet.
- Others without a clear control: athena workgroup enforce configuration, autoscaling launch template use, eventbridge global endpoint replication.

Ids: aws:athena_workgroup_enforce_configuration, aws:autoscaling_group_using_ec2_launch_template, aws:bedrock_agent_guardrail_enabled, aws:bedrock_guardrail_contextual_grounding_filter_enabled, aws:bedrock_guardrail_prompt_attack_filter_enabled, aws:bedrock_guardrail_sensitive_information_filter_enabled, aws:bedrock_guardrail_sensitive_information_filter_enforced, aws:bedrock_guardrails_configured, aws:bedrock_prompt_management_exists, aws:codeartifact_packages_external_public_publishing_disabled, aws:codebuild_project_not_publicly_accessible, aws:codebuild_project_s3_logs_encrypted, aws:codebuild_project_user_controlled_buildspec, aws:codebuild_project_uses_allowed_github_organizations, aws:codebuild_project_webhook_filters_use_anchored_patterns, aws:codebuild_report_group_export_encrypted, aws:codepipeline_project_repo_private, aws:eventbridge_global_endpoint_event_replication_enabled, aws:sagemaker_clarify_exists, aws:sagemaker_domain_sso_configured, aws:sagemaker_endpoint_config_prod_variant_instances, aws:sagemaker_models_monitor_enabled, aws:sagemaker_models_registry_in_use, azure:aiservices_deployment_content_filter_prompt_shield_enabled

## Open issues

- Some themes group many small checks (HA, database flags, Defender plans). Split them later if testers need one result per setting.
- Prowler titles were not read for every check; grouping used check ids and the metadata of two checks per theme.
