# CLOUD security test cases

121 tests. Tick the box when the test passes.


## AST

- [ ] **CLD-AST-001** Build and check the cloud asset inventory  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds resources that no one owns, tracks or patches.  
  *Steps:*
  1. List all resources in every account, region and project.
  2. Compare the list to the asset register.
  3. Find resources without owner, environment or purpose tags.
  4. Add each missing resource to the register or remove it.
  *Example:* `aws resourcegroupstaggingapi get-resources; aws configservice list-discovered-resources --resource-type AWS::EC2::Instance; az resource list; gcloud asset search-all-resources --scope=projects/<p>`  
  *Expected:* Every resource is in the register with an owner and tags. Untracked resources are removed.  
  *Refs:* cloud_native_top10: CNAS-8; cheatsheet: Infrastructure_as_Code_Security_Cheat_Sheet, Secure_Cloud_Architecture_Cheat_Sheet; attack: T1580, T1526; nist_800_53: CM-8

- [ ] **CLD-AST-002** Find undocumented APIs and microservices  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds services and API routes that run but are not in any design or API definition.  
  *Steps:*
  1. List API gateways, load balancer rules, function URLs and service names.
  2. Compare them to the API definitions and the architecture document.
  3. Find routes with no definition or owner.
  4. Check the old versions of each API.
  *Example:* `aws apigateway get-rest-apis; aws apigatewayv2 get-apis; az apim api list -g <rg> -n <svc>; gcloud api-gateway apis list`  
  *Expected:* Every running API and service is in the documents with an owner. Old API versions are removed or protected.  
  *Refs:* cloud_native_top10: CNAS-8; cheatsheet: Microservices_Security_Cheat_Sheet, Secure_Cloud_Architecture_Cheat_Sheet; attack: T1526; nist_800_53: CM-8, CM-2

- [ ] **CLD-AST-003** Find unused regions, ghost resources and stale environments  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds forgotten resources that run with old software and no monitoring.  
  *Steps:*
  1. List resources in regions that the organization does not use.
  2. Find resources with no traffic or use in the last 90 days.
  3. Find resources from finished projects and test environments.
  4. Check that regions not in use are blocked by policy.
  *Example:* `aws ec2 describe-regions; aws ec2 describe-instances --region <r>; az account list-locations; gcloud compute instances list; policy tools for region deny rules`  
  *Expected:* No resources run in unused regions. Stale resources are removed, and policy blocks new resources in regions that are not approved.  
  *Refs:* cloud_native_top10: CNAS-8; cheatsheet: Infrastructure_as_Code_Security_Cheat_Sheet, Secure_Cloud_Architecture_Cheat_Sheet; cwe: CWE-1104; attack: T1535; nist_800_53: CM-8, CM-7

- [ ] **CLD-AST-004** Check decommissioning of resources, data and access  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds deleted services that leave data, keys, DNS records or access behind.  
  *Steps:*
  1. Pick three resources retired in the last year.
  2. Check for data, snapshots and backups that remain.
  3. Check for dangling DNS records, roles and keys.
  4. Check the decommission checklist.
  *Example:* `aws ec2 describe-snapshots --owner-ids self; aws route53 list-resource-record-sets --hosted-zone-id <z>; aws iam list-roles`  
  *Expected:* Retired resources leave no data, snapshots, DNS records, roles or keys. A decommission checklist exists and was followed.  
  *Refs:* cloud_native_top10: CNAS-8; cheatsheet: Infrastructure_as_Code_Security_Cheat_Sheet; attack: T1580; nist_800_53: CM-8  
  *See:* WEB-CONF-011


## CFG

- [ ] **CLD-CFG-001** Check object storage for public access at account level  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds buckets and containers that anyone on the Internet can list or read.  
  *Steps:*
  1. List all storage buckets and containers in each account and region.
  2. Check public access blocks and policies at account and bucket level.
  3. Try an anonymous list and read request on each bucket.
  4. Check that signed URLs have short lifetimes and narrow scope.
  *Example:* `aws s3api get-public-access-block --bucket <b>; aws s3api get-bucket-policy-status --bucket <b>; az storage account show -n <a> --query allowBlobPublicAccess; gsutil iam get gs://<b>; prowler aws --services s3`  
  *Expected:* No bucket is public unless it holds only public, non-sensitive files by design. An anonymous request returns an access denied error.  
  *Refs:* cloud_native_top10: CNAS-1; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet; cwe: CWE-732, CWE-668; attack: T1530, T1619; nist_800_53: AC-3, AC-6  
  *See:* WEB-CONF-012

- [ ] **CLD-CFG-002** Check that data stores sit in private subnets with no public address  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds databases, file systems and backend servers that have a public IP or a route from the Internet.  
  *Steps:*
  1. List databases, caches, queues and backend instances.
  2. Check each one for a public IP address or endpoint.
  3. Check the subnet route tables for a route to an internet gateway.
  4. Try a connection from an outside host.
  *Example:* `aws rds describe-db-instances --query "DBInstances[].[DBInstanceIdentifier,PubliclyAccessible]"; az sql server show -n <s> -g <rg> --query publicNetworkAccess; gcloud sql instances list --format="value(name,ipAddresses)"; scout aws`  
  *Expected:* Data stores have no public address and sit in private subnets. They accept connections only from approved application tiers.  
  *Refs:* cloud_native_top10: CNAS-1, CNAS-6; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet, Network_Segmentation_Cheat_Sheet; cwe: CWE-668; attack: T1190, T1133; nist_800_53: SC-7, AC-4

- [ ] **CLD-CFG-003** Check firewall and security group rules for open admin and database ports  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds rules that allow any source to reach SSH, RDP, database or admin ports.  
  *Steps:*
  1. Export all security groups, firewall rules and network ACLs.
  2. Find rules with source 0.0.0.0/0 or ::/0.
  3. List the ports and the attached resources for each rule.
  4. Ask the owner to justify each open rule.
  *Example:* `aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0; az network nsg rule list --nsg-name <n> -g <rg>; gcloud compute firewall-rules list --filter="sourceRanges:0.0.0.0/0"`  
  *Expected:* Only reviewed public ports for load balancers or gateways are open to all sources. Admin and data ports accept only named networks.  
  *Refs:* cloud_native_top10: CNAS-1, CNAS-6; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet; cwe: CWE-668, CWE-1327; attack: T1190, T1133; nist_800_53: SC-7, CM-7

- [ ] **CLD-CFG-004** Check encryption at rest for storage, databases and volumes  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds data stores that hold data in plaintext or use keys that the account owner cannot control.  
  *Steps:*
  1. List storage buckets, volumes, snapshots and databases.
  2. Check the encryption setting of each one.
  3. Check which key protects each data store and who can use it.
  4. Check that backups and snapshots use encryption.
  *Example:* `aws ec2 describe-volumes --query "Volumes[?Encrypted==\`false\`]"; aws s3api get-bucket-encryption --bucket <b>; az storage account show -n <a> --query encryption; gcloud kms keys list --location <l> --keyring <k>`  
  *Expected:* All data stores, volumes, snapshots and backups use encryption at rest. Key use is limited to named roles and services.  
  *Refs:* cloud_native_top10: CNAS-1, CNAS-5; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet, Secrets_Management_Cheat_Sheet; cwe: CWE-311, CWE-312; attack: T1530; nist_800_53: SC-28, SC-12

- [ ] **CLD-CFG-005** Run a cloud posture scan and review failed checks  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds insecure defaults and drift across accounts, subscriptions and projects.  
  *Steps:*
  1. Give a read-only audit role to the scan tool in each account.
  2. Run the scan for all regions and services in scope.
  3. Rank the failed checks by risk and exposure.
  4. Fix each finding or record an accepted risk with an owner.
  *Example:* `prowler aws; prowler azure --az-cli-auth; prowler gcp; scout aws; scout azure --cli; scout gcp --user-account`  
  *Expected:* The scan runs on a set schedule. High findings are fixed or accepted by the owner in writing.  
  *Refs:* cloud_native_top10: CNAS-1; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet, Infrastructure_as_Code_Security_Cheat_Sheet; cwe: CWE-1188; attack: T1580, T1526; nist_800_53: CM-6, CA-7

- [ ] **CLD-CFG-006** Check that each managed service is configured within the shared responsibility model  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds services where the team assumed that the provider handles authentication, logging or patching.  
  *Steps:*
  1. List the cloud services in use and their type: IaaS, PaaS, SaaS or serverless.
  2. For each type, list the duties that the customer holds.
  3. Check that authentication, logging, patching and code security have an owner.
  4. Record gaps with an owner and a date.
  *Example:* `Review provider documentation: AWS Lambda security, GCP Cloud Functions securing, Azure Functions app security`  
  *Expected:* Each service has a written list of provider and customer duties. Every customer duty has an owner and a control.  
  *Refs:* cloud_native_top10: CNAS-1, CNAS-7; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet; cwe: CWE-693; nist_800_53: CM-2, CA-7

- [ ] **CLD-CFG-007** Check organization guardrails: SCPs, policy enforcement, tags and delegated admins  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds tenants where preventive guardrails are missing or in audit-only mode.  
  *Steps:*
  1. List the organization policies, service control policies and policy assignments.
  2. Check that deny rules block unused regions and risky actions.
  3. Check that policy effects are enforced and not audit-only.
  4. Check that security services use a delegated admin account.
  5. Create a test resource that breaks a rule.
  *Example:* `aws organizations list-policies --filter SERVICE_CONTROL_POLICY; aws organizations list-delegated-administrators; aws fms list-policies; az policy assignment list --query "[].[name,enforcementMode]"; gcloud resource-manager org-policies list --organization=<org>; prowler aws --services organizations fms`  
  *Expected:* Guardrails deny unused regions and risky actions at the root. Policies are enforced. Security services run from a delegated admin account, not the management account. The test resource is blocked.  
  *Refs:* cloud_native_top10: CNAS-1, CNAS-8; tool_check: prowler:aws:fms_policy_compliant, prowler:aws:organizations_account_part_of_organizations, prowler:aws:organizations_delegated_administrators, prowler:aws:organizations_opt_out_ai_services_policy, prowler:aws:organizations_scp_check_deny_regions, prowler:aws:organizations_security_services_delegated_admin_not_management_account, prowler:aws:organizations_tags_policies_enabled_and_attached, prowler:azure:policy_ensure_asc_enforcement_enabled; cwe: CWE-693; attack: T1535, T1578; nist_800_53: CM-6, AC-3; other: Microsoft cloud security benchmark v1 GS-2, Microsoft cloud security benchmark v1 PV-2, Microsoft cloud security benchmark v1 AM-2

- [ ] **CLD-CFG-008** Check that posture services run in every region  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds regions and accounts with no configuration recorder or security hub.  
  *Steps:*
  1. List the regions and accounts in use.
  2. Check that the configuration recorder is on in each region.
  3. Check that findings aggregate to a central admin account.
  4. Open the open high findings and their age.
  5. Turn off the recorder in a test account and look for an alert.
  *Example:* `aws configservice describe-configuration-recorders; aws configservice describe-configuration-aggregators; aws securityhub describe-hub; aws securityhub get-findings --filters '{"SeverityLabel":[{"Value":"HIGH","Comparison":"EQUALS"}]}'; az security assessment list; prowler aws --services config securityhub`  
  *Expected:* The recorder and the security hub run in all regions. Findings reach one central account. High findings have an owner and a due date.  
  *Refs:* cloud_native_top10: CNAS-1, CNAS-10; tool_check: prowler:aws:config_delegated_admin_and_org_aggregator_all_regions, prowler:aws:config_recorder_all_regions_enabled, prowler:aws:config_recorder_using_aws_service_role, prowler:aws:securityhub_delegated_admin_enabled_all_regions, prowler:aws:securityhub_enabled, prowler:aws:wellarchitected_workload_no_high_or_medium_risks; cwe: CWE-778; attack: T1685.002; nist_800_53: CM-6, CA-7; other: Microsoft cloud security benchmark v1 PV-2, Microsoft cloud security benchmark v1 GS-5

- [ ] **CLD-CFG-009** Check storage ACLs, uniform access, access points and bucket names  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds object stores that mix ACLs with policies or use names another party can claim.  
  *Steps:*
  1. List buckets, containers and file system access points.
  2. Check that ACLs are off and uniform access is on.
  3. Check that access points set a fixed root path and user identity.
  4. Search code and templates for bucket names that do not exist.
  5. Try to create a bucket with a name from a template.
  *Example:* `aws s3api get-bucket-ownership-controls --bucket <b>; gcloud storage buckets describe gs://<b> --format="value(uniform_bucket_level_access)"; aws efs describe-access-points; aws s3api head-bucket --bucket <name-in-template>; prowler aws --services s3 efs`  
  *Expected:* ACLs are off and one policy model controls access. Access points set a root path and user identity. No code uses a bucket name that is free to claim.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:efs_access_point_enforce_root_directory, prowler:aws:efs_access_point_enforce_user_identity, prowler:aws:s3_bucket_acl_prohibited, prowler:aws:s3_bucket_cross_region_replication, prowler:aws:s3_bucket_shadow_resource_vulnerability, prowler:gcp:cloudstorage_bucket_uniform_bucket_level_access; cwe: CWE-732; attack: T1530, T1584; nist_800_53: AC-3, AC-6; other: Microsoft cloud security benchmark v1 DP-8, Microsoft cloud security benchmark v1 IM-1

- [ ] **CLD-CFG-010** Check that managed data and AI services use private endpoints  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds managed services that accept traffic from the public Internet or from all trusted services.  
  *Steps:*
  1. List storage, key vault, search, database, AI and registry services.
  2. Check the public network access setting of each service.
  3. Check that private endpoints or service perimeters exist.
  4. Check that the default network rule is deny.
  5. Try to reach each service from a public network.
  *Example:* `az storage account show -n <a> --query "[publicNetworkAccess,networkRuleSet.defaultAction]"; az keyvault show -n <v> --query properties.publicNetworkAccess; az cognitiveservices account show -n <a> -g <rg> --query properties.publicNetworkAccess; az search service show -n <s> -g <rg>; gcloud access-context-manager perimeters list; prowler azure --services storage keyvault aiservices aisearch`  
  *Expected:* Public network access is off or the default rule is deny. Services use private endpoints or a service perimeter. The public test connection fails.  
  *Refs:* cloud_native_top10: CNAS-1, CNAS-6; tool_check: prowler:azure:aisearch_service_not_publicly_accessible, prowler:azure:aiservices_account_network_acls_default_action_deny, prowler:azure:aiservices_account_outbound_network_restricted, prowler:azure:aiservices_account_public_network_access_disabled, prowler:azure:aiservices_account_uses_private_endpoint, prowler:azure:containerregistry_uses_private_link, prowler:azure:cosmosdb_account_use_private_endpoints, prowler:azure:databricks_workspace_cmk_encryption_enabled, prowler:azure:databricks_workspace_no_public_ip_enabled, prowler:azure:databricks_workspace_public_network_access_disabled, prowler:azure:databricks_workspace_vnet_injection_enabled, prowler:azure:keyvault_access_only_through_private_endpoints, prowler:azure:keyvault_private_endpoints, prowler:azure:postgresql_flexible_server_allow_access_services_disabled, prowler:azure:storage_cross_tenant_replication_disabled, prowler:azure:storage_default_network_access_rule_is_denied, prowler:azure:storage_ensure_azure_services_are_trusted_to_access_is_enabled, prowler:azure:storage_ensure_private_endpoints_in_storage_accounts, prowler:gcp:cloudstorage_uses_vpc_service_controls; cwe: CWE-284; attack: T1530, T1190; nist_800_53: SC-7, AC-4; other: Microsoft cloud security benchmark v1 NS-2, Microsoft cloud security benchmark v1 NS-1

- [ ] **CLD-CFG-011** Check network isolation of AI, notebook and virtual desktop workloads  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds ML jobs, notebooks and desktops that have direct Internet access or no VPC.  
  *Steps:*
  1. List notebooks, training jobs, models, AI runtimes and desktop fleets.
  2. Check that each runs inside a private network.
  3. Check that direct Internet access is off.
  4. Check that model and job network isolation is on.
  5. Try an outbound connection from a test notebook.
  *Example:* `aws sagemaker describe-notebook-instance --notebook-instance-name <n> --query "[DirectInternetAccess,SubnetId]"; aws sagemaker describe-training-job --training-job-name <t> --query "[EnableNetworkIsolation,VpcConfig]"; aws appstream describe-fleets; gcloud notebooks instances list; prowler aws --services sagemaker bedrock appstream`  
  *Expected:* All AI and notebook workloads run in a private network with no direct Internet access. Network isolation is on. The outbound test connection fails.  
  *Refs:* cloud_native_top10: CNAS-1, CNAS-6; tool_check: prowler:aws:appstream_fleet_default_internet_access_disabled, prowler:aws:bedrock_vpc_endpoints_configured, prowler:aws:bedrockagentcore_runtime_vpc_configured, prowler:aws:sagemaker_models_network_isolation_enabled, prowler:aws:sagemaker_models_vpc_settings_configured, prowler:aws:sagemaker_notebook_instance_vpc_settings_configured, prowler:aws:sagemaker_notebook_instance_without_direct_internet_access_configured, prowler:aws:sagemaker_training_jobs_intercontainer_encryption_enabled, prowler:aws:sagemaker_training_jobs_network_isolation_enabled, prowler:aws:sagemaker_training_jobs_vpc_settings_configured, prowler:gcp:vertexai_workbench_instance_public_ip_disabled; cwe: CWE-668; attack: T1048, T1567; nist_800_53: SC-7, AC-4; other: Microsoft cloud security benchmark v1 NS-2, Microsoft cloud security benchmark v1 NS-1

- [ ] **CLD-CFG-012** Check that managed Kubernetes API endpoints and nodes are private  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds managed clusters whose control plane or nodes are open to the Internet.  
  *Steps:*
  1. List the managed clusters in each account.
  2. Check if the API endpoint is public and which source ranges can reach it.
  3. Check that nodes have private addresses only.
  4. Check that a network policy engine is on.
  5. Try to reach the API endpoint from a public network.
  *Example:* `aws eks describe-cluster --name <c> --query "cluster.resourcesVpcConfig.[endpointPublicAccess,endpointPrivateAccess,publicAccessCidrs]"; az aks show -n <c> -g <rg> --query "[apiServerAccessProfile,networkProfile.networkPolicy]"; prowler aws --services eks; prowler azure --services aks`  
  *Expected:* The API endpoint is private or limited to listed ranges. Nodes have no public address. A network policy engine is on. The public test connection fails.  
  *Refs:* cloud_native_top10: CNAS-1, CNAS-6; tool_check: prowler:aws:eks_cluster_network_policy_enabled, prowler:aws:eks_cluster_not_publicly_accessible, prowler:aws:eks_cluster_private_nodes_enabled, prowler:aws:eks_cluster_vpc_cni_network_policy_enforced, prowler:azure:aks_clusters_created_with_private_nodes, prowler:azure:aks_clusters_public_access_disabled, prowler:azure:aks_network_policy_enabled; cwe: CWE-284; attack: T1190, T1613; nist_800_53: SC-7, AC-3; other: Microsoft cloud security benchmark v1 NS-2, Microsoft cloud security benchmark v1 PV-3

- [ ] **CLD-CFG-013** Check customer-managed keys for sensitive data stores  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds sensitive data stores that use only provider-owned keys with no own control.  
  *Steps:*
  1. List the data stores with sensitive data.
  2. Find the key type of each: provider-owned or customer-managed.
  3. Check that sensitive stores use customer-managed keys.
  4. Check who can use and disable each key.
  5. Disable a test key and check that the store denies access.
  *Example:* `aws dynamodb describe-table --table-name <t> --query Table.SSEDescription; gcloud sql instances describe <i> --format="value(diskEncryptionConfiguration)"; bq show --format=prettyjson <ds>; az storage account show -n <a> --query encryption.keySource; az disk show -n <d> -g <rg> --query encryption; prowler gcp --services cloudsql bigquery`  
  *Expected:* Sensitive stores use customer-managed keys with a named owner. Key use is limited to the store service. Disabling the test key blocks access to the data.  
  *Refs:* cloud_native_top10: CNAS-1, CNAS-5; tool_check: prowler:aws:dynamodb_tables_kms_cmk_encryption_enabled, prowler:aws:kafka_cluster_encryption_at_rest_uses_cmk, prowler:aws:s3_bucket_kms_encryption, prowler:azure:aiservices_account_encrypted_with_cmk, prowler:azure:sqlserver_tde_encrypted_with_cmk, prowler:azure:storage_ensure_encryption_with_customer_managed_keys, prowler:azure:vm_ensure_attached_disks_encrypted_with_cmk, prowler:azure:vm_ensure_unattached_disks_encrypted_with_cmk, prowler:azure:vm_ensure_using_managed_disks, prowler:gcp:bigquery_dataset_cmk_encryption, prowler:gcp:bigquery_table_cmk_encryption, prowler:gcp:cloudsql_instance_cmek_encryption_enabled, prowler:gcp:dataproc_encrypted_with_cmks_disabled; cwe: CWE-311; attack: T1530, T1486; nist_800_53: SC-28, SC-12; other: Microsoft cloud security benchmark v1 DP-5, Microsoft cloud security benchmark v1 DP-4

- [ ] **CLD-CFG-014** Check encryption settings of analytics, workflow, AI and backup services  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds query results, job state, models and backups stored with default or no encryption.  
  *Steps:*
  1. List analytics workgroups, ETL jobs, workflows, ML endpoints and backup vaults.
  2. Check the encryption setting for data, logs and job state in each.
  3. Check that function variables and cluster secrets use a managed key.
  4. Find outputs written to storage with no encryption.
  5. Run a test job and look at its output setting.
  *Example:* `aws athena get-work-group --work-group <w>; aws glue get-security-configuration --name <n>; aws stepfunctions describe-state-machine --state-machine-arn <a>; aws backup describe-backup-vault --backup-vault-name <v>; aws eks describe-cluster --name <c> --query cluster.encryptionConfig; prowler aws --services glue athena backup`  
  *Expected:* Job output, logs, job state, backups and cluster secrets use encryption with a managed key. Settings are enforced by workgroup or security configuration.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:athena_workgroup_encryption, prowler:aws:awslambda_function_env_vars_not_encrypted_with_cmk, prowler:aws:backup_recovery_point_encrypted, prowler:aws:backup_vaults_encrypted, prowler:aws:backup_vaults_exist, prowler:aws:bedrock_custom_model_encrypted_with_cmk, prowler:aws:bedrock_knowledge_base_encrypted_with_cmk, prowler:aws:bedrock_prompt_encrypted_with_cmk, prowler:aws:ec2_ebs_snapshot_account_block_public_access, prowler:aws:eks_cluster_kms_cmk_encryption_in_secrets_enabled, prowler:aws:glue_data_catalogs_connection_passwords_encryption_enabled, prowler:aws:glue_data_catalogs_metadata_encryption_enabled, prowler:aws:glue_database_connections_ssl_enabled, prowler:aws:glue_development_endpoints_cloudwatch_logs_encryption_enabled, prowler:aws:glue_development_endpoints_job_bookmark_encryption_enabled, prowler:aws:glue_development_endpoints_s3_encryption_enabled, prowler:aws:glue_etl_jobs_amazon_s3_encryption_enabled, prowler:aws:glue_etl_jobs_cloudwatch_logs_encryption_enabled, prowler:aws:glue_etl_jobs_job_bookmark_encryption_enabled, prowler:aws:glue_etl_jobs_logging_enabled, prowler:aws:glue_ml_transform_encrypted_at_rest, prowler:aws:sagemaker_endpoint_config_kms_encryption_enabled, prowler:aws:sagemaker_notebook_instance_encryption_enabled, prowler:aws:sagemaker_training_jobs_volume_and_output_encryption_enabled, prowler:aws:stepfunctions_statemachine_encrypted_with_cmk; cwe: CWE-311; attack: T1530; nist_800_53: SC-28, SC-12; other: Microsoft cloud security benchmark v1 DP-5, Microsoft cloud security benchmark v1 DP-4

- [ ] **CLD-CFG-015** Check TLS on database, cache, search, stream and replication connections  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds data service connections that allow plain text or old TLS versions.  
  *Steps:*
  1. List databases, caches, search domains, brokers and replication endpoints.
  2. Check that TLS is required on each one.
  3. Check the minimum TLS version.
  4. Try a plain text connection to each service.
  5. Try a connection with TLS 1.0.
  *Example:* `aws rds describe-db-parameters --db-parameter-group-name <g> --query "Parameters[?ParameterName=='rds.force_ssl']"; aws elasticache describe-replication-groups --query "ReplicationGroups[].TransitEncryptionEnabled"; gcloud sql instances describe <i> --format="value(settings.ipConfiguration.requireSsl)"; az postgres flexible-server parameter show -g <rg> -s <s> --name require_secure_transport; openssl s_client -tls1 -connect <h>:<p>; prowler aws --services rds elasticache opensearch`  
  *Expected:* Every data connection needs TLS 1.2 or higher. The plain text test and the TLS 1.0 test both fail.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:dms_endpoint_redis_in_transit_encryption_enabled, prowler:aws:dms_endpoint_ssl_enabled, prowler:aws:dynamodb_accelerator_cluster_in_transit_encryption_enabled, prowler:aws:elasticache_redis_cluster_in_transit_encryption_enabled, prowler:aws:kafka_cluster_in_transit_encryption_enabled, prowler:aws:kafka_connector_in_transit_encryption_enabled, prowler:aws:memorydb_cluster_in_transit_encryption_enabled, prowler:aws:opensearch_service_domains_https_communications_enforced, prowler:aws:opensearch_service_domains_node_to_node_encryption_enabled, prowler:aws:rds_instance_transport_encrypted, prowler:aws:redshift_cluster_in_transit_encryption_enabled, prowler:aws:sns_subscription_not_using_http_endpoints, prowler:azure:cosmosdb_account_minimum_tls_version, prowler:azure:mysql_flexible_server_minimum_tls_version_12, prowler:azure:mysql_flexible_server_ssl_connection_enabled, prowler:azure:postgresql_flexible_server_enforce_ssl_enabled, prowler:azure:sqlserver_recommended_minimal_tls_version, prowler:gcp:cloudsql_instance_ssl_connections; cwe: CWE-319; attack: T1040, T1557; nist_800_53: SC-8, SC-13; other: Microsoft cloud security benchmark v1 DP-3, Microsoft cloud security benchmark v1 NS-8

- [ ] **CLD-CFG-016** Check secure transfer, TLS version and SMB settings of storage  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds storage endpoints that accept HTTP, old TLS or old SMB versions.  
  *Steps:*
  1. List buckets, storage accounts, file shares and file transfer servers.
  2. Check that a policy denies requests without TLS.
  3. Check the minimum TLS version of each storage account.
  4. Check the SMB version and channel encryption.
  5. Send a plain HTTP request to a test object.
  *Example:* `aws s3api get-bucket-policy --bucket <b>; az storage account show -n <a> --query "[enableHttpsTrafficOnly,minimumTlsVersion]"; az storage account file-service-properties show --account-name <a> --query protocolSettings; aws transfer describe-server --server-id <s>; curl -i http://<b>.s3.amazonaws.com/<o>; prowler azure --services storage`  
  *Expected:* Storage denies requests without TLS and requires TLS 1.2 or higher. File shares use the latest SMB with channel encryption. The HTTP test request is denied.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:s3_bucket_secure_transport_policy, prowler:aws:transfer_server_in_transit_encryption_enabled, prowler:azure:storage_ensure_minimum_tls_version_12, prowler:azure:storage_secure_transfer_required_is_enabled, prowler:azure:storage_smb_channel_encryption_with_secure_algorithm, prowler:azure:storage_smb_protocol_version_is_latest; cwe: CWE-319; attack: T1040, T1557; nist_800_53: SC-8, SC-13; other: Microsoft cloud security benchmark v1 DP-3, Microsoft cloud security benchmark v1 NS-8

- [ ] **CLD-CFG-017** Check TLS listeners, ciphers and origin traffic on load balancers and CDNs  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds public endpoints with plain text listeners, weak ciphers or open CORS.  
  *Steps:*
  1. List load balancers, CDN distributions and function URLs.
  2. Check that HTTP listeners redirect to HTTPS.
  3. Check the TLS policy for weak protocols and ciphers.
  4. Check that the CDN uses TLS to the origin.
  5. Scan each public endpoint for TLS settings.
  *Example:* `aws elbv2 describe-listeners --load-balancer-arn <a>; aws elbv2 describe-ssl-policies; aws cloudfront get-distribution-config --id <i>; aws lambda get-function-url-config --function-name <f>; sslyze <host>; testssl.sh <host>; prowler aws --services elbv2 elb cloudfront`  
  *Expected:* Public endpoints use only HTTPS with TLS 1.2 or higher and strong ciphers. CDN origins use TLS. CORS lists named origins only.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:awslambda_function_url_cors_policy, prowler:aws:cloudfront_distributions_custom_ssl_certificate, prowler:aws:cloudfront_distributions_field_level_encryption_enabled, prowler:aws:cloudfront_distributions_https_enabled, prowler:aws:cloudfront_distributions_https_sni_enabled, prowler:aws:cloudfront_distributions_origin_traffic_encrypted, prowler:aws:cloudfront_distributions_using_deprecated_ssl_protocols, prowler:aws:elb_desync_mitigation_mode, prowler:aws:elb_insecure_ssl_ciphers, prowler:aws:elb_ssl_listeners, prowler:aws:elb_ssl_listeners_use_acm_certificate, prowler:aws:elbv2_alb_drop_invalid_header_fields_enabled, prowler:aws:elbv2_desync_mitigation_mode, prowler:aws:elbv2_insecure_ssl_ciphers, prowler:aws:elbv2_listener_fips_tls_enabled, prowler:aws:elbv2_listeners_underneath, prowler:aws:elbv2_nlb_tls_termination_enabled, prowler:aws:elbv2_ssl_listeners; cwe: CWE-326; attack: T1040, T1557; nist_800_53: SC-8, SC-23; other: Microsoft cloud security benchmark v1 DP-3, Microsoft cloud security benchmark v1 NS-8

- [ ] **CLD-CFG-018** Check TLS, HTTPS redirect, client certificates and FTP on app services  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds web apps and functions that allow HTTP, old TLS or FTP deployment.  
  *Steps:*
  1. List web apps and function apps.
  2. Check the HTTPS-only setting and the minimum TLS version.
  3. Check that FTP deployment is off or FTPS only.
  4. Check client certificate settings where needed.
  5. Send an HTTP request and an FTP login to a test app.
  *Example:* `az webapp show -n <a> -g <rg> --query "[httpsOnly,siteConfig.minTlsVersion,siteConfig.ftpsState]"; az webapp config show -n <a> -g <rg>; az functionapp config show -n <f> -g <rg>; curl -i http://<app>.azurewebsites.net; prowler azure --services app network`  
  *Expected:* Apps accept HTTPS only with TLS 1.2 or higher. FTP is off or FTPS only. The HTTP request redirects. The FTP login fails.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:azure:app_client_certificates_on, prowler:azure:app_ensure_http_is_redirected_to_https, prowler:azure:app_ensure_using_http20, prowler:azure:app_ftp_deployment_disabled, prowler:azure:app_function_ensure_http_is_redirected_to_https, prowler:azure:app_function_ftps_deployment_disabled, prowler:azure:app_minimum_tls_version_12, prowler:azure:network_application_gateway_http2_enabled; cwe: CWE-319; attack: T1040, T1557; nist_800_53: SC-8, SC-23; other: Microsoft cloud security benchmark v1 DP-3, Microsoft cloud security benchmark v1 NS-8

- [ ] **CLD-CFG-019** Check certificate expiry, key algorithms and removal of expired certificates  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds expired or weak certificates that cause outages or allow downgrade.  
  *Steps:*
  1. List all certificates in the certificate manager, private CA, IAM and databases.
  2. Find certificates that expire in 30 days or less.
  3. Find certificates with weak key algorithms.
  4. Find expired certificates that are still stored.
  5. Check that renewal is automatic.
  *Example:* `aws acm list-certificates; aws acm describe-certificate --certificate-arn <a>; aws iam list-server-certificates; aws rds describe-db-instances --query "DBInstances[].CACertificateIdentifier"; aws ds describe-ldaps-settings --directory-id <d>; prowler aws --services acm rds iam`  
  *Expected:* No certificate expires within 30 days without renewal. Keys use strong algorithms. No expired certificate stays in store. Renewal is automatic.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:acm_certificates_expiration_check, prowler:aws:acm_certificates_transparency_logs_enabled, prowler:aws:acm_certificates_with_secure_key_algorithms, prowler:aws:acmpca_certificate_authority_pqc_key_algorithm, prowler:aws:directoryservice_ldap_certificate_expiration, prowler:aws:iam_no_expired_server_certificates_stored, prowler:aws:rds_instance_certificate_expiration; cwe: CWE-295; attack: T1649; nist_800_53: SC-12, SC-17; other: Microsoft cloud security benchmark v1 DP-7

- [ ] **CLD-CFG-020** Check post-quantum and FIPS TLS policies on long-lived data paths  
  *Severity if fail:* Info | *Type:* Config Review  
  *Objective:* Finds data paths that are open to later decryption because the TLS policy has no hybrid key exchange.  
  *Steps:*
  1. List the endpoints that carry data with a long secrecy period.
  2. Check the TLS or SSH policy of each endpoint.
  3. Check if a hybrid post-quantum policy or FIPS policy is set where required.
  4. Record the endpoints that cannot change.
  *Example:* `aws elbv2 describe-listeners --load-balancer-arn <a> --query "Listeners[].SslPolicy"; aws apigateway get-domain-name --domain-name <d>; aws transfer describe-server --server-id <s> --query Server.SecurityPolicyName; prowler aws --check elbv2_listener_pqc_tls_enabled transfer_server_pqc_ssh_kex_enabled`  
  *Expected:* Endpoints with long-term secrets use a hybrid post-quantum policy or a FIPS policy where the rules require it. Exceptions have an owner and a date.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:apigateway_domain_name_pqc_tls_enabled, prowler:aws:cloudfront_distributions_pqc_tls_enabled, prowler:aws:elbv2_listener_pqc_tls_enabled, prowler:aws:transfer_server_fips_security_policy_enabled, prowler:aws:transfer_server_pqc_ssh_kex_enabled; cwe: CWE-327; attack: T1040; nist_800_53: SC-13, SC-8; other: Microsoft cloud security benchmark v1 DP-3

- [ ] **CLD-CFG-021** Find snapshots, images and backups shared publicly or cross-account  
  *Severity if fail:* Critical | *Type:* Config Review  
  *Objective:* Finds disk, image and database snapshots that other accounts or the public can restore.  
  *Steps:*
  1. List snapshots, machine images and database snapshots.
  2. Find items shared with all accounts or with unknown accounts.
  3. Check that the block-public-sharing setting is on.
  4. Try to list the snapshots from an unlisted account.
  *Example:* `aws ec2 describe-snapshots --owner-ids self --restorable-by-user-ids all; aws ec2 describe-images --owners self --filters Name=is-public,Values=true; aws ec2 get-snapshot-block-public-access-state; aws rds describe-db-snapshot-attributes --db-snapshot-identifier <s>; gcloud compute images get-iam-policy <i>; prowler aws --services ec2 rds documentdb neptune`  
  *Expected:* No snapshot or image is public. Sharing goes to named accounts only. The block-public-sharing setting is on at account level.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:documentdb_cluster_public_snapshot, prowler:aws:ec2_ami_account_block_public_access, prowler:aws:ec2_ami_public, prowler:aws:ec2_ebs_public_snapshot, prowler:aws:neptune_cluster_public_snapshot, prowler:aws:rds_snapshots_public_access, prowler:gcp:compute_image_not_publicly_shared; cwe: CWE-200; attack: T1530, T1537; nist_800_53: AC-3, AC-21; other: Microsoft cloud security benchmark v1 DP-8, Microsoft cloud security benchmark v1 BR-2

- [ ] **CLD-CFG-022** Check that backup plans cover all data stores and VMs  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds data stores and VMs that have no backup plan or short retention.  
  *Steps:*
  1. List the data stores, volumes and VMs.
  2. Check that each one is in a backup plan.
  3. Check retention and the backup report plan.
  4. Check that a recovery job exists for critical systems.
  5. Restore one item to a test account.
  *Example:* `aws backup list-backup-plans; aws backup list-protected-resources; aws backup list-report-plans; aws dlm get-lifecycle-policies; az backup item list -g <rg> -v <vault>; az backup policy list -g <rg> -v <vault>; prowler aws --services backup dlm drs`  
  *Expected:* Each critical resource is in a backup plan with retention that meets the recovery goal. A test restore works.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:backup_plans_exist, prowler:aws:backup_reportplans_exist, prowler:aws:dlm_ebs_snapshot_lifecycle_policy_exists, prowler:aws:drs_job_exist, prowler:aws:dynamodb_table_protected_by_backup_plan, prowler:aws:ec2_ebs_volume_protected_by_backup_plan, prowler:aws:ec2_ebs_volume_snapshots_exists, prowler:aws:efs_have_backup_enabled, prowler:aws:rds_cluster_protected_by_backup_plan, prowler:aws:rds_instance_protected_by_backup_plan, prowler:azure:recovery_vault_backup_policy_retention_adequate, prowler:azure:recovery_vault_has_protected_items, prowler:azure:vm_backup_enabled, prowler:azure:vm_sufficient_daily_backup_retention_period; cwe: CWE-1188; attack: T1490, T1485; nist_800_53: CP-9, CP-10; other: Microsoft cloud security benchmark v1 BR-1, Microsoft cloud security benchmark v1 BR-3

- [ ] **CLD-CFG-023** Check automated backups and point-in-time recovery of databases  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds databases with no automated backup, no point-in-time recovery or old snapshots.  
  *Steps:*
  1. List databases, caches and data warehouses.
  2. Check that automated backups and point-in-time recovery are on.
  3. Check the backup retention days.
  4. Find snapshots older than the retention rule.
  5. Restore one database to a test point in time.
  *Example:* `aws rds describe-db-instances --query "DBInstances[].[DBInstanceIdentifier,BackupRetentionPeriod]"; aws dynamodb describe-continuous-backups --table-name <t>; gcloud sql instances describe <i> --format="value(settings.backupConfiguration)"; az cosmosdb show -n <a> -g <rg> --query backupPolicy; prowler aws --services rds dynamodb`  
  *Expected:* Every database has automated backup with enough retention and point-in-time recovery. Old snapshots are removed. The test restore works.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:documentdb_cluster_backup_enabled, prowler:aws:dynamodb_tables_pitr_enabled, prowler:aws:elasticache_redis_cluster_backup_enabled, prowler:aws:fsx_file_system_copy_tags_to_backups_enabled, prowler:aws:fsx_file_system_copy_tags_to_volumes_enabled, prowler:aws:lightsail_instance_automated_snapshots, prowler:aws:neptune_cluster_backup_enabled, prowler:aws:neptune_cluster_copy_tags_to_snapshots, prowler:aws:rds_cluster_copy_tags_to_snapshots, prowler:aws:rds_instance_backup_enabled, prowler:aws:rds_instance_copy_tags_to_snapshots, prowler:aws:redshift_cluster_automated_snapshot, prowler:azure:cosmosdb_account_backup_policy_continuous, prowler:azure:mysql_flexible_server_geo_redundant_backup_enabled, prowler:azure:postgresql_flexible_server_geo_redundant_backup_enabled, prowler:azure:storage_geo_redundant_enabled, prowler:gcp:cloudsql_instance_automated_backups, prowler:gcp:compute_snapshot_not_outdated; cwe: CWE-1188; attack: T1490, T1485; nist_800_53: CP-9, CP-6; other: Microsoft cloud security benchmark v1 BR-1, Microsoft cloud security benchmark v1 BR-4

- [ ] **CLD-CFG-024** Check deletion protection on databases, clusters and load balancers  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds critical resources that one wrong call or stolen key can delete.  
  *Steps:*
  1. List databases, clusters, load balancers and VMs.
  2. Check that deletion protection is on for production resources.
  3. Check who can turn the protection off.
  4. Try to delete a test resource with protection on.
  *Example:* `aws rds describe-db-instances --query "DBInstances[].[DBInstanceIdentifier,DeletionProtection]"; aws elbv2 describe-load-balancer-attributes --load-balancer-arn <a>; aws dynamodb describe-table --table-name <t> --query Table.DeletionProtectionEnabled; gcloud compute instances describe <i> --format="value(deletionProtection)"; prowler aws --services rds dynamodb elbv2`  
  *Expected:* Deletion protection is on for all production resources. Only a break-glass role can turn it off. The test delete fails.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:documentdb_cluster_deletion_protection, prowler:aws:dynamodb_table_deletion_protection_enabled, prowler:aws:eks_cluster_deletion_protection_enabled, prowler:aws:elbv2_deletion_protection, prowler:aws:neptune_cluster_deletion_protection, prowler:aws:networkfirewall_deletion_protection, prowler:aws:rds_cluster_backtrack_enabled, prowler:aws:rds_cluster_deletion_protection, prowler:aws:rds_instance_deletion_protection, prowler:gcp:compute_instance_deletion_protection_enabled; cwe: CWE-1188; attack: T1485, T1578; nist_800_53: CP-9, AC-6; other: Microsoft cloud security benchmark v1 BR-2

- [ ] **CLD-CFG-025** Check versioning, soft delete, object lock and retention of stored data  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds object stores where a delete or overwrite cannot be undone.  
  *Steps:*
  1. List buckets, containers, file shares and vaults.
  2. Check that versioning and soft delete are on.
  3. Check object lock or retention for audit data and backups.
  4. Check lifecycle rules for early deletion.
  5. Delete a test object and restore it.
  *Example:* `aws s3api get-bucket-versioning --bucket <b>; aws s3api get-object-lock-configuration --bucket <b>; aws s3api get-bucket-lifecycle-configuration --bucket <b>; az storage account blob-service-properties show -n <a> --query "[deleteRetentionPolicy,isVersioningEnabled]"; az keyvault show -n <v> --query properties.enablePurgeProtection; gcloud storage buckets describe gs://<b>; prowler azure --services storage keyvault`  
  *Expected:* Versioning, soft delete and retention are on for important data. Key vaults have purge protection. The test object is restored after delete.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:kinesis_stream_data_retention_period, prowler:aws:s3_bucket_lifecycle_enabled, prowler:aws:s3_bucket_no_mfa_delete, prowler:aws:s3_bucket_object_lock, prowler:aws:s3_bucket_object_versioning, prowler:azure:keyvault_recoverable, prowler:azure:storage_blob_versioning_is_enabled, prowler:azure:storage_ensure_file_shares_soft_delete_is_enabled, prowler:azure:storage_ensure_soft_delete_is_enabled, prowler:gcp:cloudstorage_bucket_lifecycle_management_enabled, prowler:gcp:cloudstorage_bucket_soft_delete_enabled, prowler:gcp:cloudstorage_bucket_sufficient_retention_period, prowler:gcp:cloudstorage_bucket_versioning_enabled, prowler:gcp:compute_instance_disk_auto_delete_disabled; cwe: CWE-1188; attack: T1485, T1485.001, T1486; nist_800_53: CP-9, SI-12; other: Microsoft cloud security benchmark v1 BR-2, Microsoft cloud security benchmark v1 BR-1

- [ ] **CLD-CFG-026** Check multi-zone and failover setup of managed data services  
  *Severity if fail:* Low | *Type:* Config Review, Manual  
  *Objective:* Finds data services with a single zone and no failover.  
  *Steps:*
  1. List databases, caches, file systems and brokers.
  2. Check the zone and replica setup of each one.
  3. Check that automatic failover is on.
  4. Start a failover in a test environment.
  *Example:* `aws rds describe-db-instances --query "DBInstances[].[DBInstanceIdentifier,MultiAZ]"; aws elasticache describe-replication-groups --query "ReplicationGroups[].[ReplicationGroupId,AutomaticFailover,MultiAZ]"; aws efs describe-file-systems; gcloud sql instances describe <i> --format="value(settings.availabilityType)"; prowler aws --services rds elasticache efs`  
  *Expected:* Critical data services run in more than one zone with automatic failover. The test failover finishes within the recovery goal.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:dms_instance_multi_az_enabled, prowler:aws:documentdb_cluster_multi_az_enabled, prowler:aws:dynamodb_accelerator_cluster_multi_az, prowler:aws:efs_multi_az_enabled, prowler:aws:elasticache_redis_cluster_automatic_failover_enabled, prowler:aws:elasticache_redis_cluster_multi_az_enabled, prowler:aws:fsx_windows_file_system_multi_az_enabled, prowler:aws:mq_broker_active_deployment_mode, prowler:aws:mq_broker_cluster_deployment_mode, prowler:aws:neptune_cluster_multi_az, prowler:aws:opensearch_service_domains_fault_tolerant_data_nodes, prowler:aws:opensearch_service_domains_fault_tolerant_master_nodes, prowler:aws:rds_cluster_multi_az, prowler:aws:rds_instance_multi_az, prowler:aws:redshift_cluster_multi_az_enabled, prowler:aws:storagegateway_gateway_fault_tolerant, prowler:azure:cosmosdb_account_automatic_failover_enabled, prowler:azure:mysql_flexible_server_high_availability_enabled, prowler:azure:postgresql_flexible_server_high_availability_enabled, prowler:gcp:cloudsql_instance_high_availability_enabled; cwe: CWE-1188; attack: T1499; nist_800_53: CP-6, CP-10; other: Microsoft cloud security benchmark v1 BR-1

- [ ] **CLD-CFG-027** Check zone spread, health checks and autoscaling of compute and network paths  
  *Severity if fail:* Info | *Type:* Config Review, Manual  
  *Objective:* Finds compute and network paths that fail with one zone or one instance.  
  *Steps:*
  1. List scaling groups, load balancers, VPN and direct connections.
  2. Check that each one spans more than one zone.
  3. Check that health checks and automatic healing are on.
  4. Check that spot and preemptible instances do not run critical work.
  5. Stop one instance in a test group.
  *Example:* `aws autoscaling describe-auto-scaling-groups --query "AutoScalingGroups[].[AutoScalingGroupName,AvailabilityZones]"; aws elbv2 describe-load-balancers --query "LoadBalancers[].AvailabilityZones"; aws directconnect describe-connections; gcloud compute instance-groups managed list; prowler aws --services autoscaling elbv2 directconnect`  
  *Expected:* Critical compute spans more than one zone with health checks and automatic healing. The test stop causes no outage.  
  *Refs:* cloud_native_top10: CNAS-1, CNAS-9; tool_check: prowler:aws:autoscaling_group_capacity_rebalance_enabled, prowler:aws:autoscaling_group_elb_health_check_enabled, prowler:aws:autoscaling_group_multiple_az, prowler:aws:autoscaling_group_multiple_instance_types, prowler:aws:awslambda_function_vpc_multi_az, prowler:aws:directconnect_connection_redundancy, prowler:aws:directconnect_virtual_interface_redundancy, prowler:aws:dynamodb_table_autoscaling_enabled, prowler:aws:ecs_service_fargate_latest_platform_version, prowler:aws:elb_connection_draining_enabled, prowler:aws:elb_cross_zone_load_balancing_enabled, prowler:aws:elb_is_in_multiple_az, prowler:aws:elbv2_cross_zone_load_balancing_enabled, prowler:aws:elbv2_is_in_multiple_az, prowler:aws:networkfirewall_multi_az, prowler:aws:vpc_different_regions, prowler:aws:vpc_endpoint_multi_az_enabled, prowler:aws:vpc_subnet_different_az, prowler:aws:vpc_vpn_connection_tunnels_up, prowler:azure:vm_desired_sku_size, prowler:azure:vm_scaleset_associated_with_load_balancer, prowler:gcp:compute_instance_automatic_restart_enabled, prowler:gcp:compute_instance_group_autohealing_enabled, prowler:gcp:compute_instance_group_load_balancer_attached, prowler:gcp:compute_instance_group_multiple_zones, prowler:gcp:compute_instance_on_host_maintenance_migrate, prowler:gcp:compute_instance_preemptible_vm_disabled; cwe: CWE-1188; attack: T1499; nist_800_53: CP-6, SC-5; other: Microsoft cloud security benchmark v1 BR-1

- [ ] **CLD-CFG-028** Check database engine settings: ports, minor upgrades and event alerts  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds database engines on default ports, with no auto upgrade and no event alerts.  
  *Steps:*
  1. List database instances and clusters.
  2. Check the listener port and admin name.
  3. Check that automatic minor version upgrades are on.
  4. Check that event subscriptions exist for failure and security group changes.
  5. Check connection throttling settings.
  *Example:* `aws rds describe-db-instances --query "DBInstances[].[DBInstanceIdentifier,DbInstancePort,AutoMinorVersionUpgrade]"; aws rds describe-event-subscriptions; az postgres flexible-server parameter show -g <rg> -s <s> --name connection_throttle.enable; prowler aws --services rds redshift`  
  *Expected:* Databases use non-default ports where the design allows. Minor upgrades are automatic. Event subscriptions send alerts to the response team.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:dms_instance_minor_version_upgrade_enabled, prowler:aws:elasticache_redis_cluster_auto_minor_version_upgrades, prowler:aws:memorydb_cluster_auto_minor_version_upgrades, prowler:aws:mq_broker_auto_minor_version_upgrades, prowler:aws:rds_cluster_critical_event_subscription, prowler:aws:rds_cluster_minor_version_upgrade_enabled, prowler:aws:rds_cluster_non_default_port, prowler:aws:rds_instance_critical_event_subscription, prowler:aws:rds_instance_enhanced_monitoring_enabled, prowler:aws:rds_instance_event_subscription_parameter_groups, prowler:aws:rds_instance_event_subscription_security_groups, prowler:aws:rds_instance_minor_version_upgrade_enabled, prowler:aws:rds_instance_non_default_port, prowler:aws:redshift_cluster_automatic_upgrades, prowler:aws:redshift_cluster_enhanced_vpc_routing, prowler:aws:redshift_cluster_non_default_database_name, prowler:azure:postgresql_flexible_server_connection_throttling_on; cwe: CWE-1188; attack: T1190; nist_800_53: CM-6, SI-2; other: Microsoft cloud security benchmark v1 PV-1, Microsoft cloud security benchmark v1 PV-2

- [ ] **CLD-CFG-029** Check risky database flags on managed MySQL and SQL Server instances  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds database flags that allow file reads, remote access or unsafe features.  
  *Steps:*
  1. List managed MySQL and SQL Server instances.
  2. Read the flags of each instance.
  3. Find local_infile, remote access and external scripts set to on.
  4. Find cross-database ownership chaining set to on.
  5. Change one flag in a test instance and look at the result.
  *Example:* `gcloud sql instances describe <i> --format="value(settings.databaseFlags)"; gcloud sql flags list --database-version=SQLSERVER_2019_STANDARD; prowler gcp --services cloudsql`  
  *Expected:* Risky flags are off: local_infile, remote access, external scripts, contained database authentication and cross-database ownership chaining.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:gcp:cloudsql_instance_mysql_local_infile_flag, prowler:gcp:cloudsql_instance_mysql_skip_show_database_flag, prowler:gcp:cloudsql_instance_sqlserver_contained_database_authentication_flag, prowler:gcp:cloudsql_instance_sqlserver_cross_db_ownership_chaining_flag, prowler:gcp:cloudsql_instance_sqlserver_external_scripts_enabled_flag, prowler:gcp:cloudsql_instance_sqlserver_remote_access_flag, prowler:gcp:cloudsql_instance_sqlserver_trace_flag, prowler:gcp:cloudsql_instance_sqlserver_user_connections_flag, prowler:gcp:cloudsql_instance_sqlserver_user_options_flag; cwe: CWE-1188; attack: T1190; nist_800_53: CM-6, CM-7; other: Microsoft cloud security benchmark v1 PV-1, Microsoft cloud security benchmark v1 PV-2

- [ ] **CLD-CFG-030** Check session time limits of managed virtual desktops  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds desktop fleets with long sessions and no idle disconnect.  
  *Steps:*
  1. List the desktop fleets.
  2. Read the maximum session time of each fleet.
  3. Read the idle and disconnect timeouts.
  4. Leave a test session idle.
  *Example:* `aws appstream describe-fleets --query "Fleets[].[Name,MaxUserDurationInSeconds,DisconnectTimeoutInSeconds,IdleDisconnectTimeoutInSeconds]"; prowler aws --services appstream`  
  *Expected:* Session length, idle time and disconnect time are set to the company rule. The idle test session ends on time.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:appstream_fleet_maximum_session_duration, prowler:aws:appstream_fleet_session_disconnect_timeout, prowler:aws:appstream_fleet_session_idle_disconnect_timeout; cwe: CWE-284; attack: T1563; nist_800_53: AC-12; other: Microsoft cloud security benchmark v1 PV-3


## IAC

- [ ] **CLD-IAC-005** Check stack termination protection and toolkit bootstrap version  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds infrastructure stacks that one call can delete, or old bootstrap roles.  
  *Steps:*
  1. List the production stacks.
  2. Check that termination protection is on.
  3. Check the bootstrap version of the toolkit stack.
  4. Try to delete a protected test stack.
  *Example:* `aws cloudformation describe-stacks --query "Stacks[].[StackName,EnableTerminationProtection]"; aws ssm get-parameter --name /cdk-bootstrap/hnb659fds/version; prowler aws --services cloudformation`  
  *Expected:* Production stacks have termination protection. Toolkit bootstrap is at the current version. The test delete fails.  
  *Refs:* cloud_native_top10: CNAS-4, CNAS-1; tool_check: prowler:aws:cloudformation_stack_cdktoolkit_bootstrap_version, prowler:aws:cloudformation_stacks_termination_protection_enabled; cwe: CWE-1188; attack: T1485, T1578; nist_800_53: CM-3, CP-9; other: Microsoft cloud security benchmark v1 DS-6, Microsoft cloud security benchmark v1 PV-1


## IAM

- [ ] **CLD-IAM-007** Check that the root account has no keys and a hardware MFA  
  *Severity if fail:* Critical | *Type:* Config Review  
  *Objective:* Finds a root or owner account that has access keys, weak MFA or daily use.  
  *Steps:*
  1. Get the account credential report.
  2. Check that the root account has no access keys.
  3. Check that the root account uses hardware MFA.
  4. Search the audit log for root sign-ins in the last 90 days.
  5. Check that the root credentials are stored in a sealed process.
  *Example:* `aws iam get-account-summary --query "SummaryMap.[AccountAccessKeysPresent,AccountMFAEnabled]"; aws iam generate-credential-report; aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=root; Azure: az role assignment list --role Owner --scope /subscriptions/<id>; GCP: gcloud organizations get-iam-policy <org>; prowler aws --services iam`  
  *Expected:* The root account has no access keys and a hardware MFA device. No root sign-in happens in normal work. Central root credential management is on.  
  *Refs:* cloud_native_top10: CNAS-3; tool_check: prowler:aws:iam_avoid_root_usage, prowler:aws:iam_no_root_access_key, prowler:aws:iam_root_credentials_management_enabled, prowler:aws:iam_root_hardware_mfa_enabled, prowler:aws:iam_root_mfa_enabled; cwe: CWE-308; attack: T1078.004; nist_800_53: AC-2, IA-2; other: Microsoft cloud security benchmark v1 PA-1, Microsoft cloud security benchmark v1 IM-6, Microsoft cloud security benchmark v1 PA-5

- [ ] **CLD-IAM-008** Check MFA enforcement for console users, admins and management APIs  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds human identities that sign in or call management APIs with one factor only.  
  *Steps:*
  1. List all human users with console or portal access.
  2. Find users with no MFA device or no MFA policy.
  3. Check that a policy denies actions when MFA is not present.
  4. Check that admin users use phishing-resistant MFA.
  5. Sign in with a test user that has no MFA.
  *Example:* `aws iam list-virtual-mfa-devices; aws iam get-credential-report; az rest --method get --url https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies; az rest --url https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy; gcloud compute project-info describe --format="value(commonInstanceMetadata.items)" (enable-oslogin-2fa)`  
  *Expected:* Every human identity needs MFA for sign-in and for management APIs. Admin users use hardware or passkey factors. The test user without MFA gets no access.  
  *Refs:* cloud_native_top10: CNAS-3; tool_check: prowler:aws:iam_administrator_access_with_mfa, prowler:aws:iam_user_hardware_mfa_enabled, prowler:aws:iam_user_mfa_enabled_console_access, prowler:azure:entra_authentication_methods_policy_strong_auth_enforced, prowler:azure:entra_conditional_access_policy_require_mfa_for_admin_portals, prowler:azure:entra_conditional_access_policy_require_mfa_for_management_api, prowler:azure:entra_non_privileged_user_has_mfa, prowler:azure:entra_privileged_user_has_mfa, prowler:azure:entra_security_defaults_enabled, prowler:azure:entra_user_with_vm_access_has_mfa, prowler:gcp:compute_project_os_login_2fa_enabled; cwe: CWE-308; attack: T1078.004, T1556.006, T1621; nist_800_53: IA-2, IA-5; other: Microsoft cloud security benchmark v1 IM-6, Microsoft cloud security benchmark v1 IM-1

- [ ] **CLD-IAM-009** Check password policy and temporary credential lifetime  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds weak password rules and long-lived credentials for users and user pools.  
  *Steps:*
  1. Get the password policy of the account and of each user pool.
  2. Compare length, complexity, reuse and expiry with the company rule.
  3. Find users with long-lived access keys instead of temporary credentials.
  4. Check the expiry time of temporary passwords.
  *Example:* `aws iam get-account-password-policy; aws cognito-idp describe-user-pool --user-pool-id <id> --query UserPool.Policies; aws iam get-credential-report; prowler aws --services iam cognito`  
  *Expected:* The password policy sets a minimum length of 14, complexity, reuse limit and expiry. Humans use temporary credentials. Temporary passwords expire in a short time.  
  *Refs:* cloud_native_top10: CNAS-3; tool_check: prowler:aws:cognito_user_pool_password_policy_lowercase, prowler:aws:cognito_user_pool_password_policy_minimum_length_14, prowler:aws:cognito_user_pool_password_policy_number, prowler:aws:cognito_user_pool_password_policy_symbol, prowler:aws:cognito_user_pool_password_policy_uppercase, prowler:aws:cognito_user_pool_temporary_password_expiration, prowler:aws:iam_password_policy_expires_passwords_within_90_days_or_less, prowler:aws:iam_password_policy_lowercase, prowler:aws:iam_password_policy_minimum_length_14, prowler:aws:iam_password_policy_number, prowler:aws:iam_password_policy_reuse_24, prowler:aws:iam_password_policy_symbol, prowler:aws:iam_password_policy_uppercase; cwe: CWE-521; attack: T1110; nist_800_53: IA-5; other: Microsoft cloud security benchmark v1 IM-6

- [ ] **CLD-IAM-010** Find old, unused and duplicate access keys and credentials  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds long-lived keys, unused credentials and app secrets that stay valid after a leak.  
  *Steps:*
  1. List all access keys, service account keys and app registration secrets.
  2. Find keys older than 90 days.
  3. Find keys and accounts with no use in the last 90 days.
  4. Find users with two active keys.
  5. Disable one old test key and look at the result.
  *Example:* `aws iam get-credential-report; aws iam list-access-keys --user-name <u>; aws iam get-access-key-last-used --access-key-id <k>; gcloud iam service-accounts keys list --iam-account <sa> --managed-by=user; az ad app credential list --id <app>; prowler aws --services iam`  
  *Expected:* No key is older than 90 days or unused. Each user has at most one active key. Service accounts have no user-managed keys. Unused identities are disabled.  
  *Refs:* cloud_native_top10: CNAS-3; tool_check: prowler:aws:iam_role_access_not_stale_to_bedrock, prowler:aws:iam_rotate_access_key_90_days, prowler:aws:iam_user_access_not_stale_to_bedrock, prowler:aws:iam_user_access_not_stale_to_sagemaker, prowler:aws:iam_user_accesskey_unused, prowler:aws:iam_user_console_access_unused, prowler:aws:iam_user_no_setup_initial_access_key, prowler:aws:iam_user_two_active_access_key, prowler:aws:iam_user_with_temporary_credentials, prowler:azure:entra_app_registration_credential_not_expired, prowler:azure:entra_user_with_recent_sign_in, prowler:gcp:iam_sa_no_user_managed_keys, prowler:gcp:iam_sa_user_managed_key_rotate_90_days, prowler:gcp:iam_sa_user_managed_key_unused, prowler:gcp:iam_service_account_unused; cwe: CWE-324; attack: T1078.004, T1098.001, T1552.001; nist_800_53: IA-5, AC-2; other: Microsoft cloud security benchmark v1 IM-3, Microsoft cloud security benchmark v1 PA-3, Microsoft cloud security benchmark v1 IM-8

- [ ] **CLD-IAM-011** Check API keys for restrictions, age and a better method  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds static API keys that have no limits and replace identity-based access.  
  *Steps:*
  1. List all API keys, function keys and GraphQL API keys.
  2. Find keys that have no API or caller restriction.
  3. Find keys older than 90 days.
  4. Check if an identity-based method can replace each key.
  5. Try a key from an unlisted network.
  *Example:* `gcloud services api-keys list; gcloud services api-keys describe <key>; az functionapp keys list -g <rg> -n <app>; aws appsync list-api-keys --api-id <id>; prowler gcp --services apikeys`  
  *Expected:* Each API key has an API and caller restriction and a rotation date. Keys older than 90 days are rotated. Sensitive APIs use IAM, not keys.  
  *Refs:* cloud_native_top10: CNAS-3; tool_check: prowler:aws:appsync_graphql_api_no_api_key_authentication, prowler:aws:bedrock_api_key_no_administrative_privileges, prowler:aws:bedrock_api_key_no_long_term_credentials, prowler:azure:app_function_access_keys_configured, prowler:gcp:apikeys_api_restricted_with_gemini_api, prowler:gcp:apikeys_api_restrictions_configured, prowler:gcp:apikeys_key_exists, prowler:gcp:apikeys_key_rotated_in_90_days, prowler:gcp:gemini_api_disabled; cwe: CWE-798; attack: T1552.001, T1528; nist_800_53: IA-5, AC-3; other: Microsoft cloud security benchmark v1 IM-3, Microsoft cloud security benchmark v1 IM-8

- [ ] **CLD-IAM-012** Find administrator rights on users, groups, roles and service accounts  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds identities that have full admin or owner rights without need.  
  *Steps:*
  1. List all identities with admin, owner or full-access policies.
  2. Find admin policies attached to users, not to groups or roles.
  3. Count the owners of each subscription or project.
  4. Check the written reason for each admin identity.
  5. Replace one admin policy with a scoped policy in a test.
  *Example:* `aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess; az role assignment list --role Owner --all; az role assignment list --include-inherited --role "User Access Administrator"; gcloud projects get-iam-policy <p> --flatten=bindings --filter="bindings.role:roles/owner"; prowler azure --services iam entra`  
  *Expected:* Few named identities hold admin rights, each with a written reason. Admin policies attach to roles or groups only. Service accounts have no admin roles.  
  *Refs:* cloud_native_top10: CNAS-3; tool_check: prowler:aws:bedrock_full_access_policy_attached, prowler:aws:bedrockagentcore_full_access_policy_attached, prowler:aws:iam_aws_attached_policy_no_administrative_privileges, prowler:aws:iam_customer_attached_policy_no_administrative_privileges, prowler:aws:iam_customer_unattached_policy_no_administrative_privileges, prowler:aws:iam_group_administrator_access_policy, prowler:aws:iam_inline_policy_no_administrative_privileges, prowler:aws:iam_policy_attached_only_to_group_or_roles, prowler:aws:iam_role_administratoraccess_policy, prowler:aws:iam_user_administrator_access_policy, prowler:azure:entra_global_admin_in_less_than_five_users, prowler:azure:iam_subscription_owners_between_2_and_3, prowler:azure:iam_subscription_roles_owner_custom_not_created, prowler:gcp:iam_sa_no_administrative_privileges; cwe: CWE-269; attack: T1078.004, T1098.003; nist_800_53: AC-6, AC-2; other: Microsoft cloud security benchmark v1 PA-7, Microsoft cloud security benchmark v1 PA-1, Microsoft cloud security benchmark v1 PA-2

- [ ] **CLD-IAM-013** Find policies that allow privilege escalation  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds policies where a user can give themselves more rights or assume admin roles.  
  *Steps:*
  1. Export all customer and inline policies.
  2. Find actions such as iam:PassRole, iam:CreatePolicyVersion and sts:AssumeRole on all resources.
  3. Find full access to audit log and key services.
  4. Run a privilege escalation scanner on the account.
  5. Try one found path with a test identity.
  *Example:* `aws iam get-account-authorization-details; pmapper graph create; pmapper query "who can do iam:* with *"; cloudsplaining scan --input-file <f>; prowler aws --check iam_policy_allows_privilege_escalation iam_inline_policy_allows_privilege_escalation`  
  *Expected:* No policy lets a principal raise its own rights. PassRole is limited to named roles and services. No identity has full access to audit log or key services.  
  *Refs:* cloud_native_top10: CNAS-3; tool_check: prowler:aws:bedrock_agent_role_least_privilege, prowler:aws:bedrock_agent_role_not_shared_across_agents, prowler:aws:iam_inline_policy_allows_privilege_escalation, prowler:aws:iam_inline_policy_no_full_access_to_cloudtrail, prowler:aws:iam_inline_policy_no_full_access_to_kms, prowler:aws:iam_inline_policy_no_wildcard_marketplace_subscribe, prowler:aws:iam_no_custom_policy_permissive_role_assumption, prowler:aws:iam_policy_allows_privilege_escalation, prowler:aws:iam_policy_cloudshell_admin_not_attached, prowler:aws:iam_policy_no_agentcore_workload_access_token_wildcard, prowler:aws:iam_policy_no_full_access_to_cloudtrail, prowler:aws:iam_policy_no_full_access_to_kms, prowler:aws:iam_policy_no_wildcard_marketplace_subscribe, prowler:aws:iam_policy_passrole_to_bedrock_agentcore_restricted; cwe: CWE-269; attack: T1098.003, T1078.004; nist_800_53: AC-6, AC-5; other: Microsoft cloud security benchmark v1 PA-7

- [ ] **CLD-IAM-014** Check separation of duties for key, service account and role admins  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds identities that hold two roles which together give full control.  
  *Steps:*
  1. List role assignments for key admin, key user, service account admin and service account user.
  2. Find identities that hold both roles of a pair.
  3. Find service roles granted at project level.
  4. Find custom roles that manage resource locks.
  5. Check that role changes need a second approval.
  *Example:* `gcloud projects get-iam-policy <p> --format=json; az role definition list --custom-role-only true; az role assignment list --role "User Access Administrator" --all; prowler gcp --services iam`  
  *Expected:* No identity holds both roles of a conflicting pair. Service roles apply at resource level. Only a few identities can change locks and roles.  
  *Refs:* cloud_native_top10: CNAS-3; tool_check: prowler:aws:bedrockagentcore_payments_process_payment_role_separation, prowler:azure:iam_custom_role_has_permissions_to_administer_resource_locks, prowler:azure:iam_role_user_access_admin_restricted, prowler:gcp:iam_no_service_roles_at_project_level, prowler:gcp:iam_role_kms_enforce_separation_of_duties, prowler:gcp:iam_role_sa_enforce_separation_of_duties; cwe: CWE-269; attack: T1098.003; nist_800_53: AC-5, AC-6; other: Microsoft cloud security benchmark v1 PA-1, Microsoft cloud security benchmark v1 PA-7

- [ ] **CLD-IAM-015** Check role trust, confused deputy protection and external access findings  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds roles that outside accounts, services or identity providers can assume without limits.  
  *Steps:*
  1. Read the trust policy of each role.
  2. Find trust for other accounts and services with no source account or external ID condition.
  3. Check that identity pool providers have an attribute condition.
  4. Open the external access analyzer findings.
  5. Try to assume a role from an unlisted account.
  *Example:* `aws iam list-roles --query "Roles[].[RoleName,AssumeRolePolicyDocument]"; aws accessanalyzer list-analyzers; aws accessanalyzer list-findings --analyzer-arn <a>; gcloud iam workload-identity-pools providers describe <p> --workload-identity-pool=<pool> --location=global; prowler aws --services iam accessanalyzer`  
  *Expected:* Each trust names the account or service and has a source condition or external ID. The analyzer is on in every region and has no open finding without owner.  
  *Refs:* cloud_native_top10: CNAS-3; tool_check: prowler:aws:accessanalyzer_enabled, prowler:aws:accessanalyzer_enabled_without_findings, prowler:aws:iam_check_saml_providers_sts, prowler:aws:iam_role_cross_account_readonlyaccess_policy, prowler:aws:iam_role_cross_service_confused_deputy_prevention, prowler:aws:iam_role_service_trust_restricts_source_to_account, prowler:aws:rolesanywhere_profile_restricts_session_permissions, prowler:aws:vpc_endpoint_connections_trust_boundaries, prowler:aws:vpc_endpoint_services_allowed_principals_trust_boundaries, prowler:gcp:iam_workload_identity_pool_provider_attribute_condition; cwe: CWE-441; attack: T1199, T1078.004, T1550.001; nist_800_53: AC-6, AC-3; other: Microsoft cloud security benchmark v1 IM-3, Microsoft cloud security benchmark v1 PA-4

- [ ] **CLD-IAM-016** Check resource policies of queues, topics, buses and shared resources  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds messaging and shared resources that other accounts or the public can use.  
  *Steps:*
  1. List queues, topics, event buses, email identities and shared catalogs.
  2. Read the resource policy of each one.
  3. Find Principal * and unknown account entries.
  4. Find policies with no condition on source.
  5. Send a test message from an unlisted account.
  *Example:* `aws sqs get-queue-attributes --queue-url <u> --attribute-names Policy; aws sns get-topic-attributes --topic-arn <a>; aws events describe-event-bus --name <b>; aws ses get-identity-policies --identity <i>; prowler aws --services sqs sns eventbridge ses`  
  *Expected:* Resource policies name known accounts only. No policy has Principal * without a strong condition. The test message from the unlisted account is denied.  
  *Refs:* cloud_native_top10: CNAS-3, CNAS-2; tool_check: prowler:aws:cloudwatch_cross_account_sharing_disabled, prowler:aws:dynamodb_table_cross_account_access, prowler:aws:eventbridge_bus_cross_account_access, prowler:aws:eventbridge_bus_exposed, prowler:aws:eventbridge_schema_registry_cross_account_access, prowler:aws:oam_sink_not_publicly_accessible, prowler:aws:s3_bucket_cross_account_access, prowler:aws:servicecatalog_portfolio_shared_within_organization_only, prowler:aws:ses_identity_not_publicly_accessible, prowler:aws:sns_topics_not_publicly_accessible, prowler:aws:sqs_queues_not_publicly_accessible; cwe: CWE-732; attack: T1530, T1537; nist_800_53: AC-3, AC-4; other: Microsoft cloud security benchmark v1 NS-2, Microsoft cloud security benchmark v1 DP-8

- [ ] **CLD-IAM-017** Check security contacts, support roles and incident setup for each account  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds accounts where security alerts and provider notices go to no one.  
  *Steps:*
  1. List the contact details of each account, subscription and organization.
  2. Check that a security contact has a shared mailbox and phone number.
  3. Check that a role exists for provider support access.
  4. Check that alert emails reach the on-call team.
  5. Send a test security notice.
  *Example:* `aws account get-alternate-contact --alternate-contact-type SECURITY; aws iam list-roles --query "Roles[?contains(RoleName,'Support')]"; az security contact list; gcloud essential-contacts list --organization=<org>; prowler aws --services account`  
  *Expected:* Each account has a current security contact on a shared mailbox. A support role and a security audit role exist. The test notice reaches the response team.  
  *Refs:* cloud_native_top10: CNAS-10; tool_check: prowler:aws:account_maintain_current_contact_details, prowler:aws:account_maintain_different_contact_details_to_security_billing_and_operations, prowler:aws:account_security_contact_information_is_registered, prowler:aws:account_security_questions_are_registered_in_the_aws_account, prowler:aws:directoryservice_directory_monitor_notifications, prowler:aws:directoryservice_directory_snapshots_limit, prowler:aws:iam_securityaudit_role_created, prowler:aws:iam_support_role_created, prowler:aws:ssmincidents_enabled_with_plans, prowler:aws:trustedadvisor_errors_and_warnings, prowler:aws:trustedadvisor_premium_support_plan_subscribed, prowler:azure:defender_additional_email_configured_with_a_security_contact, prowler:azure:defender_ensure_notify_alerts_severity_is_high, prowler:azure:defender_ensure_notify_emails_to_owners, prowler:gcp:iam_account_access_approval_enabled, prowler:gcp:iam_organization_essential_contacts_configured; cwe: CWE-778; attack: T1078.004; nist_800_53: IR-6, IR-8; other: Microsoft cloud security benchmark v1 IR-2, Microsoft cloud security benchmark v1 PA-8, Microsoft cloud security benchmark v1 IR-3

- [ ] **CLD-IAM-018** Check tenant settings for guests, app consent and user creation rights  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds tenant defaults that let users create apps, groups and guests or consent to apps.  
  *Steps:*
  1. Read the user and guest settings of the tenant.
  2. Check who can create apps, tenants and groups.
  3. Check the rules for user consent to apps.
  4. Check who can invite guests.
  5. Check that named locations exist for conditional access.
  *Example:* `az rest --url https://graph.microsoft.com/v1.0/policies/authorizationPolicy; az rest --url https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations; prowler azure --services entra`  
  *Expected:* Only admin roles create apps, tenants and groups. Users consent to verified apps with low risk only. Only admin roles invite guests. Guest access is limited.  
  *Refs:* cloud_native_top10: CNAS-3; tool_check: prowler:azure:entra_policy_default_users_cannot_create_security_groups, prowler:azure:entra_policy_ensure_default_user_cannot_create_apps, prowler:azure:entra_policy_ensure_default_user_cannot_create_tenants, prowler:azure:entra_policy_guest_invite_only_for_admin_roles, prowler:azure:entra_policy_guest_users_access_restrictions, prowler:azure:entra_policy_restricts_user_consent_for_apps, prowler:azure:entra_policy_user_consent_for_verified_apps, prowler:azure:entra_trusted_named_locations_exists, prowler:azure:entra_users_cannot_create_microsoft_365_groups; cwe: CWE-269; attack: T1136.003, T1528; nist_800_53: AC-6, AC-2; other: Microsoft cloud security benchmark v1 IM-1, Microsoft cloud security benchmark v1 PA-3

- [ ] **CLD-IAM-019** Check customer identity pools and directory sign-in settings  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds user pools that allow guest access, self sign-up, weak recovery or no MFA.  
  *Steps:*
  1. List user pools, identity pools and directory services.
  2. Check that guest access is off.
  3. Check MFA, advanced security and compromised credential blocking.
  4. Check the account recovery method and the self sign-up setting.
  5. Try to sign up and to recover an account with a test user.
  *Example:* `aws cognito-idp describe-user-pool --user-pool-id <id>; aws cognito-identity describe-identity-pool --identity-pool-id <id>; aws ds describe-directories; prowler aws --services cognito directoryservice`  
  *Expected:* Guest access is off. MFA and compromised credential blocking are on. Recovery does not use SMS only. Self sign-up is off unless the service needs it.  
  *Refs:* cloud_native_top10: CNAS-3; tool_check: prowler:aws:cognito_identity_pool_guest_access_disabled, prowler:aws:cognito_user_pool_account_recovery_sms_not_preferred, prowler:aws:cognito_user_pool_advanced_security_enabled, prowler:aws:cognito_user_pool_blocks_compromised_credentials_sign_in_attempts, prowler:aws:cognito_user_pool_blocks_potential_malicious_sign_in_attempts, prowler:aws:cognito_user_pool_client_prevent_user_existence_errors, prowler:aws:cognito_user_pool_client_token_revocation_enabled, prowler:aws:cognito_user_pool_deletion_protection_enabled, prowler:aws:cognito_user_pool_mfa_enabled, prowler:aws:cognito_user_pool_self_registration_disabled, prowler:aws:directoryservice_radius_server_security_protocol, prowler:aws:directoryservice_supported_mfa_radius_enabled; cwe: CWE-287; attack: T1078.004, T1110; nist_800_53: IA-2, IA-5; other: Microsoft cloud security benchmark v1 IM-6, Microsoft cloud security benchmark v1 IM-9

- [ ] **CLD-IAM-020** Check that workloads use their own attached identity and not default accounts  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds workloads that run with default service accounts or no managed identity.  
  *Steps:*
  1. List VMs, nodes, functions and app services with their identity.
  2. Find workloads that use the default service account.
  3. Find internet-facing instances with an instance profile.
  4. Check the rights of each attached identity.
  5. Check that app services need sign-in.
  *Example:* `aws ec2 describe-instances --query "Reservations[].Instances[].[InstanceId,IamInstanceProfile.Arn,PublicIpAddress]"; gcloud compute instances list --format="value(name,serviceAccounts[].email)"; az webapp identity show -g <rg> -n <app>; az webapp auth show -g <rg> -n <app>; prowler gcp --services compute gke`  
  *Expected:* Each workload has its own identity with minimal rights. No workload uses the default service account. Internet-facing hosts have only the rights they need.  
  *Refs:* cloud_native_top10: CNAS-3; tool_check: prowler:aws:ec2_instance_internet_facing_with_instance_profile, prowler:aws:ec2_instance_profile_attached, prowler:aws:rolesanywhere_trust_anchor_pqc_pki, prowler:azure:aiservices_account_managed_identity_enabled, prowler:azure:app_ensure_auth_is_set_up, prowler:azure:app_function_identity_is_configured, prowler:azure:app_function_identity_without_admin_privileges, prowler:azure:app_register_with_identity, prowler:gcp:compute_instance_default_service_account_in_use, prowler:gcp:compute_instance_default_service_account_in_use_with_full_api_access, prowler:gcp:gke_cluster_no_default_service_account; cwe: CWE-250; attack: T1078.004, T1552.005; nist_800_53: AC-6, IA-9; other: Microsoft cloud security benchmark v1 IM-3

- [ ] **CLD-IAM-021** Check database and data service authentication and default admin names  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds data services with no authentication, default admin names or no identity-based login.  
  *Steps:*
  1. List databases, caches, search domains, brokers and clusters.
  2. Check that each one needs authentication.
  3. Check that identity-based login is on where the service has it.
  4. Find default admin user names.
  5. Try to connect with no credentials.
  *Example:* `aws rds describe-db-instances --query "DBInstances[].[DBInstanceIdentifier,IAMDatabaseAuthenticationEnabled,MasterUsername]"; aws elasticache describe-replication-groups; aws opensearch describe-domain --domain-name <d>; aws kafka describe-cluster --cluster-arn <a>; prowler aws --services rds elasticache opensearch kafka`  
  *Expected:* Every data service needs authentication. Identity-based login is on. Admin names are not default. The connection with no credentials fails.  
  *Refs:* cloud_native_top10: CNAS-3; tool_check: prowler:aws:dms_endpoint_mongodb_authentication_enabled, prowler:aws:dms_endpoint_neptune_iam_authorization_enabled, prowler:aws:elasticache_redis_replication_group_auth_enabled, prowler:aws:kafka_cluster_mutual_tls_authentication_enabled, prowler:aws:kafka_cluster_unrestricted_access_disabled, prowler:aws:neptune_cluster_iam_authentication_enabled, prowler:aws:opensearch_service_domains_access_control_enabled, prowler:aws:opensearch_service_domains_internal_user_database_enabled, prowler:aws:opensearch_service_domains_use_cognito_authentication_for_kibana, prowler:aws:rds_cluster_default_admin, prowler:aws:rds_cluster_iam_authentication_enabled, prowler:aws:rds_instance_default_admin, prowler:aws:rds_instance_iam_authentication_enabled, prowler:aws:redshift_cluster_non_default_username; cwe: CWE-306; attack: T1078.004, T1190; nist_800_53: IA-2, IA-5; other: Microsoft cloud security benchmark v1 IM-1, Microsoft cloud security benchmark v1 IM-3

- [ ] **CLD-IAM-022** Check that shared keys and local accounts are off  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds services where static keys or local accounts bypass central access control.  
  *Steps:*
  1. List storage accounts, AI services, databases and clusters.
  2. Check if shared key or local authentication is on.
  3. Check that Entra or IAM authorization is the default.
  4. Check that RBAC is on for clusters.
  5. Try to call each service with a stored key.
  *Example:* `az storage account show -n <a> --query "[allowSharedKeyAccess,defaultToOAuthAuthentication]"; az cognitiveservices account show -n <a> -g <rg> --query properties.disableLocalAuth; az aks show -n <c> -g <rg> --query "[disableLocalAccounts,enableRbac]"; az cosmosdb show -n <a> -g <rg> --query disableLocalAuth; prowler azure --services storage aiservices aks`  
  *Expected:* Shared key and local authentication are off. Identity-based authorization is the default. The call with a stored key fails.  
  *Refs:* cloud_native_top10: CNAS-3; tool_check: prowler:azure:aiservices_account_local_auth_disabled, prowler:azure:aks_cluster_local_accounts_disabled, prowler:azure:aks_cluster_rbac_enabled, prowler:azure:cosmosdb_account_use_aad_and_rbac, prowler:azure:postgresql_flexible_server_entra_id_authentication_enabled, prowler:azure:sqlserver_azuread_administrator_enabled, prowler:azure:storage_account_key_access_disabled, prowler:azure:storage_default_to_entra_authorization_enabled; cwe: CWE-287; attack: T1078.004, T1552.001; nist_800_53: IA-2, AC-3; other: Microsoft cloud security benchmark v1 IM-1, Microsoft cloud security benchmark v1 IM-3


## LOG

- [ ] **CLD-LOG-006** Check that threat detection runs in all regions under a central admin  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds regions and accounts with no managed threat detection or open high findings.  
  *Steps:*
  1. List the regions and accounts in use.
  2. Check that the threat detection service is on in each region.
  3. Check that a delegated admin manages all member accounts.
  4. Open the findings and look for high severity items.
  5. Create a sample finding and follow it to the response team.
  *Example:* `aws guardduty list-detectors --region <r>; aws guardduty list-members --detector-id <d>; aws guardduty list-findings --detector-id <d> --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}'; aws guardduty create-sample-findings --detector-id <d>; prowler aws --services guardduty`  
  *Expected:* Threat detection is on in all regions and accounts under one admin account. High findings have an owner. The sample finding reaches the response team.  
  *Refs:* cloud_native_top10: CNAS-10; tool_check: prowler:aws:guardduty_centrally_managed, prowler:aws:guardduty_delegated_admin_enabled_all_regions, prowler:aws:guardduty_is_enabled, prowler:aws:guardduty_no_high_severity_findings; cwe: CWE-778; attack: T1685.002; nist_800_53: SI-4, IR-4; other: Microsoft cloud security benchmark v1 LT-1, Microsoft cloud security benchmark v1 LT-5

- [ ] **CLD-LOG-007** Check threat detection protection plans for storage, containers, functions and databases  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds workloads that the threat detection service does not watch.  
  *Steps:*
  1. List the protection plans of the threat detection service.
  2. Check that the plans for storage, Kubernetes, functions, databases and malware are on.
  3. Check that runtime monitoring agents run on the nodes.
  4. Run a test action that the plan must detect.
  *Example:* `aws guardduty get-detector --detector-id <d> --query Features; aws guardduty list-detectors; prowler aws --services guardduty`  
  *Expected:* All protection plans for the used workload types are on. Runtime agents run on all nodes. The test action creates a finding.  
  *Refs:* cloud_native_top10: CNAS-10; tool_check: prowler:aws:guardduty_ai_protection_enabled, prowler:aws:guardduty_ec2_malware_protection_enabled, prowler:aws:guardduty_eks_audit_log_enabled, prowler:aws:guardduty_eks_runtime_monitoring_enabled, prowler:aws:guardduty_lambda_protection_enabled, prowler:aws:guardduty_rds_protection_enabled, prowler:aws:guardduty_runtime_monitoring_enabled, prowler:aws:guardduty_s3_protection_enabled; cwe: CWE-778; attack: T1496, T1530; nist_800_53: SI-4; other: Microsoft cloud security benchmark v1 LT-1

- [ ] **CLD-LOG-008** Check that cloud workload protection plans are on for each resource type  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds resource types with no cloud workload protection plan.  
  *Steps:*
  1. List the protection plans of the subscription.
  2. Check that plans for servers, databases, storage, key vault, containers, DNS and resource manager are on.
  3. Check that posture management is on at the right tier.
  4. Trigger a test alert for one plan.
  *Example:* `az security pricing list --query "[].[name,pricingTier]"; az security alert list; prowler azure --services defender`  
  *Expected:* Every used resource type has its protection plan on. Posture management is at the tier the plan needs. The test alert appears in the portal.  
  *Refs:* cloud_native_top10: CNAS-10; tool_check: prowler:azure:defender_ensure_defender_cspm_is_on, prowler:azure:defender_ensure_defender_for_app_services_is_on, prowler:azure:defender_ensure_defender_for_arm_is_on, prowler:azure:defender_ensure_defender_for_azure_sql_databases_is_on, prowler:azure:defender_ensure_defender_for_containers_is_on, prowler:azure:defender_ensure_defender_for_cosmosdb_is_on, prowler:azure:defender_ensure_defender_for_databases_is_on, prowler:azure:defender_ensure_defender_for_dns_is_on, prowler:azure:defender_ensure_defender_for_keyvault_is_on, prowler:azure:defender_ensure_defender_for_os_relational_databases_is_on, prowler:azure:defender_ensure_defender_for_server_is_on, prowler:azure:defender_ensure_defender_for_sql_servers_is_on, prowler:azure:defender_ensure_defender_for_storage_is_on, prowler:azure:defender_ensure_iot_hub_defender_is_on, prowler:azure:defender_ensure_mcas_is_enabled, prowler:azure:sqlserver_microsoft_defender_enabled; cwe: CWE-778; attack: T1496, T1530; nist_800_53: SI-4, RA-5; other: Microsoft cloud security benchmark v1 LT-1, Microsoft cloud security benchmark v1 LT-2

- [ ] **CLD-LOG-009** Check agents, endpoint protection and alert routing of the workload protection service  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds VMs without agents or endpoint protection and alerts that nobody reads.  
  *Steps:*
  1. List the VMs and their agent state.
  2. Check that endpoint protection and the monitoring agent are installed.
  3. Check that auto-provisioning and vulnerability assessment are on.
  4. Check the email and attack path notification settings.
  5. Look at the alerts of the last 30 days.
  *Example:* `az security auto-provisioning-setting list; az security setting list; az security assessment list --query "[?contains(name,'endpoint')]"; az security contact list; prowler azure --services defender`  
  *Expected:* All VMs have agents and endpoint protection. Provisioning is automatic. Alert and attack path notices go to the response team.  
  *Refs:* cloud_native_top10: CNAS-10; tool_check: prowler:azure:defender_assessments_vm_endpoint_protection_installed, prowler:azure:defender_attack_path_notifications_properly_configured, prowler:azure:defender_auto_provisioning_log_analytics_agent_vms_on, prowler:azure:defender_auto_provisioning_vulnerabilty_assessments_machines_on, prowler:azure:defender_ensure_wdatp_is_enabled; cwe: CWE-778; attack: T1685, T1496; nist_800_53: SI-3, SI-4; other: Microsoft cloud security benchmark v1 ES-1, Microsoft cloud security benchmark v1 PV-5

- [ ] **CLD-LOG-010** Check sensitive data discovery on object storage  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds object storage with sensitive data that nobody has classified.  
  *Steps:*
  1. List buckets in each account.
  2. Check that automated sensitive data discovery is on.
  3. Open the findings of the last scan.
  4. Place a test file with fake card numbers in a bucket and look for a finding.
  *Example:* `aws macie2 get-macie-session; aws macie2 get-automated-discovery-configuration; aws macie2 list-findings; prowler aws --services macie`  
  *Expected:* Discovery is on for all accounts. Sensitive data findings have an owner. The test file creates a finding.  
  *Refs:* cloud_native_top10: CNAS-10, CNAS-8; tool_check: prowler:aws:macie_automated_sensitive_data_discovery_enabled, prowler:aws:macie_is_enabled; cwe: CWE-200; attack: T1530, T1619; nist_800_53: RA-2, SI-4; other: Microsoft cloud security benchmark v1 DP-1, Microsoft cloud security benchmark v1 DP-2

- [ ] **CLD-LOG-011** Check audit log detection for enumeration, privilege escalation and LLM abuse  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds missing detections on audit log patterns for recon and stolen model access.  
  *Steps:*
  1. List the detection rules on the audit log.
  2. Check rules for API enumeration, privilege escalation and model abuse.
  3. Check that AI service control-plane calls are in the audit log.
  4. Run a test enumeration with a test identity and look for an alert.
  *Example:* `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ListRoles; aws cloudtrail get-event-selectors --trail-name <t>; az monitor activity-log list; prowler aws --services cloudtrail`  
  *Expected:* Rules alert on enumeration, privilege escalation and unusual model calls. The test enumeration creates an alert.  
  *Refs:* cloud_native_top10: CNAS-10; tool_check: prowler:aws:cloudtrail_bedrock_logging_enabled, prowler:aws:cloudtrail_threat_detection_enumeration, prowler:aws:cloudtrail_threat_detection_llm_jacking, prowler:aws:cloudtrail_threat_detection_privilege_escalation, prowler:azure:apim_threat_detection_llm_jacking; cwe: CWE-778; attack: T1580, T1526, T1087.004; nist_800_53: AU-6, SI-4; other: Microsoft cloud security benchmark v1 LT-2, Microsoft cloud security benchmark v1 LT-3

- [ ] **CLD-LOG-012** Check access and execution logs of APIs, functions, workflows and build jobs  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds application services that keep no request or execution record.  
  *Steps:*
  1. List API stages, GraphQL APIs, workflows, build projects and web apps.
  2. Check that access logs and execution logs are on.
  3. Check that the logs go to central storage.
  4. Send a test request and find it in the logs.
  *Example:* `aws apigateway get-stage --rest-api-id <id> --stage-name <s> --query accessLogSettings; aws apigatewayv2 get-stages --api-id <id>; aws stepfunctions describe-state-machine --state-machine-arn <a> --query loggingConfiguration; az monitor diagnostic-settings list --resource <id>; prowler aws --services apigateway apigatewayv2 stepfunctions`  
  *Expected:* Every application service writes access and execution logs to central storage. The test request is found with caller and time.  
  *Refs:* cloud_native_top10: CNAS-10; tool_check: prowler:aws:apigateway_restapi_logging_enabled, prowler:aws:apigateway_restapi_tracing_enabled, prowler:aws:apigatewayv2_api_access_logging_enabled, prowler:aws:appsync_field_level_logging_enabled, prowler:aws:athena_workgroup_logging_enabled, prowler:aws:awslambda_function_invoke_api_operations_cloudtrail_logging_enabled, prowler:aws:codebuild_project_logging_enabled, prowler:aws:datasync_task_logging_enabled, prowler:aws:directoryservice_directory_log_forwarding_enabled, prowler:aws:stepfunctions_statemachine_logging_enabled, prowler:azure:app_function_application_insights_enabled, prowler:azure:app_http_logs_enabled, prowler:azure:appinsights_ensure_is_configured, prowler:azure:keyvault_logging_enabled; cwe: CWE-778; attack: T1685.002; nist_800_53: AU-2, AU-12; other: Microsoft cloud security benchmark v1 LT-3

- [ ] **CLD-LOG-013** Check audit and query logs of databases, search domains and brokers  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds data services that keep no record of logins, queries or schema changes.  
  *Steps:*
  1. List databases, search domains, brokers and replication tasks.
  2. Check that audit logs and log exports are on.
  3. Check log settings for connections, disconnections and statements.
  4. Run a test query and find it in the log.
  *Example:* `aws rds describe-db-instances --query "DBInstances[].[DBInstanceIdentifier,EnabledCloudwatchLogsExports]"; aws opensearch describe-domain --domain-name <d> --query DomainStatus.LogPublishingOptions; az postgres flexible-server parameter list -g <rg> -s <s>; gcloud sql instances describe <i> --format="value(settings.databaseFlags)"; prowler aws --services rds redshift opensearch`  
  *Expected:* Data services log connections, statements and schema changes to central storage. The test query is found in the log.  
  *Refs:* cloud_native_top10: CNAS-10; tool_check: prowler:aws:dms_replication_task_source_logging_enabled, prowler:aws:dms_replication_task_target_logging_enabled, prowler:aws:documentdb_cluster_cloudwatch_log_export, prowler:aws:mq_broker_logging_enabled, prowler:aws:neptune_cluster_integration_cloudwatch_logs, prowler:aws:opensearch_service_domains_audit_logging_enabled, prowler:aws:opensearch_service_domains_cloudwatch_logging_enabled, prowler:aws:rds_cluster_integration_cloudwatch_logs, prowler:aws:rds_instance_integration_cloudwatch_logs, prowler:aws:redshift_cluster_audit_logging, prowler:azure:mysql_flexible_server_audit_log_connection_activated, prowler:azure:mysql_flexible_server_audit_log_enabled, prowler:azure:postgresql_flexible_server_log_checkpoints_on, prowler:azure:postgresql_flexible_server_log_connections_on, prowler:azure:postgresql_flexible_server_log_disconnections_on, prowler:azure:postgresql_flexible_server_log_retention_days_greater_3, prowler:azure:sqlserver_auditing_enabled, prowler:gcp:cloudsql_instance_postgres_enable_pgaudit_flag, prowler:gcp:cloudsql_instance_postgres_log_connections_flag, prowler:gcp:cloudsql_instance_postgres_log_disconnections_flag, prowler:gcp:cloudsql_instance_postgres_log_error_verbosity_flag, prowler:gcp:cloudsql_instance_postgres_log_min_duration_statement_flag, prowler:gcp:cloudsql_instance_postgres_log_min_error_statement_flag, prowler:gcp:cloudsql_instance_postgres_log_min_messages_flag, prowler:gcp:cloudsql_instance_postgres_log_statement_flag; cwe: CWE-778; attack: T1213, T1685.002; nist_800_53: AU-2, AU-12; other: Microsoft cloud security benchmark v1 LT-3

- [ ] **CLD-LOG-014** Check control plane, container and cluster logs  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds clusters and container services that keep no control plane or runtime logs.  
  *Steps:*
  1. List clusters and container services.
  2. Check that all control plane log types are on.
  3. Check that container logs and metrics are on.
  4. Check that the security profile of the cluster is on.
  5. Run a test API call and find it in the log.
  *Example:* `aws eks describe-cluster --name <c> --query cluster.logging; aws ecs describe-clusters --clusters <c> --include SETTINGS; az aks show -n <c> -g <rg> --query "[addonProfiles,securityProfile]"; prowler aws --services eks ecs; prowler azure --services aks`  
  *Expected:* All control plane log types are on. Container logs and metrics are collected. The test call is found in the log.  
  *Refs:* cloud_native_top10: CNAS-10; tool_check: prowler:aws:ecs_cluster_container_insights_enabled, prowler:aws:ecs_task_definitions_logging_block_mode, prowler:aws:ecs_task_definitions_logging_enabled, prowler:aws:eks_control_plane_logging_all_types_enabled, prowler:aws:elasticbeanstalk_environment_cloudwatch_logging_enabled, prowler:aws:elasticbeanstalk_environment_enhanced_health_reporting, prowler:azure:aks_cluster_azure_monitor_enabled, prowler:azure:aks_cluster_defender_enabled; cwe: CWE-778; attack: T1613, T1610; nist_800_53: AU-2, AU-12; other: Microsoft cloud security benchmark v1 LT-3, Microsoft cloud security benchmark v1 LT-1

- [ ] **CLD-LOG-015** Check storage access logs and object change notifications  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds buckets where reads and changes leave no record.  
  *Steps:*
  1. List buckets and containers.
  2. Check that server access logging is on.
  3. Check that change notifications exist for important buckets.
  4. Read a test object and find the record.
  *Example:* `aws s3api get-bucket-logging --bucket <b>; aws s3api get-bucket-notification-configuration --bucket <b>; gcloud storage buckets describe gs://<b> --format="value(logging)"; prowler aws --services s3`  
  *Expected:* Access logs go to a separate protected bucket. Change notifications alert on important buckets. The test read is found in the log.  
  *Refs:* cloud_native_top10: CNAS-10; tool_check: prowler:aws:s3_bucket_event_notifications_enabled, prowler:aws:s3_bucket_server_access_logging_enabled, prowler:gcp:cloudstorage_bucket_logging_enabled; cwe: CWE-778; attack: T1530, T1685.002; nist_800_53: AU-2, AU-12; other: Microsoft cloud security benchmark v1 LT-3

- [ ] **CLD-LOG-016** Check detailed monitoring metrics for hosts and brokers  
  *Severity if fail:* Info | *Type:* Config Review  
  *Objective:* Finds hosts and brokers with coarse metrics that hide short attacks.  
  *Steps:*
  1. List instances, databases and brokers.
  2. Check that detailed or enhanced monitoring is on.
  3. Check that alarms use the detailed metrics.
  *Example:* `aws ec2 describe-instances --query "Reservations[].Instances[].[InstanceId,Monitoring.State]"; aws kafka describe-cluster --cluster-arn <a> --query ClusterInfo.EnhancedMonitoring; prowler aws --services ec2 kafka`  
  *Expected:* Detailed monitoring is on for critical systems. Alarms use one-minute metrics.  
  *Refs:* cloud_native_top10: CNAS-10; tool_check: prowler:aws:ec2_instance_detailed_monitoring_enabled, prowler:aws:kafka_cluster_enhanced_monitoring_enabled; cwe: CWE-778; attack: T1496; nist_800_53: SI-4, AU-6; other: Microsoft cloud security benchmark v1 LT-3

- [ ] **CLD-LOG-017** Check invocation logs and diagnostic logs of AI services  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds AI services that keep no record of model calls and data-plane use.  
  *Steps:*
  1. List the AI services and model endpoints.
  2. Check that invocation logging or diagnostic logging is on.
  3. Check that log storage is encrypted and access is limited.
  4. Make a test model call and find it in the log.
  *Example:* `aws bedrock get-model-invocation-logging-configuration; az monitor diagnostic-settings list --resource <ai-account-id>; prowler aws --services bedrock; prowler azure --services aiservices`  
  *Expected:* Model calls are logged with caller and time. Log storage is encrypted and restricted. The test call is found in the log.  
  *Refs:* cloud_native_top10: CNAS-10; tool_check: prowler:aws:bedrock_model_invocation_logging_enabled, prowler:aws:bedrock_model_invocation_logging_text_data_enabled, prowler:aws:bedrock_model_invocation_logs_encryption_enabled, prowler:aws:cloudtrail_agentcore_data_events_enabled, prowler:aws:cloudwatch_log_group_agentcore_data_protection_policy_enabled, prowler:azure:aiservices_account_diagnostic_logging_enabled; cwe: CWE-778; attack: T1685.002, T1496; nist_800_53: AU-2, AU-9; other: Microsoft cloud security benchmark v1 LT-3


## NET

- [ ] **CLD-NET-007** Check CDN origin access, dangling origins and edge settings  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds CDN origins that anyone can reach directly or that point to buckets nobody owns.  
  *Steps:*
  1. List CDN distributions and their origins.
  2. Check that each storage origin allows only the CDN identity.
  3. Find origins that point to deleted buckets.
  4. Check the default root object and the geo restrictions.
  5. Request an object directly from the origin.
  *Example:* `aws cloudfront list-distributions; aws cloudfront get-distribution-config --id <i>; aws s3api head-bucket --bucket <origin-bucket>; curl -i https://<bucket>.s3.amazonaws.com/<object>; prowler aws --services cloudfront`  
  *Expected:* Storage origins accept the CDN identity only. No origin points to a missing bucket. The direct origin request is denied.  
  *Refs:* cloud_native_top10: CNAS-6; tool_check: prowler:aws:cloudfront_distributions_default_root_object, prowler:aws:cloudfront_distributions_geo_restrictions_enabled, prowler:aws:cloudfront_distributions_multiple_origin_failover_configured, prowler:aws:cloudfront_distributions_s3_origin_access_control, prowler:aws:cloudfront_distributions_s3_origin_non_existent_bucket; cwe: CWE-284; attack: T1584, T1530; nist_800_53: SC-7, AC-3; other: Microsoft cloud security benchmark v1 NS-2, Microsoft cloud security benchmark v1 NS-6

- [ ] **CLD-NET-008** Check security group hygiene, peering, transit and VPC routing paths  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds unused or wide network rules, open transit attachments and unsafe peering routes.  
  *Steps:*
  1. List security groups, peering links, transit gateways and endpoints.
  2. Find unused groups and groups from setup wizards.
  3. Find groups with a very large number of rules.
  4. Check that peering routes are limited to needed ranges.
  5. Check that transit attachments need approval.
  *Example:* `aws ec2 describe-security-groups; aws ec2 describe-vpc-peering-connections; aws ec2 describe-transit-gateways --query "TransitGateways[].Options.AutoAcceptSharedAttachments"; aws ec2 describe-route-tables; gcloud compute instances describe <i> --format="value(canIpForward,networkInterfaces)"; prowler aws --services ec2 vpc`  
  *Expected:* No unused or wizard-made group remains. Peering routes are least-privilege. Transit attachments need approval. Hosts have one network interface unless a design needs more.  
  *Refs:* cloud_native_top10: CNAS-6; tool_check: prowler:aws:ec2_instance_uses_single_eni, prowler:aws:ec2_securitygroup_from_launch_wizard, prowler:aws:ec2_securitygroup_with_many_ingress_egress_rules, prowler:aws:ec2_transitgateway_auto_accept_vpc_attachments, prowler:aws:vpc_endpoint_for_ec2_enabled, prowler:aws:vpc_peering_routing_tables_with_least_privilege, prowler:gcp:compute_instance_ip_forwarding_is_enabled, prowler:gcp:compute_instance_single_network_interface, prowler:gcp:compute_network_default_in_use, prowler:gcp:compute_network_not_legacy; cwe: CWE-923; attack: T1021.007, T1599; nist_800_53: SC-7, CM-7; other: Microsoft cloud security benchmark v1 NS-7, Microsoft cloud security benchmark v1 NS-1

- [ ] **CLD-NET-009** Check network firewall coverage and flow visibility for each VPC  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds VPCs with no central traffic inspection or network monitor.  
  *Steps:*
  1. List VPCs and virtual networks.
  2. Check that a firewall or bastion service covers each one.
  3. Check the default action of firewall policies.
  4. Check that rule groups are linked.
  5. Check that the network monitor is on in each region.
  *Example:* `aws network-firewall list-firewalls; aws network-firewall describe-firewall-policy --firewall-policy-name <p>; az network bastion list; az network watcher list; prowler aws --services networkfirewall; prowler azure --services network`  
  *Expected:* Each VPC has traffic inspection with a deny or alert default. Rule groups are linked. A network monitor runs in each region.  
  *Refs:* cloud_native_top10: CNAS-6; tool_check: prowler:aws:networkfirewall_in_all_vpc, prowler:aws:networkfirewall_policy_default_action_fragmented_packets, prowler:aws:networkfirewall_policy_default_action_full_packets, prowler:aws:networkfirewall_policy_rule_group_associated, prowler:azure:network_bastion_host_exists, prowler:azure:network_watcher_enabled; cwe: CWE-693; attack: T1048, T1071; nist_800_53: SC-7, SI-4; other: Microsoft cloud security benchmark v1 NS-3, Microsoft cloud security benchmark v1 NS-4

- [ ] **CLD-NET-010** Check DNSSEC, domain transfer lock and mail domain signing  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds domains with weak DNSSEC, no transfer lock or no mail signing.  
  *Steps:*
  1. List domains and public DNS zones.
  2. Check that DNSSEC is on and does not use RSASHA1.
  3. Check that the transfer lock is on.
  4. Check that privacy protection hides contact data.
  5. Check DKIM for mail domains.
  *Example:* `aws route53domains get-domain-detail --domain-name <d>; gcloud dns managed-zones describe <z> --format="value(dnssecConfig)"; aws ses get-identity-dkim-attributes --identities <d>; dig +dnssec <d>; prowler gcp --services dns; prowler aws --services route53 ses`  
  *Expected:* DNSSEC is on with strong algorithms. Domains have transfer lock and privacy protection. Mail domains sign with DKIM.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:route53_domains_privacy_protection_enabled, prowler:aws:route53_domains_transferlock_enabled, prowler:aws:ses_identity_dkim_enabled, prowler:gcp:dns_dnssec_disabled, prowler:gcp:dns_rsasha1_in_use_to_key_sign_in_dnssec, prowler:gcp:dns_rsasha1_in_use_to_zone_sign_in_dnssec; cwe: CWE-345; attack: T1584.001, T1584.002; nist_800_53: SC-20, SC-21; other: Microsoft cloud security benchmark v1 NS-10

- [ ] **CLD-NET-011** Find dangling DNS records that allow subdomain takeover  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds DNS records that point to released IP addresses or deleted services.  
  *Steps:*
  1. Export all DNS records of each zone.
  2. Find records that point to cloud IP addresses or service names.
  3. Check that each target still belongs to the account.
  4. Try to claim one released target in a test.
  *Example:* `aws route53 list-resource-record-sets --hosted-zone-id <z>; aws ec2 describe-addresses; dig <name>; subjack -w <list>; prowler aws --check route53_dangling_ip_subdomain_takeover`  
  *Expected:* Every record points to a resource that the account owns. Records for removed resources are deleted before the resource is released.  
  *Refs:* cloud_native_top10: CNAS-8; tool_check: prowler:aws:route53_dangling_ip_subdomain_takeover; cwe: CWE-1188; attack: T1584.001, T1583.001; nist_800_53: SC-20, CM-8; other: Microsoft cloud security benchmark v1 NS-10, Microsoft cloud security benchmark v1 AM-3

- [ ] **CLD-NET-012** Check managed admin access to VMs and block serial ports  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds VMs that use shared SSH keys, serial ports or open admin ports.  
  *Steps:*
  1. List VMs and the admin access method of each.
  2. Check that project-wide SSH keys are blocked.
  3. Check that OS Login, session manager or just-in-time access is in use.
  4. Check that serial port access is off.
  5. Check connection logs for remote access endpoints.
  *Example:* `gcloud compute instances describe <i> --format="value(metadata.items)"; gcloud compute project-info describe; az vm show -n <v> -g <rg> --query osProfile.linuxConfiguration.disablePasswordAuthentication; az security jit-policy list; aws ssm describe-instance-information; aws ec2 describe-client-vpn-endpoints; prowler gcp --services compute`  
  *Expected:* Admins reach VMs through managed channels with identity and logs. Project-wide keys and serial ports are off. Password login is off.  
  *Refs:* cloud_native_top10: CNAS-6, CNAS-3; tool_check: prowler:aws:ec2_client_vpn_endpoint_connection_logging_enabled, prowler:aws:ec2_instance_managed_by_ssm, prowler:azure:vm_jit_access_enabled, prowler:azure:vm_linux_enforce_ssh_authentication, prowler:gcp:compute_instance_block_project_wide_ssh_keys_disabled, prowler:gcp:compute_instance_serial_ports_in_use, prowler:gcp:compute_project_os_login_enabled; cwe: CWE-798; attack: T1021, T1098.004, T1133; nist_800_53: AC-17, AC-2; other: Microsoft cloud security benchmark v1 PA-2, Microsoft cloud security benchmark v1 PA-6, Microsoft cloud security benchmark v1 NS-8

- [ ] **CLD-NET-013** Check VM boot integrity, confidential computing and enclave host exposure  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds VMs without boot integrity checks and enclave hosts that are open to the network.  
  *Steps:*
  1. List VMs and their security type.
  2. Check that secure boot and a virtual TPM are on.
  3. Check that confidential VMs are used for sensitive work.
  4. Check that enclave hosts have no public address and limited inbound rules.
  5. Check the virtualization type of old instances.
  *Example:* `gcloud compute instances describe <i> --format="value(shieldedInstanceConfig,confidentialInstanceConfig)"; az vm show -n <v> -g <rg> --query securityProfile; aws ec2 describe-instances --query "Reservations[].Instances[].[InstanceId,VirtualizationType,EnclaveOptions]"; prowler gcp --services compute`  
  *Expected:* Boot integrity checks are on. Sensitive work runs on confidential VMs. Enclave hosts are private with narrow inbound rules. No old paravirtual instances remain.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:ec2_confidential_workload_host_not_running, prowler:aws:ec2_confidential_workload_host_unrestricted_ingress, prowler:aws:ec2_confidential_workload_host_vsock_proxy_exposed, prowler:aws:ec2_instance_paravirtual_type, prowler:azure:vm_trusted_launch_enabled, prowler:gcp:compute_instance_confidential_computing_enabled, prowler:gcp:compute_instance_shielded_vm_enabled; cwe: CWE-693; attack: T1542; nist_800_53: SI-7, SC-39; other: Microsoft cloud security benchmark v1 PV-3, Microsoft cloud security benchmark v1 PV-4

- [ ] **CLD-NET-014** Check root and terminal access on managed notebooks  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds notebook users that can get root, a terminal or download files.  
  *Steps:*
  1. List notebook instances and workbenches.
  2. Check that root access is off.
  3. Check if terminal access and file download are off for sensitive data.
  4. Open a test notebook and try to get root.
  *Example:* `aws sagemaker describe-notebook-instance --notebook-instance-name <n> --query RootAccess; gcloud workbench instances describe <i> --location=<l>; prowler aws --services sagemaker; prowler gcp --services vertexai`  
  *Expected:* Users have no root access. Terminal and file download are off for sensitive data. The root test fails.  
  *Refs:* cloud_native_top10: CNAS-3; tool_check: prowler:aws:sagemaker_notebook_instance_root_access_disabled, prowler:gcp:vertexai_workbench_instance_auto_upgrade_enabled, prowler:gcp:vertexai_workbench_instance_file_download_disabled, prowler:gcp:vertexai_workbench_instance_root_access_disabled, prowler:gcp:vertexai_workbench_instance_terminal_access_disabled; cwe: CWE-250; attack: T1059, T1048; nist_800_53: AC-6, CM-7; other: Microsoft cloud security benchmark v1 PA-7, Microsoft cloud security benchmark v1 PV-3


## SEC

- [ ] **CLD-SEC-006** Check KMS key use, deletion state, multi-region keys and enclave attestation  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds unused keys, keys set for deletion and keys with weak attestation conditions.  
  *Steps:*
  1. List all keys with state and last use.
  2. Find unused keys and keys pending deletion.
  3. Find multi-region keys and the reason for each.
  4. Read key policies for attestation conditions.
  5. Check that debug mode enclaves cannot use the key.
  *Example:* `aws kms list-keys; aws kms describe-key --key-id <k>; aws kms get-key-policy --key-id <k> --policy-name default; aws kms list-grants --key-id <k>; prowler aws --services kms`  
  *Expected:* Unused keys are removed after review. No key is set for deletion without approval. Key policies need attestation and block debug enclaves.  
  *Refs:* cloud_native_top10: CNAS-5; tool_check: prowler:aws:kms_cmk_are_used, prowler:aws:kms_cmk_not_deleted_unintentionally, prowler:aws:kms_cmk_not_multi_region, prowler:aws:kms_key_enclave_attestation_bypassable_path, prowler:aws:kms_key_enclave_attestation_no_deployment_binding, prowler:aws:kms_key_enclave_attestation_not_enforced, prowler:aws:kms_key_enclave_attestation_pcr_mismatch, prowler:aws:kms_key_enclave_attestation_unknown_image, prowler:aws:kms_key_enclave_debug_attestation_detected; cwe: CWE-311; attack: T1485, T1553; nist_800_53: SC-12, SC-28; other: Microsoft cloud security benchmark v1 DP-6, Microsoft cloud security benchmark v1 DP-8


## SRV

- [ ] **CLD-SRV-007** Check function dead letter queues and cross-account layers  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds functions that lose failed events or load code layers from outside accounts.  
  *Steps:*
  1. List all functions and their layers.
  2. Find layers owned by other accounts.
  3. Check that each async function has a dead letter queue or failure target.
  4. Send a failing event to a test function.
  *Example:* `aws lambda list-functions; aws lambda get-function --function-name <f> --query "Configuration.[Layers,DeadLetterConfig]"; prowler aws --check awslambda_function_no_dead_letter_queue awslambda_function_using_cross_account_layers`  
  *Expected:* Layers come from trusted accounts only. Failed events go to a dead letter queue with an alert. The failing test event is stored and alerted.  
  *Refs:* cloud_native_top10: CNAS-4, CNAS-2; tool_check: prowler:aws:awslambda_function_no_dead_letter_queue, prowler:aws:awslambda_function_using_cross_account_layers; cwe: CWE-829; attack: T1648, T1195.002; nist_800_53: SI-7, SR-3; other: Microsoft cloud security benchmark v1 PV-3

- [ ] **CLD-SRV-008** Check client certificates and cache encryption on API gateways  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds API stages that send unauthenticated calls to backends or cache clear text data.  
  *Steps:*
  1. List API stages.
  2. Check that stages use a client certificate to the backend.
  3. Check that the stage cache is encrypted.
  4. Call the backend directly without the certificate.
  *Example:* `aws apigateway get-stage --rest-api-id <id> --stage-name <s> --query "[clientCertificateId,cacheClusterEnabled]"; aws apigateway get-rest-apis; curl -i https://<backend>/; prowler aws --services apigateway`  
  *Expected:* The backend accepts calls with the gateway certificate only. The stage cache is encrypted. The direct call is denied.  
  *Refs:* cloud_native_top10: CNAS-3; tool_check: prowler:aws:apigateway_restapi_cache_encrypted, prowler:aws:apigateway_restapi_client_certificate_enabled; cwe: CWE-306; attack: T1190; nist_800_53: SC-8, SC-28; other: Microsoft cloud security benchmark v1 NS-2, Microsoft cloud security benchmark v1 IM-4

- [ ] **CLD-SRV-009** Check container task definitions for privilege, host sharing and root file system  
  *Severity if fail:* High | *Type:* Config Review, Code Review  
  *Objective:* Finds tasks that run privileged, share the host or write to the root file system.  
  *Steps:*
  1. List the task definitions in use.
  2. Find privileged containers.
  3. Find host network and host process sharing.
  4. Check that the root file system is read-only.
  5. Check that logging is on.
  *Example:* `aws ecs list-task-definitions; aws ecs describe-task-definition --task-definition <t> --query "taskDefinition.[networkMode,pidMode,containerDefinitions[].[privileged,readonlyRootFilesystem]]"; prowler aws --services ecs`  
  *Expected:* No task is privileged or shares the host. Root file systems are read-only. Logging is on for every container.  
  *Refs:* cloud_native_top10: CNAS-1; tool_check: prowler:aws:ecs_task_definitions_containers_readonly_access, prowler:aws:ecs_task_definitions_host_namespace_not_shared, prowler:aws:ecs_task_definitions_host_networking_mode_users, prowler:aws:ecs_task_definitions_no_privileged_containers; cwe: CWE-250; attack: T1611, T1610; nist_800_53: CM-7, AC-6; other: Microsoft cloud security benchmark v1 PV-3


## SUP

- [ ] **CLD-SUP-005** Check image tag immutability and lifecycle rules in registries  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds registries where a tag can point to a new image or old images pile up.  
  *Steps:*
  1. List the repositories.
  2. Check that tag immutability is on.
  3. Check that a lifecycle policy removes old images.
  4. Push a changed image to an existing tag in a test repository.
  *Example:* `aws ecr describe-repositories --query "repositories[].[repositoryName,imageTagMutability]"; aws ecr get-lifecycle-policy --repository-name <r>; prowler aws --services ecr`  
  *Expected:* Tags are immutable. Lifecycle rules remove old images. The push to an existing tag fails.  
  *Refs:* cloud_native_top10: CNAS-4; tool_check: prowler:aws:ecr_repositories_lifecycle_policy_enabled, prowler:aws:ecr_repositories_tag_immutability; cwe: CWE-494; attack: T1525, T1195.002; nist_800_53: CM-2, SI-7; other: Microsoft cloud security benchmark v1 DS-2, Microsoft cloud security benchmark v1 AM-3

- [ ] **CLD-SUP-006** Check database vulnerability assessment scans and reports  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds databases with no recurring vulnerability scan or no report recipient.  
  *Steps:*
  1. List the managed database servers.
  2. Check that vulnerability assessment is on.
  3. Check that scans run each week.
  4. Check that reports go to the admins.
  5. Open the latest report and examine the findings.
  *Example:* `az sql server va-setting show -g <rg> -n <s>; az sql db threat-policy show -g <rg> -s <s> -n <d>; prowler azure --services sqlserver`  
  *Expected:* Vulnerability assessment runs on a schedule. Reports go to the admins. Open findings have an owner and a due date.  
  *Refs:* cloud_native_top10: CNAS-7; tool_check: prowler:azure:sqlserver_va_emails_notifications_admins_enabled, prowler:azure:sqlserver_va_periodic_recurring_scans_enabled, prowler:azure:sqlserver_va_scan_reports_configured, prowler:azure:sqlserver_vulnerability_assessment_enabled; cwe: CWE-1188; attack: T1190; nist_800_53: RA-5, SI-2; other: Microsoft cloud security benchmark v1 PV-5, Microsoft cloud security benchmark v1 PV-6


## IAC

- [ ] **CLD-IAC-001** Review who can run and change infrastructure code  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds identities with wide rights to deploy or edit infrastructure.  
  *Steps:*
  1. List the people and automation roles that can apply infrastructure changes.
  2. Check that each role has only the rights its stack needs.
  3. Check that changes need review and a protected branch.
  4. Check that the rights granted to created resources are limited.
  *Example:* `aws iam list-attached-role-policies --role-name <deploy-role>; git log --merges <iac-repo>; checkov -d <iac-dir>`  
  *Expected:* Deploy roles have limited rights per stack. Changes need review. The resources that the code creates get minimal permissions.  
  *Refs:* cloud_native_top10: CNAS-1, CNAS-3; cheatsheet: Infrastructure_as_Code_Security_Cheat_Sheet; cwe: CWE-272; attack: T1578, T1578.005; nist_800_53: CM-3, CM-5, AC-6  
  *See:* CICD-IAM-001

- [ ] **CLD-IAC-002** Scan infrastructure code for misconfigurations before deploy  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds insecure settings in templates before they reach a cloud account.  
  *Steps:*
  1. Run an IaC scanner on all templates and modules.
  2. Review high findings such as public access, open ports and missing encryption.
  3. Check that failed checks block the merge.
  4. Compare the scan result to the posture scan of the account.
  *Example:* `checkov -d <iac-dir>; trivy config <iac-dir>; tfsec <iac-dir>`  
  *Expected:* Templates have no high findings without a written exception. The scan gates the deploy and matches the live posture.  
  *Refs:* cloud_native_top10: CNAS-1; cheatsheet: Infrastructure_as_Code_Security_Cheat_Sheet; cwe: CWE-1188; attack: T1578; nist_800_53: CM-6, SA-11  
  *See:* CICD-VULN-005

- [ ] **CLD-IAC-003** Check for configuration drift and immutable infrastructure  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds live resources that differ from the code, so manual changes escape review.  
  *Steps:*
  1. Run a drift check of the live account against the code.
  2. List resources that someone changed by hand.
  3. Check who can change resources outside the pipeline.
  4. Check that changes replace the resource and do not patch it in place.
  *Example:* `terraform plan -detailed-exitcode; aws cloudformation detect-stack-drift --stack-name <s>; az deployment group what-if -g <rg> --template-file <t>`  
  *Expected:* The live state matches the code. Manual changes are blocked or raise an alert. Changes are made by new versions of the resource.  
  *Refs:* cloud_native_top10: CNAS-1, CNAS-8; cheatsheet: Infrastructure_as_Code_Security_Cheat_Sheet; cwe: CWE-1188; attack: T1578; nist_800_53: CM-2, CM-3

- [ ] **CLD-IAC-004** Check deploy-time tags, inventory and secrets handling in infrastructure code  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds templates that create untagged resources or place secrets in code and state.  
  *Steps:*
  1. Check that templates set owner and purpose tags on every resource.
  2. Search templates, variables and state for secret values.
  3. Check that secrets come from a secret store at deploy.
  4. Check access to state files.
  *Example:* `checkov -d <iac-dir>; gitleaks detect --source <iac-repo>; grep -rIiE "password|secret|key" <iac-dir>`  
  *Expected:* Every created resource has tags and an inventory entry. Templates and state hold no secrets, and state files have limited access.  
  *Refs:* cloud_native_top10: CNAS-8, CNAS-5; cheatsheet: Infrastructure_as_Code_Security_Cheat_Sheet, Secrets_Management_Cheat_Sheet; cwe: CWE-798; attack: T1552.001; nist_800_53: CM-8, IA-5  
  *See:* CICD-CRED-003


## IAM

- [ ] **CLD-IAM-001** Find over-permissive IAM roles and policies  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds identities with wildcard actions or resources and more rights than their task needs.  
  *Steps:*
  1. Export all policies and role assignments.
  2. Find Allow statements with * for action or resource.
  3. List the identities that can change IAM or create roles.
  4. Compare actual use with granted rights.
  *Example:* `aws iam get-account-authorization-details; aws accessanalyzer list-findings; az role assignment list --all; gcloud projects get-iam-policy <p>; prowler aws --services iam`  
  *Expected:* No identity has wildcard admin rights without a written reason. Each role holds only the actions and resources its task needs.  
  *Refs:* cloud_native_top10: CNAS-3; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet, Serverless_FaaS_Security_Cheat_Sheet; cwe: CWE-272, CWE-269; attack: T1078.004, T1098.003; nist_800_53: AC-6, AC-2

- [ ] **CLD-IAM-002** Check that workloads use short-lived identities and not stored keys  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds access keys and service credentials that stay valid after a leak.  
  *Steps:*
  1. List all access keys, service account keys and client secrets.
  2. Find keys older than the policy age or never used.
  3. Check that workloads use role-based or federated credentials.
  4. Revoke unused keys in a test or after approval.
  *Example:* `aws iam generate-credential-report; aws iam list-access-keys --user-name <u>; gcloud iam service-accounts keys list --iam-account <sa>; az ad app credential list --id <app>`  
  *Expected:* Workloads use short-lived credentials from roles or workload identity federation. Remaining static keys are few, rotated and owned.  
  *Refs:* cloud_native_top10: CNAS-3, CNAS-5; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet, Secrets_Management_Cheat_Sheet, Serverless_FaaS_Security_Cheat_Sheet; cwe: CWE-798, CWE-522; attack: T1078.004, T1552.005; nist_800_53: IA-5, AC-2

- [ ] **CLD-IAM-003** Check human access: SSO, MFA and the root or owner account  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds cloud accounts where people sign in with passwords alone or share admin accounts.  
  *Steps:*
  1. Check that people sign in through the central identity provider.
  2. Check that MFA is on for all console and CLI users.
  3. Check that the root or owner account has MFA, no keys and a recovery process.
  4. List local users and shared accounts.
  *Example:* `aws iam get-account-summary; aws iam list-virtual-mfa-devices; az ad user list --query "[].userPrincipalName"; gcloud organizations get-iam-policy <org>`  
  *Expected:* All human users sign in with SSO and MFA. The root account has no access keys and is used only for break-glass work.  
  *Refs:* cloud_native_top10: CNAS-3; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet, Secrets_Management_Cheat_Sheet; cwe: CWE-287; attack: T1078.004, T1136.003; nist_800_53: IA-2, AC-2

- [ ] **CLD-IAM-004** Find stale accounts, roles and external trusts  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds unused identities, old roles and cross-account trusts that give unknown parties access.  
  *Steps:*
  1. List identities with no sign-in or API use in the last 90 days.
  2. List roles with trust to other accounts, external IDs or public principals.
  3. Check each trust against the list of known partners.
  4. Remove or restrict the entries that have no owner.
  *Example:* `aws iam get-credential-report; aws iam list-roles --query "Roles[].AssumeRolePolicyDocument"; aws accessanalyzer list-analyzers; az role assignment list --all --include-inherited`  
  *Expected:* Every identity and trust has an owner and recent use. Unused identities are removed. Trusts name specific accounts and conditions.  
  *Refs:* cloud_native_top10: CNAS-3, CNAS-8; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet; cwe: CWE-284, CWE-269; attack: T1078.004, T1136.003, T1098.003; nist_800_53: AC-2, AC-6

- [ ] **CLD-IAM-005** Test for IAM privilege escalation paths  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds identities that can raise their own rights through rights such as policy edit, role pass or key creation.  
  *Steps:*
  1. Pick a low-rights test identity.
  2. List what it can do to IAM, compute and function resources.
  3. Try actions that attach a stronger policy, pass a role or create a new key.
  4. Record each path that works.
  *Example:* `pacu (AWS); aws iam simulate-principal-policy --policy-source-arn <arn> --action-names iam:PassRole iam:AttachUserPolicy`  
  *Expected:* A low-rights identity cannot raise its rights. Rights to pass roles and edit policies are held by few admins and have conditions.  
  *Refs:* cloud_native_top10: CNAS-3; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet; cwe: CWE-269, CWE-266; attack: T1548.005, T1098.003; nist_800_53: AC-6, AC-5

- [ ] **CLD-IAM-006** Test microservice and cloud API endpoints for missing authentication  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds internal APIs and managed service endpoints that answer without credentials.  
  *Steps:*
  1. List API gateway routes, function URLs and service endpoints.
  2. Call each one with no credentials.
  3. Call each internal service directly, skipping the gateway.
  4. Record each response that returns data.
  *Example:* `curl -i https://<endpoint>/<path>; aws apigateway get-rest-apis; aws lambda list-function-url-configs --function-name <f>; az functionapp function show --name <f> -g <rg> -n <fn>`  
  *Expected:* Every endpoint needs authentication and authorization. Calls without valid credentials return 401 or 403.  
  *Refs:* cloud_native_top10: CNAS-3; cheatsheet: Microservices_Security_Cheat_Sheet, Serverless_FaaS_Security_Cheat_Sheet; cwe: CWE-306, CWE-862; attack: T1190; nist_800_53: IA-2, AC-3  
  *See:* API-MSVC-001, API-MSVC-004


## INJ

- [ ] **CLD-INJ-001** List all event sources that feed code and treat each as untrusted  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds event paths such as storage triggers, queues and topics that carry attacker-controlled data.  
  *Steps:*
  1. List functions, workers and services that react to events.
  2. Map each event source: API call, object upload, queue, topic, IoT message or schedule.
  3. Mark which fields an outside party controls, such as object names and metadata.
  4. Rank sources by exposure.
  *Example:* `aws lambda list-event-source-mappings; aws s3api get-bucket-notification-configuration --bucket <b>; gcloud eventarc triggers list; az eventgrid topic list`  
  *Expected:* Every event source is listed with its owner and the fields that outside parties control. Each handler validates these fields.  
  *Refs:* cloud_native_top10: CNAS-2; cheatsheet: Serverless_FaaS_Security_Cheat_Sheet; cwe: CWE-20; attack: T1648; nist_800_53: SI-10

- [ ] **CLD-INJ-002** Send crafted values through event fields to the handlers  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds handlers that pass event data into commands, queries or templates without checks.  
  *Steps:*
  1. Create a test object with a name that holds shell and SQL meta characters.
  2. Send a queue message with the same values in each field.
  3. Watch the handler logs and downstream systems for errors or changed behavior.
  4. Send oversize, wrong type and extra fields.
  *Example:* `aws s3 cp test.txt "s3://<b>/a;id;.txt"; aws sqs send-message --queue-url <q> --message-body "{\"id\":\"1 OR 1=1\"}"; gcloud pubsub topics publish <t> --message "<payload>"`  
  *Expected:* Handlers reject or neutralize malformed values. No command runs, no query changes, and errors show no internals.  
  *Refs:* cloud_native_top10: CNAS-2; cheatsheet: Serverless_FaaS_Security_Cheat_Sheet; cwe: CWE-20, CWE-78, CWE-89; attack: T1648, T1059.009; nist_800_53: SI-10  
  *See:* WEB-INJ-001, WEB-INJ-014, WEB-INJ-025

- [ ] **CLD-INJ-003** Check input validation, parameterized access and least rights in handlers  
  *Severity if fail:* High | *Type:* Code Review  
  *Objective:* Finds handler code that builds queries or commands from event data, with roles that make the damage worse.  
  *Steps:*
  1. Read the handler code for string-built queries and shell calls.
  2. Check for allow-list validation of type, length and format.
  3. Check that data access uses parameterized calls.
  4. Check that the handler role cannot reach other data.
  *Example:* `semgrep --config auto <handler-dir>; grep -rnE "os.system|subprocess|exec\(|eval\(" <handler-dir>`  
  *Expected:* Handlers validate input with allow-lists and use parameterized access. The role limits the damage of a flaw.  
  *Refs:* cloud_native_top10: CNAS-2; cheatsheet: Serverless_FaaS_Security_Cheat_Sheet; cwe: CWE-20, CWE-89, CWE-78; attack: T1648; nist_800_53: SI-10, AC-6  
  *See:* WEB-INJ-004

- [ ] **CLD-INJ-004** Check message and event integrity in queues, topics and buses  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds messaging systems where any writer can inject events that other services trust.  
  *Steps:*
  1. List who can publish to each queue, topic and event bus.
  2. Check the access policies for public or wide principals.
  3. Publish a forged event with a test identity that has no rights.
  4. Check that consumers check the source and format.
  *Example:* `aws sqs get-queue-attributes --queue-url <q> --attribute-names Policy; aws sns get-topic-attributes --topic-arn <t>; gcloud pubsub topics get-iam-policy <t>`  
  *Expected:* Only named producers can publish. Consumers check source and message format, and a forged message is rejected.  
  *Refs:* cloud_native_top10: CNAS-2, CNAS-3; cheatsheet: Serverless_FaaS_Security_Cheat_Sheet; cwe: CWE-345, CWE-862; attack: T1648; nist_800_53: SI-10, AC-3


## LOG

- [ ] **CLD-LOG-001** Check that audit logs are on in every account and region  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds accounts and regions where cloud API activity leaves no record.  
  *Steps:*
  1. List all accounts, subscriptions, projects and regions in use.
  2. Check that the audit trail is on for each, with management and data events.
  3. Make a test change and find its record.
  4. Check that the record shows identity, source address and time.
  *Example:* `aws cloudtrail describe-trails; aws cloudtrail get-trail-status --name <t>; az monitor diagnostic-settings subscription list; gcloud logging sinks list`  
  *Expected:* Audit logs cover all accounts and regions. The test change appears with identity, source address and time.  
  *Refs:* cloud_native_top10: CNAS-10; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet, Logging_Cheat_Sheet; cwe: CWE-778; attack: T1685.002, T1651; nist_800_53: AU-2, AU-12

- [ ] **CLD-LOG-002** Check protection and retention of cloud logs  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds logs that an attacker with account access can edit or delete.  
  *Steps:*
  1. Find the storage target of each log source.
  2. Check that the target is in a separate account with write-once or locked storage.
  3. Check who can delete or change the logs and the log settings.
  4. Check the retention time against the rules.
  *Example:* `aws cloudtrail get-trail --name <t> --query Trail.LogFileValidationEnabled; aws s3api get-object-lock-configuration --bucket <b>; gcloud logging buckets list`  
  *Expected:* Logs go to a separate protected store with integrity checks. Few identities can change or delete logs, and retention meets the rules.  
  *Refs:* cloud_native_top10: CNAS-10; cheatsheet: Logging_Cheat_Sheet, Secure_Cloud_Architecture_Cheat_Sheet, Network_Segmentation_Cheat_Sheet; cwe: CWE-778; attack: T1685.002, T1070; nist_800_53: AU-9, AU-11

- [ ] **CLD-LOG-003** Check network flow, DNS and load balancer logs  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds networks where traffic between services and to the Internet cannot be traced.  
  *Steps:*
  1. List VPCs, subnets and load balancers.
  2. Check that flow logs, DNS logs and access logs are on.
  3. Make a test connection between two services.
  4. Find it in the logs.
  *Example:* `aws ec2 describe-flow-logs; az network watcher flow-log list -l <region>; gcloud compute networks subnets describe <s> --format="value(logConfig)"`  
  *Expected:* Flow, DNS and load balancer logs are on for all networks. The test connection appears in the log.  
  *Refs:* cloud_native_top10: CNAS-10, CNAS-6; cheatsheet: Logging_Cheat_Sheet, Secure_Cloud_Architecture_Cheat_Sheet; cwe: CWE-778; attack: T1046, T1048; nist_800_53: AU-2, AU-12

- [ ] **CLD-LOG-004** Test alerts for security events and cost or usage anomalies  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds environments where known attack steps raise no alert.  
  *Steps:*
  1. List the alert rules for sign-in, IAM change, log change, key use and storage policy change.
  2. Do a test action for each rule in a test account.
  3. Check that the alert reaches the response team.
  4. Check alerts for unusual usage of compute, functions, databases and cost.
  *Example:* `aws cloudwatch describe-alarms; aws events list-rules; aws budgets describe-budgets --account-id <id>; az monitor activity-log alert list; gcloud alpha monitoring policies list`  
  *Expected:* Each test action raises an alert in the agreed time. Alerts for usage and cost anomalies exist and have an owner.  
  *Refs:* cloud_native_top10: CNAS-10, CNAS-9; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet, Logging_Cheat_Sheet; cwe: CWE-778; attack: T1685.002, T1496; nist_800_53: AU-6, SI-4  
  *See:* WEB-LOG-014

- [ ] **CLD-LOG-005** Check that logs hold no secrets and that time sources agree  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds logs that expose credentials or cannot be matched across systems.  
  *Steps:*
  1. Search sample logs of functions, gateways and agents for tokens and keys.
  2. Check the field list against the log standard.
  3. Compare timestamps of one request across three systems.
  4. Check the time sync setting of the hosts.
  *Example:* `grep -rIiE "password|token|secret|authorization" <log-sample>; compare timestamps of one correlation ID`  
  *Expected:* Logs hold no credentials or protected personal data. Timestamps agree and every record carries a correlation ID.  
  *Refs:* cloud_native_top10: CNAS-10; cheatsheet: Logging_Cheat_Sheet, Microservices_Security_Cheat_Sheet, Secure_Cloud_Architecture_Cheat_Sheet; cwe: CWE-532; attack: T1552.001; nist_800_53: AU-3  
  *See:* WEB-LOG-006


## NET

- [ ] **CLD-NET-001** Check the network is split into frontend, middleware and backend zones  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds flat networks where a breach of a web server gives direct access to databases and key stores.  
  *Steps:*
  1. Get the network diagram and the list of VPCs and subnets.
  2. Map each system to a zone: frontend, middleware or backend.
  3. Check the rules between zones and the allowed flows.
  4. From a frontend host, try to reach a backend host.
  *Example:* `aws ec2 describe-subnets; aws ec2 describe-route-tables; az network vnet list; gcloud compute networks subnets list; nmap -Pn -p <db-port> <backend-host>`  
  *Expected:* Frontend hosts cannot reach backend systems directly. Each flow between zones is allowed by a written rule.  
  *Refs:* cloud_native_top10: CNAS-6; cheatsheet: Network_Segmentation_Cheat_Sheet, Secure_Cloud_Architecture_Cheat_Sheet; cwe: CWE-923, CWE-668; attack: T1046; nist_800_53: SC-7, AC-4

- [ ] **CLD-NET-002** Find internal services that the Internet can reach  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds microservices, admin tools and queues exposed by load balancers, public IPs or function URLs.  
  *Steps:*
  1. List all public IP addresses, load balancers and public endpoints.
  2. Map each one to a service and an owner.
  3. Scan the public addresses for open ports.
  4. Mark each endpoint that is not meant to be public.
  *Example:* `aws ec2 describe-addresses; aws elbv2 describe-load-balancers --query "LoadBalancers[?Scheme==\`internet-facing\`]"; az network public-ip list; gcloud compute addresses list; nmap -sV <ip>`  
  *Expected:* Only reviewed edge services are public. Internal services use private addresses or private endpoints.  
  *Refs:* cloud_native_top10: CNAS-6, CNAS-8; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet, Network_Segmentation_Cheat_Sheet, Microservices_Security_Cheat_Sheet; cwe: CWE-668; attack: T1190, T1133; nist_800_53: SC-7, CM-7

- [ ] **CLD-NET-003** Check egress filtering and monitoring of traffic to unknown domains  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds workloads that can send data to any Internet host with no record.  
  *Steps:*
  1. List egress routes, NAT gateways and egress firewall rules.
  2. From a test workload, connect to an unlisted external domain.
  3. Check for DNS and flow logs of the connection.
  4. Check for an alert on traffic to unknown or bad domains.
  *Example:* `aws ec2 describe-nat-gateways; aws network-firewall list-firewalls; curl -m 3 https://example.org (from a test workload); query flow logs for the connection`  
  *Expected:* Egress is limited to approved destinations. The test connection fails or raises an alert, and flow logs show the connection.  
  *Refs:* cloud_native_top10: CNAS-6, CNAS-10; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet, Network_Segmentation_Cheat_Sheet; cwe: CWE-923; attack: T1048, T1071; nist_800_53: SC-7, SI-4

- [ ] **CLD-NET-004** Check hardening of the instance metadata service  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds compute resources whose metadata service gives role credentials to any local process or to SSRF.  
  *Steps:*
  1. List all VMs and nodes with their metadata settings.
  2. Find resources that allow the old metadata version without a session token.
  3. Check the hop limit for container hosts.
  4. From a test workload, request the metadata address.
  *Example:* `aws ec2 describe-instances --query "Reservations[].Instances[].[InstanceId,MetadataOptions.HttpTokens,MetadataOptions.HttpPutResponseHopLimit]"; curl -m 3 http://169.254.169.254/latest/meta-data/ (test host)`  
  *Expected:* All compute resources require session-token metadata access (IMDSv2) and the old version is off. Workloads cannot read role credentials without a token.  
  *Refs:* cloud_native_top10: CNAS-6, CNAS-3; cheatsheet: Server_Side_Request_Forgery_Prevention_Cheat_Sheet, Secure_Cloud_Architecture_Cheat_Sheet; cwe: CWE-918, CWE-668; attack: T1552.005; nist_800_53: AC-6, SC-7  
  *See:* API-SSRF-007, K8S-LAT-003

- [ ] **CLD-NET-005** Check TLS and authentication on traffic between services  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds east-west traffic that is plaintext or accepts any caller.  
  *Steps:*
  1. List the service-to-service connections from the diagram.
  2. Capture traffic between two test services.
  3. Check for TLS and for mutual authentication or signed tokens.
  4. Send a call with no valid identity.
  *Example:* `tcpdump -i any -A port <port> (test hosts); openssl s_client -connect <svc>:<port>; curl -v http://<svc>:<port>`  
  *Expected:* Service traffic uses TLS with mutual authentication or validated signed tokens. A call with no valid identity is rejected.  
  *Refs:* cloud_native_top10: CNAS-6, CNAS-3; cheatsheet: Microservices_Security_Cheat_Sheet, Network_Segmentation_Cheat_Sheet; cwe: CWE-319, CWE-306; attack: T1071; nist_800_53: SC-8, IA-3  
  *See:* API-CONF-001, API-MSVC-004

- [ ] **CLD-NET-006** Check WAF and DDoS protection at internet-facing endpoints  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds public endpoints with no web filter or protection against traffic floods.  
  *Steps:*
  1. List all internet-facing applications and CDNs.
  2. Check that a WAF with managed rules is attached to each.
  3. Check custom rules for sensitive routes and rate limits.
  4. Check that DDoS protection is on based on the risk of the application.
  *Example:* `aws wafv2 list-web-acls --scope REGIONAL; aws shield describe-subscription; az network application-gateway waf-policy list; gcloud compute security-policies list`  
  *Expected:* Each public application has a WAF in block mode with custom rules and rate limits. DDoS protection follows the application risk.  
  *Refs:* cloud_native_top10: CNAS-6, CNAS-9; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet, Denial_of_Service_Cheat_Sheet; cwe: CWE-770; attack: T1498, T1190; nist_800_53: SC-5, SC-7


## QTA

- [ ] **CLD-QTA-001** Check service quotas and budget limits per account  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds accounts where one resource or attacker can use up quotas or run up large cost.  
  *Steps:*
  1. List service quotas and current use for compute, storage and network.
  2. Check budget limits and cost alerts for each account.
  3. Check who can raise quotas or create large resources.
  4. Check for alerts when use passes a set share of the limit.
  *Example:* `aws service-quotas list-service-quotas --service-code ec2; aws budgets describe-budgets --account-id <id>; az consumption budget list; gcloud alpha billing budgets list --billing-account <id>`  
  *Expected:* Each account has quotas and budgets with alerts. Few identities can raise quotas or create large resources.  
  *Refs:* cloud_native_top10: CNAS-9; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet, Denial_of_Service_Cheat_Sheet; cwe: CWE-770; attack: T1496, T1499; nist_800_53: SC-5, SC-6

- [ ] **CLD-QTA-002** Test rate limits and throttling on public APIs and gateways  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds gateways that accept unlimited requests from one caller.  
  *Steps:*
  1. List the rate and burst settings of each gateway stage and route.
  2. Send requests above the limit from one test client.
  3. Check that the gateway returns a throttling response.
  4. Check that limits apply per caller, not only in total.
  *Example:* `aws apigateway get-usage-plans; hey -n 1000 -c 50 https://<api>/<path>; az apim api show; gcloud api-gateway api-configs list`  
  *Expected:* Each route has rate and burst limits per caller. Requests above the limit get HTTP 429 and the backend stays healthy.  
  *Refs:* cloud_native_top10: CNAS-9; cheatsheet: Denial_of_Service_Cheat_Sheet, Secure_Cloud_Architecture_Cheat_Sheet; cwe: CWE-770, CWE-799; attack: T1499; nist_800_53: SC-5  
  *See:* API-RES-001

- [ ] **CLD-QTA-003** Check autoscaling limits and scale-out protection  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds autoscaling groups with no upper limit or with no alert, so a flood causes cost and instability.  
  *Steps:*
  1. List autoscaling groups, container services and function settings.
  2. Find groups with no maximum size.
  3. Check the metrics and alarms that start scale-out.
  4. Check that scale limits match the budget.
  *Example:* `aws autoscaling describe-auto-scaling-groups --query "AutoScalingGroups[].[AutoScalingGroupName,MaxSize]"; az monitor autoscale list -g <rg>; gcloud compute instance-groups managed list`  
  *Expected:* Every scaling group has a maximum size that fits the budget, with alarms for scale-out events.  
  *Refs:* cloud_native_top10: CNAS-9; cheatsheet: Denial_of_Service_Cheat_Sheet, Secure_Cloud_Architecture_Cheat_Sheet; cwe: CWE-770; attack: T1496; nist_800_53: SC-5, SC-6

- [ ] **CLD-QTA-004** Check CPU, memory and storage limits on cloud container services  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds container tasks and VM workloads with no resource limits.  
  *Steps:*
  1. List container tasks, jobs and services.
  2. Check the CPU and memory limits in each definition.
  3. Find tasks with no limit.
  4. Check the disk and log growth limits.
  *Example:* `aws ecs describe-task-definition --task-definition <t> --query "taskDefinition.[cpu,memory]"; az container show -n <c> -g <rg> --query containers[].resources; gcloud run services describe <s>`  
  *Expected:* Every container task sets CPU and memory limits and storage and log growth limits.  
  *Refs:* cloud_native_top10: CNAS-9, CNAS-1; cheatsheet: Docker_Security_Cheat_Sheet, Denial_of_Service_Cheat_Sheet; cwe: CWE-770; attack: T1499, T1496; nist_800_53: SC-5, SC-6  
  *See:* K8S-WRK-007, API-RES-009


## SEC

- [ ] **CLD-SEC-001** Check access control and audit records of the cloud secret store  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds secret stores where many identities can read all secrets and reads leave no record.  
  *Steps:*
  1. List the identities that can read, write or delete secrets.
  2. Check that each workload can read only its own secrets.
  3. Read a test secret and find the audit record.
  4. Check for an alert when a secret is read from an unexpected source.
  *Example:* `aws secretsmanager list-secrets; aws secretsmanager get-resource-policy --secret-id <id>; az keyvault show -n <v> --query properties.enableRbacAuthorization; gcloud secrets get-iam-policy <s>; query the audit log for the read event`  
  *Expected:* Access is scoped per secret and per workload. Each read is logged with identity and source, and unusual reads raise an alert.  
  *Refs:* cloud_native_top10: CNAS-5, CNAS-3; cheatsheet: Secrets_Management_Cheat_Sheet; cwe: CWE-284, CWE-522; attack: T1555.006; nist_800_53: AC-6, AU-2  
  *See:* K8S-SEC-008

- [ ] **CLD-SEC-002** Find secrets in function settings, instance data and environment variables  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds credentials stored in platform configuration where many readers and tools can see them.  
  *Steps:*
  1. List environment variables of functions, containers and VM templates.
  2. List instance user data and startup scripts.
  3. Search them for passwords, tokens and keys.
  4. Check that code fetches secrets from a vault at run time.
  *Example:* `aws lambda get-function-configuration --function-name <f> --query Environment; aws ec2 describe-instance-attribute --instance-id <i> --attribute userData; az functionapp config appsettings list; gcloud functions describe <f>`  
  *Expected:* Platform configuration holds no secret values. Code fetches secrets at run time from a secret store with a short-lived identity.  
  *Refs:* cloud_native_top10: CNAS-5; cheatsheet: Serverless_FaaS_Security_Cheat_Sheet, Secrets_Management_Cheat_Sheet; cwe: CWE-798, CWE-312; attack: T1552.001, T1552.005; nist_800_53: IA-5, SC-28  
  *See:* CICD-CRED-003

- [ ] **CLD-SEC-003** Check secret rotation, expiry and revocation  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds credentials that never rotate and so stay valid after a leak.  
  *Steps:*
  1. List secrets with their creation and last rotation date.
  2. Find secrets that exceed the rotation period.
  3. Check that rotation runs automatically.
  4. Revoke a test secret and check that its use fails.
  *Example:* `aws secretsmanager describe-secret --secret-id <id> --query "[RotationEnabled,LastRotatedDate]"; az keyvault secret list --vault-name <v> --query "[].attributes.expires"; gcloud secrets versions list <s>`  
  *Expected:* Secrets rotate on a set schedule and carry an expiry date. A revoked secret stops working in the agreed time.  
  *Refs:* cloud_native_top10: CNAS-5; cheatsheet: Secrets_Management_Cheat_Sheet; cwe: CWE-798; attack: T1552.001; nist_800_53: IA-5, SC-12

- [ ] **CLD-SEC-004** Check key management and envelope encryption for stored data  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds keys with broad use rights, no rotation or no separation from the data owners.  
  *Steps:*
  1. List the encryption keys and their policies.
  2. Find keys that many identities can use or manage.
  3. Check key rotation settings.
  4. Check that key administration and key use are held by different roles.
  *Example:* `aws kms list-keys; aws kms get-key-policy --key-id <k> --policy-name default; aws kms get-key-rotation-status --key-id <k>; az keyvault key list --vault-name <v>; gcloud kms keys list --keyring <r> --location <l>`  
  *Expected:* Keys have narrow policies, automatic rotation, and separate roles for administration and use.  
  *Refs:* cloud_native_top10: CNAS-5; cheatsheet: Secrets_Management_Cheat_Sheet; cwe: CWE-311; attack: T1552.004; nist_800_53: SC-12, SC-13

- [ ] **CLD-SEC-005** Scan repositories, storage and images for secrets  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds credentials that leaked into code, buckets, logs or images.  
  *Steps:*
  1. Scan the repositories and their history for secrets.
  2. Scan storage buckets for key files, backups and config files.
  3. Scan images and logs for tokens.
  4. Revoke and rotate each credential found.
  *Example:* `gitleaks detect --source <repo>; trufflehog git file://<repo>; trivy image --scanners secret <image>; aws s3 sync s3://<b> ./copy (scan the copy)`  
  *Expected:* No live credential is found. Each credential found is revoked and rotated, and its source is fixed.  
  *Refs:* cloud_native_top10: CNAS-5; cheatsheet: Secrets_Management_Cheat_Sheet, Infrastructure_as_Code_Security_Cheat_Sheet; cwe: CWE-798; attack: T1552.001, T1530; nist_800_53: IA-5, RA-5  
  *See:* CICD-CRED-001, CICD-CRED-005


## SRV

- [ ] **CLD-SRV-001** Check that each function has its own minimal role  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds functions that share a broad role and so give a breach the rights of many functions.  
  *Steps:*
  1. List all functions and their execution roles.
  2. Find roles that more than one function shares.
  3. Find roles with wildcard actions or resources.
  4. Compare the role actions to the actions in the function code.
  *Example:* `aws lambda list-functions --query "Functions[].[FunctionName,Role]"; aws iam list-attached-role-policies --role-name <r>; gcloud functions list --format="value(name,serviceAccountEmail)"; az functionapp identity show -n <f> -g <rg>`  
  *Expected:* Each function has a separate role with only the actions and resources it needs. No wildcard policy is attached.  
  *Refs:* cloud_native_top10: CNAS-3, CNAS-1; cheatsheet: Serverless_FaaS_Security_Cheat_Sheet; cwe: CWE-272, CWE-250; attack: T1078.004, T1648; nist_800_53: AC-6

- [ ] **CLD-SRV-002** Check authentication on every function trigger  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds triggers that let anyone invoke a function or feed it events.  
  *Steps:*
  1. List all triggers: API gateways, function URLs, queues, topics, buckets and schedules.
  2. Check the authorizer or access policy of each trigger.
  3. Invoke each public trigger without credentials.
  4. Check the resource policy for public principals.
  *Example:* `aws lambda get-policy --function-name <f>; aws lambda get-function-url-config --function-name <f>; curl -i https://<function-url>; gcloud functions get-iam-policy <f>`  
  *Expected:* Every trigger needs authentication and authorization. Resource policies allow only named principals, and a call without credentials fails.  
  *Refs:* cloud_native_top10: CNAS-3; cheatsheet: Serverless_FaaS_Security_Cheat_Sheet; cwe: CWE-306, CWE-862; attack: T1190, T1648; nist_800_53: IA-2, AC-3

- [ ] **CLD-SRV-003** Check network isolation and egress of functions  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds functions with unneeded Internet access or access to internal networks.  
  *Steps:*
  1. List functions with VPC or network settings.
  2. Find functions in the default network or with open egress.
  3. Check that sensitive functions sit in a separate network from general functions.
  4. From a test function, connect to an unlisted host.
  *Example:* `aws lambda get-function-configuration --function-name <f> --query VpcConfig; gcloud functions describe <f> --format="value(vpcConnector,ingressSettings)"; az functionapp vnet-integration list -n <f> -g <rg>`  
  *Expected:* Functions that need no Internet access have none. Sensitive functions run in private subnets with controlled egress.  
  *Refs:* cloud_native_top10: CNAS-6, CNAS-1; cheatsheet: Serverless_FaaS_Security_Cheat_Sheet; cwe: CWE-923; attack: T1048; nist_800_53: SC-7

- [ ] **CLD-SRV-004** Check execution context reuse and temporary storage  
  *Severity if fail:* Medium | *Type:* Code Review  
  *Objective:* Finds functions that keep secrets or user data in global variables or /tmp between calls.  
  *Steps:*
  1. Read the function code for global variables that hold secrets or user data.
  2. Call the function twice with different test users.
  3. Check /tmp and memory for data from the first call.
  4. Check for use of single-use environments for sensitive functions.
  *Example:* `Code review of global and static variables; invoke the function with two test identities and print the /tmp listing in a test build`  
  *Expected:* No secret or user data persists between calls. Code reads secrets fresh and clears temporary files.  
  *Refs:* cloud_native_top10: CNAS-5, CNAS-1; cheatsheet: Serverless_FaaS_Security_Cheat_Sheet; cwe: CWE-200, CWE-312; attack: T1648; nist_800_53: SC-28

- [ ] **CLD-SRV-005** Check function-to-function calls and chaining  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds functions that call other functions with no caller proof, so a breach can trigger the whole chain.  
  *Steps:*
  1. Map which functions invoke other functions.
  2. Check that each call uses a workload identity or a signed token.
  3. Check that the callee checks the caller identity.
  4. Check which role may invoke which function.
  *Example:* `aws lambda list-event-source-mappings; aws lambda get-policy --function-name <f>; gcloud functions get-iam-policy <f>`  
  *Expected:* Function calls are authenticated with workload identity or signed tokens. Each function allows only named callers.  
  *Refs:* cloud_native_top10: CNAS-3; cheatsheet: Serverless_FaaS_Security_Cheat_Sheet, Microservices_Security_Cheat_Sheet; cwe: CWE-306; attack: T1648; nist_800_53: IA-3, AC-3

- [ ] **CLD-SRV-006** Check concurrency limits and throttling for functions  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds functions that can scale without bound and cause cost or denial of service.  
  *Steps:*
  1. List concurrency and timeout settings of each function.
  2. Find functions with no reserved or maximum concurrency.
  3. Check API gateway throttling in front of them.
  4. Check the cost alerts for function invocations.
  *Example:* `aws lambda get-function-concurrency --function-name <f>; aws lambda get-function-configuration --function-name <f> --query Timeout; aws apigateway get-stages --rest-api-id <id>`  
  *Expected:* Functions have concurrency and timeout limits. Gateways throttle callers, and cost and invocation alerts exist.  
  *Refs:* cloud_native_top10: CNAS-9; cheatsheet: Serverless_FaaS_Security_Cheat_Sheet, Denial_of_Service_Cheat_Sheet, Secure_Cloud_Architecture_Cheat_Sheet; cwe: CWE-770; attack: T1499, T1496; nist_800_53: SC-5, SC-6


## SUP

- [ ] **CLD-SUP-001** Check cloud container registries for access, source and transport  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds registries that allow anonymous or wide push and pull, or that accept images from untrusted sources.  
  *Steps:*
  1. List the container registries and repositories.
  2. Check the access policy for each repository.
  3. Try an anonymous pull and push.
  4. Check that only the build system can push and that transfers use TLS.
  *Example:* `aws ecr describe-repositories; aws ecr get-repository-policy --repository-name <r>; az acr list; az acr repository list -n <acr>; gcloud artifacts repositories list`  
  *Expected:* Registries need authentication. Only build identities can push, pull rights follow need, and all transfers use TLS.  
  *Refs:* cloud_native_top10: CNAS-4; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet, Docker_Security_Cheat_Sheet; cwe: CWE-284, CWE-319; attack: T1525, T1195.002; nist_800_53: AC-3, SR-3  
  *See:* K8S-IMG-005, CICD-ART-007

- [ ] **CLD-SUP-002** Check that only trusted and current images run in cloud services  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds services that run untrusted, unsigned or stale images.  
  *Steps:*
  1. List images used by container services and functions.
  2. Find images from public or unknown sources.
  3. Check the age of each image and its last rebuild.
  4. Check the rule that blocks untrusted images at deploy.
  *Example:* `aws ecs list-task-definitions; aws lambda list-functions --query "Functions[?PackageType==\`Image\`]"; az containerapp list; gcloud run services list`  
  *Expected:* Services run only images from approved registries with known digests. Images are rebuilt on a set schedule.  
  *Refs:* cloud_native_top10: CNAS-4, CNAS-7; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet, Docker_Security_Cheat_Sheet; cwe: CWE-494, CWE-829; attack: T1204.003, T1195.002; nist_800_53: SR-3, SR-11, SI-7  
  *See:* K8S-IMG-001, CICD-ART-002

- [ ] **CLD-SUP-003** Check patching of self-managed hosts, images and managed service versions  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds VMs, machine images and managed services that run versions with known flaws.  
  *Steps:*
  1. List VM images, instance OS versions and managed service engine versions.
  2. Compare them to the current advisories and support dates.
  3. Check the patch and image rebuild process.
  4. Find services at end of life.
  *Example:* `aws ssm describe-instance-patch-states; aws inspector2 list-findings; az vm list -d; gcloud compute images list; aws rds describe-db-instances --query "DBInstances[].[DBInstanceIdentifier,EngineVersion]"`  
  *Expected:* Hosts and images are patched on a set schedule. No service runs an unsupported version without a written plan.  
  *Refs:* cloud_native_top10: CNAS-7; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet, Vulnerable_Dependency_Management_Cheat_Sheet; cwe: CWE-1104, CWE-1395; attack: T1190; nist_800_53: SI-2, RA-5

- [ ] **CLD-SUP-004** Check vulnerability scanning for cloud workloads and dependencies  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds workloads that run vulnerable libraries or images that no scan covers.  
  *Steps:*
  1. List all workloads: VMs, containers and functions.
  2. Check that each has a scan for images, packages and dependencies.
  3. Review open findings for age and exposure.
  4. Check the process to fix or accept each finding.
  *Example:* `trivy image <image>; trivy fs <path>; grype <image>; aws inspector2 list-findings; dependency-check --scan <path>`  
  *Expected:* All workloads have regular scans. High findings are fixed in the agreed time or accepted in writing.  
  *Refs:* cloud_native_top10: CNAS-7; cheatsheet: Vulnerable_Dependency_Management_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-1395, CWE-1104; attack: T1190, T1195.002; nist_800_53: RA-5, SI-2  
  *See:* CICD-VULN-001, CICD-VULN-002, CICD-VULN-003
