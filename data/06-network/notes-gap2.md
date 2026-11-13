# NET sheet gap2 notes: OS and service hardening (ComplianceAsCode)

Files: data/06-network/gap2-{pam,ssh,audit,kern,os,fw,pkg,svc}.yaml. 69 tests (NET-PAM 001-011, SSH 001-007, AUDIT 001-012, KERN 001-007, OS 001-012, FW 001-006, PKG 001-006, SVC 008-021).
Each test covers one theme. The covered rule ids are in refs.tool_check. NIST 800-53, PCI DSS and CWE ids come only from the references block of those rule.yml files and only when the id exists in the catalog.
sources_read lists rule.yml files from sources/repos/ComplianceAsCode that were opened (first, quarter, middle, three-quarter and last rule of the theme).
Pass values that depend on a profile variable (for example lockout count, password length) are left to the organization standard. Fixed values (sysctl values, PermitRootLogin, file modes) come from the rule files.

## Themes and rule counts
- NET-PAM-001 (faillock, 25 rules): Check that PAM locks accounts after repeated failed logins
- NET-PAM-002 (pwquality, 27 rules): Check that PAM enforces password complexity rules
- NET-PAM-003 (pwhash, 30 rules): Check password hashing, password history and PAM module order
- NET-PAM-004 (pwage, 16 rules): Check password aging and account expiration settings
- NET-PAM-005 (acct, 35 rules): Check local accounts for duplicates, empty passwords and root misuse
- NET-PAM-006 (session, 38 rules): Check user session limits, umask, home directories and root PATH
- NET-PAM-007 (banner, 20 rules): Check the login warning banners and the files that hold them
- NET-PAM-008 (console, 17 rules): Check console access controls, Ctrl-Alt-Del and session lock tools
- NET-PAM-009 (smartcard, 15 rules): Check smart card login settings for PAM and SSSD
- NET-PAM-010 (pam_sssd, 36 rules): Check central authentication clients: SSSD, LDAP, Kerberos and authselect
- NET-PAM-011 (sudo_cfg, 29 rules): Check sudo configuration, file permissions and privilege rules
- NET-SSH-001 (ssh_auth, 18 rules): Check that the SSH daemon blocks root login and weak authentication
- NET-SSH-002 (ssh_crypto, 12 rules): Check the ciphers, MACs and key exchange of the SSH daemon
- NET-SSH-003 (ssh_fwd, 7 rules): Check SSH forwarding, X11 and warning banner settings
- NET-SSH-004 (ssh_limits, 13 rules): Check SSH session limits, logging and privilege separation
- NET-SSH-005 (ssh_perm, 17 rules): Check the owner and mode of SSH daemon files and host keys
- NET-SSH-006 (ssh_svc, 9 rules): Check the SSH package, service and firewall state against the host role
- NET-SSH-007 (ssh_client, 5 rules): Check SSH client settings for ciphers, MACs and entropy
- NET-AUDIT-001 (audit_core, 9 rules): Check that auditd is installed, enabled and active from boot
- NET-AUDIT-002 (audit_ret, 29 rules): Check auditd log size, disk-full actions and flush settings
- NET-AUDIT-003 (audit_perm, 27 rules): Check the owner and mode of audit logs, rules and tools
- NET-AUDIT-004 (audit_policy, 8 rules): Check the base audit rules, immutable mode and OSPP rule set
- NET-AUDIT-005 (audit_auth, 29 rules): Check audit rules for identity files, logins, sudoers and cron
- NET-AUDIT-006 (audit_priv, 73 rules): Check audit rules for privileged commands and security tools
- NET-AUDIT-007 (audit_dac, 44 rules): Check audit rules for permission, owner and extended attribute changes
- NET-AUDIT-008 (audit_fail, 78 rules): Check audit rules for failed access, file creation, change and deletion
- NET-AUDIT-009 (audit_events, 35 rules): Check audit rules for kernel modules, time, network and MAC changes
- NET-AUDIT-010 (rsyslog, 23 rules): Check rsyslog and syslog-ng files, remote input and logging services
- NET-AUDIT-011 (journald, 16 rules): Check journald storage, forwarding and journal file permissions
- NET-AUDIT-012 (logperm, 53 rules): Check /var/log file permissions and the log rotation setup
- NET-KERN-001 (sysctl_ipv4, 28 rules): Check the IPv4 sysctl settings for routing, redirects and spoofing
- NET-KERN-002 (sysctl_ipv6, 27 rules): Check the IPv6 sysctl settings and the IPv6 interface plan
- NET-KERN-003 (sysctl_k, 33 rules): Check kernel and filesystem sysctl hardening values
- NET-KERN-004 (coredump, 7 rules): Check core dump storage and execution protection settings
- NET-KERN-005 (kmod, 22 rules): Check that unneeded kernel modules cannot load
- NET-KERN-006 (boot_args, 35 rules): Check the kernel command line for mitigation and memory hardening options
- NET-KERN-007 (kconfig, 68 rules): Check the kernel build options for hardening
- NET-OS-001 (perm_acct, 34 rules): Check the owner and mode of account files and their backups
- NET-OS-002 (perm_world, 11 rules): Find world-writable, unowned and unauthorized setuid files
- NET-OS-003 (perm_sys, 26 rules): Check ownership and mode of system binaries, libraries and boot map files
- NET-OS-004 (mnt_opts, 41 rules): Check mount options nodev, nosuid and noexec on partitions
- NET-OS-005 (mnt_part, 13 rules): Check separate partitions and disk encryption for data and logs
- NET-OS-006 (mnt_media, 8 rules): Check that USB storage, automount and BIOS boot options are limited
- NET-OS-007 (boot_pw, 27 rules): Check bootloader password, file permissions and recovery options
- NET-OS-008 (secboot, 1 rules): Check that UEFI Secure Boot is on
- NET-OS-009 (selinux, 23 rules): Check that SELinux is enforcing with the targeted policy
- NET-OS-010 (sebool, 296 rules): Check that risky SELinux booleans are off
- NET-OS-011 (apparmor, 7 rules): Check that AppArmor is loaded and its profiles are enforced
- NET-OS-012 (gnome, 39 rules): Check desktop login, screen lock and remote access settings
- NET-FW-001 (fw_firewalld, 11 rules): Check that firewalld runs with a default deny zone
- NET-FW-002 (fw_ipt, 18 rules): Check iptables and ip6tables default policies and rule persistence
- NET-FW-003 (fw_nft, 13 rules): Check nftables tables, base chains and default deny policy
- NET-FW-004 (fw_ufw, 13 rules): Check UFW and SuSEfirewall2 state and default policy
- NET-FW-005 (fw_ipsec, 12 rules): Check IPsec packages, tunnels and configuration file permissions
- NET-FW-006 (net_misc, 16 rules): Check host network settings: DHCP, DDNS, zeroconf, sniffing and DNS mode
- NET-PKG-001 (crypto, 21 rules): Check the system crypto policy and its use by services
- NET-PKG-002 (fips, 13 rules): Check FIPS mode, boot setup and certified OS status
- NET-PKG-003 (av, 13 rules): Check endpoint protection, HIDS and user data backup tools
- NET-PKG-004 (updates, 23 rules): Check package signature checks, repositories and automatic updates
- NET-PKG-005 (apt, 26 rules): Check APT sources, keys, authentication and file permissions
- NET-PKG-006 (pkgtools, 38 rules): Check installed and removed system tool packages against the standard
- NET-SVC-008 (chrony, 31 rules): Check time synchronization client settings: chrony, ntpd and timesyncd
- NET-SVC-009 (cron, 42 rules): Check cron and at: service state, user lists and file permissions
- NET-SVC-010 (obsolete, 42 rules): Check for obsolete clear-text services: telnet, rsh, tftp, NIS, talk, rsync, xinetd
- NET-SVC-011 (nfs, 21 rules): Check NFS and RPC services, exports and client mounts
- NET-SVC-012 (samba_ftp, 17 rules): Check Samba and FTP services for signing, uploads and anonymous access
- NET-SVC-013 (dhcp_dns, 23 rules): Check DHCP, DNS, proxy, RADIUS and routing daemons on the host
- NET-SVC-014 (mail, 19 rules): Check Postfix and Dovecot: network listening, relay and TLS
- NET-SVC-015 (snmp, 3 rules): Check the SNMP agent: installation, service state and protocol version
- NET-SVC-016 (svc_misc, 36 rules): Check that unneeded services and daemons are off
- NET-SVC-017 (usbguard, 11 rules): Check USBGuard and fapolicyd allow-list controls
- NET-SVC-018 (httpd_a, 11 rules): Check Apache httpd TLS, authentication and banner settings
- NET-SVC-019 (httpd_b, 19 rules): Check Apache httpd directory access, methods and file permissions
- NET-SVC-020 (httpd_c, 31 rules): Check Apache httpd and nginx modules, logging, tokens and role
- NET-SVC-021 (docker, 4 rules): Check Docker host settings: storage driver, SELinux and daemon state

Total rules in tests: 2066 of 2,530.

## Mapped to existing tests (data/mappings/tool-os.json, 50 rules)
- NET-ADM-003: ssh_keys_passphrase_protected, ssh_private_keys_have_passcode (key storage and passphrase).
- NET-REV-006 (file integrity): aide_*, package_aide_installed, rpm_verify_*, prelink rules.
- NET-LOG-002 (central, secure log transport): rsyslog TLS and remote host rules, auditd remote and encrypted offload, journal upload rules.
- NET-SVC-005 (NTP): ntpd_configure_restrictions, chronyd_no_chronyc_network, chronyd_client_only.
- NET-SVC-003 (SNMP): snmpd_no_rwusers, snmpd_not_default_password.
- NET-DNS-001 (zone transfers): dns_server_disable_zone_transfers, dns_server_authenticate_zone_transfers.
- NET-REV-003 (host firewall rules for open ports): the *_rules_for_open_ports and only-required-services firewall rules.
- NET-VULN-004: security_patches_up_to_date. NET-VULN-007: installed_OS_is_vendor_supported.

## Skipped
- 414 rules under applications/openshift and applications/openshift-virtualization: cluster rules for the K8S sheet, not host or service hardening.
- No other group skipped. Rules for architectures (aarch64, ppc64le) and product variants (stig, cis, coreos, zipl, SUSE) are folded into the theme of the generic rule.

## Open issues
- A theme test is a broad check. A tester should use an automated scanner (OpenSCAP with the matching profile) to look at each rule id in refs.tool_check.
- httpd TLS rules may overlap the WEB TLS tests. They stay here because they check the host configuration files.
- Rule text is partly template code (Jinja). Fixed values were taken from the template variables where visible.
- tools/check_mappings.py was extended with the tool_check key so that tool-os.json is validated.
- Prowler, Kubescape and openshift checks in catalog/checks.json (1,382 other rules) are not part of this task.
