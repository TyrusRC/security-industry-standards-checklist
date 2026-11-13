# NETWORK security test cases

233 tests. Tick the box when the test passes.


## ADM

- [ ] **NET-ADM-001** Make sure remote administration uses a managed access point with MFA  
  *Severity if fail:* Critical | *Type:* Manual  
  *Objective:* Finds administration paths that are open to the internet or that need only a password.  
  *Steps:*
  1. Make a list of all remote administration methods, such as SSH, RDP, web consoles and VPN.
  2. Scan the public ranges and the user networks for the ports of these methods.
  3. Read the rules and the documentation of each method and its rationale.
  4. Try to log in with a password only, with no second factor.
  5. Make sure the administration traffic goes through a dedicated, managed interface.
  *Example:* `nmap -Pn -sV -p 22,23,80,443,3389,5985,5986,8443,8080 <range> ; ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no <user>@<host>`  
  *Expected:* Remote administration is not reachable from the internet. Each method goes through a managed access point and needs multi-factor authentication.  
  *Refs:* wstg: WSTG-CONF-05; attack: T1133, T1021; cwe: CWE-287, CWE-1390; nist_800_53: AC-17, AC-17(3), SC-7(15); pci_dss: 8.4.2, 8.4.3  
  *See:* WEB-CONF-007

- [ ] **NET-ADM-002** Check that all non-console administration uses strong cryptography  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds Telnet, HTTP and other clear-text administration paths on servers and devices.  
  *Steps:*
  1. Scan the devices for administration ports and list the protocol of each.
  2. Log in as an administrator and capture the traffic.
  3. Look for passwords and commands in clear text in the capture.
  4. Scan the encrypted administration services for protocol versions and algorithms.
  5. Compare the result with the cryptography standard of the organization.
  *Example:* `nmap -Pn -sV -p 22,23,80,443,8443 --script ssh2-enum-algos,ssl-enum-ciphers <host> ; ssh-audit <host> ; tshark -i eth0 -Y "telnet || http.authorization"`  
  *Expected:* All non-console administration uses encrypted protocols with strong algorithms. No clear-text administration port answers.  
  *Refs:* attack: T1021.004, T1040; cwe: CWE-319, CWE-327; nist_800_53: AC-17(2), SC-8, SC-13; pci_dss: 2.2.7, 2.2.5

- [ ] **NET-ADM-003** Check SSH keys, host keys and key storage on managed systems  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds shared, unprotected or never-changed SSH keys that give access to many systems.  
  *Steps:*
  1. List the authorized keys on a sample of servers and devices.
  2. Match each key to an owner and a current need.
  3. Look for private keys in home folders, scripts, repositories and backups.
  4. Look at the permissions of the private key files.
  5. Make sure keys of former staff and old systems are removed.
  *Example:* `find / -name authorized_keys 2>/dev/null ; find / -name "id_*" -not -name "*.pub" 2>/dev/null ; ls -l ~/.ssh ; ssh-keygen -lf <key.pub>`  
  *Expected:* Each authorized key has a current owner and need. No private key is in scripts, repositories or backups, and key files are not readable by other users.  
  *Refs:* attack: T1552.004, T1021.004; cheatsheet: Secrets_Management_Cheat_Sheet; cwe: CWE-522, CWE-798; nist_800_53: SC-12, IA-5, AC-6

- [ ] **NET-ADM-004** Review the VPN gateway for strong authentication and limited network access  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds VPN services that give too much network access or accept weak login.  
  *Steps:*
  1. Scan the VPN gateway for open ports and look at the product and version.
  2. Scan the gateway for protocol versions and algorithms.
  3. Log in with a test account without the second factor.
  4. Connect with a test account and scan the internal ranges.
  5. Compare the reachable ranges with the access rights of that account.
  *Example:* `nmap -sU -sT -p 500,4500,443,1194 -sV <vpn-ip> ; ike-scan <vpn-ip> ; testssl.sh <vpn-ip>:443 ; nmap -Pn -p- <internal-range> from the VPN client`  
  *Expected:* The VPN uses current software and strong cryptography. It needs multi-factor authentication, and a user can reach only the ranges that the rights allow.  
  *Refs:* attack: T1133; cwe: CWE-287, CWE-1395; nist_800_53: AC-17, AC-17(2), SC-7; pci_dss: 8.4.3, 2.2.7; other: NIST SP 800-115 appendix lists IKE-Scan for remote access testing

- [ ] **NET-ADM-005** Check session timeout and the way to disable remote access fast  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds administration sessions that stay open and remote access that cannot be stopped fast in an incident.  
  *Steps:*
  1. Open an administration session and leave it idle.
  2. Measure the time until the system ends the session.
  3. Read the procedure to disable remote access for an account or a method.
  4. Test the procedure on a test account and measure the time.
  *Example:* `show line | include timeout ; grep -E "ClientAliveInterval|TMOUT" /etc/ssh/sshd_config /etc/profile ; time <disable-account-command>`  
  *Expected:* Idle sessions end after the set time. The team can disable remote access within the time that the policy sets.  
  *Refs:* nist_800_53: AC-12, SC-10, AC-17(9)

- [ ] **NET-ADM-006** Review the management plane of network devices for exposure and role limits  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds routers, switches and appliances whose management interface is open to user networks.  
  *Steps:*
  1. Find the management addresses of routers, switches, firewalls and load balancers.
  2. Scan those addresses from the user network, the server network and the internet.
  3. Read the access lists on the management interfaces.
  4. Look at the roles and accounts on each device.
  5. Make sure each administrator has only the rights that the role needs.
  *Example:* `nmap -Pn -sV -p 22,23,80,443,161,830,8443 <mgmt-range> ; show running-config | section line|aaa|snmp|http ; show users`  
  *Expected:* The management interfaces answer only from a dedicated management network. Each account has only the rights that its role needs.  
  *Refs:* wstg: WSTG-CONF-05; attack: T1602.002; cwe: CWE-284, CWE-668; nist_800_53: AC-6, AC-6(1), SC-7(15), CM-5; pci_dss: 1.2.8

- [ ] **NET-ADM-007** Check that network configurations are controlled, backed up and checked for change  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds device and infrastructure configurations that change without approval or record.  
  *Steps:*
  1. Get the stored configuration of a sample of devices.
  2. Compare it with the running configuration.
  3. Look for the change tickets of the differences.
  4. Make sure the infrastructure code or the configuration store has access control and version history.
  5. Make sure secrets are not stored in the infrastructure code.
  *Example:* `diff <(ssh <device> show running-config) stored/<device>.cfg ; git log --stat -- network/ ; tfsec . or checkov -d .`  
  *Expected:* Running configurations match the stored and approved ones. Each change has a ticket and a version record, and the code holds no secrets.  
  *Refs:* cheatsheet: Infrastructure_as_Code_Security_Cheat_Sheet; nist_800_53: CM-3, CM-5, CM-6; pci_dss: 1.2.2, 1.2.8


## BKP

- [ ] **NET-BKP-001** Look for backups, dumps and state files on exposed hosts and shares  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds backup archives, database dumps and configuration copies that anyone on the network can read.  
  *Steps:*
  1. List the file shares, FTP and TFTP services, and storage services found by the port scan.
  2. List the files that anonymous or low-rights users can read.
  3. Look for archives, database dumps, configuration backups, state files and environment files.
  4. Open a small sample of the files and look for secrets and personal data.
  5. Write down each file, its location and the data that it holds.
  *Example:* `smbmap -H <host> -u guest ; ftp -n <host> (anonymous) ; nmap --script ftp-anon,nfs-ls -p 21,2049 <host> ; find /srv /mnt \( -name "*.bak" -o -name "*.sql" -o -name "*.tar.gz" -o -name "*.tfstate" -o -name ".env" \) -perm -o+r`  
  *Expected:* Low-rights users and outside users cannot read backups, dumps, state files or configuration copies. No such file sits on a public or shared location.  
  *Refs:* wstg: WSTG-CONF-04, WSTG-CONF-11; attack: T1135, T1602; cwe: CWE-200, CWE-548; nist_800_53: AC-3, CM-7  
  *See:* WEB-CONF-004, WEB-CONF-012

- [ ] **NET-BKP-002** Check that backups are encrypted, kept apart and reachable by few  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds backups that an attacker on the production network can read or delete.  
  *Steps:*
  1. Find the storage systems and the network paths that carry backups.
  2. Make sure the backup data is encrypted in transit and at rest.
  3. Make sure a copy is in a separate facility that is not with the operational system.
  4. Look at which hosts and accounts can reach the backup storage on the network.
  5. Try to read a backup from a normal server account.
  *Example:* `nmap -Pn -sV -p- <backup-server> ; showmount -e <backup-server> ; smbclient -L //<backup-server> -U <server-account> ; check rules for the backup zone`  
  *Expected:* Backups are encrypted and a copy is stored in a separate place. Only the backup system and backup admins can reach the backup storage.  
  *Refs:* nist_800_53: CP-9, CP-9(3), CP-9(8), SC-28(1), SC-8; pci_dss: 1.4.4

- [ ] **NET-BKP-003** Check who can read the configuration backups of network devices  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds configuration copies with passwords and community strings that many hosts can read.  
  *Steps:*
  1. Find the systems that store configuration backups of routers, switches and firewalls.
  2. Look at the protocol the devices use to send their backups.
  3. Look at the permissions of the backup folder and the network services that serve it.
  4. Search the backup files for clear-text secrets.
  *Example:* `nmap -sU -p 69 --script tftp-enum <host> ; ls -l /srv/tftp /var/backups/network ; grep -rniE "password|secret|community" /srv/tftp`  
  *Expected:* Device backups are stored on a protected system and sent over an encrypted channel. Only network administrators can read them and they hold no clear-text secrets.  
  *Refs:* attack: T1602.002; cwe: CWE-200, CWE-256, CWE-319; nist_800_53: CM-2, CM-2(3), AC-3; pci_dss: 1.2.8, 8.6.2


## CRED

- [ ] **NET-CRED-001** Look for vendor default accounts on network services and devices  
  *Severity if fail:* Critical | *Type:* Automated  
  *Objective:* Finds routers, switches, databases and services that still use vendor default passwords.  
  *Steps:*
  1. Use the service and version results to list devices and products with a login.
  2. Get the default accounts for each product from the vendor documentation.
  3. Try each default account on the login of the service, within the agreed rate.
  4. Look at the system accounts of each product that the admins did not change.
  5. Write down each default account that is active.
  *Example:* `nmap -sV --script default-http-login-hunter,ftp-anon,mysql-empty-password -p <ports> <host> ; hydra -C defaults.txt <host> ssh`  
  *Expected:* No vendor default account works. Default accounts are removed or disabled, or they have a unique strong password.  
  *Refs:* owasp_top10: A02:2025; wstg: WSTG-ATHN-02, WSTG-CONF-01; attack: T1078.001; capec: CAPEC-70; cwe: CWE-1188, CWE-798; nist_800_53: IA-5, CM-6; pci_dss: 2.2.2, 2.3.1  
  *See:* WEB-AUTHN-001

- [ ] **NET-CRED-002** Check the password policy settings on network systems and directories  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds systems that accept short, common or breached passwords.  
  *Steps:*
  1. Export the password policy of the directory and of each network device or service with local accounts.
  2. Make sure the minimum length is 12 characters, or the maximum the system supports.
  3. Make sure the system checks new passwords against a list of common and breached passwords.
  4. Make sure the lockout limit is not more than 10 failed attempts, for at least 30 minutes.
  5. Compare the policy with the written password policy.
  *Example:* `Get-ADDefaultDomainPasswordPolicy ; net accounts ; chage -l <user> ; grep -E "PASS_MIN_LEN|minlen" /etc/login.defs /etc/security/pwquality.conf`  
  *Expected:* Passwords have at least 12 characters and are checked against a list of common and breached passwords. Failed logins lock the account after at most 10 tries.  
  *Refs:* wstg: WSTG-ATHN-07, WSTG-ATHN-03; cwe: CWE-521, CWE-307; nist_800_53: IA-5; pci_dss: 8.3.6, 8.3.4  
  *See:* WEB-PWD-001

- [ ] **NET-CRED-003** Test online password guessing and lockout on remote services  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds remote services that let an attacker try many passwords with no limit.  
  *Steps:*
  1. Pick remote services with a login, such as SSH, RDP, VPN and management interfaces.
  2. Send repeated failed logins with a test account until the lockout limit.
  3. Try one common password against many test accounts at a slow rate.
  4. Make sure the service locks the account or slows the logins.
  5. Make sure the service logs the failed logins.
  *Example:* `hydra -l testuser -P short-list.txt -t 2 ssh://<host> ; medusa -h <host> -u testuser -P short-list.txt -M ssh`  
  *Expected:* The service blocks or slows repeated failed logins from one source or against one account. Failed logins appear in the logs.  
  *Refs:* wstg: WSTG-ATHN-03; attack: T1110.001, T1110.003; capec: CAPEC-112, CAPEC-49; cwe: CWE-307; nist_800_53: AC-7, IA-5; pci_dss: 8.3.4  
  *See:* WEB-AUTHN-002, WEB-AUTHN-003

- [ ] **NET-CRED-004** Crack password hashes offline to find weak passwords  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds accounts with passwords that an attacker can recover from hashes.  
  *Steps:*
  1. Get the password hashes from the system or from a capture, as the plan says.
  2. Set up the cracker with the rules of the password policy.
  3. Run a dictionary attack, then a hybrid attack, then a limited brute force attack.
  4. Count the accounts that the cracker recovers and the time it needed.
  5. Report the accounts to the owner without the plain passwords. Delete the hashes and results at the end.
  *Example:* `hashcat -m <mode> hashes.txt wordlist.txt -r rules/best64.rule ; john --wordlist=wordlist.txt hashes.txt`  
  *Expected:* The cracker recovers no password in the agreed time. The hashes use a salted hash with a high work factor, such as Argon2id.  
  *Refs:* attack: T1110.002; capec: CAPEC-55; cheatsheet: Password_Storage_Cheat_Sheet; cwe: CWE-257, CWE-521; nist_800_53: IA-5; pci_dss: 8.3.2, 8.3.6; other: NIST SP 800-115 section 5.1 (password cracking)  
  *See:* WEB-PWD-001

- [ ] **NET-CRED-005** Look for hard-coded passwords in device configurations and scripts  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds passwords in clear text in configuration files, scripts and backups.  
  *Steps:*
  1. Export the running and saved configurations of routers, switches and firewalls.
  2. Collect the scripts and configuration files of servers and automation tools.
  3. Search the files for passwords, community strings, keys and tokens.
  4. Check that password fields hold hashes or encrypted values.
  5. Write down each clear-text secret and where it is stored.
  *Example:* `grep -rniE "password|passwd|secret|community|key" /etc /opt/scripts ; show running-config | include password|secret ; trufflehog filesystem <dir>`  
  *Expected:* No file holds a clear-text secret. Secrets come from a secrets store, and stored passwords are hashed or encrypted.  
  *Refs:* attack: T1552.001, T1602.002; cwe: CWE-798, CWE-256, CWE-555; nist_800_53: IA-5; pci_dss: 8.6.2, 8.3.2


## DISC

- [ ] **NET-DISC-001** Find live hosts in scope and compare them with the inventory  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds hosts that are on the network but not in the inventory.  
  *Steps:*
  1. Get the list of address ranges in scope and the asset inventory.
  2. Run a host discovery scan from the external viewpoint.
  3. Run a host discovery scan from the internal viewpoint.
  4. Compare the live hosts with the inventory.
  5. Write down each live host that has no owner or is not in the inventory.
  *Example:* `nmap -sn -PE -PS22,80,443 -PA3389 -oA disc-ext <range> ; masscan <range> -p80,443,22 --rate 1000 -oL masscan.txt`  
  *Expected:* Every live host is in the inventory and has an owner. No unknown host answers in the ranges in scope.  
  *Refs:* wstg: WSTG-INFO-04; attack: T1018, T1595.001; capec: CAPEC-292; nist_800_53: CM-8, CA-7; other: NIST SP 800-115 section 4.1 (network discovery)  
  *See:* WEB-INFO-004

- [ ] **NET-DISC-002** Use passive discovery to find hosts, protocols and traffic relations  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds hosts and flows that active scans miss, such as hosts that are off or filtered.  
  *Steps:*
  1. Connect the sniffer to a tap or a mirror port on the segment.
  2. Capture traffic for a full business cycle.
  3. List the IP and MAC addresses, the protocols and the talk pairs in the capture.
  4. Compare the list with the inventory and the active scan results.
  5. Write down each host, protocol or flow that is not in the inventory or the diagram.
  *Example:* `tshark -i eth1 -a duration:3600 -w seg.pcap ; tshark -r seg.pcap -q -z conv,ip ; Wireshark: Statistics > Conversations`  
  *Expected:* Every host, protocol and flow in the capture is in the inventory and the data-flow diagram. No unapproved protocol is in use.  
  *Refs:* attack: T1040; capec: CAPEC-313; nist_800_53: CM-8, SI-4; other: NIST SP 800-115 sections 3.5 and 4.1 (passive discovery)

- [ ] **NET-DISC-003** Detect rogue wired devices and trace them to the switch port  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds unauthorized devices that connect to the wired network.  
  *Steps:*
  1. Get the list of approved devices, vendors and operating systems.
  2. Scan the network and list the MAC address vendor and the operating system of each host.
  3. Mark each host that does not match the approved list.
  4. Find the switch and the port of each marked host in the switch MAC table.
  5. Make sure the network has a control that alerts on new devices.
  *Example:* `nmap -O -sV --osscan-guess <range> -oX os.xml ; show mac address-table | include <mac> (on the switch)`  
  *Expected:* Only approved devices are on the network. The network raises an alert when an unknown device connects.  
  *Refs:* attack: T1200; nist_800_53: CM-8, SC-7; other: NIST SP 800-115 section 4.1 (rogue device detection)

- [ ] **NET-DISC-004** Scan all TCP ports and compare open ports with the approved list  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds open ports that are not approved or that have no business need.  
  *Steps:*
  1. Get the list of approved services, protocols and ports for each host.
  2. Run a TCP scan of all 65535 ports from the external viewpoint.
  3. Run the same scan from the internal viewpoint.
  4. Compare the open ports with the approved list.
  5. Write down each open port that is not approved.
  *Example:* `nmap -Pn -sS -p- --min-rate 500 -T3 -oA tcp-all <host> ; masscan <range> -p0-65535 --rate 1000 -oL masscan.txt`  
  *Expected:* Only approved ports are open. Each open port has a business reason, an owner and an approval.  
  *Refs:* wstg: WSTG-CONF-01, WSTG-INFO-04; attack: T1046; capec: CAPEC-300, CAPEC-287; cwe: CWE-1327; nist_800_53: CM-7, SC-7; pci_dss: 1.2.5, 2.2.4; other: NIST SP 800-115 section 4.2 (port and service identification)  
  *See:* WEB-INFO-004

- [ ] **NET-DISC-005** Scan UDP ports and look for unapproved UDP services  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds UDP services, such as SNMP, TFTP and NTP, that are open without approval.  
  *Steps:*
  1. Run a UDP scan of the common service ports on each host in scope.
  2. Run a version scan on the open and open-filtered ports.
  3. Compare the result with the approved list of services.
  4. Write down each UDP service that is not approved.
  *Example:* `nmap -Pn -sU --top-ports 200 -sV --version-intensity 0 -oA udp-top <host>`  
  *Expected:* Only approved UDP services answer. Services that need no external access do not answer from untrusted networks.  
  *Refs:* attack: T1046; capec: CAPEC-308; nist_800_53: CM-7, SC-7; pci_dss: 1.2.5, 2.2.4; other: NIST SP 800-115 section 4.2 (port and service identification)

- [ ] **NET-DISC-006** Identify services and versions and compare them with the approved list  
  *Severity if fail:* Low | *Type:* Automated  
  *Objective:* Finds services that run another product or version than the inventory lists.  
  *Steps:*
  1. Run a service and version scan on each open port.
  2. Look at the banner of each service.
  3. Compare the product and version with the inventory.
  4. Do not trust the port number. Confirm the real service on each port.
  5. Write down each service that is unknown, old or not supported.
  *Example:* `nmap -Pn -sV --version-all -p <ports> -oX svc.xml <host> ; nc -nv <host> <port> (banner grab)`  
  *Expected:* Each port runs the approved service and a supported version. Banners do not give more detail than needed.  
  *Refs:* wstg: WSTG-CONF-01, WSTG-INFO-04; attack: T1046; capec: CAPEC-312, CAPEC-310; cwe: CWE-200; nist_800_53: CM-7, RA-5; other: NIST SP 800-115 section 4.2 (service identification and banner grabbing)  
  *See:* WEB-INFO-002

- [ ] **NET-DISC-007** Compare the scan result with the firewall ruleset  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds rules that do not work as the ruleset says, and paths that go around the firewall.  
  *Steps:*
  1. Get the firewall rules that apply to the hosts in scope.
  2. Scan the hosts from an untrusted network with the normal scan type.
  3. Scan again with other scan types, for example ACK, FIN and Xmas scans.
  4. Compare the result with the rules.
  5. Write down each port that answers and is not allowed by a rule.
  *Example:* `nmap -Pn -sS -sA -p- <host> ; nmap -Pn -sF -sX -p 1-1024 <host> ; Wireshark capture behind the firewall`  
  *Expected:* The scan shows only the ports that the ruleset allows. Other scan types do not find more open ports.  
  *Refs:* wstg: WSTG-CONF-01; capec: CAPEC-305, CAPEC-302, CAPEC-303; nist_800_53: SC-7; pci_dss: 1.3.1, 1.4.2; other: NIST SP 800-115 sections 3.3 and 4.2 (ruleset review and alternate scan types)

- [ ] **NET-DISC-008** Make sure no insecure or clear-text service listens on the network  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds Telnet, FTP, TFTP and similar services that send data or passwords in clear text.  
  *Steps:*
  1. Use the open-port results of the TCP and UDP scans.
  2. Look for Telnet, FTP, TFTP, rlogin, rsh and other clear-text services.
  3. Look for clear-text management ports on routers, switches and servers.
  4. Check if each insecure service has a documented business reason and extra controls.
  *Example:* `nmap -Pn -p 21,23,69,79,512-514,5900 -sV <range> ; nmap -sU -p 69 --script tftp-enum <host>`  
  *Expected:* No insecure service listens. A service that must stay has a written reason and extra controls, and it is not reachable from untrusted networks.  
  *Refs:* attack: T1046; cwe: CWE-319; nist_800_53: CM-7, SC-8; pci_dss: 2.2.5, 2.2.7; other: NIST SP 800-115 section 4.2 (insecure protocols such as TFTP and telnet)

- [ ] **NET-DISC-009** Make sure the origin server is not reachable without the CDN  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds origin servers that accept traffic from the internet and not only from the CDN.  
  *Steps:*
  1. Find origin IP addresses from DNS history, certificate transparency logs and leaked headers.
  2. Send a request directly to each origin IP address.
  3. Send the request with the Host header of the public site.
  4. Read the rules that restrict the origin to the CDN or load balancer.
  *Example:* `curl -sk --resolve www.example.com:443:<origin-ip> https://www.example.com/ -o /dev/null -w "%{http_code}\n"`  
  *Expected:* The origin does not answer to the internet. It answers only to the CDN or load balancer address ranges.  
  *Refs:* wstg: WSTG-CONF-01; nist_800_53: SC-7; other: WSTG-CONF-01 table row on load balancer and CDN configuration

- [ ] **NET-DISC-010** Check that discovery scans run on a schedule and find new devices  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds networks where new devices and services appear and nobody sees them.  
  *Steps:*
  1. Look at the schedule of discovery and port scans.
  2. Make sure the scan covers all address ranges, including new ranges.
  3. Add a test host and a test listener in a scan window.
  4. Make sure the scan or the monitoring tool reports the new host and the new service.
  *Example:* `cron: nmap -sS -p- -oX scan-$(date +%F).xml <range> ; ndiff scan-old.xml scan-new.xml`  
  *Expected:* Scans run on a fixed schedule. New hosts and new open ports create an alert and a ticket.  
  *Refs:* nist_800_53: CM-8, SI-4, CA-7; other: NIST SP 800-115 section 4.1 (continuous discovery)

- [ ] **NET-DISC-011** Search internet scan databases for exposed assets of the organization  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds services, devices and certificates that outsiders can already see.  
  *Steps:*
  1. List the domains, address ranges and organization names in scope.
  2. Search internet scan databases for these names and ranges.
  3. Compare the hosts and open services found with the inventory and the approved port list.
  4. Write down each host or service that is not in the inventory.
  *Example:* `shodan search net:<range> ; shodan host <ip> ; censys search "ip: <range>" ; compare with nmap -sV results`  
  *Expected:* The databases show only approved hosts and services. Each exposed service is in the inventory and has an owner.  
  *Refs:* wstg: WSTG-INFO-01; attack: T1590.005, T1595.001; capec: CAPEC-169; nist_800_53: CM-8, RA-5(4)  
  *See:* WEB-INFO-001


## DNS

- [ ] **NET-DNS-001** Make sure name servers refuse DNS zone transfers from unknown hosts  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds name servers that give the full list of hosts in a zone to anyone.  
  *Steps:*
  1. List the name servers of each domain in scope.
  2. Request a zone transfer from each name server.
  3. Request a zone transfer again from a host that is not on the transfer allow list.
  4. Write down each name server that returns zone data.
  *Example:* `dig NS example.com +short ; dig AXFR example.com @ns1.example.com ; host -l example.com ns1.example.com ; dnsrecon -d example.com -t axfr`  
  *Expected:* Each name server refuses zone transfers from unknown hosts. Only listed secondary servers can get a transfer.  
  *Refs:* wstg: WSTG-INFO-04; attack: T1590.002; capec: CAPEC-291; cwe: CWE-200; nist_800_53: SC-22

- [ ] **NET-DNS-002** Check the DNS record inventory and the order of service decommissioning  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds DNS records with no owner and processes that leave records for removed services.  
  *Steps:*
  1. Get the DNS inventory that links each record to a resource and an owner.
  2. Export all records of the zone and compare them with the inventory.
  3. Look for CNAME, NS and MX records that point to removed or third-party services.
  4. Read the decommission procedure. Make sure it removes the DNS record before the resource.
  5. Make sure a scheduled scan checks that each record target still exists.
  *Example:* `dig AXFR example.com @ns1 (if allowed) ; dnsrecon -d example.com -t std ; for h in $(cat cnames.txt); do dig +short $h; done`  
  *Expected:* Every record has an owner and a live target. The procedure removes the DNS record first, and a scan finds dangling records at least weekly.  
  *Refs:* wstg: WSTG-CONF-10; cheatsheet: Subdomain_Takeover_Prevention_Cheat_Sheet; nist_800_53: CM-8, SC-22  
  *See:* WEB-CONF-011

- [ ] **NET-DNS-003** Check CAA records and Certificate Transparency monitoring for the domains  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds domains where any certificate authority can issue certificates and nobody sees new ones.  
  *Steps:*
  1. Query the CAA records of each domain and subdomain.
  2. Compare the listed certificate authorities with the ones the organization uses.
  3. Search the Certificate Transparency logs for certificates of the domain.
  4. Look for certificates that nobody in the organization asked for.
  5. Make sure an alert exists for new certificates.
  *Example:* `dig CAA example.com +short ; curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r ".[].name_value" | sort -u`  
  *Expected:* CAA records list only approved certificate authorities. Each logged certificate is known, and new certificates raise an alert.  
  *Refs:* wstg: WSTG-INFO-04; cheatsheet: Transport_Layer_Security_Cheat_Sheet, Subdomain_Takeover_Prevention_Cheat_Sheet; nist_800_53: SC-17, SC-12; attack: T1596.003

- [ ] **NET-DNS-004** Make sure recursive resolvers do not answer queries from the internet  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds open resolvers that attackers use for amplification and for cache attacks.  
  *Steps:*
  1. Find the hosts that answer on UDP and TCP port 53.
  2. From an external host, send a query for a name that the server does not host.
  3. Look at the response flags to see if the server resolves the name for you.
  4. Make sure authoritative and recursive roles run on separate servers.
  *Example:* `nmap -sU -sT -p 53 --script dns-recursion <range> ; dig @<ns-ip> www.example.net A +norecurse ; dig @<ns-ip> www.example.net A`  
  *Expected:* Authoritative servers do not resolve names for outside hosts. Recursive resolvers answer only internal clients.  
  *Refs:* attack: T1498.002; capec: CAPEC-490; cheatsheet: Denial_of_Service_Cheat_Sheet; cwe: CWE-668; nist_800_53: SC-22, SC-21, SC-5

- [ ] **NET-DNS-005** Check DNSSEC signing of zones and validation on resolvers  
  *Severity if fail:* Low | *Type:* Automated  
  *Objective:* Finds zones and resolvers with no data origin authentication of DNS answers.  
  *Steps:*
  1. Query the DNSKEY and DS records of each public zone.
  2. Check that answers from the authoritative servers carry signatures.
  3. Send a query for a name with a bad signature to the internal resolver.
  4. Look at the answer to see if the resolver rejects it.
  *Example:* `dig DNSKEY example.com +dnssec +multi ; dig DS example.com +trace ; dig @<resolver> dnssec-failed.org A (expect SERVFAIL)`  
  *Expected:* Public zones are signed and the chain of trust is complete. Resolvers check signatures and reject answers that fail.  
  *Refs:* attack: T1584.002; cwe: CWE-345; nist_800_53: SC-20, SC-21

- [ ] **NET-DNS-006** Look for internal host names and addresses in public DNS data  
  *Severity if fail:* Low | *Type:* Automated  
  *Objective:* Finds public DNS data that shows the internal layout of the network.  
  *Steps:*
  1. Query the public zone for all common record types.
  2. Run reverse queries on the public address ranges.
  3. Search passive DNS and certificate logs for the domain.
  4. Look for internal host names, private addresses and test systems in the results.
  *Example:* `dnsrecon -d example.com -t std,brt,rvl -r <range>/24 ; dig -x <ip> +short ; dig example.com ANY`  
  *Expected:* Public DNS data holds no internal host names and no private addresses. Reverse records exist only for hosts that need them.  
  *Refs:* wstg: WSTG-INFO-04; attack: T1590.002, T1596.001; capec: CAPEC-169; cwe: CWE-200; nist_800_53: SC-22; pci_dss: 1.4.5


## DOS

- [ ] **NET-DOS-001** Review the DoS inventory for single points of failure and scaling options  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds components whose failure or overload stops the service, with no redundancy.  
  *Steps:*
  1. Get the list of network and service components and their capacity.
  2. Mark each component that has no second instance or no fail-over.
  3. Look for the scaling options of each marked component.
  4. Look for a plan for graceful degradation if a part fails.
  5. Write down each single point of failure that has no plan.
  *Example:* `Review of the architecture diagram and the load balancer and firewall fail-over configuration: show failover ; haproxy -c -f haproxy.cfg`  
  *Expected:* No single point of failure stops the service without a plan. Each critical component has a fail-over or a scaling option.  
  *Refs:* cheatsheet: Denial_of_Service_Cheat_Sheet; cwe: CWE-400; nist_800_53: SC-5, SC-22

- [ ] **NET-DOS-002** Test slow connection attacks against network edge services  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds servers and load balancers that hold connections open for slow clients until they run out of slots.  
  *Steps:*
  1. Read the minimum data rate, read timeout and connection timeout settings of the service.
  2. Open many connections and send the request very slowly.
  3. Look at the number of connections that the server keeps open.
  4. Send a normal request from another host and look at the answer time.
  *Example:* `slowhttptest -c 1000 -H -g -o slow -i 10 -r 200 -t GET -u https://<test-host>/ ; nmap --script http-slowloris-check <test-host>`  
  *Expected:* The server closes slow connections after the set timeout. Normal requests still get an answer during the test.  
  *Refs:* cheatsheet: Denial_of_Service_Cheat_Sheet; attack: T1499.002, T1499.003; capec: CAPEC-227, CAPEC-469; cwe: CWE-400, CWE-770; nist_800_53: SC-5

- [ ] **NET-DOS-003** Check rate limits, connection limits and timeouts on edge devices  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds edge devices that accept unlimited traffic, connections or sessions from one source.  
  *Steps:*
  1. Read the configuration of firewalls, load balancers and proxies.
  2. Look for a minimum ingress data rate with a read timeout.
  3. Look for an absolute connection timeout and a maximum data rate.
  4. Look for a total bandwidth limit and a load limit per resource.
  5. Look at the session timeout for inactive sessions.
  *Example:* `show running-config | include rate|limit|timeout ; nginx -T | grep -E "limit_req|limit_conn|timeout" ; httpd -M | grep reqtimeout`  
  *Expected:* The edge devices set a minimum data rate, connection timeouts, rate limits and a load limit. Inactive sessions end after a set time.  
  *Refs:* cheatsheet: Denial_of_Service_Cheat_Sheet; cwe: CWE-770, CWE-400; nist_800_53: SC-5, CM-6

- [ ] **NET-DOS-004** Test the connection limits of edge devices with a low-rate flood  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds devices that fail when many half-open or new connections arrive.  
  *Steps:*
  1. Read the connection table limit and the flood protection settings of the device.
  2. Send TCP SYN packets to the test target at a low, agreed rate.
  3. Raise the rate in small steps and stop at the agreed limit.
  4. Look at the connection table, the CPU of the device and the answer time of normal requests.
  *Example:* `hping3 -S -p 443 -i u1000 <test-target> ; show conn count ; Wireshark and the device monitoring`  
  *Expected:* The device uses flood protection and keeps its connection table below the limit. Normal requests still work at the agreed test rate.  
  *Refs:* cheatsheet: Denial_of_Service_Cheat_Sheet; attack: T1499.001, T1498.001; capec: CAPEC-482, CAPEC-125; cwe: CWE-770; nist_800_53: SC-5

- [ ] **NET-DOS-005** Check the ISP and DDoS filtering service for coverage and capacity  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds services that depend on one link and have no plan against volumetric attacks.  
  *Steps:*
  1. Get the contract or service description of the ISP and of the DDoS filtering provider.
  2. Look for more than one internet access point and for the bandwidth of each.
  3. Look at the mitigation capacity and the layers that the provider covers.
  4. Look at the contact and the escalation process for an attack.
  5. Look at where the provider routes and inspects the traffic, and compare it with the privacy rules.
  *Example:* `Review of contracts and runbooks. Check routes with: traceroute -n <service-ip> ; dig +short <service-name> to see if DNS points to the filter`  
  *Expected:* The service has more than one access point and enough capacity. A filtering service covers the large attacks, and the escalation process is known.  
  *Refs:* cheatsheet: Denial_of_Service_Cheat_Sheet; attack: T1498; nist_800_53: SC-5, SC-5(2)

- [ ] **NET-DOS-006** Check that DoS indicators are monitored and create alerts  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds networks where a flood or resource drain goes unseen until the service fails.  
  *Steps:*
  1. Look at the monitoring of bandwidth, connection counts, CPU and memory on edge systems.
  2. Look at the alert thresholds and the persons who get the alerts.
  3. Send a small, safe burst of test traffic that crosses a threshold.
  4. Look at the alert and the time until a responder sees it.
  *Example:* `iperf3 -c <test-host> -t 30 -P 8 (test link only) ; check the monitoring dashboard and the alert mail`  
  *Expected:* The monitoring shows the flood or drain and raises an alert to the responders in the agreed time.  
  *Refs:* cheatsheet: Denial_of_Service_Cheat_Sheet; nist_800_53: SC-5, SI-4; pci_dss: 11.5.1


## AUDIT

- [ ] **NET-AUDIT-001** Check that auditd is installed, enabled and active from boot  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts where audit events are lost because the daemon or the early boot audit is missing.  
  *Steps:*
  1. Look for the audit and audit plugin packages.
  2. Look at the auditd service state.
  3. Look at the kernel command line for audit=1 and the audit_backlog_limit value.
  4. Read auditctl -s and look at the enabled flag and the lost counter.
  *Example:* `rpm -q audit audispd-plugins || dpkg -l auditd ; systemctl is-enabled auditd ; systemctl is-active auditd ; cat /proc/cmdline ; auditctl -s`  
  *Expected:* The audit packages are installed. The auditd service is enabled and active. The kernel starts auditing at boot with a backlog limit that meets the standard.  
  *Refs:* tool_check: cac:coreos_audit_backlog_limit_kernel_argument, cac:coreos_audit_option, cac:grub2_audit_argument, cac:grub2_audit_backlog_limit_argument, cac:package_audispd-plugins_installed, cac:package_audit-audispd-plugins_installed, cac:package_audit-libs_installed, cac:package_audit_installed, cac:service_auditd_enabled; nist_800_53: CM-6, AU-14, AU-7, AU-10; pci_dss: 10.3, 10.1

- [ ] **NET-AUDIT-002** Check auditd log size, disk-full actions and flush settings  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts that lose audit records or keep running with no audit when the disk is full.  
  *Steps:*
  1. Read /etc/audit/auditd.conf.
  2. Look at max_log_file, max_log_file_action, num_logs and space_left.
  3. Look at space_left_action, admin_space_left_action, disk_full_action and disk_error_action.
  4. Look at flush, freq, overflow_action, log_format, name_format and local_events.
  5. Look at the size of the partition that holds /var/log/audit.
  *Example:* `grep -vE "^#|^$" /etc/audit/auditd.conf ; df -h /var/log/audit ; grep -E "active|direction|path|type" /etc/audit/plugins.d/*.conf`  
  *Expected:* Audit logs have enough space and rotate by the standard. A full disk sends an alert and halts or changes to single user mode. The daemon writes to disk at the set rate.  
  *Refs:* tool_check: cac:auditd_audispd_configure_sufficiently_large_partition, cac:auditd_audispd_disk_full_action, cac:auditd_audispd_network_failure_action, cac:auditd_audispd_remote_daemon_activated, cac:auditd_audispd_remote_daemon_direction, cac:auditd_audispd_remote_daemon_path, cac:auditd_audispd_remote_daemon_type, cac:auditd_audispd_syslog_plugin_activated, cac:auditd_data_disk_error_action, cac:auditd_data_disk_error_action_stig, cac:auditd_data_disk_full_action, cac:auditd_data_disk_full_action_stig, cac:auditd_data_retention_action_mail_acct, cac:auditd_data_retention_admin_space_left_action, cac:auditd_data_retention_admin_space_left_percentage, cac:auditd_data_retention_flush, cac:auditd_data_retention_max_log_file, cac:auditd_data_retention_max_log_file_action, cac:auditd_data_retention_max_log_file_action_stig, cac:auditd_data_retention_num_logs, cac:auditd_data_retention_space_left, cac:auditd_data_retention_space_left_action, cac:auditd_data_retention_space_left_percentage, cac:auditd_freq, cac:auditd_local_events, cac:auditd_log_format, cac:auditd_name_format, cac:auditd_overflow_action, cac:auditd_write_logs; nist_800_53: AU-5, CM-6, AU-11, AU-4; pci_dss: 10.7

- [ ] **NET-AUDIT-003** Check the owner and mode of audit logs, rules and tools  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds audit logs, rule files or audit binaries that other users can read or change.  
  *Steps:*
  1. List the files in /var/log/audit and the directory itself.
  2. List /etc/audit/auditd.conf, /etc/audit/audit.rules and /etc/audit/rules.d.
  3. List the audit binaries auditctl, auditd, ausearch, aureport, autrace and augenrules.
  4. Make sure root owns each item and the modes are as strict as the standard sets.
  *Example:* `stat -c "%U:%G %a %n" /var/log/audit /var/log/audit/* /etc/audit/auditd.conf /etc/audit/rules.d/* /sbin/auditctl /sbin/auditd /sbin/ausearch /sbin/aureport /sbin/augenrules`  
  *Expected:* Root owns audit logs, configuration and tools. Logs have a mode of 0600 or 0640, the log directory 0700 or 0750, and the binaries 0755 or stricter.  
  *Refs:* tool_check: cac:directory_access_var_log_audit, cac:directory_group_ownership_var_log_audit, cac:directory_ownership_var_log_audit, cac:directory_permissions_var_log_audit, cac:file_audit_tools_group_ownership, cac:file_audit_tools_ownership, cac:file_audit_tools_permissions, cac:file_group_ownership_var_log_audit, cac:file_group_ownership_var_log_audit_stig, cac:file_groupownership_audit_binaries, cac:file_groupownership_audit_configuration, cac:file_ownership_audit_binaries, cac:file_ownership_audit_configuration, cac:file_ownership_var_log_audit, cac:file_ownership_var_log_audit_stig, cac:file_permissions_audit_binaries, cac:file_permissions_audit_configuration, cac:file_permissions_audit_configuration_stig, cac:file_permissions_etc_audit_auditd, cac:file_permissions_etc_audit_auditd_stig, cac:file_permissions_etc_audit_rules, cac:file_permissions_etc_audit_rulesd, cac:file_permissions_local_var_log_messages, cac:file_permissions_var_log_audit, cac:file_permissions_var_log_audit_stig, cac:permissions_local_audit_binaries, cac:permissions_local_var_log_audit; nist_800_53: AU-9, AC-6, CM-6, AU-12; pci_dss: 10.5.1, 10.5

- [ ] **NET-AUDIT-004** Check the base audit rules, immutable mode and OSPP rule set  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts where an attacker can switch off or change audit rules after a login.  
  *Steps:*
  1. Read the rule files in /etc/audit/rules.d.
  2. Look for the first rule that clears old rules and for the backlog and failure mode settings.
  3. Look for the immutable flag -e 2 as the last rule.
  4. Look for the rules that watch module loading and login UIDs.
  5. Run auditctl -s and look at the enabled value.
  *Example:* `cat /etc/audit/rules.d/*.rules ; auditctl -s | grep enabled ; auditctl -l | head -20 ; grep -rn "loginuid_immutable\|^-e " /etc/audit/rules.d/`  
  *Expected:* The rules start from a clean state, set a backlog limit and log failures to the system log. The configuration is immutable and the login UID cannot change.  
  *Refs:* tool_check: cac:audit_basic_configuration, cac:audit_immutable_login_uids, cac:audit_module_load, cac:audit_module_load_ppc64le, cac:audit_ospp_general, cac:audit_ospp_general_aarch64, cac:audit_ospp_general_ppc64le, cac:audit_rules_for_ospp; nist_800_53: AU-2

- [ ] **NET-AUDIT-005** Check audit rules for identity files, logins, sudoers and cron  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds hosts that do not record changes to accounts, logins, privilege rules and scheduled jobs.  
  *Steps:*
  1. Run auditctl -l and compare the output with the rules in /etc/audit/rules.d.
  2. Look for watches on /etc/passwd, /etc/shadow, /etc/group and /etc/gshadow.
  3. Look for watches on /etc/sudoers, /etc/sudoers.d, /etc/cron.d and /var/spool/cron.
  4. Look for watches on login, session and failure logs such as faillock, lastlog, wtmp, btmp and utmp.
  5. Change a test account and make sure ausearch shows the event.
  *Example:* `auditctl -l | grep -E "passwd|shadow|group|gshadow|sudoers|cron|faillock|lastlog|wtmp|btmp|utmp|setuid" ; ausearch -k identity -ts recent ; augenrules --check`  
  *Expected:* Each identity, login, sudoers and cron file has an audit watch with a key. A change to a watched file creates an audit record.  
  *Refs:* tool_check: cac:audit_rules_cron_execution, cac:audit_rules_etc_cron_d, cac:audit_rules_etc_group_open, cac:audit_rules_etc_group_open_by_handle_at, cac:audit_rules_etc_group_openat, cac:audit_rules_etc_gshadow_open, cac:audit_rules_etc_gshadow_open_by_handle_at, cac:audit_rules_etc_gshadow_openat, cac:audit_rules_etc_passwd_open, cac:audit_rules_etc_passwd_open_by_handle_at, cac:audit_rules_etc_passwd_openat, cac:audit_rules_etc_shadow_open, cac:audit_rules_etc_shadow_open_by_handle_at, cac:audit_rules_etc_shadow_openat, cac:audit_rules_login_events, cac:audit_rules_login_events_faillock, cac:audit_rules_login_events_faillog, cac:audit_rules_login_events_lastlog, cac:audit_rules_login_events_tallylog, cac:audit_rules_session_events, cac:audit_rules_session_events_btmp, cac:audit_rules_session_events_utmp, cac:audit_rules_session_events_wtmp, cac:audit_rules_sudoers, cac:audit_rules_sudoers_d, cac:audit_rules_suid_auid_privilege_function, cac:audit_rules_suid_privilege_function, cac:audit_rules_sysadmin_actions, cac:audit_rules_var_spool_cron; nist_800_53: AU-12, AU-2, AC-6, CM-6; pci_dss: 10.2.2

- [ ] **NET-AUDIT-006** Check audit rules for privileged commands and security tools  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts that do not record the use of setuid programs and of tools that change access rules.  
  *Steps:*
  1. Find the setuid and setgid programs on the local file systems.
  2. Run auditctl -l and look for a rule for each program, with the auid filter and a key.
  3. Look for rules on chacl, setfacl, chcon, restorecon, semanage and setsebool.
  4. Look for rules on shutdown, reboot, poweroff and init.
  5. Run one program and look for the record with ausearch.
  *Example:* `find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null ; auditctl -l | grep -E "privileged|perm=x" ; ausearch -k privileged -ts recent`  
  *Expected:* Each setuid and setgid program has an audit rule for user executions. The rules for access-change tools and for shutdown commands exist.  
  *Refs:* tool_check: cac:audit_privileged_commands_init, cac:audit_privileged_commands_poweroff, cac:audit_privileged_commands_reboot, cac:audit_privileged_commands_shutdown, cac:audit_rules_execution_chacl, cac:audit_rules_execution_chcon, cac:audit_rules_execution_chmod, cac:audit_rules_execution_restorecon, cac:audit_rules_execution_rm, cac:audit_rules_execution_semanage, cac:audit_rules_execution_setfacl, cac:audit_rules_execution_setfiles, cac:audit_rules_execution_setsebool, cac:audit_rules_execution_seunshare, cac:audit_rules_privileged_commands, cac:audit_rules_privileged_commands_apparmor_parser, cac:audit_rules_privileged_commands_at, cac:audit_rules_privileged_commands_chage, cac:audit_rules_privileged_commands_chfn, cac:audit_rules_privileged_commands_chsh, cac:audit_rules_privileged_commands_crontab, cac:audit_rules_privileged_commands_dbus_daemon_launch_helper, cac:audit_rules_privileged_commands_fdisk, cac:audit_rules_privileged_commands_fusermount, cac:audit_rules_privileged_commands_fusermount3, cac:audit_rules_privileged_commands_gpasswd, cac:audit_rules_privileged_commands_grub2_set_bootflag, cac:audit_rules_privileged_commands_insmod, cac:audit_rules_privileged_commands_kmod, cac:audit_rules_privileged_commands_modprobe, cac:audit_rules_privileged_commands_mount, cac:audit_rules_privileged_commands_mount_nfs, cac:audit_rules_privileged_commands_newgidmap, cac:audit_rules_privileged_commands_newgrp, cac:audit_rules_privileged_commands_newuidmap, cac:audit_rules_privileged_commands_pam_timestamp_check, cac:audit_rules_privileged_commands_passmass, cac:audit_rules_privileged_commands_passwd, cac:audit_rules_privileged_commands_pkexec, cac:audit_rules_privileged_commands_polkit_helper, cac:audit_rules_privileged_commands_postdrop, cac:audit_rules_privileged_commands_postqueue, cac:audit_rules_privileged_commands_pt_chown, cac:audit_rules_privileged_commands_rmmod, cac:audit_rules_privileged_commands_ssh_agent, cac:audit_rules_privileged_commands_ssh_keysign, cac:audit_rules_privileged_commands_sssd_krb5_child, cac:audit_rules_privileged_commands_sssd_ldap_child, cac:audit_rules_privileged_commands_sssd_proxy_child, cac:audit_rules_privileged_commands_sssd_selinux_child, cac:audit_rules_privileged_commands_su, cac:audit_rules_privileged_commands_sudo, cac:audit_rules_privileged_commands_sudoedit, cac:audit_rules_privileged_commands_umount, cac:audit_rules_privileged_commands_unix2_chkpwd, cac:audit_rules_privileged_commands_unix_chkpwd, cac:audit_rules_privileged_commands_unix_update, cac:audit_rules_privileged_commands_useradd, cac:audit_rules_privileged_commands_userhelper, cac:audit_rules_privileged_commands_usermod, cac:audit_rules_privileged_commands_usernetctl, cac:audit_rules_privileged_commands_utempter, cac:audit_rules_privileged_commands_write, cac:audit_rules_usergroup_modification, cac:audit_rules_usergroup_modification_group, cac:audit_rules_usergroup_modification_gshadow, cac:audit_rules_usergroup_modification_nsswitch_conf, cac:audit_rules_usergroup_modification_opasswd, cac:audit_rules_usergroup_modification_pam_conf, cac:audit_rules_usergroup_modification_pamd, cac:audit_rules_usergroup_modification_passwd, cac:audit_rules_usergroup_modification_shadow, cac:audit_sudo_log_events; nist_800_53: AU-12, AU-2, AC-6, CM-6; pci_dss: 10.2.2

- [ ] **NET-AUDIT-007** Check audit rules for permission, owner and extended attribute changes  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts that do not record changes of file modes, owners and extended attributes.  
  *Steps:*
  1. Run auditctl -l and compare the output with the rules in /etc/audit/rules.d.
  2. Look for rules on chmod, fchmod, fchmodat, chown, fchown, fchownat and lchown.
  3. Look for rules on setxattr, lsetxattr, fsetxattr, removexattr and the related calls.
  4. Look for the b32 and b64 variants and the auid filter.
  5. Run chmod on a test file and look for the record with ausearch.
  *Example:* `auditctl -l | grep -E "chmod|chown|setxattr|removexattr" ; touch /tmp/t && chmod 600 /tmp/t && ausearch -k perm_mod -ts recent`  
  *Expected:* Rules exist for each permission, owner and attribute system call, for both 32-bit and 64-bit calls. A mode change creates an audit record.  
  *Refs:* tool_check: cac:audit_owner_change_failed, cac:audit_owner_change_failed_aarch64, cac:audit_owner_change_failed_ppc64le, cac:audit_owner_change_success, cac:audit_owner_change_success_aarch64, cac:audit_owner_change_success_ppc64le, cac:audit_perm_change_failed, cac:audit_perm_change_failed_aarch64, cac:audit_perm_change_failed_ppc64le, cac:audit_perm_change_success, cac:audit_perm_change_success_aarch64, cac:audit_perm_change_success_ppc64le, cac:audit_rules_dac_modification_chmod, cac:audit_rules_dac_modification_chown, cac:audit_rules_dac_modification_fchmod, cac:audit_rules_dac_modification_fchmodat, cac:audit_rules_dac_modification_fchmodat2, cac:audit_rules_dac_modification_fchown, cac:audit_rules_dac_modification_fchownat, cac:audit_rules_dac_modification_fremovexattr, cac:audit_rules_dac_modification_fsetxattr, cac:audit_rules_dac_modification_lchown, cac:audit_rules_dac_modification_lremovexattr, cac:audit_rules_dac_modification_lsetxattr, cac:audit_rules_dac_modification_removexattr, cac:audit_rules_dac_modification_setxattr, cac:audit_rules_dac_modification_umount, cac:audit_rules_dac_modification_umount2, cac:audit_rules_successful_file_modification_chmod, cac:audit_rules_successful_file_modification_chown, cac:audit_rules_successful_file_modification_fremovexattr, cac:audit_rules_successful_file_modification_fsetxattr, cac:audit_rules_successful_file_modification_lremovexattr, cac:audit_rules_successful_file_modification_lsetxattr, cac:audit_rules_successful_file_modification_removexattr, cac:audit_rules_successful_file_modification_setxattr, cac:audit_rules_unsuccessful_file_modification_chmod, cac:audit_rules_unsuccessful_file_modification_chown, cac:audit_rules_unsuccessful_file_modification_fremovexattr, cac:audit_rules_unsuccessful_file_modification_fsetxattr, cac:audit_rules_unsuccessful_file_modification_lremovexattr, cac:audit_rules_unsuccessful_file_modification_lsetxattr, cac:audit_rules_unsuccessful_file_modification_removexattr, cac:audit_rules_unsuccessful_file_modification_setxattr; nist_800_53: AU-2, AU-12, CM-6

- [ ] **NET-AUDIT-008** Check audit rules for failed access, file creation, change and deletion  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts that do not record denied access or the deletion and change of files by users.  
  *Steps:*
  1. Run auditctl -l and compare the output with the rules in /etc/audit/rules.d.
  2. Look for rules on open, openat, truncate and creat that log EACCES and EPERM results.
  3. Look for rules on unlink, unlinkat, rename, renameat and rmdir.
  4. Look for rules on file creation and change with success results.
  5. Try to open a protected file as a test user and look for the record with ausearch.
  *Example:* `auditctl -l | grep -E "EACCES|EPERM|unlink|rename|rmdir|creat|truncate" ; ausearch -k access -ts recent ; ausearch -k delete -ts recent`  
  *Expected:* Failed access and file delete or change calls have audit rules. A denied access try creates an audit record with the user ID.  
  *Refs:* tool_check: cac:audit_access_failed, cac:audit_access_failed_aarch64, cac:audit_access_failed_ppc64le, cac:audit_access_success, cac:audit_access_success_aarch64, cac:audit_access_success_ppc64le, cac:audit_create_failed, cac:audit_create_failed_aarch64, cac:audit_create_failed_ppc64le, cac:audit_create_success, cac:audit_create_success_aarch64, cac:audit_create_success_ppc64le, cac:audit_delete_failed, cac:audit_delete_failed_aarch64, cac:audit_delete_failed_ppc64le, cac:audit_delete_success, cac:audit_delete_success_aarch64, cac:audit_delete_success_ppc64le, cac:audit_modify_failed, cac:audit_modify_failed_aarch64, cac:audit_modify_failed_ppc64le, cac:audit_modify_success, cac:audit_modify_success_aarch64, cac:audit_modify_success_ppc64le, cac:audit_rules_file_deletion_events, cac:audit_rules_file_deletion_events_rename, cac:audit_rules_file_deletion_events_renameat, cac:audit_rules_file_deletion_events_renameat2, cac:audit_rules_file_deletion_events_rmdir, cac:audit_rules_file_deletion_events_unlink, cac:audit_rules_file_deletion_events_unlinkat, cac:audit_rules_successful_file_modification_creat, cac:audit_rules_successful_file_modification_fchmod, cac:audit_rules_successful_file_modification_fchmodat, cac:audit_rules_successful_file_modification_fchown, cac:audit_rules_successful_file_modification_fchownat, cac:audit_rules_successful_file_modification_ftruncate, cac:audit_rules_successful_file_modification_lchown, cac:audit_rules_successful_file_modification_open, cac:audit_rules_successful_file_modification_open_by_handle_at, cac:audit_rules_successful_file_modification_open_by_handle_at_o_creat, cac:audit_rules_successful_file_modification_open_by_handle_at_o_trunc_write, cac:audit_rules_successful_file_modification_open_o_creat, cac:audit_rules_successful_file_modification_open_o_trunc_write, cac:audit_rules_successful_file_modification_openat, cac:audit_rules_successful_file_modification_openat_o_creat, cac:audit_rules_successful_file_modification_openat_o_trunc_write, cac:audit_rules_successful_file_modification_rename, cac:audit_rules_successful_file_modification_renameat, cac:audit_rules_successful_file_modification_truncate, cac:audit_rules_successful_file_modification_unlink, cac:audit_rules_successful_file_modification_unlinkat, cac:audit_rules_unsuccessful_file_modification, cac:audit_rules_unsuccessful_file_modification_creat, cac:audit_rules_unsuccessful_file_modification_fchmod, cac:audit_rules_unsuccessful_file_modification_fchmodat, cac:audit_rules_unsuccessful_file_modification_fchown, cac:audit_rules_unsuccessful_file_modification_fchownat, cac:audit_rules_unsuccessful_file_modification_ftruncate, cac:audit_rules_unsuccessful_file_modification_lchown, cac:audit_rules_unsuccessful_file_modification_open, cac:audit_rules_unsuccessful_file_modification_open_by_handle_at, cac:audit_rules_unsuccessful_file_modification_open_by_handle_at_o_creat, cac:audit_rules_unsuccessful_file_modification_open_by_handle_at_o_trunc_write, cac:audit_rules_unsuccessful_file_modification_open_by_handle_at_rule_order, cac:audit_rules_unsuccessful_file_modification_open_o_creat, cac:audit_rules_unsuccessful_file_modification_open_o_trunc_write, cac:audit_rules_unsuccessful_file_modification_open_rule_order, cac:audit_rules_unsuccessful_file_modification_openat, cac:audit_rules_unsuccessful_file_modification_openat_o_creat, cac:audit_rules_unsuccessful_file_modification_openat_o_trunc_write, cac:audit_rules_unsuccessful_file_modification_openat_rule_order, cac:audit_rules_unsuccessful_file_modification_rename, cac:audit_rules_unsuccessful_file_modification_renameat, cac:audit_rules_unsuccessful_file_modification_renameat2, cac:audit_rules_unsuccessful_file_modification_truncate, cac:audit_rules_unsuccessful_file_modification_unlink, cac:audit_rules_unsuccessful_file_modification_unlinkat; nist_800_53: AU-2, AU-12, CM-6; pci_dss: 10.2.1

- [ ] **NET-AUDIT-009** Check audit rules for kernel modules, time, network and MAC changes  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts that do not record module loads, clock changes, network setting changes and policy changes.  
  *Steps:*
  1. Look for rules on init_module, finit_module and delete_module.
  2. Look for rules on adjtimex, settimeofday, clock_settime and /etc/localtime.
  3. Look for rules on sethostname, setdomainname and the network configuration files.
  4. Look for watches on the SELinux or AppArmor policy directories.
  5. Look for the audit rules for system shutdown, media export and journal files.
  *Example:* `auditctl -l | grep -E "module|adjtimex|settimeofday|clock_settime|localtime|sethostname|/etc/hosts|selinux|apparmor|mount" ; ausearch -k modules -ts recent`  
  *Expected:* Rules exist for module loads, clock changes, network identity changes and mandatory access control policy files. Each rule has a key.  
  *Refs:* tool_check: cac:audit_rules_continue_loading, cac:audit_rules_enable_syscall_auditing, cac:audit_rules_immutable, cac:audit_rules_immutable_login_uids, cac:audit_rules_kernel_module_loading, cac:audit_rules_kernel_module_loading_create, cac:audit_rules_kernel_module_loading_delete, cac:audit_rules_kernel_module_loading_finit, cac:audit_rules_kernel_module_loading_init, cac:audit_rules_kernel_module_loading_query, cac:audit_rules_mac_modification, cac:audit_rules_mac_modification_etc_apparmor, cac:audit_rules_mac_modification_etc_apparmor_d, cac:audit_rules_mac_modification_etc_selinux, cac:audit_rules_mac_modification_usr_share, cac:audit_rules_mac_modification_var_lib_selinux, cac:audit_rules_media_export, cac:audit_rules_networkconfig_modification, cac:audit_rules_networkconfig_modification_etc_hosts, cac:audit_rules_networkconfig_modification_etc_issue, cac:audit_rules_networkconfig_modification_etc_issue_net, cac:audit_rules_networkconfig_modification_etc_networkmanager_system_connections, cac:audit_rules_networkconfig_modification_etc_sysconfig_network, cac:audit_rules_networkconfig_modification_hostname_file, cac:audit_rules_networkconfig_modification_network_scripts, cac:audit_rules_networkconfig_modification_networkmanager, cac:audit_rules_networkconfig_modification_setdomainname, cac:audit_rules_networkconfig_modification_sethostname, cac:audit_rules_system_shutdown, cac:audit_rules_time_adjtimex, cac:audit_rules_time_clock_settime, cac:audit_rules_time_settimeofday, cac:audit_rules_time_stime, cac:audit_rules_time_watch_localtime, cac:audit_rules_var_log_journal; nist_800_53: CM-6, AU-2, AU-12, AC-6; pci_dss: 10.4.2

- [ ] **NET-AUDIT-010** Check rsyslog and syslog-ng files, remote input and logging services  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds log services that accept remote messages without a need or create log files that others can read.  
  *Steps:*
  1. Look at the state of the rsyslog or syslog-ng service and make sure only one log service is active.
  2. Read the rsyslog configuration for the FileCreateMode and the owner of the files.
  3. Look for imtcp, imudp and the listen options. Make sure they are off unless the host is a log server.
  4. Look for rules that log cron, authentication and kernel messages.
  5. Look at the logwatch settings on a log server.
  *Example:* `systemctl is-active rsyslog syslog-ng journald ; grep -rnE "FileCreateMode|imtcp|imudp|InputTCPServerRun|\$ModLoad" /etc/rsyslog.conf /etc/rsyslog.d/ ; ss -ulnp | grep :514 ; grep -E "cron|authpriv" /etc/rsyslog.conf`  
  *Expected:* One log service runs and logs the standard facilities. New log files have a mode of 0640 or stricter. Remote input is off, except on a named log server.  
  *Refs:* tool_check: cac:disable_logwatch_for_logserver, cac:ensure_journald_and_rsyslog_not_active_together, cac:ensure_rtc_utc_configuration, cac:logging_services_active, cac:logwatch_configured_hostlimit, cac:logwatch_configured_splithosts, cac:package_rsyslog-gnutls_installed, cac:package_rsyslog_installed, cac:package_syslogng_installed, cac:rsyslog_accept_remote_messages_tcp, cac:rsyslog_accept_remote_messages_udp, cac:rsyslog_cron_logging, cac:rsyslog_filecreatemode, cac:rsyslog_files_groupownership, cac:rsyslog_files_ownership, cac:rsyslog_files_permissions, cac:rsyslog_logging_configured, cac:rsyslog_nolisten, cac:rsyslog_remote_access_monitoring, cac:service_rsyslog_enabled, cac:service_syslogng_enabled, cac:syslogng_filecreatemode, cac:syslogng_nolisten; nist_800_53: CM-6, AU-6, CM-7, AC-6; pci_dss: 10.5.1

- [ ] **NET-AUDIT-011** Check journald storage, forwarding and journal file permissions  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts where the system journal is lost at restart or can be read by other users.  
  *Steps:*
  1. Read /etc/systemd/journald.conf and the files under journald.conf.d.
  2. Look at Storage, Compress and ForwardToSyslog.
  3. List /var/log/journal and the journal files with their owner and mode.
  4. Look at the owner and mode of the journalctl program.
  5. Look for the journal-remote socket and make sure it is off unless the host receives logs.
  *Example:* `systemd-analyze cat-config systemd/journald.conf ; stat -c "%U:%G %a %n" /var/log/journal /var/log/journal/* /usr/bin/journalctl ; systemctl is-enabled systemd-journal-remote.socket`  
  *Expected:* Storage is persistent. Journal files and the journal directory are owned by root and the systemd-journal group with restricted modes. The remote receive socket is off.  
  *Refs:* tool_check: cac:dir_groupowner_system_journal, cac:dir_owner_system_journal, cac:dir_permissions_system_journal, cac:file_groupowner_journalctl, cac:file_groupowner_system_journal, cac:file_owner_journalctl, cac:file_owner_system_journal, cac:file_permissions_journalctl, cac:file_permissions_system_journal, cac:journald_compress, cac:journald_disable_forward_to_syslog, cac:journald_forward_to_syslog, cac:journald_storage, cac:package_systemd-journal-remote_installed, cac:service_systemd-journald_enabled, cac:socket_systemd-journal-remote_disabled; nist_800_53: SC-24

- [ ] **NET-AUDIT-012** Check /var/log file permissions and the log rotation setup  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds log files that all users can read or change and logs that grow with no rotation.  
  *Steps:*
  1. List the files and directories under /var/log with their owner, group and mode.
  2. Look for log files with a mode wider than 0640 and for files with the wrong group.
  3. Look at the package and the timer or cron job for logrotate.
  4. Read /etc/logrotate.conf and look at the rotation count and the size limits.
  *Example:* `find /var/log -type f \( -perm -0004 -o -perm -0020 \) -ls ; stat -c "%U:%G %a %n" /var/log/messages /var/log/secure /var/log/syslog /var/log/auth.log /var/log/wtmp /var/log/btmp ; systemctl is-enabled logrotate.timer ; grep -vE "^#|^$" /etc/logrotate.conf`  
  *Expected:* Log files are not readable or changeable by other users. Root owns them and the modes follow the standard. Logrotate runs on a schedule.  
  *Refs:* tool_check: cac:ensure_logrotate_activated, cac:file_groupowner_var_log, cac:file_groupowner_var_log_auth, cac:file_groupowner_var_log_cloud_init, cac:file_groupowner_var_log_journal, cac:file_groupowner_var_log_lastlog, cac:file_groupowner_var_log_localmessages, cac:file_groupowner_var_log_messages, cac:file_groupowner_var_log_secure, cac:file_groupowner_var_log_syslog, cac:file_groupowner_var_log_waagent, cac:file_groupowner_var_log_wbtmp, cac:file_groupownerships_var_log, cac:file_groupownerships_var_log_apt, cac:file_groupownerships_var_log_gdm, cac:file_groupownerships_var_log_gdm3, cac:file_groupownerships_var_log_landscape, cac:file_groupownerships_var_log_sssd, cac:file_owner_var_log, cac:file_owner_var_log_auth, cac:file_owner_var_log_cloud_init, cac:file_owner_var_log_journal, cac:file_owner_var_log_lastlog, cac:file_owner_var_log_localmessages, cac:file_owner_var_log_messages, cac:file_owner_var_log_secure, cac:file_owner_var_log_syslog, cac:file_owner_var_log_waagent, cac:file_owner_var_log_wbtmp, cac:file_ownerships_var_log, cac:file_ownerships_var_log_apt, cac:file_ownerships_var_log_gdm, cac:file_ownerships_var_log_gdm3, cac:file_ownerships_var_log_landscape, cac:file_ownerships_var_log_sssd, cac:file_permissions_var_log, cac:file_permissions_var_log_apt, cac:file_permissions_var_log_auth, cac:file_permissions_var_log_cloud-init, cac:file_permissions_var_log_gdm, cac:file_permissions_var_log_gdm3, cac:file_permissions_var_log_lastlog, cac:file_permissions_var_log_localmessages, cac:file_permissions_var_log_messages, cac:file_permissions_var_log_secure, cac:file_permissions_var_log_sssd, cac:file_permissions_var_log_stig, cac:file_permissions_var_log_syslog, cac:file_permissions_var_log_waagent, cac:file_permissions_var_log_wbtmp, cac:package_logrotate_installed, cac:permissions_local_var_log, cac:timer_logrotate_enabled; nist_800_53: CM-6, SI-11; pci_dss: 10.7


## FW

- [ ] **NET-FW-001** Check that firewalld runs with a default deny zone  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds hosts where firewalld is off or the default zone accepts traffic that no rule allows.  
  *Steps:*
  1. Look at the firewalld package and service state. Make sure only one firewall service is active.
  2. Run firewall-cmd --get-default-zone and --list-all.
  3. Look at the target of the zone. Make sure it is DROP or REJECT (default).
  4. Look at the loopback rules and at the rate limit settings.
  5. Look at the backend setting in /etc/firewalld/firewalld.conf.
  *Example:* `systemctl is-active firewalld ; firewall-cmd --get-default-zone ; firewall-cmd --list-all ; firewall-cmd --permanent --zone=public --get-target ; grep FirewallBackend /etc/firewalld/firewalld.conf`  
  *Expected:* firewalld is active and enabled. The default zone target is DROP or REJECT. Loopback traffic is allowed only on the loopback interface.  
  *Refs:* tool_check: cac:configure_firewalld_rate_limiting, cac:configured_firewalld_default_deny, cac:firewalld-backend, cac:firewalld_loopback_traffic_restricted, cac:firewalld_loopback_traffic_trusted, cac:package_firewalld_installed, cac:package_firewalld_removed, cac:service_firewalld_disabled, cac:service_firewalld_enabled, cac:set_firewalld_appropriate_zone, cac:set_firewalld_default_zone; nist_800_53: SC-5, CM-6, CM-7, CA-3; pci_dss: 1.4

- [ ] **NET-FW-002** Check iptables and ip6tables default policies and rule persistence  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds hosts where the INPUT, FORWARD or OUTPUT policy is ACCEPT and rules are lost after a restart.  
  *Steps:*
  1. Run iptables -S and ip6tables -S.
  2. Look at the default policy of INPUT and FORWARD. Look at the OUTPUT rules for new and established connections.
  3. Look at the rules for the loopback interface and for loopback spoofing.
  4. Look at the persistence service and the owner and mode of /etc/iptables.
  5. Make sure the saved rules match the live rules.
  *Example:* `iptables -S ; ip6tables -S ; iptables -L -v -n ; systemctl is-enabled iptables ip6tables netfilter-persistent ; stat -c "%U:%G %a %n" /etc/iptables /etc/sysconfig/iptables`  
  *Expected:* The INPUT and FORWARD policies are DROP. Only the needed outbound and established traffic is allowed. Rules for both IPv4 and IPv6 persist after a restart.  
  *Refs:* tool_check: cac:directory_groupowner_etc_iptables, cac:directory_owner_etc_iptables, cac:directory_permissions_etc_iptables, cac:ensure_iptables_are_flushed, cac:package_iptables-nft_installed, cac:package_iptables-persistent_installed, cac:package_iptables-persistent_removed, cac:package_iptables-services_installed, cac:package_iptables-services_removed, cac:package_iptables_installed, cac:service_ip6tables_enabled, cac:service_iptables_enabled, cac:set_ip6tables_default_rule, cac:set_iptables_default_rule, cac:set_iptables_default_rule_forward, cac:set_iptables_outbound_n_established, cac:set_ipv6_loopback_traffic, cac:set_loopback_traffic; nist_800_53: CM-6, CM-7, CA-3, SC-7; pci_dss: 1.3, 1.4.1

- [ ] **NET-FW-003** Check nftables tables, base chains and default deny policy  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds hosts where nftables has no base chains or accepts traffic by default.  
  *Steps:*
  1. Run nft list ruleset.
  2. Look for a table and base chains for input, forward and output.
  3. Look at the policy of each base chain. Look for the loopback and established rules.
  4. Read the saved ruleset in /etc/nftables and make sure the service loads it at boot.
  5. Look at the owner and mode of /etc/nftables.
  *Example:* `nft list ruleset ; systemctl is-enabled nftables ; grep -rn "include" /etc/nftables.conf ; stat -c "%U:%G %a %n" /etc/nftables /etc/nftables.conf`  
  *Expected:* Base chains for input, forward and output exist. The input and forward policy is drop. The ruleset loads at boot and only root can change the files.  
  *Refs:* tool_check: cac:directory_groupowner_etc_nftables, cac:directory_owner_etc_nftables, cac:directory_permissions_etc_nftables, cac:nftables_ensure_default_deny_policy, cac:nftables_rules_permanent, cac:package_nftables_installed, cac:package_nftables_removed, cac:service_nftables_disabled, cac:service_nftables_enabled, cac:set_nftables_base_chain, cac:set_nftables_loopback_traffic, cac:set_nftables_new_connections, cac:set_nftables_table; pci_dss: 1.4.1

- [ ] **NET-FW-004** Check UFW and SuSEfirewall2 state and default policy  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds hosts where the front-end firewall is installed but not active, or allows traffic by default.  
  *Steps:*
  1. Run ufw status verbose.
  2. Look at the default incoming, outgoing and routed policies.
  3. Look for the loopback rules and the rate limit rule for SSH.
  4. On SUSE hosts, look at the SuSEfirewall2 package, service and DoS protection settings.
  5. Make sure no second firewall service is active.
  *Example:* `ufw status verbose ; grep -E "^DEFAULT" /etc/default/ufw ; systemctl is-enabled ufw SuSEfirewall2 ; grep FW_PROTECT_FROM_INT /etc/sysconfig/SuSEfirewall2`  
  *Expected:* The firewall service is active. Incoming and routed policy is deny. Outgoing policy follows the standard. Loopback rules exist.  
  *Refs:* tool_check: cac:check_ufw_active, cac:package_SuSEfirewall2_installed, cac:package_ufw_installed, cac:package_ufw_removed, cac:service_SuSEfirewall2_enabled, cac:service_ufw_enabled, cac:set_ufw_default_rule, cac:set_ufw_loopback_traffic, cac:susefirewall2_ddos_protection, cac:ufw_default_incoming_rule, cac:ufw_default_outgoing_rule, cac:ufw_disabled_routed, cac:ufw_rate_limit

- [ ] **NET-FW-005** Check IPsec packages, tunnels and configuration file permissions  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds IPsec tunnels that no one approved or secret files that other users can read.  
  *Steps:*
  1. Look for the libreswan or strongswan package.
  2. List the active tunnels with ipsec status.
  3. Compare each tunnel with the approved tunnel list.
  4. List /etc/ipsec.conf, /etc/ipsec.secrets and /etc/ipsec.d with owner and mode.
  *Example:* `rpm -q libreswan strongswan ; ipsec status ; ipsec trafficstatus ; stat -c "%U:%G %a %n" /etc/ipsec.conf /etc/ipsec.secrets /etc/ipsec.d`  
  *Expected:* Every tunnel is on the approved list. Root owns the IPsec files and the secrets file has a mode of 0600.  
  *Refs:* tool_check: cac:directory_groupowner_etc_ipsecd, cac:directory_owner_etc_ipsecd, cac:directory_permissions_etc_ipsecd, cac:file_groupowner_etc_ipsec_conf, cac:file_groupowner_etc_ipsec_secrets, cac:file_owner_etc_ipsec_conf, cac:file_owner_etc_ipsec_secrets, cac:file_permissions_etc_ipsec_conf, cac:file_permissions_etc_ipsec_secrets, cac:libreswan_approved_tunnels, cac:package_libreswan_installed, cac:package_strongswan_installed; nist_800_53: CM-6, AC-17, MA-4, AC-4; pci_dss: 4.1

- [ ] **NET-FW-006** Check host network settings: DHCP, DDNS, zeroconf, sniffing and DNS mode  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts with automatic network features that an attacker on the LAN can use.  
  *Steps:*
  1. List the interfaces and look for the promiscuous flag.
  2. Look at DHCP client options in /etc/dhcp/dhclient.conf and at the use of static addresses.
  3. Look for zeroconf, DDNS updates and wireless or Bluetooth interfaces that the role does not need.
  4. Read the name resolution and NetworkManager DNS mode settings.
  5. Look at the permissions to change network settings with nmcli.
  *Example:* `ip -d link | grep -i promisc ; grep -vE "^#|^$" /etc/dhcp/dhclient.conf ; grep -r NOZEROCONF /etc/sysconfig/network ; nmcli radio ; grep dns /etc/NetworkManager/NetworkManager.conf ; nmcli general permissions`  
  *Expected:* No interface is in promiscuous mode. Zeroconf and DDNS are off. Unused wireless and Bluetooth interfaces are off. Only approved users can change network settings.  
  *Refs:* tool_check: cac:dhcp_client_restrict_options, cac:firewall_single_service_active, cac:network_configure_name_resolution, cac:network_disable_ddns_interfaces, cac:network_disable_zeroconf, cac:network_implement_access_control, cac:network_nmcli_permissions, cac:network_sniffer_disabled, cac:networkmanager_dns_mode, cac:only_allow_dod_certs, cac:only_allow_specific_certs, cac:package_dhcp_client_removed, cac:service_bluetooth_disabled, cac:sysconfig_networking_bootproto_ifcfg, cac:wireless_disable_in_bios, cac:wireless_disable_interfaces; nist_800_53: CM-7, CM-6, AC-18, MP-7; pci_dss: 1.3.3


## KERN

- [ ] **NET-KERN-001** Check the IPv4 sysctl settings for routing, redirects and spoofing  
  *Severity if fail:* Medium | *Type:* Config Review, Automated  
  *Objective:* Finds hosts that act as routers, accept redirects or source routes, or skip reverse path checks.  
  *Steps:*
  1. Read the live values with sysctl for net.ipv4.conf.all, net.ipv4.conf.default and net.ipv4.
  2. Look at ip_forward, accept_redirects, send_redirects, secure_redirects and accept_source_route.
  3. Look at rp_filter, log_martians, icmp_echo_ignore_broadcasts and tcp_syncookies.
  4. Look at the files under /etc/sysctl.d and /etc/sysctl.conf. Make sure the values stay after a restart.
  *Example:* `sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route net.ipv4.conf.all.rp_filter net.ipv4.conf.all.log_martians net.ipv4.tcp_syncookies net.ipv4.icmp_echo_ignore_broadcasts ; sysctl --system | grep -i ipv4`  
  *Expected:* Forwarding, redirects and source routing are off unless the host is a router. Reverse path filtering, martian logging, SYN cookies and the broadcast ping filter are on. The values persist.  
  *Refs:* tool_check: cac:sysctl_net_ipv4_conf_all_accept_local, cac:sysctl_net_ipv4_conf_all_accept_redirects, cac:sysctl_net_ipv4_conf_all_accept_source_route, cac:sysctl_net_ipv4_conf_all_arp_filter, cac:sysctl_net_ipv4_conf_all_arp_ignore, cac:sysctl_net_ipv4_conf_all_drop_gratuitous_arp, cac:sysctl_net_ipv4_conf_all_forwarding, cac:sysctl_net_ipv4_conf_all_log_martians, cac:sysctl_net_ipv4_conf_all_route_localnet, cac:sysctl_net_ipv4_conf_all_rp_filter, cac:sysctl_net_ipv4_conf_all_secure_redirects, cac:sysctl_net_ipv4_conf_all_send_redirects, cac:sysctl_net_ipv4_conf_all_shared_media, cac:sysctl_net_ipv4_conf_default_accept_redirects, cac:sysctl_net_ipv4_conf_default_accept_source_route, cac:sysctl_net_ipv4_conf_default_forwarding, cac:sysctl_net_ipv4_conf_default_log_martians, cac:sysctl_net_ipv4_conf_default_rp_filter, cac:sysctl_net_ipv4_conf_default_secure_redirects, cac:sysctl_net_ipv4_conf_default_send_redirects, cac:sysctl_net_ipv4_conf_default_shared_media, cac:sysctl_net_ipv4_icmp_echo_ignore_broadcasts, cac:sysctl_net_ipv4_icmp_ignore_bogus_error_responses, cac:sysctl_net_ipv4_ip_forward, cac:sysctl_net_ipv4_ip_local_port_range, cac:sysctl_net_ipv4_tcp_invalid_ratelimit, cac:sysctl_net_ipv4_tcp_rfc1337, cac:sysctl_net_ipv4_tcp_syncookies; nist_800_53: CM-7, SC-5, CM-6, SC-7; pci_dss: 1.4.3, 1.3.1

- [ ] **NET-KERN-002** Check the IPv6 sysctl settings and the IPv6 interface plan  
  *Severity if fail:* Medium | *Type:* Config Review, Automated  
  *Objective:* Finds hosts that accept router advertisements, redirects or source routes, or that run IPv6 with no plan.  
  *Steps:*
  1. Read the live values of net.ipv6.conf.all and net.ipv6.conf.default with sysctl.
  2. Look at accept_ra, accept_redirects, accept_source_route, forwarding, autoconf and max_addresses.
  3. Look at disable_ipv6 and compare it with the plan: IPv6 in use or IPv6 off.
  4. Look at the address, gateway and privacy extension settings of the network manager.
  *Example:* `sysctl -a 2>/dev/null | grep -E "net.ipv6.conf.(all|default).(accept_ra|accept_redirects|accept_source_route|forwarding|autoconf|disable_ipv6|max_addresses)" ; ip -6 addr ; nmcli -f ipv6 connection show <name>`  
  *Expected:* Router advertisements, redirects and source routes are off unless the host needs them. If the network does not use IPv6, IPv6 is off. Values persist after a restart.  
  *Refs:* tool_check: cac:network_ipv6_default_gateway, cac:network_ipv6_disable_interfaces, cac:network_ipv6_disable_rpc, cac:network_ipv6_privacy_extensions, cac:network_ipv6_static_address, cac:sysctl_net_ipv6_conf_all_accept_ra, cac:sysctl_net_ipv6_conf_all_accept_ra_defrtr, cac:sysctl_net_ipv6_conf_all_accept_ra_pinfo, cac:sysctl_net_ipv6_conf_all_accept_ra_rtr_pref, cac:sysctl_net_ipv6_conf_all_accept_redirects, cac:sysctl_net_ipv6_conf_all_accept_source_route, cac:sysctl_net_ipv6_conf_all_autoconf, cac:sysctl_net_ipv6_conf_all_disable_ipv6, cac:sysctl_net_ipv6_conf_all_forwarding, cac:sysctl_net_ipv6_conf_all_max_addresses, cac:sysctl_net_ipv6_conf_all_router_solicitations, cac:sysctl_net_ipv6_conf_default_accept_ra, cac:sysctl_net_ipv6_conf_default_accept_ra_defrtr, cac:sysctl_net_ipv6_conf_default_accept_ra_pinfo, cac:sysctl_net_ipv6_conf_default_accept_ra_rtr_pref, cac:sysctl_net_ipv6_conf_default_accept_redirects, cac:sysctl_net_ipv6_conf_default_accept_source_route, cac:sysctl_net_ipv6_conf_default_autoconf, cac:sysctl_net_ipv6_conf_default_disable_ipv6, cac:sysctl_net_ipv6_conf_default_forwarding, cac:sysctl_net_ipv6_conf_default_max_addresses, cac:sysctl_net_ipv6_conf_default_router_solicitations; nist_800_53: CM-7, CM-6; pci_dss: 1.4.3

- [ ] **NET-KERN-003** Check kernel and filesystem sysctl hardening values  
  *Severity if fail:* Medium | *Type:* Config Review, Automated  
  *Objective:* Finds hosts that leak kernel addresses, allow unsafe debug features or lack link and file protections.  
  *Steps:*
  1. Read the values with sysctl: kernel.kptr_restrict, kernel.dmesg_restrict, kernel.randomize_va_space and kernel.yama.ptrace_scope.
  2. Read kernel.kexec_load_disabled, kernel.sysrq, kernel.unprivileged_bpf_disabled and net.core.bpf_jit_harden.
  3. Read kernel.perf_event_paranoid, user.max_user_namespaces and vm.mmap_min_addr.
  4. Read fs.protected_symlinks, fs.protected_hardlinks, fs.protected_fifos, fs.protected_regular and fs.suid_dumpable.
  5. Look at the owner and mode of /etc/sysctl.d and make sure the values persist.
  *Example:* `sysctl kernel.kptr_restrict kernel.dmesg_restrict kernel.randomize_va_space kernel.yama.ptrace_scope kernel.kexec_load_disabled kernel.sysrq kernel.unprivileged_bpf_disabled net.core.bpf_jit_harden kernel.perf_event_paranoid vm.mmap_min_addr fs.protected_symlinks fs.suid_dumpable ; stat -c "%U:%G %a" /etc/sysctl.d`  
  *Expected:* Values are at least as strict as the rule values: for example kptr_restrict 1, randomize_va_space 2, suid_dumpable 0, protected_symlinks 1 and sysrq 0. Root owns /etc/sysctl.d.  
  *Refs:* tool_check: cac:directory_groupowner_etc_sysctld, cac:directory_owner_etc_sysctld, cac:directory_permissions_etc_sysctld, cac:sysctl_conf_symlink_etc_sysctl_d, cac:sysctl_fs_protected_fifos, cac:sysctl_fs_protected_hardlinks, cac:sysctl_fs_protected_regular, cac:sysctl_fs_protected_symlinks, cac:sysctl_fs_suid_dumpable, cac:sysctl_kernel_apparmor_restrict_unprivileged_unconfined, cac:sysctl_kernel_core_pattern, cac:sysctl_kernel_core_pattern_empty_string, cac:sysctl_kernel_core_uses_pid, cac:sysctl_kernel_dmesg_restrict, cac:sysctl_kernel_exec_shield, cac:sysctl_kernel_kexec_load_disabled, cac:sysctl_kernel_kptr_restrict, cac:sysctl_kernel_modules_disabled, cac:sysctl_kernel_panic_on_oops, cac:sysctl_kernel_perf_cpu_time_max_percent, cac:sysctl_kernel_perf_event_max_sample_rate, cac:sysctl_kernel_perf_event_paranoid, cac:sysctl_kernel_pid_max, cac:sysctl_kernel_randomize_va_space, cac:sysctl_kernel_sysrq, cac:sysctl_kernel_unprivileged_bpf_disabled, cac:sysctl_kernel_unprivileged_bpf_disabled_accept_default, cac:sysctl_kernel_yama_ptrace_scope, cac:sysctl_net_core_bpf_jit_harden, cac:sysctl_reapply_after_network, cac:sysctl_user_max_user_namespaces, cac:sysctl_user_max_user_namespaces_no_remediation, cac:sysctl_vm_mmap_min_addr; nist_800_53: CM-6, AC-6, SC-7, SC-30; pci_dss: 2.2.1

- [ ] **NET-KERN-004** Check core dump storage and execution protection settings  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds hosts that write process memory to disk, where it can expose keys and passwords.  
  *Steps:*
  1. Read /etc/security/limits.conf and limits.d for the core limit of users.
  2. Read /etc/systemd/coredump.conf and look at Storage and ProcessSizeMax.
  3. Look at the state of systemd-coredump and at kernel.core_pattern.
  4. Look at the daemon umask and at the BIOS or CPU no-execute setting.
  *Example:* `grep -rE "^\*.*core" /etc/security/limits.conf /etc/security/limits.d/ ; grep -vE "^#|^$" /etc/systemd/coredump.conf ; sysctl kernel.core_pattern fs.suid_dumpable ; systemctl is-enabled systemd-coredump.socket ; grep umask /etc/sysconfig/init`  
  *Expected:* Core dumps are off for users or are not stored. The core pattern does not write files. The no-execute feature is on.  
  *Refs:* tool_check: cac:bios_enable_execution_restrictions, cac:coredump_disable_backtraces, cac:coredump_disable_storage, cac:disable_users_coredumps, cac:install_PAE_kernel_on_x86-32, cac:service_systemd-coredump_disabled, cac:umask_for_daemons; nist_800_53: CM-6, SC-7, SC-39, AC-6; pci_dss: 3.2

- [ ] **NET-KERN-005** Check that unneeded kernel modules cannot load  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds hosts that can load rare network, wireless, file system and media modules that add attack surface.  
  *Steps:*
  1. Find the modprobe files that set install lines or blacklist entries.
  2. Look for the modules atm, can, dccp, firewire-core, rds, sctp and tipc.
  3. Look for the file system modules cramfs, freevxfs, hfs, hfsplus, jffs2, squashfs, udf, vfat and usb-storage.
  4. Look for the wireless, bluetooth and uvcvideo modules on servers.
  5. Run lsmod. Try modprobe for one module and make sure it does not load.
  *Example:* `grep -rE "install .* /bin/(true|false)|blacklist" /etc/modprobe.d/ ; for m in dccp sctp rds tipc cramfs squashfs udf usb-storage; do modprobe -n -v $m; done ; lsmod | grep -E "dccp|sctp|rds|tipc|cramfs|squashfs|udf|usb_storage"`  
  *Expected:* The modules that the host role does not need cannot load. Each one is blacklisted or has an install line that runs /bin/false. lsmod does not list them.  
  *Refs:* tool_check: cac:kernel_module_atm_disabled, cac:kernel_module_bluetooth_disabled, cac:kernel_module_can_disabled, cac:kernel_module_cfg80211_disabled, cac:kernel_module_cramfs_disabled, cac:kernel_module_dccp_disabled, cac:kernel_module_firewire-core_disabled, cac:kernel_module_freevxfs_disabled, cac:kernel_module_hfs_disabled, cac:kernel_module_hfsplus_disabled, cac:kernel_module_ipv6_option_disabled, cac:kernel_module_iwlmvm_disabled, cac:kernel_module_iwlwifi_disabled, cac:kernel_module_jffs2_disabled, cac:kernel_module_mac80211_disabled, cac:kernel_module_overlayfs_disabled, cac:kernel_module_rds_disabled, cac:kernel_module_sctp_disabled, cac:kernel_module_squashfs_disabled, cac:kernel_module_tipc_disabled, cac:kernel_module_udf_disabled, cac:kernel_module_uvcvideo_disabled; nist_800_53: CM-7, AC-18, CM-6, MP-7; pci_dss: 1.4.2

- [ ] **NET-KERN-006** Check the kernel command line for mitigation and memory hardening options  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts that boot without CPU flaw mitigations or kernel memory protections.  
  *Steps:*
  1. Read /proc/cmdline and the default kernel arguments in /etc/default/grub.
  2. Look for pti, spectre_v2, spec_store_bypass_disable, l1tf, mds, mitigations and nosmep or nosmap (must be absent).
  3. Look for slab_nomerge, init_on_alloc, init_on_free, page_alloc.shuffle and vsyscall.
  4. Look for audit=1 and the debug-shell argument (must be absent).
  5. Read the mitigation status files under /sys/devices/system/cpu/vulnerabilities.
  *Example:* `cat /proc/cmdline ; grep GRUB_CMDLINE_LINUX /etc/default/grub ; grep -r . /sys/devices/system/cpu/vulnerabilities/ ; grubby --info=ALL | grep args`  
  *Expected:* The command line has the mitigation and memory options that the standard lists and none of the options that switch protections off. The CPU status files show mitigations.  
  *Refs:* tool_check: cac:coreos_page_poison_kernel_argument, cac:coreos_pti_kernel_argument, cac:coreos_slub_debug_kernel_argument, cac:coreos_vsyscall_kernel_argument, cac:grub2_enable_iommu_force, cac:grub2_init_on_alloc_argument, cac:grub2_init_on_free, cac:grub2_ipv6_disable_argument, cac:grub2_kernel_trust_cpu_rng, cac:grub2_l1tf_argument, cac:grub2_mce_argument, cac:grub2_mds_argument, cac:grub2_mitigation_argument, cac:grub2_nosmap_argument_absent, cac:grub2_nosmep_argument_absent, cac:grub2_page_alloc_shuffle_argument, cac:grub2_page_poison_argument, cac:grub2_pti_argument, cac:grub2_quiet_argument, cac:grub2_rng_core_default_quality_argument, cac:grub2_slab_nomerge_argument, cac:grub2_slub_debug_argument, cac:grub2_spec_store_bypass_disable_argument, cac:grub2_spectre_v2_argument, cac:grub2_vsyscall_argument, cac:kernel_disable_entropy_contribution_for_solid_state_drives, cac:zipl_audit_argument, cac:zipl_audit_backlog_limit_argument, cac:zipl_enable_selinux, cac:zipl_init_on_alloc_argument, cac:zipl_page_alloc_shuffle_argument, cac:zipl_page_poison_argument, cac:zipl_slub_debug_argument, cac:zipl_systemd_debug-shell_argument_absent, cac:zipl_vsyscall_argument; nist_800_53: CM-6, SI-16, CM-7, SC-3; pci_dss: 1.3.1, 1.3.2

- [ ] **NET-KERN-007** Check the kernel build options for hardening  
  *Severity if fail:* Low | *Type:* Config Review, Code Review  
  *Objective:* Finds kernels that were built without memory protection, module signing and attack surface reduction.  
  *Steps:*
  1. Find the kernel config file for the running kernel.
  2. Look for CONFIG_MODULE_SIG, CONFIG_MODULE_SIG_FORCE, CONFIG_STRICT_KERNEL_RWX and CONFIG_HARDENED_USERCOPY.
  3. Look for CONFIG_STACKPROTECTOR_STRONG, CONFIG_FORTIFY_SOURCE, CONFIG_RANDOMIZE_BASE and CONFIG_SLAB_FREELIST_HARDENED.
  4. Look for CONFIG_DEBUG_FS, CONFIG_DEVKMEM, CONFIG_ACPI_CUSTOM_METHOD and CONFIG_IA32_EMULATION (should be off where not needed).
  5. Compare the result with the build standard of the organization.
  *Example:* `zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r) | grep -E "CONFIG_(MODULE_SIG|STRICT_KERNEL_RWX|HARDENED_USERCOPY|STACKPROTECTOR_STRONG|FORTIFY_SOURCE|RANDOMIZE_BASE|DEBUG_FS|DEVKMEM|SLAB_FREELIST_HARDENED)="`  
  *Expected:* The kernel config enables the memory protections, signing and randomization options of the standard. Debug and legacy options are off.  
  *Refs:* tool_check: cac:kernel_config_acpi_custom_method, cac:kernel_config_arm64_sw_ttbr0_pan, cac:kernel_config_binfmt_misc, cac:kernel_config_bug, cac:kernel_config_bug_on_data_corruption, cac:kernel_config_compat_brk, cac:kernel_config_compat_vdso, cac:kernel_config_debug_credentials, cac:kernel_config_debug_fs, cac:kernel_config_debug_list, cac:kernel_config_debug_notifiers, cac:kernel_config_debug_sg, cac:kernel_config_debug_wx, cac:kernel_config_default_mmap_min_addr, cac:kernel_config_devkmem, cac:kernel_config_fortify_source, cac:kernel_config_gcc_plugin_latent_entropy, cac:kernel_config_gcc_plugin_randstruct, cac:kernel_config_gcc_plugin_stackleak, cac:kernel_config_gcc_plugin_structleak, cac:kernel_config_gcc_plugin_structleak_byref_all, cac:kernel_config_hardened_usercopy, cac:kernel_config_hardened_usercopy_fallback, cac:kernel_config_hibernation, cac:kernel_config_ia32_emulation, cac:kernel_config_ipv6, cac:kernel_config_kexec, cac:kernel_config_legacy_ptys, cac:kernel_config_legacy_vsyscall_emulate, cac:kernel_config_legacy_vsyscall_none, cac:kernel_config_legacy_vsyscall_xonly, cac:kernel_config_modify_ldt_syscall, cac:kernel_config_module_sig, cac:kernel_config_module_sig_all, cac:kernel_config_module_sig_force, cac:kernel_config_module_sig_hash, cac:kernel_config_module_sig_key, cac:kernel_config_module_sig_sha512, cac:kernel_config_page_poisoning, cac:kernel_config_page_poisoning_no_sanity, cac:kernel_config_page_poisoning_zero, cac:kernel_config_page_table_isolation, cac:kernel_config_panic_on_oops, cac:kernel_config_panic_timeout, cac:kernel_config_proc_kcore, cac:kernel_config_randomize_base, cac:kernel_config_randomize_memory, cac:kernel_config_refcount_full, cac:kernel_config_retpoline, cac:kernel_config_sched_stack_end_check, cac:kernel_config_seccomp, cac:kernel_config_seccomp_filter, cac:kernel_config_security, cac:kernel_config_security_dmesg_restrict, cac:kernel_config_security_writable_hooks, cac:kernel_config_security_yama, cac:kernel_config_slab_freelist_hardened, cac:kernel_config_slab_freelist_random, cac:kernel_config_slab_merge_default, cac:kernel_config_slub_debug, cac:kernel_config_stackprotector, cac:kernel_config_stackprotector_strong, cac:kernel_config_strict_kernel_rwx, cac:kernel_config_strict_module_rwx, cac:kernel_config_syn_cookies, cac:kernel_config_unmap_kernel_at_el0, cac:kernel_config_vmap_stack, cac:kernel_config_x86_vsyscall_emulation


## OS

- [ ] **NET-OS-001** Check the owner and mode of account files and their backups  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds password and group files that other users can read or change.  
  *Steps:*
  1. List /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow and /etc/shells.
  2. List the backup files with a dash suffix, such as /etc/shadow-.
  3. List /etc/security/opasswd and opasswd.old.
  4. Make sure root owns the files and the modes are as strict as the standard sets.
  *Example:* `stat -c "%U:%G %a %n" /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/shells /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow- /etc/security/opasswd`  
  *Expected:* Root owns all account files. /etc/passwd and /etc/group have a mode of 0644 or stricter. Shadow files and password history have a mode of 0000 or 0640 at most.  
  *Refs:* tool_check: cac:file_etc_security_opasswd, cac:file_groupowner_backup_etc_group, cac:file_groupowner_backup_etc_gshadow, cac:file_groupowner_backup_etc_passwd, cac:file_groupowner_backup_etc_shadow, cac:file_groupowner_etc_group, cac:file_groupowner_etc_gshadow, cac:file_groupowner_etc_passwd, cac:file_groupowner_etc_security_opasswd, cac:file_groupowner_etc_security_opasswd_old, cac:file_groupowner_etc_shadow, cac:file_groupowner_etc_shells, cac:file_owner_backup_etc_group, cac:file_owner_backup_etc_gshadow, cac:file_owner_backup_etc_passwd, cac:file_owner_backup_etc_shadow, cac:file_owner_etc_group, cac:file_owner_etc_gshadow, cac:file_owner_etc_passwd, cac:file_owner_etc_security_opasswd, cac:file_owner_etc_security_opasswd_old, cac:file_owner_etc_shadow, cac:file_owner_etc_shells, cac:file_permissions_backup_etc_group, cac:file_permissions_backup_etc_gshadow, cac:file_permissions_backup_etc_passwd, cac:file_permissions_backup_etc_shadow, cac:file_permissions_etc_group, cac:file_permissions_etc_gshadow, cac:file_permissions_etc_passwd, cac:file_permissions_etc_security_opasswd, cac:file_permissions_etc_security_opasswd_old, cac:file_permissions_etc_shadow, cac:file_permissions_etc_shells; nist_800_53: CM-6, AC-6, AC-3, MP-2

- [ ] **NET-OS-002** Find world-writable, unowned and unauthorized setuid files  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds files that any user can change, files without an owner and setuid programs that are not approved.  
  *Steps:*
  1. Find world-writable files on the local file systems.
  2. Find world-writable directories without the sticky bit.
  3. Find files and directories with no owner or no group.
  4. Find setuid and setgid files and compare them with the approved list.
  *Example:* `find / -xdev -type f -perm -0002 -ls ; find / -xdev -type d -perm -0002 ! -perm -1000 -ls ; find / -xdev \( -nouser -o -nogroup \) -ls ; find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls`  
  *Expected:* No file is world-writable. Each world-writable directory has the sticky bit. No file lacks an owner or a group. Only approved programs have setuid or setgid.  
  *Refs:* tool_check: cac:dir_perms_world_writable_root_owned, cac:dir_perms_world_writable_sticky_bits, cac:dir_perms_world_writable_system_owned, cac:dir_perms_world_writable_system_owned_group, cac:file_permissions_unauthorized_sgid, cac:file_permissions_unauthorized_suid, cac:file_permissions_unauthorized_world_writable, cac:file_permissions_ungroupowned, cac:no_files_or_dirs_ungroupowned, cac:no_files_or_dirs_unowned_by_user, cac:no_files_unowned_by_user; nist_800_53: CM-6, AC-6

- [ ] **NET-OS-003** Check ownership and mode of system binaries, libraries and boot map files  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds system programs and libraries that non-root users can replace.  
  *Steps:*
  1. List the files in /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin and /usr/local/sbin with their owner and mode.
  2. List the files in /lib, /lib64, /usr/lib and /usr/lib64.
  3. Find files with a group-write or world-write bit and files not owned by root.
  4. List System.map, /etc/crypttab and the sysconfig files for sshd.
  *Example:* `find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /lib /lib64 /usr/lib /usr/lib64 \( -perm /022 -o ! -user root \) -ls ; stat -c "%U:%G %a %n" /boot/System.map-* /etc/crypttab`  
  *Expected:* Root owns all system programs and libraries. None has a group-write or world-write bit. System.map and crypttab have a mode of 0600 or 0644 and are owned by root.  
  *Refs:* tool_check: cac:dir_group_ownership_library_dirs, cac:dir_groupownership_binary_dirs, cac:dir_ownership_binary_dirs, cac:dir_ownership_library_dirs, cac:dir_permissions_binary_dirs, cac:dir_permissions_library_dirs, cac:dir_system_commands_group_root_owned, cac:dir_system_commands_root_owned, cac:file_groupowner_etc_crypttab, cac:file_groupowner_etc_sysconfig_sshd, cac:file_groupowner_systemmap, cac:file_groupownership_system_commands_dirs, cac:file_owner_etc_crypttab, cac:file_owner_etc_sysconfig_sshd, cac:file_owner_systemmap, cac:file_ownership_binary_dirs, cac:file_ownership_library_dirs, cac:file_permissions_binary_dirs, cac:file_permissions_etc_crypttab, cac:file_permissions_etc_sysconfig_sshd, cac:file_permissions_library_dirs, cac:file_permissions_system_commands_dirs, cac:file_permissions_systemmap, cac:root_permissions_syslibrary_files, cac:rootfiles_configured, cac:run_chkstat; nist_800_53: CM-5, CM-6, AC-6

- [ ] **NET-OS-004** Check mount options nodev, nosuid and noexec on partitions  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds partitions where users can run programs, create devices or use setuid files.  
  *Steps:*
  1. Read /etc/fstab and the live mounts with findmnt.
  2. Look at /tmp, /var/tmp, /dev/shm, /home, /boot, /var and /var/log and /var/log/audit.
  3. Make sure each one has nodev, nosuid and noexec where the role allows.
  4. Look at the mount options of removable media and of remote file systems (NFS, SMB).
  5. Look at hidepid on /proc and at the quota options on /home.
  *Example:* `findmnt -no TARGET,OPTIONS /tmp /var/tmp /dev/shm /home /boot /var /var/log /var/log/audit /proc ; grep -vE "^#" /etc/fstab ; mount | grep -E "nfs|cifs"`  
  *Expected:* Each partition has the options that the standard lists, at least nodev and nosuid, and noexec on /tmp, /var/tmp and /dev/shm. Remote and removable file systems use nosuid, nodev and noexec.  
  *Refs:* tool_check: cac:mount_option_boot_efi_nosuid, cac:mount_option_boot_noauto, cac:mount_option_boot_nodev, cac:mount_option_boot_noexec, cac:mount_option_boot_nosuid, cac:mount_option_dev_shm_nodev, cac:mount_option_dev_shm_noexec, cac:mount_option_dev_shm_nosuid, cac:mount_option_home_grpquota, cac:mount_option_home_nodev, cac:mount_option_home_noexec, cac:mount_option_home_nosuid, cac:mount_option_home_usrquota, cac:mount_option_krb_sec_remote_filesystems, cac:mount_option_nodev_nonroot_local_partitions, cac:mount_option_nodev_remote_filesystems, cac:mount_option_nodev_removable_partitions, cac:mount_option_noexec_remote_filesystems, cac:mount_option_noexec_removable_partitions, cac:mount_option_nosuid_remote_filesystems, cac:mount_option_nosuid_removable_partitions, cac:mount_option_opt_nosuid, cac:mount_option_proc_hidepid, cac:mount_option_smb_client_signing, cac:mount_option_srv_nosuid, cac:mount_option_tmp_nodev, cac:mount_option_tmp_noexec, cac:mount_option_tmp_nosuid, cac:mount_option_var_log_audit_nodev, cac:mount_option_var_log_audit_noexec, cac:mount_option_var_log_audit_nosuid, cac:mount_option_var_log_nodev, cac:mount_option_var_log_noexec, cac:mount_option_var_log_nosuid, cac:mount_option_var_nodev, cac:mount_option_var_noexec, cac:mount_option_var_nosuid, cac:mount_option_var_tmp_bind, cac:mount_option_var_tmp_nodev, cac:mount_option_var_tmp_noexec, cac:mount_option_var_tmp_nosuid; nist_800_53: AC-6, CM-7, CM-6, MP-7

- [ ] **NET-OS-005** Check separate partitions and disk encryption for data and logs  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds hosts where a full or abused directory can stop the system, or where data on disk is not encrypted.  
  *Steps:*
  1. List the mounts with lsblk and findmnt.
  2. Look for separate partitions for /boot, /home, /tmp, /var, /var/tmp, /var/log, /var/log/audit, /srv, /opt, /usr and /dev/shm.
  3. Check if /tmp is a systemd tmp.mount unit or a partition.
  4. Look for encrypted volumes with cryptsetup.
  *Example:* `lsblk -f ; findmnt -no TARGET,SOURCE /boot /home /tmp /var /var/tmp /var/log /var/log/audit /srv /opt ; systemctl is-enabled tmp.mount ; cryptsetup status <name>`  
  *Expected:* The directories that the standard names are on separate partitions. Data volumes are encrypted at rest.  
  *Refs:* tool_check: cac:encrypt_partitions, cac:partition_for_boot, cac:partition_for_dev_shm, cac:partition_for_home, cac:partition_for_opt, cac:partition_for_srv, cac:partition_for_tmp, cac:partition_for_usr, cac:partition_for_var, cac:partition_for_var_log, cac:partition_for_var_log_audit, cac:partition_for_var_tmp, cac:systemd_tmp_mount_enabled; nist_800_53: CM-6, SC-5, SC-28, AU-4

- [ ] **NET-OS-006** Check that USB storage, automount and BIOS boot options are limited  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds hosts that mount removable media on their own or boot from an unapproved device.  
  *Steps:*
  1. Look at the autofs package and service.
  2. Look at the usb-storage module and the nousb kernel argument.
  3. Look at the udisks and desktop automount settings.
  4. Read the firmware settings for boot devices and the firmware password.
  *Example:* `systemctl is-enabled autofs ; modprobe -n -v usb-storage ; grep -o "nousb" /proc/cmdline ; lsmod | grep usb_storage`  
  *Expected:* Automount is off. USB storage is blocked on hosts that do not need it. Boot from removable media is off and the firmware has a password.  
  *Refs:* tool_check: cac:bios_assign_password, cac:bios_disable_usb_boot, cac:coreos_nousb_kernel_argument, cac:grub2_nousb_argument, cac:kernel_module_usb-storage_disabled, cac:kernel_module_vfat_disabled, cac:package_autofs_removed, cac:service_autofs_disabled; nist_800_53: CM-7, CM-6, MP-7

- [ ] **NET-OS-007** Check bootloader password, file permissions and recovery options  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts where a person with console access can change boot options or start a root shell.  
  *Steps:*
  1. Read /boot/grub2/grub.cfg or /boot/efi/EFI/<vendor>/grub.cfg and the user.cfg file.
  2. Look for the superuser line and the password hash. Make sure the hash is PBKDF2.
  3. List the owner and mode of grub.cfg and user.cfg.
  4. Look for the recovery menu entries and for the removable media boot option.
  5. Look at the zipl bootmap on s390 systems if they are in scope.
  *Example:* `grep -E "set superusers|password_pbkdf2" /boot/grub2/grub.cfg /boot/grub2/user.cfg /boot/efi/EFI/*/user.cfg ; stat -c "%U:%G %a %n" /boot/grub2/grub.cfg /boot/grub2/user.cfg /boot/efi/EFI/*/grub.cfg ; grep -c "recovery" /boot/grub2/grub.cfg`  
  *Expected:* The bootloader needs a superuser and a hashed password to edit boot entries. Root owns the grub files and the mode is 0600 or 0700 as the standard says. Recovery entries are off.  
  *Refs:* tool_check: cac:file_groupowner_boot_grub2, cac:file_groupowner_efi_grub2_cfg, cac:file_groupowner_efi_user_cfg, cac:file_groupowner_grub2_cfg, cac:file_groupowner_user_cfg, cac:file_owner_boot_grub2, cac:file_owner_efi_grub2_cfg, cac:file_owner_efi_user_cfg, cac:file_owner_grub2_cfg, cac:file_owner_user_cfg, cac:file_permissions_boot_grub2, cac:file_permissions_efi_grub2_cfg, cac:file_permissions_efi_user_cfg, cac:file_permissions_grub2_cfg, cac:file_permissions_user_cfg, cac:grub2_admin_username, cac:grub2_disable_recovery, cac:grub2_no_removeable_media, cac:grub2_password, cac:grub2_password_legacy, cac:grub2_systemd_debug-shell_argument_absent, cac:grub2_uefi_admin_username, cac:grub2_uefi_password, cac:grub2_uefi_password_legacy, cac:uefi_no_removeable_media, cac:zipl_bls_entries_only, cac:zipl_bootmap_is_up_to_date; nist_800_53: CM-6, AC-6, AC-3; pci_dss: 7.1

- [ ] **NET-OS-008** Check that UEFI Secure Boot is on  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts that start unsigned boot components.  
  *Steps:*
  1. Run mokutil --sb-state or read the firmware setting.
  2. Look at the kernel messages for the Secure Boot line.
  3. Look at the list of enrolled keys.
  *Example:* `mokutil --sb-state ; dmesg | grep -i "secure boot" ; bootctl status | grep -i secure`  
  *Expected:* Secure Boot is enabled and the host starts only signed boot components.  
  *Refs:* tool_check: cac:secure_boot_enabled

- [ ] **NET-OS-009** Check that SELinux is enforcing with the targeted policy  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds hosts where mandatory access control is off or lets daemons run unconfined.  
  *Steps:*
  1. Run getenforce and sestatus.
  2. Read /etc/selinux/config for SELINUX and SELINUXTYPE.
  3. Look at the kernel command line for selinux=0 or enforcing=0.
  4. List unconfined processes and unlabeled device files.
  5. Look at the SELinux user mappings for logins.
  *Example:* `getenforce ; sestatus ; grep -E "^SELINUX" /etc/selinux/config ; grep -E "selinux=0|enforcing=0" /proc/cmdline ; ps -eZ | grep unconfined_service_t ; semanage login -l`  
  *Expected:* SELinux runs in enforcing mode with the targeted policy. No daemon runs unconfined and no device file is unlabeled. The SELinux packages are installed and troubleshooting tools are removed.  
  *Refs:* tool_check: cac:coreos_enable_selinux_kernel_argument, cac:directory_groupowner_etc_selinux, cac:directory_owner_etc_selinux, cac:directory_permissions_etc_selinux, cac:file_groupowner_etc_sestatus_conf, cac:file_owner_etc_sestatus_conf, cac:file_permissions_etc_sestatus_conf, cac:grub2_enable_selinux, cac:package_libselinux_installed, cac:package_mcstrans_removed, cac:package_policycoreutils-python-utils_installed, cac:package_policycoreutils_installed, cac:package_setroubleshoot-plugins_removed, cac:package_setroubleshoot-server_removed, cac:package_setroubleshoot_removed, cac:selinux_all_devicefiles_labeled, cac:selinux_confine_to_least_privilege, cac:selinux_confinement_of_daemons, cac:selinux_context_elevation_for_sudo, cac:selinux_not_disabled, cac:selinux_policytype, cac:selinux_state, cac:selinux_user_login_roles; nist_800_53: AC-3, CM-7, AC-6, CM-6

- [ ] **NET-OS-010** Check that risky SELinux booleans are off  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds SELinux booleans that give daemons more rights than the default policy.  
  *Steps:*
  1. List all booleans with getsebool -a.
  2. Compare the on booleans with the list of rules in the tool check references.
  3. Find each boolean that is on and is not in the approved list.
  4. Check the need and the owner of each exception.
  *Example:* `getsebool -a | grep -- "--> on" ; semanage boolean -l -C`  
  *Expected:* The booleans that the standard names as risky are off. Each boolean that is on has a written need.  
  *Refs:* tool_check: cac:sebool_abrt_anon_write, cac:sebool_abrt_handle_event, cac:sebool_abrt_upload_watch_anon_write, cac:sebool_antivirus_can_scan_system, cac:sebool_antivirus_use_jit, cac:sebool_auditadm_exec_content, cac:sebool_authlogin_nsswitch_use_ldap, cac:sebool_authlogin_radius, cac:sebool_authlogin_yubikey, cac:sebool_awstats_purge_apache_log_files, cac:sebool_boinc_execmem, cac:sebool_cdrecord_read_content, cac:sebool_cluster_can_network_connect, cac:sebool_cluster_manage_all_files, cac:sebool_cluster_use_execmem, cac:sebool_cobbler_anon_write, cac:sebool_cobbler_can_network_connect, cac:sebool_cobbler_use_cifs, cac:sebool_cobbler_use_nfs, cac:sebool_collectd_tcp_network_connect, cac:sebool_condor_tcp_network_connect, cac:sebool_conman_can_network, cac:sebool_container_connect_any, cac:sebool_cron_can_relabel, cac:sebool_cron_system_cronjob_use_shares, cac:sebool_cron_userdomain_transition, cac:sebool_cups_execmem, cac:sebool_cvs_read_shadow, cac:sebool_daemons_dump_core, cac:sebool_daemons_enable_cluster_mode, cac:sebool_daemons_use_tcp_wrapper, cac:sebool_daemons_use_tty, cac:sebool_dbadm_exec_content, cac:sebool_dbadm_manage_user_files, cac:sebool_dbadm_read_user_files, cac:sebool_deny_execmem, cac:sebool_deny_ptrace, cac:sebool_dhcpc_exec_iptables, cac:sebool_dhcpd_use_ldap, cac:sebool_domain_fd_use, cac:sebool_domain_kernel_load_modules, cac:sebool_entropyd_use_audio, cac:sebool_exim_can_connect_db, cac:sebool_exim_manage_user_files, cac:sebool_exim_read_user_files, cac:sebool_fcron_crond, cac:sebool_fenced_can_network_connect, cac:sebool_fenced_can_ssh, cac:sebool_fips_mode, cac:sebool_ftpd_anon_write, cac:sebool_ftpd_connect_all_unreserved, cac:sebool_ftpd_connect_db, cac:sebool_ftpd_full_access, cac:sebool_ftpd_use_cifs, cac:sebool_ftpd_use_fusefs, cac:sebool_ftpd_use_nfs, cac:sebool_ftpd_use_passive_mode, cac:sebool_git_cgi_enable_homedirs, cac:sebool_git_cgi_use_cifs, cac:sebool_git_cgi_use_nfs, cac:sebool_git_session_bind_all_unreserved_ports, cac:sebool_git_session_users, cac:sebool_git_system_enable_homedirs, cac:sebool_git_system_use_cifs, cac:sebool_git_system_use_nfs, cac:sebool_gitosis_can_sendmail, cac:sebool_glance_api_can_network, cac:sebool_glance_use_execmem, cac:sebool_glance_use_fusefs, cac:sebool_global_ssp, cac:sebool_gluster_anon_write, cac:sebool_gluster_export_all_ro, cac:sebool_gluster_export_all_rw, cac:sebool_gpg_web_anon_write, cac:sebool_gssd_read_tmp, cac:sebool_guest_exec_content, cac:sebool_haproxy_connect_any, cac:sebool_httpd_anon_write, cac:sebool_httpd_builtin_scripting, cac:sebool_httpd_can_check_spam, cac:sebool_httpd_can_connect_ftp, cac:sebool_httpd_can_connect_ldap, cac:sebool_httpd_can_connect_mythtv, cac:sebool_httpd_can_connect_zabbix, cac:sebool_httpd_can_network_connect, cac:sebool_httpd_can_network_connect_cobbler, cac:sebool_httpd_can_network_connect_db, cac:sebool_httpd_can_network_memcache, cac:sebool_httpd_can_network_relay, cac:sebool_httpd_can_sendmail, cac:sebool_httpd_dbus_avahi, cac:sebool_httpd_dbus_sssd, cac:sebool_httpd_dontaudit_search_dirs, cac:sebool_httpd_enable_cgi, cac:sebool_httpd_enable_ftp_server, cac:sebool_httpd_enable_homedirs, cac:sebool_httpd_execmem, cac:sebool_httpd_graceful_shutdown, cac:sebool_httpd_manage_ipa, cac:sebool_httpd_mod_auth_ntlm_winbind, cac:sebool_httpd_mod_auth_pam, cac:sebool_httpd_read_user_content, cac:sebool_httpd_run_ipa, cac:sebool_httpd_run_preupgrade, cac:sebool_httpd_run_stickshift, cac:sebool_httpd_serve_cobbler_files, cac:sebool_httpd_setrlimit, cac:sebool_httpd_ssi_exec, cac:sebool_httpd_sys_script_anon_write, cac:sebool_httpd_tmp_exec, cac:sebool_httpd_tty_comm, cac:sebool_httpd_unified, cac:sebool_httpd_use_cifs, cac:sebool_httpd_use_fusefs, cac:sebool_httpd_use_gpg, cac:sebool_httpd_use_nfs, cac:sebool_httpd_use_openstack, cac:sebool_httpd_use_sasl, cac:sebool_httpd_verify_dns, cac:sebool_icecast_use_any_tcp_ports, cac:sebool_irc_use_any_tcp_ports, cac:sebool_irssi_use_full_network, cac:sebool_kdumpgui_run_bootloader, cac:sebool_kerberos_enabled, cac:sebool_ksmtuned_use_cifs, cac:sebool_ksmtuned_use_nfs, cac:sebool_logadm_exec_content, cac:sebool_logging_syslogd_can_sendmail, cac:sebool_logging_syslogd_run_nagios_plugins, cac:sebool_logging_syslogd_use_tty, cac:sebool_login_console_enabled, cac:sebool_logrotate_use_nfs, cac:sebool_logwatch_can_network_connect_mail, cac:sebool_lsmd_plugin_connect_any, cac:sebool_mailman_use_fusefs, cac:sebool_mcelog_client, cac:sebool_mcelog_exec_scripts, cac:sebool_mcelog_foreground, cac:sebool_mcelog_server, cac:sebool_minidlna_read_generic_user_content, cac:sebool_mmap_low_allowed, cac:sebool_mock_enable_homedirs, cac:sebool_mount_anyfile, cac:sebool_mozilla_plugin_bind_unreserved_ports, cac:sebool_mozilla_plugin_can_network_connect, cac:sebool_mozilla_plugin_use_bluejeans, cac:sebool_mozilla_plugin_use_gps, cac:sebool_mozilla_plugin_use_spice, cac:sebool_mozilla_read_content, cac:sebool_mpd_enable_homedirs, cac:sebool_mpd_use_cifs, cac:sebool_mpd_use_nfs, cac:sebool_mplayer_execstack, cac:sebool_mysql_connect_any, cac:sebool_nagios_run_pnp4nagios, cac:sebool_nagios_run_sudo, cac:sebool_named_tcp_bind_http_port, cac:sebool_named_write_master_zones, cac:sebool_neutron_can_network, cac:sebool_nfs_export_all_ro, cac:sebool_nfs_export_all_rw, cac:sebool_nfsd_anon_write, cac:sebool_nis_enabled, cac:sebool_nscd_use_shm, cac:sebool_openshift_use_nfs, cac:sebool_openvpn_can_network_connect, cac:sebool_openvpn_enable_homedirs, cac:sebool_openvpn_run_unconfined, cac:sebool_pcp_bind_all_unreserved_ports, cac:sebool_pcp_read_generic_logs, cac:sebool_piranha_lvs_can_network_connect, cac:sebool_polipo_connect_all_unreserved, cac:sebool_polipo_session_bind_all_unreserved_ports, cac:sebool_polipo_session_users, cac:sebool_polipo_use_cifs, cac:sebool_polipo_use_nfs, cac:sebool_polyinstantiation_enabled, cac:sebool_postfix_local_write_mail_spool, cac:sebool_postgresql_can_rsync, cac:sebool_postgresql_selinux_transmit_client_label, cac:sebool_postgresql_selinux_unconfined_dbadm, cac:sebool_postgresql_selinux_users_ddl, cac:sebool_pppd_can_insmod, cac:sebool_pppd_for_user, cac:sebool_privoxy_connect_any, cac:sebool_prosody_bind_http_port, cac:sebool_puppetagent_manage_all_files, cac:sebool_puppetmaster_use_db, cac:sebool_racoon_read_shadow, cac:sebool_rsync_anon_write, cac:sebool_rsync_client, cac:sebool_rsync_export_all_ro, cac:sebool_rsync_full_access, cac:sebool_samba_create_home_dirs, cac:sebool_samba_domain_controller, cac:sebool_samba_enable_home_dirs, cac:sebool_samba_export_all_ro, cac:sebool_samba_export_all_rw, cac:sebool_samba_load_libgfapi, cac:sebool_samba_portmapper, cac:sebool_samba_run_unconfined, cac:sebool_samba_share_fusefs, cac:sebool_samba_share_nfs, cac:sebool_sanlock_use_fusefs, cac:sebool_sanlock_use_nfs, cac:sebool_sanlock_use_samba, cac:sebool_saslauthd_read_shadow, cac:sebool_secadm_exec_content, cac:sebool_secure_mode, cac:sebool_secure_mode_insmod, cac:sebool_secure_mode_policyload, cac:sebool_selinuxuser_direct_dri_enabled, cac:sebool_selinuxuser_execheap, cac:sebool_selinuxuser_execmod, cac:sebool_selinuxuser_execstack, cac:sebool_selinuxuser_mysql_connect_enabled, cac:sebool_selinuxuser_ping, cac:sebool_selinuxuser_postgresql_connect_enabled, cac:sebool_selinuxuser_rw_noexattrfile, cac:sebool_selinuxuser_share_music, cac:sebool_selinuxuser_tcp_server, cac:sebool_selinuxuser_udp_server, cac:sebool_selinuxuser_use_ssh_chroot, cac:sebool_sge_domain_can_network_connect, cac:sebool_sge_use_nfs, cac:sebool_smartmon_3ware, cac:sebool_smbd_anon_write, cac:sebool_spamassassin_can_network, cac:sebool_spamd_enable_home_dirs, cac:sebool_squid_connect_any, cac:sebool_squid_use_tproxy, cac:sebool_ssh_chroot_rw_homedirs, cac:sebool_ssh_keysign, cac:sebool_ssh_sysadm_login, cac:sebool_staff_exec_content, cac:sebool_staff_use_svirt, cac:sebool_swift_can_network, cac:sebool_sysadm_exec_content, cac:sebool_telepathy_connect_all_ports, cac:sebool_telepathy_tcp_connect_generic_network_ports, cac:sebool_tftp_anon_write, cac:sebool_tftp_home_dir, cac:sebool_tmpreaper_use_nfs, cac:sebool_tmpreaper_use_samba, cac:sebool_tor_bind_all_unreserved_ports, cac:sebool_tor_can_network_relay, cac:sebool_unconfined_chrome_sandbox_transition, cac:sebool_unconfined_login, cac:sebool_unconfined_mozilla_plugin_transition, cac:sebool_unprivuser_use_svirt, cac:sebool_use_ecryptfs_home_dirs, cac:sebool_use_fusefs_home_dirs, cac:sebool_use_lpd_server, cac:sebool_use_nfs_home_dirs, cac:sebool_use_samba_home_dirs, cac:sebool_user_exec_content, cac:sebool_varnishd_connect_any, cac:sebool_virt_read_qemu_ga_data, cac:sebool_virt_rw_qemu_ga_data, cac:sebool_virt_sandbox_use_all_caps, cac:sebool_virt_sandbox_use_audit, cac:sebool_virt_sandbox_use_mknod, cac:sebool_virt_sandbox_use_netlink, cac:sebool_virt_sandbox_use_sys_admin, cac:sebool_virt_transition_userdomain, cac:sebool_virt_use_comm, cac:sebool_virt_use_execmem, cac:sebool_virt_use_fusefs, cac:sebool_virt_use_nfs, cac:sebool_virt_use_rawip, cac:sebool_virt_use_samba, cac:sebool_virt_use_sanlock, cac:sebool_virt_use_usb, cac:sebool_virt_use_xserver, cac:sebool_webadm_manage_user_files, cac:sebool_webadm_read_user_files, cac:sebool_wine_mmap_zero_ignore, cac:sebool_xdm_bind_vnc_tcp_port, cac:sebool_xdm_exec_bootloader, cac:sebool_xdm_sysadm_login, cac:sebool_xdm_write_home, cac:sebool_xen_use_nfs, cac:sebool_xend_run_blktap, cac:sebool_xend_run_qemu, cac:sebool_xguest_connect_network, cac:sebool_xguest_exec_content, cac:sebool_xguest_mount_media, cac:sebool_xguest_use_bluetooth, cac:sebool_xserver_clients_write_xshm, cac:sebool_xserver_execmem, cac:sebool_xserver_object_manager, cac:sebool_zabbix_can_network, cac:sebool_zarafa_setrlimit, cac:sebool_zebra_write_config, cac:sebool_zoneminder_anon_write, cac:sebool_zoneminder_run_sudo; nist_800_53: SC-12, IA-7, SC-13, CM-6

- [ ] **NET-OS-011** Check that AppArmor is loaded and its profiles are enforced  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts where profiles are missing or are only in complain mode.  
  *Steps:*
  1. Run aa-status.
  2. Look at the number of profiles in enforce, complain and unconfined mode.
  3. Look for the AppArmor kernel argument and packages.
  4. Look at the pam_apparmor module.
  *Example:* `aa-status ; cat /sys/module/apparmor/parameters/enabled ; grep apparmor /proc/cmdline ; dpkg -l apparmor apparmor-utils libpam-apparmor`  
  *Expected:* AppArmor is on. All profiles are in enforce mode. The packages are installed.  
  *Refs:* tool_check: cac:all_apparmor_profiles_enforced, cac:all_apparmor_profiles_in_enforce_complain_mode, cac:apparmor_configured, cac:grub2_enable_apparmor, cac:package_apparmor-utils_installed, cac:package_apparmor_installed, cac:package_pam_apparmor_installed; nist_800_53: AC-6, CM-7, AC-3, SC-7

- [ ] **NET-OS-012** Check desktop login, screen lock and remote access settings  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds desktop hosts that allow guest login, automatic login, unlocked screens or open remote desktops.  
  *Steps:*
  1. Read /etc/gdm/custom.conf and /etc/dconf/db for the lock, idle and login settings.
  2. Look at AutomaticLogin, TimedLogin, guest login and XDMCP.
  3. Look at the idle delay, the lock delay and the settings locks.
  4. Look at automount, autorun, remote access encryption and the user list.
  5. Look for X server packages on hosts that do not need a desktop.
  *Example:* `grep -rE "AutomaticLogin|TimedLogin|Enable=" /etc/gdm/custom.conf ; dconf dump /org/gnome/desktop/screensaver/ ; gsettings get org.gnome.desktop.session idle-delay ; systemctl get-default ; rpm -q gdm xorg-x11-server-common`  
  *Expected:* Automatic login, guest login and XDMCP are off. The screen locks after idle time and users cannot change the lock settings. Servers have no desktop.  
  *Refs:* tool_check: cac:dconf_db_up_to_date, cac:dconf_gnome_disable_automount, cac:dconf_gnome_disable_automount_open, cac:dconf_gnome_disable_autorun, cac:dconf_gnome_disable_ctrlaltdel_reboot, cac:dconf_gnome_disable_geolocation, cac:dconf_gnome_disable_power_settings, cac:dconf_gnome_disable_restart_shutdown, cac:dconf_gnome_disable_thumbnailers, cac:dconf_gnome_disable_user_admin, cac:dconf_gnome_disable_user_list, cac:dconf_gnome_disable_wifi_create, cac:dconf_gnome_disable_wifi_notification, cac:dconf_gnome_enable_smartcard_auth, cac:dconf_gnome_lock_screen_on_smartcard_removal, cac:dconf_gnome_login_retries, cac:dconf_gnome_remote_access_credential_prompt, cac:dconf_gnome_remote_access_encryption, cac:dconf_gnome_screensaver_idle_activation_enabled, cac:dconf_gnome_screensaver_idle_activation_locked, cac:dconf_gnome_screensaver_idle_delay, cac:dconf_gnome_screensaver_lock_delay, cac:dconf_gnome_screensaver_lock_enabled, cac:dconf_gnome_screensaver_lock_locked, cac:dconf_gnome_screensaver_mode_blank, cac:dconf_gnome_screensaver_user_info, cac:dconf_gnome_screensaver_user_locks, cac:dconf_gnome_session_idle_user_locks, cac:enable_dconf_user_profile, cac:gnome_gdm_disable_automatic_login, cac:gnome_gdm_disable_guest_login, cac:gnome_gdm_disable_unattended_automatic_login, cac:gnome_gdm_disable_xdmcp, cac:package_gdm_removed, cac:package_xorg-x11-server-Xwayland_removed, cac:package_xorg-x11-server-common_removed, cac:xwayland_disabled, cac:xwindows_remove_packages, cac:xwindows_runlevel_target; nist_800_53: CM-6, CM-7, IA-2, AC-11; pci_dss: 6.2, 8.3


## PAM

- [ ] **NET-PAM-001** Check that PAM locks accounts after repeated failed logins  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts where online password guessing is not slowed or stopped by an account lockout.  
  *Steps:*
  1. Open the PAM files /etc/pam.d/system-auth and /etc/pam.d/password-auth, or the files that the distribution uses.
  2. Look for the pam_faillock module in the auth section, before and after pam_unix.
  3. Read /etc/security/faillock.conf for the deny, fail_interval and unlock_time values.
  4. Look at the lockout of the root account and at the directory that stores the failure records.
  5. Try wrong passwords on a test account until the limit. Make sure the account locks and the lockout is logged.
  *Example:* `grep -rE "pam_faillock|pam_tally2|pam_faildelay" /etc/pam.d/ ; grep -vE "^#|^$" /etc/security/faillock.conf ; faillock --user testuser ; grep FAIL_DELAY /etc/login.defs`  
  *Expected:* The pam_faillock module is active in auth. The deny, interval and unlock values meet the organization standard. Lockouts are logged and persist after a restart.  
  *Refs:* tool_check: cac:account_password_pam_faillock_password_auth, cac:account_password_pam_faillock_system_auth, cac:account_password_selinux_faillock_dir, cac:account_passwords_pam_faillock_audit, cac:account_passwords_pam_faillock_dir, cac:accounts_logon_fail_delay, cac:accounts_passwords_pam_faildelay_delay, cac:accounts_passwords_pam_faillock_audit, cac:accounts_passwords_pam_faillock_deny, cac:accounts_passwords_pam_faillock_deny_root, cac:accounts_passwords_pam_faillock_dir, cac:accounts_passwords_pam_faillock_enabled, cac:accounts_passwords_pam_faillock_enforce_local, cac:accounts_passwords_pam_faillock_even_deny_root_or_root_unlock_time, cac:accounts_passwords_pam_faillock_interval, cac:accounts_passwords_pam_faillock_root_unlock_time, cac:accounts_passwords_pam_faillock_silent, cac:accounts_passwords_pam_faillock_unlock_time, cac:accounts_passwords_pam_faillock_unlock_time_with_zero, cac:accounts_passwords_pam_tally2, cac:accounts_passwords_pam_tally2_deny_root, cac:accounts_passwords_pam_tally2_file, cac:accounts_passwords_pam_tally2_file_selinux, cac:accounts_passwords_pam_tally2_unlock_time, cac:display_login_attempts; nist_800_53: AC-7, CM-6, IA-5, AC-9

- [ ] **NET-PAM-002** Check that PAM enforces password complexity rules  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts that accept short, simple or dictionary passwords.  
  *Steps:*
  1. Make sure the pam_pwquality package is installed and the module is in the password stack.
  2. Read /etc/security/pwquality.conf and the options in /etc/pam.d/system-auth and password-auth.
  3. Look at minlen, minclass, the credit values, difok, maxrepeat, maxsequence and dictcheck.
  4. Look for enforce_for_root and the retry limit.
  5. Try to set a short or common password on a test account. Make sure the system refuses it.
  *Example:* `rpm -q libpwquality || dpkg -l libpam-pwquality ; grep -vE "^#|^$" /etc/security/pwquality.conf ; grep -r pwquality /etc/pam.d/ ; grep PASS_MIN_LEN /etc/login.defs`  
  *Expected:* pam_pwquality is active for all password changes. Minimum length, character classes and dictionary checks meet the organization standard. The rules also apply to root.  
  *Refs:* tool_check: cac:accounts_password_minlen_login_defs, cac:accounts_password_pam_dcredit, cac:accounts_password_pam_dictcheck, cac:accounts_password_pam_difok, cac:accounts_password_pam_enforce_root, cac:accounts_password_pam_lcredit, cac:accounts_password_pam_maxclassrepeat, cac:accounts_password_pam_maxrepeat, cac:accounts_password_pam_maxsequence, cac:accounts_password_pam_minclass, cac:accounts_password_pam_minlen, cac:accounts_password_pam_ocredit, cac:accounts_password_pam_pwquality_enabled, cac:accounts_password_pam_pwquality_password_auth, cac:accounts_password_pam_pwquality_retry, cac:accounts_password_pam_pwquality_system_auth, cac:accounts_password_pam_retry, cac:accounts_password_pam_ucredit, cac:cracklib_accounts_password_pam_dcredit, cac:cracklib_accounts_password_pam_difok, cac:cracklib_accounts_password_pam_lcredit, cac:cracklib_accounts_password_pam_minlen, cac:cracklib_accounts_password_pam_ocredit, cac:cracklib_accounts_password_pam_retry, cac:cracklib_accounts_password_pam_ucredit, cac:package_pam_pwquality_installed, cac:passwd_system-auth_substack; nist_800_53: IA-5, CM-6, AC-7; pci_dss: 8.2.3

- [ ] **NET-PAM-003** Check password hashing, password history and PAM module order  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds weak stored hashes, password reuse and PAM stacks that skip the required modules.  
  *Steps:*
  1. Read the password lines in the PAM files and look for pam_unix options such as sha512, yescrypt, rounds and use_authtok.
  2. Look at ENCRYPT_METHOD and the rounds or cost values in /etc/login.defs and /etc/libuser.conf.
  3. Look for pam_pwhistory with the remember option, and for the same setting for root.
  4. Look at the authselect profile or the PAM files for pam_wheel on su and for pam_namespace.
  5. Make sure all password hashes in /etc/shadow use the approved algorithm.
  *Example:* `grep -rE "pam_unix|pam_pwhistory|pam_wheel|pam_namespace" /etc/pam.d/ ; grep -E "ENCRYPT_METHOD|SHA_CRYPT|YESCRYPT" /etc/login.defs ; authselect current ; awk -F: '$2 ~ /^\$/ {print $1, substr($2,1,3)}' /etc/shadow`  
  *Expected:* Passwords use the approved hash with enough rounds. The history keeps the number of old passwords that the standard sets, also for root. su is limited to a wheel group.  
  *Refs:* tool_check: cac:accounts_password_all_shadowed_sha512, cac:accounts_password_pam_enforce_local, cac:accounts_password_pam_enforcing, cac:accounts_password_pam_modules_in_authselect_profile, cac:accounts_password_pam_pwhistory_enabled, cac:accounts_password_pam_pwhistory_enforce_for_root, cac:accounts_password_pam_pwhistory_enforce_root, cac:accounts_password_pam_pwhistory_remember, cac:accounts_password_pam_pwhistory_remember_password_auth, cac:accounts_password_pam_pwhistory_remember_system_auth, cac:accounts_password_pam_pwhistory_use_authtok, cac:accounts_password_pam_unix_authtok, cac:accounts_password_pam_unix_enabled, cac:accounts_password_pam_unix_no_remember, cac:accounts_password_pam_unix_remember, cac:accounts_password_pam_unix_rounds_password_auth, cac:accounts_password_pam_unix_rounds_system_auth, cac:disallow_bypass_password_sudo, cac:enable_pam_namespace, cac:ensure_pam_wheel_group_empty, cac:set_password_hashing_algorithm_auth_stig, cac:set_password_hashing_algorithm_commonauth, cac:set_password_hashing_algorithm_libuserconf, cac:set_password_hashing_algorithm_logindefs, cac:set_password_hashing_algorithm_passwordauth, cac:set_password_hashing_algorithm_systemauth, cac:set_password_hashing_min_rounds_logindefs, cac:set_password_hashing_yescrypt_cost_factor_logindefs, cac:use_pam_wheel_for_su, cac:use_pam_wheel_group_for_su; nist_800_53: IA-5, CM-6, IA-7, AC-2; pci_dss: 8.2.1, 8.2.5

- [ ] **NET-PAM-004** Check password aging and account expiration settings  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds accounts with passwords that never expire, never warn or stay active after long inactivity.  
  *Steps:*
  1. Read PASS_MAX_DAYS, PASS_MIN_DAYS and PASS_WARN_AGE in /etc/login.defs.
  2. Read the default inactivity period with useradd -D.
  3. List the aging values of the existing accounts with chage.
  4. Look at emergency and temporary accounts for an expiration date.
  5. Find accounts with a last change date in the future.
  *Example:* `grep -E "^PASS_(MAX|MIN|WARN)" /etc/login.defs ; useradd -D | grep INACTIVE ; chage -l <user> ; awk -F: '{print $1,$3,$4,$5,$7}' /etc/shadow`  
  *Expected:* New and existing accounts follow the aging limits of the organization standard. Temporary accounts have an end date. No last change date is in the future.  
  *Refs:* tool_check: cac:account_disable_inactivity_password_auth, cac:account_disable_inactivity_system_auth, cac:account_disable_post_pw_expiration, cac:account_emergency_admin, cac:account_emergency_expire_date, cac:account_temp_expire_date, cac:accounts_maximum_age_login_defs, cac:accounts_minimum_age_login_defs, cac:accounts_password_last_change_is_in_past, cac:accounts_password_set_max_life_existing, cac:accounts_password_set_max_life_root, cac:accounts_password_set_min_life_existing, cac:accounts_password_set_warn_age_existing, cac:accounts_password_warn_age_login_defs, cac:accounts_set_post_pw_existing, cac:policy_temp_passwords_immediate_change; nist_800_53: IA-5, CM-6, AC-2, IA-4; pci_dss: 8.2.4

- [ ] **NET-PAM-005** Check local accounts for duplicates, empty passwords and root misuse  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds shared identifiers, empty passwords, extra UID 0 accounts and weak root controls.  
  *Steps:*
  1. List accounts with an empty password field in /etc/shadow.
  2. List accounts with UID 0 and groups with GID 0. Only root may appear.
  3. Look for duplicate user names, group names, UIDs and GIDs.
  4. Look for legacy "+" NIS entries in passwd, group and shadow.
  5. Look for .rhosts, .netrc and .forward files and for system accounts with a shell or an unlocked password.
  *Example:* `awk -F: '($2==""){print $1}' /etc/shadow ; awk -F: '($3==0){print $1}' /etc/passwd ; getent passwd | cut -d: -f1 | sort | uniq -d ; grep "^+" /etc/passwd /etc/group /etc/shadow ; find /home /root -name ".rhosts" -o -name ".netrc" -o -name ".forward"`  
  *Expected:* No account has an empty password. Only root has UID 0 and GID 0. All names and IDs are unique. System accounts are locked and have no login shell.  
  *Refs:* tool_check: cac:account_unique_id, cac:account_unique_name, cac:account_use_centralized_automated_auth, cac:accounts_authorized_local_users, cac:accounts_no_uid_except_zero, cac:accounts_password_all_shadowed, cac:accounts_root_gid_zero, cac:ensure_root_access_controlled, cac:ensure_root_password_configured, cac:ensure_shadow_group_empty, cac:ensure_sudo_group_restricted, cac:gid_passwd_group_same, cac:group_unique_id, cac:group_unique_name, cac:groups_no_zero_gid_except_root, cac:no_direct_root_logins, cac:no_duplicate_uids, cac:no_empty_passwords, cac:no_empty_passwords_etc_shadow, cac:no_empty_passwords_unix, cac:no_forward_files, cac:no_invalid_shell_accounts_unlocked, cac:no_legacy_plus_entries_etc_group, cac:no_legacy_plus_entries_etc_passwd, cac:no_legacy_plus_entries_etc_shadow, cac:no_netrc_files, cac:no_nologin_in_shells, cac:no_password_auth_for_systemaccounts, cac:no_rhost_files, cac:no_root_webbrowsing, cac:no_shelllogin_for_systemaccounts, cac:prevent_direct_root_logins, cac:restrict_serial_port_logins, cac:root_path_default, cac:securetty_root_login_console_only; nist_800_53: CM-6, IA-5, AC-6, IA-2; pci_dss: 8.1.1, 8.5

- [ ] **NET-PAM-006** Check user session limits, umask, home directories and root PATH  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds loose default file modes, open home directories, unsafe root paths and sessions that never end.  
  *Steps:*
  1. Read the umask value in /etc/login.defs, /etc/profile, /etc/bashrc and the PAM umask setting.
  2. Read the TMOUT value and the limits for concurrent logins in /etc/security/limits.conf.
  3. Look at the owner and mode of each interactive home directory and of the files in it.
  4. Look at the initialization files and the shell history for wrong owners and wide modes.
  5. Print the PATH of root. Look for a dot, an empty entry or a writable directory.
  *Example:* `grep -rn umask /etc/login.defs /etc/profile /etc/profile.d /etc/bashrc ; grep -rn TMOUT /etc/profile.d /etc/profile ; grep maxlogins /etc/security/limits.conf /etc/security/limits.d/ ; stat -c "%U %a %n" /home/* ; sudo -i sh -c 'echo $PATH'`  
  *Expected:* The umask blocks access by other users. Idle sessions end after the set time. Home directories have a mode of 0750 or stricter and the right owner. Root PATH has only safe directories.  
  *Refs:* tool_check: cac:accounts_have_homedir_login_defs, cac:accounts_max_concurrent_login_sessions, cac:accounts_polyinstantiated_tmp, cac:accounts_polyinstantiated_var_tmp, cac:accounts_root_path_dirs_no_write, cac:accounts_tmout, cac:accounts_umask_etc_bashrc, cac:accounts_umask_etc_csh_cshrc, cac:accounts_umask_etc_login_defs, cac:accounts_umask_etc_profile, cac:accounts_umask_interactive_users, cac:accounts_umask_pam_postlogin, cac:accounts_umask_root, cac:accounts_user_dot_group_ownership, cac:accounts_user_dot_no_world_writable_programs, cac:accounts_user_dot_user_ownership, cac:accounts_user_home_paths_only, cac:accounts_user_interactive_home_directory_defined, cac:accounts_user_interactive_home_directory_exists, cac:accounts_user_interactive_home_directory_on_separate_partition, cac:accounts_users_home_files_groupownership, cac:accounts_users_home_files_ownership, cac:accounts_users_home_files_permissions, cac:accounts_users_netrc_file_permissions, cac:accounts_users_own_home_directories, cac:file_groupownership_home_directories, cac:file_groupownership_lastlog, cac:file_ownership_home_directories, cac:file_ownership_lastlog, cac:file_permission_user_bash_history, cac:file_permission_user_init_files, cac:file_permission_user_init_files_root, cac:file_permissions_home_directories, cac:file_permissions_home_dirs, cac:file_permissions_lastlog, cac:no_dirs_unowned_by_root, cac:root_path_all_dirs, cac:root_path_no_dot; nist_800_53: CM-6, SI-11, AC-6, AC-10

- [ ] **NET-PAM-007** Check the login warning banners and the files that hold them  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds hosts that show no legal notice or let ordinary users change the banner text.  
  *Steps:*
  1. Read /etc/issue, /etc/issue.net and /etc/motd.
  2. Compare the text with the banner text of the organization.
  3. Look at the owner, group and mode of the three files.
  4. Make sure the SSH daemon and the graphical login show the same banner.
  *Example:* `cat /etc/issue /etc/issue.net /etc/motd ; stat -c "%U:%G %a %n" /etc/issue /etc/issue.net /etc/motd ; sshd -T | grep -i banner ; dconf read /org/gnome/login-screen/banner-message-text`  
  *Expected:* The banner files hold the approved text. Root owns the files and the mode is 0644 or stricter. Each remote and local login path shows the banner.  
  *Refs:* tool_check: cac:banner_etc_gdm_banner, cac:banner_etc_issue, cac:banner_etc_issue_cis, cac:banner_etc_issue_net, cac:banner_etc_issue_net_cis, cac:banner_etc_motd, cac:banner_etc_motd_cis, cac:banner_etc_profiled_ssh_confirm, cac:dconf_gnome_banner_enabled, cac:dconf_gnome_login_banner_text, cac:file_groupowner_etc_issue, cac:file_groupowner_etc_issue_net, cac:file_groupowner_etc_motd, cac:file_owner_etc_issue, cac:file_owner_etc_issue_net, cac:file_owner_etc_motd, cac:file_permissions_etc_issue, cac:file_permissions_etc_issue_net, cac:file_permissions_etc_motd, cac:gui_login_dod_acknowledgement; nist_800_53: AC-8

- [ ] **NET-PAM-008** Check console access controls, Ctrl-Alt-Del and session lock tools  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts where a person at the console can reboot, skip authentication or avoid the screen lock.  
  *Steps:*
  1. Look at the systemd target for Ctrl-Alt-Del and its burst action.
  2. Read the rescue and emergency service files and make sure they need a password.
  3. Look for the debug-shell service and for interactive boot options.
  4. Look for tmux, screen or vlock settings that lock the session after inactivity.
  5. Read the idle session settings of logind.
  *Example:* `systemctl status ctrl-alt-del.target ; grep -E "ExecStart" /usr/lib/systemd/system/rescue.service /usr/lib/systemd/system/emergency.service ; systemctl is-enabled debug-shell.service ; grep -r "lock-" /etc/tmux.conf ; grep StopIdleSessionSec /etc/systemd/logind.conf`  
  *Expected:* Ctrl-Alt-Del does not reboot the host. Single user and emergency modes need a password. The debug shell is off and idle sessions lock or end.  
  *Refs:* tool_check: cac:configure_bashrc_exec_tmux, cac:configure_bashrc_tmux, cac:configure_tmux_lock_after_time, cac:configure_tmux_lock_command, cac:configure_tmux_lock_keybinding, cac:coreos_disable_interactive_boot, cac:disable_ctrlaltdel_burstaction, cac:disable_ctrlaltdel_reboot, cac:grub2_disable_interactive_boot, cac:logind_session_timeout, cac:no_tmux_in_shells, cac:package_screen_installed, cac:package_tmux_installed, cac:require_emergency_target_auth, cac:require_singleuser_auth, cac:service_debug-shell_disabled, cac:vlock_installed; nist_800_53: CM-6, AC-11, SC-2, AC-6

- [ ] **NET-PAM-009** Check smart card login settings for PAM and SSSD  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds hosts that claim multifactor login but do not check the card certificate chain or revocation status.  
  *Steps:*
  1. Look for the opensc, pcsc-lite and pcscd packages and services.
  2. Read the PAM files and look for the smart card option in the auth stack.
  3. Read the card driver and CA settings of opensc and the NSS database.
  4. Look at the certificate status check and the CRL cache settings.
  5. Try a login with a card from an unknown CA. Make sure the login fails.
  *Example:* `rpm -q opensc pcsc-lite ; systemctl is-enabled pcscd.socket ; grep -rE "pam_pkcs11|pam_sss.*cert|try_cert_auth|use_mappers" /etc/pam.d/ ; grep -E "card_drivers|cert_policy" /etc/pam_pkcs11/pam_pkcs11.conf`  
  *Expected:* Smart card login is on where the policy needs it. The login checks the CA chain and the revocation status, and unknown cards are refused.  
  *Refs:* tool_check: cac:configure_opensc_card_drivers, cac:configure_opensc_nss_db, cac:force_opensc_card_drivers, cac:install_smartcard_packages, cac:package_opensc_installed, cac:package_pcsc-lite-ccid_installed, cac:package_pcsc-lite_installed, cac:service_pcscd_enabled, cac:smartcard_auth, cac:smartcard_configure_ca, cac:smartcard_configure_cert_checking, cac:smartcard_configure_crl, cac:smartcard_pam_enabled, cac:socket_pcscd_enabled, cac:verify_use_mappers; nist_800_53: IA-2, CM-6; pci_dss: 8.3

- [ ] **NET-PAM-010** Check central authentication clients: SSSD, LDAP, Kerberos and authselect  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds central login clients that use clear-text binds, skip certificate checks or let PAM files drift.  
  *Steps:*
  1. Look at the authselect profile or the PAM files and make sure they are not changed by hand.
  2. Read /etc/sssd/sssd.conf and look at the ldap_id_use_start_tls, ldap_tls_reqcert and CA settings.
  3. Read /etc/openldap/ldap.conf and the nss_ldap settings for TLS.
  4. Look at the offline credential and cache expiration values.
  5. Look for unused LDAP, Kerberos and 389-ds server packages.
  *Example:* `authselect current ; grep -vE "^#|^$" /etc/sssd/sssd.conf ; grep -E "TLS|URI" /etc/openldap/ldap.conf ; ls -l /etc/krb5.keytab ; rpm -q openldap-servers krb5-server 389-ds-base`  
  *Expected:* Directory binds use TLS with a full certificate check. The SSSD service runs as the sssd user. Credential caches expire. Unneeded directory servers are not installed.  
  *Refs:* tool_check: cac:authconfig_config_files_symlinks, cac:enable_authselect, cac:enable_ldap_client, cac:kerberos_disable_no_keytab, cac:ldap_client_start_tls, cac:ldap_client_tls_cacertpath, cac:package_389-ds-base_removed, cac:package_authselect_installed, cac:package_krb5-server_removed, cac:package_nss_sss_installed, cac:package_openldap-clients_removed, cac:package_openldap-servers_removed, cac:package_pam_installed, cac:package_pam_modules_installed, cac:package_pam_runtime_installed, cac:package_pam_sss_installed, cac:package_sssd-ipa_installed, cac:package_sssd_installed, cac:pam_disable_automatic_configuration, cac:service_slapd_disabled, cac:service_sssd_enabled, cac:sssd_certificate_verification, cac:sssd_certification_path_trust_anchor, cac:sssd_enable_certmap, cac:sssd_enable_pam_services, cac:sssd_enable_smartcards, cac:sssd_enable_user_cert, cac:sssd_has_trust_anchor, cac:sssd_ldap_configure_tls_ca, cac:sssd_ldap_configure_tls_ca_dir, cac:sssd_ldap_configure_tls_reqcert, cac:sssd_ldap_start_tls, cac:sssd_memcache_timeout, cac:sssd_offline_cred_expiration, cac:sssd_run_as_sssd_user, cac:sssd_ssh_known_hosts_timeout; nist_800_53: CM-6, CM-7, SC-12, IA-5; pci_dss: 8.3

- [ ] **NET-PAM-011** Check sudo configuration, file permissions and privilege rules  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds sudo rules that give passwordless root, keep unsafe environments or allow users to avoid the log.  
  *Steps:*
  1. Read /etc/sudoers and all files under /etc/sudoers.d.
  2. Look for NOPASSWD, !authenticate and negated commands. Look for rules that target ALL or the root user.
  3. Look for the Defaults use_pty, env_reset, logfile, passwd_timeout and timestamp settings.
  4. Look at the owner and mode of the sudo binary, /etc/sudoers and /etc/sudoers.d.
  5. Make sure the include directory is only the default one and that visudo accepts the files.
  *Example:* `grep -rnE "NOPASSWD|!authenticate|^Defaults" /etc/sudoers /etc/sudoers.d/ ; visudo -c ; stat -c "%U:%G %a %n" /etc/sudoers /etc/sudoers.d /usr/bin/sudo ; sudo -l -U <user>`  
  *Expected:* Sudo needs a password and a real terminal. The environment is reset. Rules name exact commands. Only root owns the sudo files and the log file records each command.  
  *Refs:* tool_check: cac:directory_groupowner_etc_sudoersd, cac:directory_owner_etc_sudoersd, cac:directory_permissions_etc_sudoersd, cac:file_groupowner_etc_sudoers, cac:file_owner_etc_sudoers, cac:file_permissions_etc_sudoers, cac:file_permissions_sudo, cac:package_sudo_installed, cac:sudo_add_env_reset, cac:sudo_add_ignore_dot, cac:sudo_add_noexec, cac:sudo_add_passwd_timeout, cac:sudo_add_requiretty, cac:sudo_add_umask, cac:sudo_add_use_pty, cac:sudo_custom_logfile, cac:sudo_dedicated_group, cac:sudo_remove_no_authenticate, cac:sudo_remove_nopasswd, cac:sudo_require_authentication, cac:sudo_require_reauthentication, cac:sudo_restrict_others_executable_permission, cac:sudo_restrict_privilege_elevation_to_authorized, cac:sudo_vdsm_nopasswd, cac:sudoers_default_includedir, cac:sudoers_explicit_command_args, cac:sudoers_no_command_negation, cac:sudoers_no_root_target, cac:sudoers_validate_passwd; nist_800_53: CM-6, IA-11


## PKG

- [ ] **NET-PKG-001** Check the system crypto policy and its use by services  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts that use the LEGACY policy or have local overrides that bring back weak algorithms.  
  *Steps:*
  1. Run update-crypto-policies --show.
  2. Make sure the policy is not LEGACY and that no module in /etc/crypto-policies/policies/modules weakens it.
  3. Look at the symlinks in /etc/crypto-policies/back-ends. Make sure they point to the generated files.
  4. Look at the OpenSSL, GnuTLS, BIND, Kerberos, SSH and Libreswan settings and make sure they follow the policy.
  5. Look at the random number source for OpenSSL.
  *Example:* `update-crypto-policies --show ; update-crypto-policies --check ; ls -l /etc/crypto-policies/back-ends/ ; grep -r "crypto-policies" /etc/ssh/ssh_config.d /etc/ssh/sshd_config.d ; openssl list -cipher-algorithms | head`  
  *Expected:* The policy is DEFAULT or stricter, not LEGACY. No local file overrides the back-end files. The services use the system policy.  
  *Refs:* tool_check: cac:configure_bind_crypto_policy, cac:configure_crypto_policy, cac:configure_custom_crypto_policy_cis, cac:configure_gnutls_tls_crypto_policy, cac:configure_kerberos_crypto_policy, cac:configure_libreswan_crypto_policy, cac:configure_openssl_crypto_policy, cac:configure_openssl_tls_crypto_policy, cac:configure_ssh_crypto_policy, cac:crypto_policy_not_legacy, cac:crypto_policy_not_overridden, cac:fips_crypto_policy_symlinks, cac:harden_openssl_crypto_policy, cac:harden_ssh_client_crypto_policy, cac:harden_sshd_ciphers_openssh_conf_crypto_policy, cac:harden_sshd_ciphers_opensshserver_conf_crypto_policy, cac:harden_sshd_crypto_policy, cac:harden_sshd_macs_openssh_conf_crypto_policy, cac:harden_sshd_macs_opensshserver_conf_crypto_policy, cac:openssl_use_strong_entropy, cac:package_crypto-policies_installed; nist_800_53: AC-17, SC-12, SC-13, MA-4; pci_dss: 2.2

- [ ] **NET-PKG-002** Check FIPS mode, boot setup and certified OS status  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds hosts that must use validated cryptography but run with FIPS mode off.  
  *Steps:*
  1. Read /proc/sys/crypto/fips_enabled.
  2. Run fips-mode-setup --check.
  3. Look at the kernel command line for fips=1 and the dracut fips module.
  4. Look at the crypto policy and sub-policy names.
  5. Compare the result with the compliance requirement of the host.
  *Example:* `cat /proc/sys/crypto/fips_enabled ; fips-mode-setup --check ; grep -o "fips=1" /proc/cmdline ; lsinitrd | grep fips ; update-crypto-policies --show`  
  *Expected:* On hosts that need FIPS, FIPS mode is on at boot and the crypto policy is FIPS. The OS build is a certified build.  
  *Refs:* tool_check: cac:enable_dracut_fips_module, cac:enable_fips_mode, cac:ensure_tuxcare_fips_packages_installed, cac:etc_system_fips_exists, cac:fips_crypto_subpolicy, cac:fips_custom_stig_sub_policy, cac:grub2_enable_fips_mode, cac:installed_OS_is_FIPS_certified, cac:is_fips_mode_enabled, cac:package_dracut-fips-aesni_installed, cac:package_dracut-fips_installed, cac:sysctl_crypto_fips_enabled, cac:system_booted_in_fips_mode; nist_800_53: SC-12, SC-13, IA-7, CM-6

- [ ] **NET-PKG-003** Check endpoint protection, HIDS and user data backup tools  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds hosts with no malware scanner, no host intrusion detection or no backup of user data.  
  *Steps:*
  1. Look for the endpoint protection or antivirus agent and its service state.
  2. Look at the date of the last signature update.
  3. Look for a host intrusion detection tool, or for a written reason why audit and SELinux are enough.
  4. Look for the backup job for user data and find the last good run.
  *Example:* `systemctl status nails mfetpd 2>/dev/null ; rpm -qa | grep -iE "mcafee|MFE|clamav|aide|ossec|wazuh" ; ls -l /var/log/backup* ; crontab -l`  
  *Expected:* An approved endpoint protection agent runs with current signatures. A host intrusion detection tool or an approved alternative exists. User data backups run on schedule.  
  *Refs:* tool_check: cac:agent_mfetpd_running, cac:configure_user_data_backups, cac:install_antivirus, cac:install_endpoint_security_software, cac:install_hids, cac:install_mcafee_antivirus, cac:install_mcafee_cma_rt, cac:install_mcafee_hbss_accm, cac:install_mcafee_hbss_pa, cac:mcafee_antivirus_definitions_updated, cac:package_MFEhiplsm_installed, cac:package_mcafeetp_installed, cac:service_nails_enabled; nist_800_53: CM-6, SI-3, SC-28, SI-2; pci_dss: 11.4

- [ ] **NET-PKG-004** Check package signature checks, repositories and automatic updates  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds hosts that install unsigned packages or take packages from unapproved repositories.  
  *Steps:*
  1. Read the gpgcheck, localpkg_gpgcheck and repo_gpgcheck values in /etc/dnf/dnf.conf or /etc/yum.conf.
  2. Read each file in /etc/yum.repos.d and look for gpgcheck=0.
  3. List the repositories. Compare them with the approved list. Look for EPEL.
  4. Run rpm -qa gpg-pubkey and compare the keys with the vendor keys.
  5. Look at dnf-automatic and its timer, the upgrade type and the weak dependency setting.
  *Example:* `grep -rE "gpgcheck" /etc/dnf/dnf.conf /etc/yum.conf /etc/yum.repos.d/ ; dnf repolist ; rpm -qa gpg-pubkey ; systemctl is-enabled dnf-automatic.timer ; grep -E "upgrade_type|apply_updates" /etc/dnf/automatic.conf`  
  *Expected:* Package, local package and repository metadata signature checks are on for all repositories. Only approved repositories are enabled. The vendor keys match.  
  *Refs:* tool_check: cac:clean_components_post_updating, cac:disable_weak_deps, cac:dnf-automatic_apply_updates, cac:dnf-automatic_security_updates_only, cac:enable_gpgcheck_for_all_repositories, cac:ensure_GPG_keys_are_configured, cac:ensure_almalinux_gpgkey_installed, cac:ensure_amazon_gpgkey_installed, cac:ensure_epel_repos_disabled, cac:ensure_fedora_gpgkey_installed, cac:ensure_gpgcheck_globally_activated, cac:ensure_gpgcheck_local_packages, cac:ensure_gpgcheck_never_disabled, cac:ensure_gpgcheck_repo_metadata, cac:ensure_oracle_gpgkey_installed, cac:ensure_package_repositories_are_configured, cac:ensure_redhat_gpgkey_installed, cac:ensure_suse_gpgkey_installed, cac:ensure_tuxcare_esu_repo_enabled, cac:package_dnf-automatic_installed, cac:package_gnome_software_installed, cac:timer_dnf-automatic_enabled, cac:zypper_only_requires_enabled; nist_800_53: SC-12, CM-6, CM-11, CM-5; pci_dss: 6.2

- [ ] **NET-PKG-005** Check APT sources, keys, authentication and file permissions  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds hosts that accept unauthenticated packages or allow others to change the package sources.  
  *Steps:*
  1. Read /etc/apt/sources.list and /etc/apt/sources.list.d. Compare the sources with the official list.
  2. Search /etc/apt/apt.conf.d for AllowUnauthenticated.
  3. Look at APT::Install-Recommends, APT::Install-Suggests and the weak dependency setting.
  4. List the owner and mode of the source, key and auth.conf.d directories and files.
  *Example:* `grep -rn "AllowUnauthenticated\|Install-Recommends\|Install-Suggests" /etc/apt/apt.conf.d/ ; cat /etc/apt/sources.list /etc/apt/sources.list.d/* ; stat -c "%U:%G %a %n" /etc/apt/sources.list.d /etc/apt/trusted.gpg.d /etc/apt/auth.conf.d /usr/share/keyrings`  
  *Expected:* APT does not allow unauthenticated packages. The sources are official and signed. Root owns the APT files and no other user can write to them.  
  *Refs:* tool_check: cac:apt_conf_disable_recommends, cac:apt_conf_disable_suggests, cac:apt_conf_disallow_unauthenticated, cac:apt_disable_weak_dependencies, cac:apt_sources_list_official, cac:directory_groupowner_apt_auth_conf_d, cac:directory_groupowner_apt_sources_list_d, cac:directory_groupowner_apt_trusted_gpg_d, cac:directory_groupowner_usr_share_keyrings, cac:directory_owner_apt_auth_conf_d, cac:directory_owner_apt_sources_list_d, cac:directory_owner_apt_trusted_gpg_d, cac:directory_owner_usr_share_keyrings, cac:directory_permissions_apt_auth_conf_d, cac:directory_permissions_apt_sources_list_d, cac:directory_permissions_apt_trusted_gpg_d, cac:directory_permissions_usr_share_keyrings, cac:file_groupowner_apt_auth_conf_d, cac:file_groupowner_apt_gpg_keys, cac:file_groupowner_apt_sources_list_d, cac:file_owner_apt_auth_conf_d, cac:file_owner_apt_gpg_keys, cac:file_owner_apt_sources_list_d, cac:file_permissions_apt_auth_conf_d, cac:file_permissions_apt_gpg_keys, cac:file_permissions_apt_sources_list_d

- [ ] **NET-PKG-006** Check installed and removed system tool packages against the standard  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds hosts that miss required security tools or keep crash reporters and extra tools that leak data.  
  *Steps:*
  1. List the installed packages with rpm -qa or dpkg -l.
  2. Look for the required tools: cryptsetup, openscap-scanner, scap-security-guide, rng-tools, nss-tools, gnutls-utils, tar and vim.
  3. Look for the packages that the standard removes: abrt and its plug-ins, libreport plug-ins, tuned, pigz, geolite2 and gssproxy.
  4. Look at the OS word size and the entropy settings.
  *Example:* `rpm -q cryptsetup openscap-scanner scap-security-guide rng-tools nss-tools gnutls-utils ; rpm -qa | grep -E "^(abrt|libreport|tuned|pigz|geolite2|gssproxy)" ; uname -m`  
  *Expected:* The required tools are installed. The removed packages are not installed. Any deviation has an approval.  
  *Refs:* tool_check: cac:accounts_authorized_local_users_sidadm_orasid, cac:package_abrt-addon-ccpp_removed, cac:package_abrt-addon-kerneloops_removed, cac:package_abrt-addon-python_removed, cac:package_abrt-cli_removed, cac:package_abrt-libs_removed, cac:package_abrt-plugin-logger_removed, cac:package_abrt-plugin-rhtsupport_removed, cac:package_abrt-plugin-sosreport_removed, cac:package_abrt-server-info-page_removed, cac:package_binutils_installed, cac:package_cryptsetup-luks_installed, cac:package_dnf-plugin-subscription-manager_installed, cac:package_geolite2-city_removed, cac:package_geolite2-country_removed, cac:package_glibc_installed, cac:package_gnutls-utils_installed, cac:package_gssproxy_removed, cac:package_iprutils_removed, cac:package_krb5-workstation_removed, cac:package_libcap-ng-utils_installed, cac:package_libdnf-plugin-subscription-manager_installed, cac:package_libreport-plugin-logger_removed, cac:package_libreport-plugin-rhtsupport_removed, cac:package_nss-tools_installed, cac:package_openscap-scanner_installed, cac:package_pigz_removed, cac:package_python3-abrt-addon_removed, cac:package_rear_installed, cac:package_rng-tools_installed, cac:package_scap-security-guide_installed, cac:package_sequoia-sq_installed, cac:package_subscription-manager_installed, cac:package_tar_installed, cac:package_tuned_removed, cac:package_uuidd_installed, cac:package_vim_installed, cac:prefer_64bit_os


## SSH

- [ ] **NET-SSH-001** Check that the SSH daemon blocks root login and weak authentication  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds SSH settings that allow direct root login, empty passwords or trust based on host names.  
  *Steps:*
  1. Print the effective SSH daemon configuration with sshd -T.
  2. Look at PermitRootLogin, PermitEmptyPasswords, HostbasedAuthentication and IgnoreRhosts.
  3. Look at PubkeyAuthentication, GSSAPIAuthentication, KerberosAuthentication and UsePAM.
  4. Look at PermitUserEnvironment, StrictModes and IgnoreUserKnownHosts.
  5. Try to log in as root and with an empty password. Make sure both fail.
  *Example:* `sshd -T | grep -iE "permitrootlogin|permitemptypasswords|hostbasedauthentication|ignorerhosts|pubkeyauthentication|gssapiauthentication|kerberosauthentication|usepam|permituserenvironment|strictmodes|ignoreuserknownhosts" ; ssh -o PreferredAuthentications=password root@<host>`  
  *Expected:* Root cannot log in over SSH with a password. Empty passwords and host-based trust are off. Only the needed authentication methods are on.  
  *Refs:* tool_check: cac:disable_host_auth, cac:sshd_allow_only_protocol2, cac:sshd_disable_empty_passwords, cac:sshd_disable_gssapi_auth, cac:sshd_disable_kerb_auth, cac:sshd_disable_pubkey_auth, cac:sshd_disable_rhosts, cac:sshd_disable_rhosts_rsa, cac:sshd_disable_root_login, cac:sshd_disable_root_password_login, cac:sshd_disable_user_known_hosts, cac:sshd_do_not_permit_user_env, cac:sshd_enable_gssapi_auth, cac:sshd_enable_pam, cac:sshd_enable_pubkey_auth, cac:sshd_enable_strictmodes, cac:sshd_limit_user_access, cac:sshd_set_allow_groups; nist_800_53: CM-7, AC-17, CM-6, AC-3; pci_dss: 2.2.4

- [ ] **NET-SSH-002** Check the ciphers, MACs and key exchange of the SSH daemon  
  *Severity if fail:* Medium | *Type:* Config Review, Automated  
  *Objective:* Finds SSH services that accept weak ciphers, weak MACs, weak key exchange or compression before login.  
  *Steps:*
  1. Print the Ciphers, MACs, KexAlgorithms and Compression values with sshd -T.
  2. Compare the lists with the approved algorithms of the organization.
  3. Look for the include line of the system crypto policy in sshd_config.
  4. Look at the RekeyLimit value and the SSH_USE_STRONG_RNG setting.
  5. Scan the port with a tool that lists the offered algorithms.
  *Example:* `sshd -T | grep -iE "^(ciphers|macs|kexalgorithms|compression|rekeylimit)" ; grep -rn "crypto-policies" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ ; nmap -p22 --script ssh2-enum-algos <host> ; ssh-audit <host>`  
  *Expected:* The daemon offers only the approved strong ciphers, MACs and key exchange algorithms. Compression is off or delayed. Session keys renew at the set limit.  
  *Refs:* tool_check: cac:sshd_disable_compression, cac:sshd_include_crypto_policy, cac:sshd_rekey_limit, cac:sshd_use_approved_ciphers, cac:sshd_use_approved_ciphers_ordered_stig, cac:sshd_use_approved_kex_ordered_stig, cac:sshd_use_approved_macs, cac:sshd_use_approved_macs_ordered_stig, cac:sshd_use_strong_ciphers, cac:sshd_use_strong_kex, cac:sshd_use_strong_macs, cac:sshd_use_strong_rng; nist_800_53: AC-17, SC-12, CM-6, CM-7; pci_dss: 2.3

- [ ] **NET-SSH-003** Check SSH forwarding, X11 and warning banner settings  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds SSH settings that let users tunnel traffic past the firewall or log in with no legal notice.  
  *Steps:*
  1. Print the effective SSH daemon configuration with sshd -T.
  2. Look at DisableForwarding, AllowTcpForwarding, X11Forwarding and X11UseLocalhost.
  3. Look at the Banner path and read the file.
  4. Try to open a port forward with ssh -L from a test account. Make sure it fails.
  *Example:* `sshd -T | grep -iE "disableforwarding|allowtcpforwarding|x11forwarding|x11uselocalhost|banner" ; ssh -L 8080:127.0.0.1:80 testuser@<host>`  
  *Expected:* Forwarding is off unless a written need exists. X11 forwarding is off or bound to the loopback address. The banner file shows the approved notice.  
  *Refs:* tool_check: cac:sshd_disable_forwarding, cac:sshd_disable_tcp_forwarding, cac:sshd_disable_x11_forwarding, cac:sshd_enable_warning_banner, cac:sshd_enable_warning_banner_net, cac:sshd_enable_x11_forwarding, cac:sshd_x11_use_localhost; nist_800_53: CM-6, AC-8, AC-17; pci_dss: 2.2.4

- [ ] **NET-SSH-004** Check SSH session limits, logging and privilege separation  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds SSH services that allow unlimited guessing, keep idle sessions or log too little.  
  *Steps:*
  1. Print the effective SSH daemon configuration with sshd -T.
  2. Look at MaxAuthTries, LoginGraceTime, MaxSessions and MaxStartups.
  3. Look at ClientAliveInterval and ClientAliveCountMax.
  4. Look at LogLevel and PrintLastLog.
  5. Make sure privilege separation is on and the AllowGroups or AllowUsers rule limits access.
  *Example:* `sshd -T | grep -iE "maxauthtries|logingracetime|maxsessions|maxstartups|clientalive|loglevel|printlastlog|useprivilegeseparation|allowgroups|allowusers"`  
  *Expected:* Authentication tries, grace time and open sessions have limits that meet the standard. Idle sessions end. LogLevel is INFO or VERBOSE. Only approved groups can log in.  
  *Refs:* tool_check: cac:firewalld_sshd_port_enabled, cac:sshd_print_last_log, cac:sshd_set_idle_timeout, cac:sshd_set_keepalive, cac:sshd_set_keepalive_0, cac:sshd_set_login_grace_time, cac:sshd_set_loglevel_info, cac:sshd_set_loglevel_verbose, cac:sshd_set_max_auth_tries, cac:sshd_set_max_sessions, cac:sshd_set_maxstartups, cac:sshd_use_directory_configuration, cac:sshd_use_priv_separation; nist_800_53: AC-17, CM-6, AC-2, AC-12; pci_dss: 2.2.4

- [ ] **NET-SSH-005** Check the owner and mode of SSH daemon files and host keys  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds SSH configuration files and host private keys that other users can read or change.  
  *Steps:*
  1. List /etc/ssh/sshd_config, /etc/ssh/sshd_config.d and the vendor drop-in files.
  2. List the host private keys /etc/ssh/ssh_host_*_key.
  3. List the host public keys /etc/ssh/ssh_host_*_key.pub.
  4. Make sure root owns each file and the modes are not wider than the standard allows.
  *Example:* `stat -c "%U:%G %a %n" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub`  
  *Expected:* Root owns all SSH daemon files. Configuration files have a mode of 0600 or 0644, private keys 0600 or 0640, and public keys 0644 or stricter.  
  *Refs:* tool_check: cac:directory_groupowner_sshd_config_d, cac:directory_owner_sshd_config_d, cac:directory_permissions_sshd_config_d, cac:file_groupowner_sshd_config, cac:file_groupowner_sshd_drop_in_config, cac:file_groupownership_sshd_private_key, cac:file_groupownership_sshd_pub_key, cac:file_owner_sshd_config, cac:file_owner_sshd_drop_in_config, cac:file_ownership_sshd_private_key, cac:file_ownership_sshd_pub_key, cac:file_permissions_sshd_config, cac:file_permissions_sshd_config_not_modified, cac:file_permissions_sshd_drop_in_config, cac:file_permissions_sshd_private_key, cac:file_permissions_sshd_pub_key, cac:file_sshd_50_redhat_exists; nist_800_53: AC-17, CM-6, AC-6; pci_dss: 2.2.4

- [ ] **NET-SSH-006** Check the SSH package, service and firewall state against the host role  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds hosts where the SSH server is on without a need, or is needed but blocked.  
  *Steps:*
  1. Look for the OpenSSH server and client packages.
  2. Look at the sshd service state.
  3. Look at the firewall rule for the SSH service.
  4. Compare the result with the role of the host.
  *Example:* `rpm -q openssh-server openssh-clients || dpkg -l openssh-server ; systemctl is-enabled sshd ; firewall-cmd --list-services ; ss -tlnp | grep :22`  
  *Expected:* The SSH server is on only where the host role needs it. The firewall allows the port only from approved sources.  
  *Refs:* tool_check: cac:firewalld_sshd_disabled, cac:iptables_sshd_disabled, cac:package_openssh-clients_installed, cac:package_openssh-server_installed, cac:package_openssh-server_removed, cac:package_openssh_installed, cac:package_openssh_removed, cac:service_sshd_disabled, cac:service_sshd_enabled; nist_800_53: SC-8, CM-6, CM-3, IA-2

- [ ] **NET-SSH-007** Check SSH client settings for ciphers, MACs and entropy  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds SSH clients that connect with weak algorithms or weak random number sources.  
  *Steps:*
  1. Print the effective client configuration with ssh -G.
  2. Look at the Ciphers, MACs and RekeyLimit values.
  3. Compare the lists with the approved algorithms.
  4. Look at the SSH_USE_STRONG_RNG variable in the shell profile files.
  *Example:* `ssh -G <host> | grep -iE "^(ciphers|macs|rekeylimit)" ; grep -rn SSH_USE_STRONG_RNG /etc/profile.d/ /etc/profile /etc/csh.cshrc`  
  *Expected:* The client offers only approved ciphers and MACs. The client uses a strong random source for the seed.  
  *Refs:* tool_check: cac:ssh_client_rekey_limit, cac:ssh_client_use_approved_ciphers_ordered_stig, cac:ssh_client_use_strong_rng_csh, cac:ssh_client_use_strong_rng_sh, cac:ssh_use_approved_macs_ordered_stig


## SVC

- [ ] **NET-SVC-008** Check time synchronization client settings: chrony, ntpd and timesyncd  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts with no time source, one weak time source or a time service that runs as root.  
  *Steps:*
  1. Look at which time service is active. Make sure only one is active.
  2. Read /etc/chrony.conf, /etc/ntp.conf or /etc/systemd/timesyncd.conf.
  3. Look for at least two remote servers or a pool, and for NTS if the server supports it.
  4. Look at the maxpoll value and the user that runs the daemon.
  5. Run chronyc tracking or timedatectl and look at the offset and the synchronized flag.
  *Example:* `systemctl is-active chronyd ntpd systemd-timesyncd ; grep -vE "^#|^$" /etc/chrony.conf ; chronyc tracking ; chronyc sources -v ; timedatectl status ; stat -c "%U:%G %a" /etc/chrony.keys`  
  *Expected:* One time service runs with at least two remote sources. The clock is synchronized with a small offset. The daemon runs as an unprivileged user and key files are root-only.  
  *Refs:* tool_check: cac:chrony_set_nts, cac:chronyd_configure_local_socket, cac:chronyd_configure_pool_and_server, cac:chronyd_or_ntpd_set_maxpoll, cac:chronyd_or_ntpd_specify_multiple_servers, cac:chronyd_or_ntpd_specify_remote_server, cac:chronyd_run_as_chrony_user, cac:chronyd_server_directive, cac:chronyd_specify_remote_server, cac:chronyd_sync_clock, cac:file_groupowner_etc_chrony_keys, cac:file_owner_etc_chrony_keys, cac:file_permissions_etc_chrony_keys, cac:ntp_single_service_active, cac:ntpd_run_as_ntp_user, cac:ntpd_specify_multiple_servers, cac:ntpd_specify_remote_server, cac:package_chrony_installed, cac:package_ntp_installed, cac:package_ntp_removed, cac:package_timesyncd_installed, cac:package_timesyncd_removed, cac:service_chronyd_disabled, cac:service_chronyd_enabled, cac:service_chronyd_or_ntpd_enabled, cac:service_ntp_enabled, cac:service_ntpd_enabled, cac:service_timesyncd_configured, cac:service_timesyncd_disabled, cac:service_timesyncd_enabled, cac:service_timesyncd_root_distance_configured; nist_800_53: AU-8, CM-6, AU-12, CM-7; pci_dss: 10.4.3, 10.4

- [ ] **NET-SVC-009** Check cron and at: service state, user lists and file permissions  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts where any user can schedule jobs or where job files can be changed by others.  
  *Steps:*
  1. Look at the cron and atd service state.
  2. List /etc/crontab, /etc/cron.d, /etc/cron.hourly, /etc/cron.daily, /etc/cron.weekly, /etc/cron.monthly and /etc/cron.yearly with owner and mode.
  3. Look for /etc/cron.allow and /etc/at.allow. Make sure cron.deny and at.deny do not exist.
  4. List the owner and mode of the allow files.
  5. Look at anacron if the host is not always on.
  *Example:* `systemctl is-enabled crond cron atd ; stat -c "%U:%G %a %n" /etc/crontab /etc/cron.* /etc/at.allow ; ls -l /etc/cron.deny /etc/at.deny`  
  *Expected:* Root owns all cron files and none is writable by group or others. Only listed users can use cron and at. The at service is off if no one needs it.  
  *Refs:* tool_check: cac:disable_anacron, cac:file_at_allow_exists, cac:file_at_deny_not_exist, cac:file_cron_allow_exists, cac:file_cron_deny_not_exist, cac:file_groupowner_at_allow, cac:file_groupowner_at_deny, cac:file_groupowner_cron_allow, cac:file_groupowner_cron_d, cac:file_groupowner_cron_daily, cac:file_groupowner_cron_deny, cac:file_groupowner_cron_hourly, cac:file_groupowner_cron_monthly, cac:file_groupowner_cron_weekly, cac:file_groupowner_cron_yearly, cac:file_groupowner_crontab, cac:file_owner_at_allow, cac:file_owner_at_deny, cac:file_owner_cron_allow, cac:file_owner_cron_d, cac:file_owner_cron_daily, cac:file_owner_cron_deny, cac:file_owner_cron_hourly, cac:file_owner_cron_monthly, cac:file_owner_cron_weekly, cac:file_owner_cron_yearly, cac:file_owner_crontab, cac:file_permissions_at_allow, cac:file_permissions_at_deny, cac:file_permissions_cron_allow, cac:file_permissions_cron_d, cac:file_permissions_cron_daily, cac:file_permissions_cron_hourly, cac:file_permissions_cron_monthly, cac:file_permissions_cron_not_modified, cac:file_permissions_cron_weekly, cac:file_permissions_cron_yearly, cac:file_permissions_crontab, cac:package_cron_installed, cac:service_atd_disabled, cac:service_cron_enabled, cac:service_crond_enabled; nist_800_53: CM-6, AC-6, CM-7

- [ ] **NET-SVC-010** Check for obsolete clear-text services: telnet, rsh, tftp, NIS, talk, rsync, xinetd  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds old remote access and file transfer services that send passwords in clear text or trust host names.  
  *Steps:*
  1. Look for the packages telnet, rsh, rlogin, rexec, talk, tftp, ypbind, ypserv, rsync and xinetd.
  2. Look at the state of the matching services and sockets.
  3. Look for .rhosts, hosts.equiv and other host trust files.
  4. Look at nsswitch.conf for NIS entries.
  5. Read /etc/hosts.allow and /etc/hosts.deny where TCP wrappers are in use.
  *Example:* `rpm -qa | grep -E "telnet|rsh|talk|tftp|ypbind|ypserv|xinetd|rsync" ; systemctl list-unit-files | grep -E "telnet|rsh|rlogin|rexec|tftp|rsyncd|xinetd|ypbind" ; find / -name ".rhosts" -o -name hosts.equiv 2>/dev/null ; grep nis /etc/nsswitch.conf`  
  *Expected:* None of the obsolete packages or services is present. No host trust file exists. If TFTP must stay, it runs in secure mode.  
  *Refs:* tool_check: cac:configure_etc_hosts_deny, cac:file_groupowner_etc_hosts_allow, cac:file_groupowner_etc_hosts_deny, cac:file_owner_etc_hosts_allow, cac:file_owner_etc_hosts_deny, cac:file_permissions_etc_hosts_allow, cac:file_permissions_etc_hosts_deny, cac:no_host_based_files, cac:no_nis_in_nsswitch, cac:no_rsh_trust_files, cac:no_user_host_based_files, cac:package_inetutils-telnet_removed, cac:package_inetutils-telnetd_removed, cac:package_nis_removed, cac:package_ntpdate_removed, cac:package_rsh-server_removed, cac:package_rsh_removed, cac:package_rsync_removed, cac:package_talk-server_removed, cac:package_talk_removed, cac:package_tcp_wrappers_installed, cac:package_tcp_wrappers_removed, cac:package_telnet-server_removed, cac:package_telnet_removed, cac:package_telnetd-ssl_removed, cac:package_telnetd_removed, cac:package_tftp-server_removed, cac:package_tftp_removed, cac:package_xinetd_removed, cac:package_ypbind_removed, cac:package_ypserv_removed, cac:service_rexec_disabled, cac:service_rlogin_disabled, cac:service_rsh_disabled, cac:service_rsyncd_disabled, cac:service_telnet_disabled, cac:service_tftp_disabled, cac:service_xinetd_disabled, cac:service_ypbind_disabled, cac:service_ypserv_disabled, cac:tftp_uses_secure_mode_systemd, cac:tftpd_uses_secure_mode; nist_800_53: CM-7, CM-6, IA-5, AC-6; pci_dss: 2.2.2

- [ ] **NET-SVC-011** Check NFS and RPC services, exports and client mounts  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds NFS servers that export to all hosts or trust remote root, and hosts that run RPC with no need.  
  *Steps:*
  1. Look at the NFS, rpcbind and rpc services and the packages.
  2. Read /etc/exports.
  3. Look for no_root_squash, all_squash, insecure_locks, wildcard clients and missing Kerberos security flavors.
  4. Look at the fixed ports of lockd, mountd and statd.
  5. Look at the client mount options for sec=krb5, nosuid, nodev and noexec.
  *Example:* `systemctl is-enabled nfs-server rpcbind ; cat /etc/exports ; exportfs -v ; rpcinfo -p ; findmnt -t nfs,nfs4`  
  *Expected:* The NFS and RPC services run only on hosts that serve or use NFS. Exports name hosts, use root squash and Kerberos, and clients mount with nosuid, nodev and noexec.  
  *Refs:* tool_check: cac:nfs_fixed_lockd_tcp_port, cac:nfs_fixed_lockd_udp_port, cac:nfs_fixed_mountd_port, cac:nfs_fixed_statd_port, cac:nfs_no_anonymous, cac:no_all_squash_exports, cac:no_insecure_locks_exports, cac:package_nfs-common_removed, cac:package_nfs-kernel-server_removed, cac:package_nfs-utils_removed, cac:package_rpcbind_removed, cac:restrict_nfs_clients_to_privileged_ports, cac:service_netfs_disabled, cac:service_nfs_disabled, cac:service_nfslock_disabled, cac:service_rpcbind_disabled, cac:service_rpcgssd_disabled, cac:service_rpcidmapd_disabled, cac:service_rpcsvcgssd_disabled, cac:use_kerberos_security_all_exports, cac:use_root_squashing_all_exports; nist_800_53: CM-7, CM-6, IA-2, AC-17

- [ ] **NET-SVC-012** Check Samba and FTP services for signing, uploads and anonymous access  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds file transfer services that allow anonymous login, uploads or unsigned SMB sessions.  
  *Steps:*
  1. Look at the samba and vsftpd packages and services.
  2. Read /etc/samba/smb.conf and look at client signing, server signing and root login.
  3. Read /etc/vsftpd/vsftpd.conf and look at anonymous_enable, write_enable, xferlog_enable and banner settings.
  4. Look at the firewall rule for FTP and at the file system of the FTP home.
  *Example:* `rpm -q samba vsftpd ; testparm -s | grep -iE "signing|root|guest" ; grep -vE "^#|^$" /etc/vsftpd/vsftpd.conf ; systemctl is-enabled smb vsftpd`  
  *Expected:* Samba and FTP are off unless the host role needs them. Where in use, SMB signing is required, anonymous login is off, uploads are off and transfers are logged.  
  *Refs:* tool_check: cac:ftp_configure_firewall, cac:ftp_disable_uploads, cac:ftp_home_partition, cac:ftp_limit_users, cac:ftp_log_transactions, cac:ftp_present_banner, cac:ftp_restrict_to_anon, cac:package_ftp_removed, cac:package_samba-common_installed, cac:package_samba_removed, cac:package_tnftp_removed, cac:package_vsftpd_installed, cac:package_vsftpd_removed, cac:require_smb_client_signing, cac:service_smb_disabled, cac:service_vsftpd_disabled, cac:smb_server_disable_root; nist_800_53: CM-7, CM-6, IA-5, AC-3

- [ ] **NET-SVC-013** Check DHCP, DNS, proxy, RADIUS and routing daemons on the host  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds servers with network infrastructure daemons that the host role does not need or that are not hardened.  
  *Steps:*
  1. Look for the packages and services dhcpd, kea, named, dnsmasq, unbound, squid, freeradius and quagga.
  2. For each one found, compare it with the role of the host.
  3. For a DHCP server, read dhcpd.conf for logging, bootp and DDNS settings.
  4. For a DNS server, look at dynamic updates in named.conf.
  *Example:* `rpm -qa | grep -E "dhcp|kea|bind|dnsmasq|unbound|squid|freeradius|quagga" ; systemctl is-enabled dhcpd named dnsmasq squid zebra ; grep -E "ddns-update-style|deny bootp|log-facility" /etc/dhcp/dhcpd.conf ; grep allow-update /etc/named.conf`  
  *Expected:* No unneeded daemon is installed or enabled. A server that must run has logging on, bootp and dynamic updates off, and serves only the data that it needs.  
  *Refs:* tool_check: cac:dhcp_server_configure_logging, cac:dhcp_server_deny_bootp, cac:dhcp_server_deny_decline, cac:dhcp_server_disable_ddns, cac:dhcp_server_minimize_served_info, cac:dns_server_disable_dynamic_updates, cac:package_bind_removed, cac:package_dhcp_removed, cac:package_dnsmasq_removed, cac:package_freeradius_removed, cac:package_kea_removed, cac:package_quagga_removed, cac:package_squid_removed, cac:package_unbound_removed, cac:service_dhcpd6_disabled, cac:service_dhcpd_disabled, cac:service_dnsmasq_disabled, cac:service_kea_dhcp4_server_disabled, cac:service_kea_dhcp6_server_disabled, cac:service_kea_dhcp_ddns_server_disabled, cac:service_named_disabled, cac:service_squid_disabled, cac:service_zebra_disabled; nist_800_53: CM-7, CM-6, AU-12

- [ ] **NET-SVC-014** Check Postfix and Dovecot: network listening, relay and TLS  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds mail services that relay for anyone, listen on all interfaces or accept clear-text passwords.  
  *Steps:*
  1. Look at which MTA is installed. Make sure sendmail is not.
  2. Read /etc/postfix/main.cf and look at inet_interfaces, smtpd_banner and the relay restrictions.
  3. Look at the relayhost and the root and postmaster aliases.
  4. Read the Dovecot settings for ssl, ssl_cert, ssl_key and disable_plaintext_auth.
  5. Try an open relay test from another host.
  *Example:* `postconf -n | grep -E "inet_interfaces|smtpd_banner|smtpd_relay_restrictions|mynetworks|relayhost" ; doveconf -n | grep -E "^ssl|disable_plaintext_auth" ; ss -tlnp | grep -E ":25|:143|:993"`  
  *Expected:* A local-only MTA listens on the loopback address. A mail server relays only for approved networks. IMAP and POP need TLS and refuse clear-text passwords.  
  *Refs:* tool_check: cac:dovecot_configure_ssl_cert, cac:dovecot_configure_ssl_key, cac:dovecot_disable_plaintext_auth, cac:dovecot_enable_ssl, cac:has_nonlocal_mta, cac:package_cyrus-imapd_removed, cac:package_dovecot_removed, cac:package_mailx_installed, cac:package_postfix_installed, cac:package_s-nail_installed, cac:package_sendmail_removed, cac:postfix_client_configure_mail_alias, cac:postfix_client_configure_mail_alias_postmaster, cac:postfix_client_configure_relayhost, cac:postfix_network_listening_disabled, cac:postfix_prevent_unrestricted_relay, cac:postfix_server_banner, cac:service_dovecot_disabled, cac:service_postfix_enabled; nist_800_53: CM-7, CM-6, CM-3, AC-8  
  *See:* NET-MAIL-001

- [ ] **NET-SVC-015** Check the SNMP agent: installation, service state and protocol version  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts with an SNMP agent that is not needed or that uses SNMP version 1 or 2c.  
  *Steps:*
  1. Look for the net-snmp package and the snmpd service.
  2. Read /etc/snmp/snmpd.conf and look at the version, the users and the access control entries.
  3. Make sure SNMP version 3 with authentication and privacy is in use.
  *Example:* `rpm -q net-snmp ; systemctl is-enabled snmpd ; grep -vE "^#|^$" /etc/snmp/snmpd.conf ; ss -ulnp | grep :161`  
  *Expected:* The SNMP agent is removed if not needed. Where in use, only SNMP version 3 with authentication and encryption is on.  
  *Refs:* tool_check: cac:package_net-snmp_removed, cac:service_snmpd_disabled, cac:snmpd_use_newer_protocol

- [ ] **NET-SVC-016** Check that unneeded services and daemons are off  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds services that add attack surface or leak information and that the host role does not need.  
  *Steps:*
  1. List the enabled unit files and the listening sockets.
  2. Look for avahi, cups, abrt, apport, cockpit, kdump, netconsole, rdisc, saslauthd, sysstat and rhnsd.
  3. Look for the services acpid, certmonger, oddjobd, portreserve, qpidd and quota_nld.
  4. Look at the list of masked units. Compare the rest with the role of the host.
  5. Look at the avahi and cups settings if they must stay.
  *Example:* `systemctl list-unit-files --state=enabled ; ss -tulnp ; systemctl is-enabled avahi-daemon cups abrtd apport cockpit.socket kdump rdisc ; grep -vE "^#|^$" /etc/avahi/avahi-daemon.conf`  
  *Expected:* Only the services that the host role needs are enabled. Print, discovery, crash report and remote management services are off.  
  *Refs:* tool_check: cac:avahi_check_ttl, cac:avahi_disable_publishing, cac:avahi_ip_only, cac:avahi_prevent_port_sharing, cac:avahi_restrict_published_information, cac:cups_disable_browsing, cac:cups_disable_printserver, cac:mask_nonessential_services, cac:package_abrt_removed, cac:package_avahi-autoipd_removed, cac:package_avahi_removed, cac:package_cups_removed, cac:package_psacct_installed, cac:service_abrtd_disabled, cac:service_acpid_disabled, cac:service_apport_disabled, cac:service_avahi-daemon_disabled, cac:service_certmonger_disabled, cac:service_cockpit_disabled, cac:service_cpupower_disabled, cac:service_cups_disabled, cac:service_kdump_disabled, cac:service_mdmonitor_disabled, cac:service_netconsole_disabled, cac:service_ntpdate_disabled, cac:service_oddjobd_disabled, cac:service_portreserve_disabled, cac:service_psacct_enabled, cac:service_qpidd_disabled, cac:service_quota_nld_disabled, cac:service_rdisc_disabled, cac:service_rhnsd_disabled, cac:service_rhsmcertd_disabled, cac:service_rngd_enabled, cac:service_saslauthd_disabled, cac:service_sysstat_disabled; nist_800_53: CM-7, CM-6, AU-12, AC-4

- [ ] **NET-SVC-017** Check USBGuard and fapolicyd allow-list controls  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds hosts that accept any USB device or run any program without a policy.  
  *Steps:*
  1. Look at the usbguard and fapolicyd packages and services.
  2. Run usbguard list-rules and look at the HID, hub and default policy.
  3. Read the usbguard audit backend setting.
  4. Read the fapolicyd rules and look for a final deny rule and the home folder rule.
  5. Try to run a program from a home folder or plug a test device.
  *Example:* `systemctl is-active usbguard fapolicyd ; usbguard list-rules ; grep -E "AuditBackend|ImplicitPolicyTarget" /etc/usbguard/usbguard-daemon.conf ; fapolicyd-cli --list | tail -5`  
  *Expected:* USBGuard blocks devices that no rule allows and logs its decisions. fapolicyd uses a deny-all policy with exceptions for approved software.  
  *Refs:* tool_check: cac:configure_usbguard_auditbackend, cac:fapolicy_default_deny, cac:fapolicyd_prevent_home_folder_access, cac:package_fapolicyd_installed, cac:package_usbguard_installed, cac:service_fapolicyd_enabled, cac:service_usbguard_enabled, cac:usbguard_allow_hid, cac:usbguard_allow_hid_and_hub, cac:usbguard_allow_hub, cac:usbguard_generate_policy; nist_800_53: CM-8, IA-3, CM-6, SI-4

- [ ] **NET-SVC-018** Check Apache httpd TLS, authentication and banner settings  
  *Severity if fail:* High | *Type:* Config Review, Automated  
  *Objective:* Finds web servers that offer old TLS versions, accept clear-text logins or show internal notices.  
  *Steps:*
  1. Read /etc/httpd/conf.modules.d/ssl.conf and the ssl.conf in /etc/httpd/conf.d.
  2. Look at the SSLProtocol, SSLCipherSuite and certificate settings.
  3. Look at the authentication method for protected paths: digest, LDAP or client certificate.
  4. Look for the use of TLS for logins, sessions and uploads.
  5. Scan the TLS port to list the protocols.
  *Example:* `grep -rnE "SSLProtocol|SSLCipherSuite|SSLCertificateFile|SSLVerifyClient|AuthType" /etc/httpd/ ; httpd -M | grep -E "ssl|auth" ; nmap -p443 --script ssl-enum-ciphers <host>`  
  *Expected:* Only TLS 1.2 and newer are on, with a valid server certificate. Logins, sessions and uploads use TLS. Protected paths need strong authentication.  
  *Refs:* tool_check: cac:httpd_configure_banner_page, cac:httpd_configure_remote_session_encryption, cac:httpd_configure_tls, cac:httpd_configure_valid_server_cert, cac:httpd_digest_authentication, cac:httpd_encrypt_file_uploads, cac:httpd_entrust_passwords, cac:httpd_install_mod_ssl, cac:httpd_ldap_support, cac:httpd_nipr_accredited_dmz, cac:httpd_require_client_certs

- [ ] **NET-SVC-019** Check Apache httpd directory access, methods and file permissions  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds web servers that allow overrides, symlinks, dangerous methods or loose rights on content and logs.  
  *Steps:*
  1. Read the Directory blocks for the root, the document root and the critical directories.
  2. Look at AllowOverride, Options (FollowSymLinks, Indexes) and the LimitExcept rules.
  3. List the owner and mode of the configuration, module and log directories.
  4. Look for backup files, sample CGI scripts and anonymous content in the document root.
  5. Look at the partition of the web content.
  *Example:* `grep -rnE "AllowOverride|Options|LimitExcept|TraceEnable" /etc/httpd/ ; stat -c "%U:%G %a %n" /etc/httpd/conf /etc/httpd/conf.d /etc/httpd/conf.modules.d /var/log/httpd ; find /var/www -name "*.bak" -o -name "*~" ; findmnt /var/www`  
  *Expected:* The root directory denies access by default. Overrides and symlinks are off. Only needed methods are allowed. Only root can change the configuration and logs.  
  *Refs:* tool_check: cac:dir_perms_etc_httpd_conf, cac:dir_perms_var_log_httpd, cac:file_permissions_httpd_server_conf_d_files, cac:file_permissions_httpd_server_conf_files, cac:file_permissions_httpd_server_modules_files, cac:http_configure_log_file_ownership, cac:httpd_anonymous_content_sharing, cac:httpd_cgi_support, cac:httpd_configure_documentroot, cac:httpd_configure_script_permissions, cac:httpd_disable_anonymous_ftp_access, cac:httpd_disable_content_symlinks, cac:httpd_ignore_htaccess_files, cac:httpd_limit_available_methods, cac:httpd_remove_backups, cac:httpd_restrict_critical_directories, cac:httpd_restrict_root_directory, cac:httpd_restrict_web_directory, cac:partition_for_web_content; nist_800_53: CM-7, CM-6, AC-6

- [ ] **NET-SVC-020** Check Apache httpd and nginx modules, logging, tokens and role  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds web servers with unneeded modules, little logging, version leaks or a wrong placement.  
  *Steps:*
  1. Look at the httpd and nginx packages and services. Compare them with the role of the host.
  2. List the loaded modules with httpd -M. Look for status, info, proxy, cache, webdav, rewrite, include and cgi.
  3. Look at ServerTokens, ServerSignature, LogLevel, LogFormat and KeepAliveRequests.
  4. Look for mod_security and for compilers and sample files on the host.
  5. Look at the firewall rule and the network zone of the server.
  *Example:* `httpd -M ; grep -rnE "ServerTokens|ServerSignature|LogLevel|LogFormat|MaxKeepAliveRequests|ErrorLog|CustomLog" /etc/httpd/ ; rpm -q mod_security gcc ; curl -sI http://<host> | grep -i server`  
  *Expected:* Only needed modules load. ServerTokens is Prod and ServerSignature is Off. Errors and access are logged. The web server is off when the host does not serve web content.  
  *Refs:* tool_check: cac:httpd_antivirus_scan_uploads, cac:httpd_cache_support, cac:httpd_configure_firewall, cac:httpd_configure_log_format, cac:httpd_configure_max_keepalive_requests, cac:httpd_configure_perl_taint, cac:httpd_disable_mime_types, cac:httpd_enable_error_logging, cac:httpd_enable_log_config, cac:httpd_enable_loglevel, cac:httpd_enable_system_logging, cac:httpd_install_mod_security, cac:httpd_limit_java_files, cac:httpd_mime_magic, cac:httpd_mod_rewrite, cac:httpd_no_compilers_in_prod, cac:httpd_private_server_on_separate_subnet, cac:httpd_proxy_support, cac:httpd_public_resources_not_shared, cac:httpd_remove_robots_file, cac:httpd_server_activity_status, cac:httpd_server_configuration_display, cac:httpd_server_side_includes, cac:httpd_serversignature_off, cac:httpd_servertokens_prod, cac:httpd_url_correction, cac:httpd_webdav, cac:package_httpd_removed, cac:package_nginx_removed, cac:service_httpd_disabled, cac:service_nginx_disabled; nist_800_53: CM-7, CM-6

- [ ] **NET-SVC-021** Check Docker host settings: storage driver, SELinux and daemon state  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds container hosts that use loopback storage or run containers without SELinux support.  
  *Steps:*
  1. Look at the docker package and service.
  2. Run docker info and look at the storage driver and the SELinux flag.
  3. Read /etc/docker/daemon.json for storage-opts and selinux-enabled.
  *Example:* `docker info | grep -iE "storage driver|security options|selinux" ; cat /etc/docker/daemon.json ; systemctl is-enabled docker`  
  *Expected:* Docker uses a supported production storage driver, not loopback devices. SELinux support is on in the daemon where the host uses SELinux.  
  *Refs:* tool_check: cac:docker_selinux_enabled, cac:docker_storage_configured, cac:package_docker_installed, cac:service_docker_enabled


## AD

- [ ] **NET-AD-001** Review membership of privileged and operator groups in Active Directory  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds accounts, service accounts and nested groups that hold domain-wide admin or operator rights without need.  
  *Steps:*
  1. List the members of Domain Admins, Enterprise Admins, Schema Admins and Administrators. Include nested groups.
  2. List the members of Server Operators, Backup Operators, Print Operators and Account Operators.
  3. Note each service account and each stale account (no logon for 90 days) in these groups.
  4. Ask the owner of each account for a written reason.
  5. Make sure each privileged person uses a separate admin account.
  *Example:* `Get-ADGroupMember "Domain Admins" -Recursive | Select SamAccountName,objectClass ; Get-ADGroupMember "Backup Operators" -Recursive ; Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties MemberOf,LastLogonDate`  
  *Expected:* Privileged groups hold only named admin accounts with a recorded reason. Operator groups are empty or hold documented members. No service account or stale account is a member.  
  *Refs:* attack: T1078.002; capec: CAPEC-122; nist_800_53: AC-6, AC-6(5), AC-2; other: https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts, MDI assessments: service accounts in privileged groups, operator groups

- [ ] **NET-AD-002** Check that admin accounts belong to Protected Users and tier limits  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds admin accounts that can leave NTLM, RC4 or unlimited-lifetime tickets on member hosts.  
  *Steps:*
  1. List the members of the Protected Users group.
  2. Compare the list with the members of the privileged groups.
  3. Make sure no service account or computer account is in Protected Users.
  4. Make sure the domain functional level is Windows Server 2012 R2 or higher.
  5. Look at authentication policies and silos in Active Directory Administrative Center. Note the TGT lifetime and the allowed devices for admin accounts.
  6. Note that the built-in Administrator (RID 500) is exempt from authentication policies.
  *Example:* `Get-ADGroupMember "Protected Users" ; (Get-ADDomain).DomainMode ; Get-ADAuthenticationPolicy -Filter * ; Get-ADAuthenticationPolicySilo -Filter *`  
  *Expected:* Interactive admin accounts are in Protected Users, or an authentication policy limits where they sign in. Service and computer accounts are not members.  
  *Refs:* attack: T1550.002, T1003.001; capec: CAPEC-644; nist_800_53: AC-6(5), IA-2; other: https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/protected-users-security-group, https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/how-to-configure-protected-accounts

- [ ] **NET-AD-003** Check that privileged accounts have the sensitive-and-cannot-be-delegated flag  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds privileged accounts that a service can impersonate through Kerberos delegation.  
  *Steps:*
  1. List all members of the privileged groups.
  2. Read the UserAccountControl value of each account.
  3. Look for the NOT_DELEGATED flag (0x100000).
  4. Do the same for privileged computer accounts.
  *Example:* `Get-ADUser -Filter * -Properties AccountNotDelegated,MemberOf | Where {$_.AccountNotDelegated -eq $false} ; Get-ADGroupMember "Domain Admins" -Recursive | Get-ADUser -Properties AccountNotDelegated`  
  *Expected:* Every Domain Admin, Enterprise Admin and privileged service account has "Account is sensitive and cannot be delegated" set, or is in Protected Users.  
  *Refs:* attack: T1558, T1134; nist_800_53: AC-6(5); other: https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#ensure-privileged-accounts-are-not-delegated, https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/how-to-configure-protected-accounts

- [ ] **NET-AD-004** Find unconstrained, constrained and resource-based delegation on non-DC objects  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds servers and accounts that can act for any user, including a domain admin, towards other services.  
  *Steps:*
  1. Search for computers and users with the TrustedForDelegation flag. Ignore domain controllers.
  2. Search for objects that have a value in msDS-AllowedToDelegateTo.
  3. Look for the protocol transition flag (TrustedToAuthForDelegation) on these objects.
  4. Search for objects that have a value in msDS-AllowedToActOnBehalfOfOtherIdentity.
  5. Note any entry that points to a sensitive service, such as a domain controller.
  6. Make sure each remaining entry has a business owner.
  *Example:* `Get-ADComputer -Filter {TrustedForDelegation -eq $true} ; Get-ADUser -Filter {TrustedForDelegation -eq $true} ; Get-ADObject -LDAPFilter "(msDS-AllowedToDelegateTo=*)" -Properties msDS-AllowedToDelegateTo ; Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount`  
  *Expected:* Only domain controllers use unconstrained delegation. Each constrained or resource-based entry has an owner and does not point to a sensitive service or user.  
  *Refs:* attack: T1558, T1134; capec: CAPEC-122; nist_800_53: AC-6, AC-3; other: https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#unsecure-kerberos-delegation, https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview

- [ ] **NET-AD-005** Check service accounts with SPNs for gMSA use and password age  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds user accounts with an SPN whose weak or old password an attacker can crack offline.  
  *Steps:*
  1. List all user accounts that have a ServicePrincipalName.
  2. Note the password last set date and the password policy of each account.
  3. Note the accounts that are not gMSA, sMSA or dMSA.
  4. Look for privileged accounts in this list.
  5. Look at the supported Kerberos encryption types of each account.
  6. Ask the owner whether the service can use a managed service account.
  *Example:* `Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName,PasswordLastSet,msDS-SupportedEncryptionTypes,MemberOf ; Get-ADServiceAccount -Filter * ; Get-ADDefaultDomainPasswordPolicy`  
  *Expected:* Services use managed service accounts. Each remaining SPN account has a long random password, no privileged group membership and AES encryption types.  
  *Refs:* attack: T1558.003; capec: CAPEC-509, CAPEC-652; cwe: CWE-521; nist_800_53: IA-5, AC-6; other: https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts, https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-service-accounts, CAPEC-509 mitigations  
  *See:* NET-CRED-004

- [ ] **NET-AD-006** Find account attributes that weaken Kerberos or password protection  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds accounts with no pre-authentication, DES, reversible encryption or no password requirement.  
  *Steps:*
  1. Search for accounts with the flag Do not require Kerberos preauthentication.
  2. Search for accounts with Use Kerberos DES encryption types.
  3. Search for accounts with Store password using reversible encryption.
  4. Search for accounts with Password not required.
  5. Search for user accounts that have no AES encryption type set.
  6. Note the accounts that fail and the privilege of each.
  *Example:* `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} ; Get-ADUser -Filter {UseDESKeyOnly -eq $true} ; Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} ; Get-ADUser -Filter {PasswordNotRequired -eq $true}`  
  *Expected:* No account has these attributes. Every account that uses Kerberos has AES enabled.  
  *Refs:* attack: T1558.004, T1558.003; capec: CAPEC-509; cwe: CWE-257, CWE-327; nist_800_53: IA-5, SC-13; other: https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#unsecure-account-attributes

- [ ] **NET-AD-007** Check the krbtgt and built-in Administrator password age  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds a krbtgt key that is old enough for an attacker to reuse stolen keys to forge tickets.  
  *Steps:*
  1. Read the PasswordLastSet value of the krbtgt account in each domain.
  2. Compare it to the limit of 180 days.
  3. Read the PasswordLastSet value of the built-in Administrator account.
  4. Ask the owner for the date of the last double reset of krbtgt.
  *Example:* `Get-ADUser krbtgt -Properties PasswordLastSet ; Get-ADUser -Filter {SamAccountName -eq "Administrator"} -Properties PasswordLastSet`  
  *Expected:* The krbtgt password changed in the last 180 days, with two resets at least 10 hours apart. The built-in Administrator password is current.  
  *Refs:* attack: T1558.001; nist_800_53: IA-5; other: https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#change-password-for-krbtgt-account

- [ ] **NET-AD-008** Check that Windows LAPS manages local administrator passwords on all hosts  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds hosts that share one local administrator password, which allows lateral movement.  
  *Steps:*
  1. List the computer objects in the domain. Read the Windows LAPS attributes for each.
  2. Note the hosts with no LAPS password or with a password older than the policy age.
  3. Read the LAPS policy: account name, password age, length and complexity.
  4. Make sure domain controllers back up the DSRM password.
  5. Look for the legacy LAPS client extension on hosts that use native Windows LAPS.
  *Example:* `Get-ADComputer -Filter * -Properties msLAPS-PasswordExpirationTime,ms-Mcs-AdmPwdExpirationTime | Where {-not $_."msLAPS-PasswordExpirationTime" -and -not $_."ms-Mcs-AdmPwdExpirationTime"} ; Get-LapsADPassword -Identity <host> (read only for the test host) ; gpresult /h gp.html`  
  *Expected:* Every managed host has a unique password with a future expiry. The policy sets a length and a rotation age. Domain controllers back up the DSRM password.  
  *Refs:* attack: T1078.003, T1550.002; capec: CAPEC-644; cwe: CWE-798; nist_800_53: IA-5, AC-6; other: https://learn.microsoft.com/windows-server/identity/laps/laps-overview, https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#microsoft-laps-usage  
  *See:* NET-CRED-001

- [ ] **NET-AD-009** Review who can read or reset Windows LAPS passwords  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds accounts that can read local administrator passwords and so become local admins everywhere.  
  *Steps:*
  1. Read the ACL on each OU that holds managed computers. Find the extended right to read the LAPS password attributes.
  2. List the principals that hold this right.
  3. Make sure password encryption is on in the LAPS policy and that only named groups can decrypt.
  4. Look for the event log entries that record password reads.
  *Example:* `Find-LapsADExtendedRights -Identity "OU=Servers,DC=corp,DC=example" ; Get-LapsAADPassword is for Entra ID ; Get-WinEvent -LogName "Microsoft-Windows-LAPS/Operational"`  
  *Expected:* Only named admin groups can read or reset LAPS passwords. Password encryption is on. Reads leave an audit event.  
  *Refs:* attack: T1078.003; cwe: CWE-732; nist_800_53: AC-6, AC-3, IA-5; other: https://learn.microsoft.com/windows-server/identity/laps/laps-overview

- [ ] **NET-AD-010** Find non-admin accounts that hold directory replication rights  
  *Severity if fail:* Critical | *Type:* Config Review, Manual  
  *Objective:* Finds accounts that can copy password hashes from a domain controller (DCSync).  
  *Steps:*
  1. Read the ACL on the domain root object.
  2. Find the rights Replicating Directory Changes and Replicating Directory Changes All.
  3. List each principal that holds both rights.
  4. Note each principal that is not a domain controller, Domain Admin or Enterprise Admin.
  5. Note service accounts, such as sync accounts, and the owner of each.
  *Example:* `(Get-Acl "AD:DC=corp,DC=example").Access | Where {$_.ObjectType -in "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2","1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"} | Select IdentityReference,ObjectType`  
  *Expected:* Only domain controllers and a short list of documented admin groups hold the two replication rights.  
  *Refs:* attack: T1003.006; cwe: CWE-732; nist_800_53: AC-6, AC-3; other: https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#remove-non-admin-accounts-with-dcsync-permissions

- [ ] **NET-AD-011** Find non-admin write rights on sensitive groups and AdminSDHolder  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds identities that can change membership or ACLs of privileged groups.  
  *Steps:*
  1. Read the ACL of Domain Admins, Enterprise Admins and Administrators.
  2. Look for WriteDACL, WriteOwner, GenericAll and member write rights held by non-admin identities.
  3. Read the ACL of the AdminSDHolder object in the System container.
  4. Note any non-sensitive account on this ACL.
  5. Look for the event that records a change to AdminSDHolder.
  *Example:* `(Get-Acl "AD:CN=AdminSDHolder,CN=System,DC=corp,DC=example").Access ; (Get-Acl "AD:CN=Domain Admins,CN=Users,DC=corp,DC=example").Access | Where {$_.ActiveDirectoryRights -match "WriteDacl|WriteOwner|GenericAll|WriteProperty"}`  
  *Expected:* Only privileged groups and system principals hold write rights on sensitive groups and on AdminSDHolder.  
  *Refs:* attack: T1222.001, T1098; cwe: CWE-732; nist_800_53: AC-6, AC-3; other: https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#remove-access-rights-on-suspicious-accounts-with-the-admin-sdholder-permission, https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#ensure-non-admin-identities-cannot-have-writedacl-permissions-on-sensitive-groups

- [ ] **NET-AD-012** Review admin sign-in restrictions: log on rights and authentication policy silos  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds admin accounts that can sign in to low-trust hosts and leave credentials there.  
  *Steps:*
  1. Read the user rights "Deny log on locally" and "Deny access to this computer from the network".
  2. Note whether the privileged groups are in these deny lists for hosts of a lower tier.
  3. Read the authentication policies and silos for admin accounts.
  4. Read the Log On To restriction of privileged service accounts.
  *Example:* `gpresult /h gp.html ; secedit /export /cfg sec.inf (read SeDenyInteractiveLogonRight and SeDenyNetworkLogonRight) ; Get-ADAuthenticationPolicy -Filter * | fl`  
  *Expected:* Domain admin accounts cannot sign in to workstations or member servers outside their tier. Authentication policies or deny rights enforce this.  
  *Refs:* attack: T1078.002, T1003.001; nist_800_53: AC-6, AC-6(1); other: https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/how-to-configure-protected-accounts, https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#identify-service-accounts-in-privileged-groups


## ADCS

- [ ] **NET-ADCS-001** Find certificate templates that let the requester supply the SAN  
  *Severity if fail:* Critical | *Type:* Config Review, Manual  
  *Objective:* Finds templates that allow any enrolled user to request a certificate for another account (ESC1).  
  *Steps:*
  1. List all certificate templates that a CA publishes.
  2. Look at the Subject Name tab. Note each template with Supply in the request turned on.
  3. Look at the EKUs. Note each template with Client Authentication, Smartcard Logon, PKINIT Client Authentication or Any Purpose.
  4. Look at the enrollment ACL. Note each template that Authenticated Users, Domain Users or Everyone can enroll.
  5. Look for Manager approval or required authorized signatures on each template you noted.
  *Example:* `certutil -v -template > templates.txt ; Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example" -Filter * -Properties msPKI-Certificate-Name-Flag,pKIExtendedKeyUsage,nTSecurityDescriptor ; msPKI-Certificate-Name-Flag bit ENROLLEE_SUPPLIES_SUBJECT (1)`  
  *Expected:* No authentication template has Supply in the request on while an unprivileged group can enroll without Manager approval or authorized signatures.  
  *Refs:* attack: T1649; other: https://learn.microsoft.com/defender-for-identity/security-posture-assessments/certificates, Microsoft ESC id: ESC1; cwe: CWE-269

- [ ] **NET-ADCS-002** Find templates with Any Purpose EKU, no EKU or arbitrary Application Policies  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds templates that let an unprivileged user get a broadly trusted certificate (ESC2, ESC15).  
  *Steps:*
  1. List the published templates and their EKUs.
  2. Note each template with the Any Purpose EKU or with no EKU.
  3. Note each template that an unprivileged group can enroll.
  4. Note each schema version 1 template with Supply in the request turned on.
  5. Look for the patch for CVE-2024-49019 on each CA server.
  6. Look for Manager approval and signing requirements on the templates you noted.
  *Example:* `certutil -v -template ; Get-ADObject -LDAPFilter "(objectClass=pKICertificateTemplate)" -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example" -Properties pKIExtendedKeyUsage,msPKI-Template-Schema-Version ; Get-HotFix on each CA`  
  *Expected:* No published template has Any Purpose or no EKU with open enrollment. Supply in the request is off on version 1 templates. Each CA has the CVE-2024-49019 patch.  
  *Refs:* attack: T1649; other: https://learn.microsoft.com/defender-for-identity/security-posture-assessments/certificates, Microsoft ESC id: ESC2, ESC15 (CVE-2024-49019); cwe: CWE-732

- [ ] **NET-ADCS-003** Review enrollment agent certificate templates and agent restrictions  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds enrollment agent templates that let a user request certificates for any other user (ESC3).  
  *Steps:*
  1. Find each template that has the Certificate Request Agent EKU.
  2. Look at the enrollment ACL. Note each template that an unprivileged group can enroll.
  3. Look for Manager approval on the template and on the CA.
  4. Open the CA properties. Look at the Enrollment Agents tab for restrictions on agents, templates and subjects.
  5. Make sure the enrollment agents are not also certificate managers.
  *Example:* `certutil -v -template | findstr /i "1.3.6.1.4.1.311.20.2.1" ; certsrv.msc > CA Properties > Enrollment Agents ; certutil -CAInfo role`  
  *Expected:* Only a named agent group can enroll the agent template. The CA limits each agent to listed templates and subjects. Agents cannot approve their own requests.  
  *Refs:* attack: T1649; other: https://learn.microsoft.com/defender-for-identity/security-posture-assessments/certificates, Microsoft ESC id: ESC3; cwe: CWE-269

- [ ] **NET-ADCS-004** Review the owner and ACL of certificate template objects  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds templates that unprivileged groups can change or own (ESC4).  
  *Steps:*
  1. List the ACL of each template object in the Certificate Templates container.
  2. Note any Full Control, Write DACL, Write Owner or Write property right for Authenticated Users, Domain Users or Everyone.
  3. Look at the owner of each template. Make sure a privileged and monitored account owns it.
  4. List the templates that no CA publishes. Make a note to remove them.
  *Example:* `(Get-Acl "AD:CN=<template>,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example").Access ; (Get-Acl ...).Owner`  
  *Expected:* Only PKI administrators can write to template objects and own them. No unprivileged built-in group holds a write right. Templates that nobody needs are not published.  
  *Refs:* attack: T1649; other: https://learn.microsoft.com/defender-for-identity/security-posture-assessments/certificates, Microsoft ESC id: ESC4; cwe: CWE-732

- [ ] **NET-ADCS-005** Make sure the CA does not let requesters set the SAN  
  *Severity if fail:* Critical | *Type:* Config Review, Manual  
  *Objective:* Finds a CA where EDITF_ATTRIBUTESUBJECTALTNAME2 lets every requester name the SAN on any template (ESC6).  
  *Steps:*
  1. Read the CA policy EditFlags value on each CA.
  2. Look for the EDITF_ATTRIBUTESUBJECTALTNAME2 flag in the value.
  3. Ask why the flag is on, if you find it.
  *Example:* `certutil -getreg policy\EditFlags ; reg query HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA name>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy /v EditFlags`  
  *Expected:* The EDITF_ATTRIBUTESUBJECTALTNAME2 flag is off on every CA.  
  *Refs:* attack: T1649; other: https://learn.microsoft.com/defender-for-identity/security-posture-assessments/certificates, Microsoft ESC id: ESC6; cwe: CWE-1188

- [ ] **NET-ADCS-006** Review CA permissions and the split between CA roles  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds unprivileged users that hold Manage CA or Manage Certificates rights on a CA (ESC7).  
  *Steps:*
  1. Open the CA properties. Look at the Security tab.
  2. Note each unprivileged group with Manage CA or Manage Certificates.
  3. Compare the members of CA administrator, certificate manager, enrollment agent and auditor groups. Look for overlap.
  4. Read the CA role information and look at whether role separation is on.
  5. Look for CA events 4882 and 4890 in the Security log for permission changes.
  *Example:* `certsrv.msc > CA Properties > Security ; certutil -CAInfo role ; Get-WinEvent -FilterHashtable @{LogName="Security";Id=4882,4890}`  
  *Expected:* Only named PKI groups hold Manage CA or Manage Certificates. The role groups do not overlap. Each change to CA permissions leaves an event.  
  *Refs:* attack: T1649; other: https://learn.microsoft.com/defender-for-identity/security-posture-assessments/certificates, Microsoft ESC id: ESC7; cwe: CWE-732

- [ ] **NET-ADCS-007** Check AD CS web enrollment endpoints for NTLM relay protection  
  *Severity if fail:* Critical | *Type:* Config Review, Manual  
  *Objective:* Finds HTTP enrollment endpoints that accept NTLM without HTTPS or Extended Protection for Authentication (ESC8).  
  *Steps:*
  1. List the servers that run the Certificate Authority Web Enrollment or Certificate Enrollment Web Service role.
  2. Look at the IIS bindings for the certsrv and CES sites. Make sure HTTPS is the only binding.
  3. Look at the Windows Authentication settings. Make sure Extended Protection is set to Required.
  4. Look at whether NTLM is off for these sites, if Kerberos works.
  *Example:* `Import-Module WebAdministration; Get-WebBinding -Name "Default Web Site" ; Get-WebConfigurationProperty -Filter system.webServer/security/authentication/windowsAuthentication/extendedProtection -Name tokenChecking -PSPath IIS:\ -Location "Default Web Site/CertSrv"`  
  *Expected:* The enrollment endpoints use HTTPS only. Extended Protection for Authentication is Required, or NTLM is off.  
  *Refs:* attack: T1649, T1557.001; other: https://learn.microsoft.com/defender-for-identity/security-posture-assessments/certificates, Microsoft ESC id: ESC8; cwe: CWE-300  
  *See:* NET-WIN-003

- [ ] **NET-ADCS-008** Check that the CA RPC enrollment interface needs encryption  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds a CA that accepts unencrypted RPC certificate requests that an attacker can relay (ESC11).  
  *Steps:*
  1. Read the CA InterfaceFlags value on each CA.
  2. Look for the IF_ENFORCEENCRYPTICERTREQUEST flag.
  3. Find clients that need the flag to be off. Plan an upgrade for them.
  *Example:* `certutil -getreg CA\InterfaceFlags`  
  *Expected:* The IF_ENFORCEENCRYPTICERTREQUEST flag is on, so the RPC interface needs packet privacy.  
  *Refs:* attack: T1649, T1557.001; other: https://learn.microsoft.com/defender-for-identity/security-posture-assessments/certificates, Microsoft ESC id: ESC11; cwe: CWE-319

- [ ] **NET-ADCS-009** Check CA audit filter and the Audit Certification Services policy  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds a CA that does not log requests, issuance and permission changes.  
  *Steps:*
  1. Read the CA AuditFilter value. Compare it to the full filter value 127.
  2. Read the effective audit policy for the Audit Certification Services subcategory. Look for Success and Failure.
  3. Find events 4886, 4887, 4888, 4882, 4885 and 4890 in the Security log.
  4. Make sure the CA forwards these events to a collector and that the log is large enough.
  *Example:* `certutil -getreg CA\AuditFilter ; auditpol /get /subcategory:"Certification Services" ; Get-WinEvent -FilterHashtable @{LogName="Security";Id=4886,4887,4888}`  
  *Expected:* The AuditFilter is 127 or an approved baseline. Success and Failure are on. The CA events arrive at a central collector.  
  *Refs:* attack: T1649; other: https://learn.microsoft.com/windows-server/identity/ad-cs/secure-delegate-audit-certification-authority, Microsoft ESC id: AD CS auditing


## EXPO

- [ ] **NET-EXPO-001** Find Java debug (JDWP) and JMX/RMI ports open to the network  
  *Severity if fail:* Critical | *Type:* Manual, Automated  
  *Objective:* Finds Java processes that give code execution to any host that can reach a debug or management port.  
  *Steps:*
  1. Scan the hosts in scope for TCP ports 5005, 8000, 1098, 1099 and 9010. Use service detection.
  2. Send the JDWP handshake string to each open port. Look for the same string in the reply.
  3. Ask the RMI registry for its bound names. Look for JMX connectors.
  4. Make sure no JDWP port answers from any host except the developer workstation.
  5. Make sure each JMX port needs authentication and TLS, or listens only on localhost.
  *Example:* `nmap -sV -p5005,8000,1098,1099,9010 host ; nmap -p1099 --script rmi-dumpregistry host ; printf "JDWP-Handshake" | nc host 5005`  
  *Expected:* No JDWP port answers from the network. JMX and RMI ports are not reachable, or need authentication and TLS.  
  *Refs:* nist_800_53: CM-7, SC-7; cwe: CWE-489, CWE-306; attack: T1210; other: J, D, W, P,  , h, a, s,  , n, o,  , a, u, t, h, e, n, t, i, c, a, t, i, o, n,  , i, n,  , t, h, e,  , p, r, o, t, o, c, o, l, ;,  , r, u, n,  , J, a, v, a,  , w, i, t, h,  , t, h, e,  , d, e, b, u, g,  , a, g, e, n, t,  , o, n, l, y,  , o, n,  , l, o, c, a, l, h, o, s, t  
  *See:* NET-DISC-008

- [ ] **NET-EXPO-002** Find distcc and X11 services that accept connections from the network  
  *Severity if fail:* Critical | *Type:* Manual, Automated  
  *Objective:* Finds build and display services that run commands or show screens without a login.  
  *Steps:*
  1. Scan the hosts in scope for TCP port 3632 and for the TCP ports 6000 to 6009.
  2. Run the nmap distcc script against each open port 3632. Do not run a command.
  3. Run xdpyinfo against each open X11 port. Look for a reply without credentials.
  4. Make sure X11 listens only on a Unix socket, and distcc has an allow list of build hosts.
  5. Make sure the host firewall blocks both ports from other networks.
  *Example:* `nmap -sV -p3632,6000-6009 host ; nmap -p3632 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd=id" host (only with a written approval) ; xdpyinfo -display host:0`  
  *Expected:* Ports 3632 and 6000 to 6009 are closed to the network. Distcc accepts only listed build hosts. X11 accepts no TCP connection.  
  *Refs:* nist_800_53: CM-7, SC-7; cwe: CWE-306, CWE-284; attack: T1210, T1021; other: d, i, s, t, c, c,  , d, a, e, m, o, n,  , a, n, d,  , X,  , s, e, r, v, e, r,  , T, C, P,  , l, i, s, t, e, n, i, n, g,  , o, p, t, i, o, n, s  
  *See:* NET-DISC-008

- [ ] **NET-EXPO-003** Find AJP and FastCGI ports open outside the web tier  
  *Severity if fail:* Critical | *Type:* Manual, Automated  
  *Objective:* Finds back-end web protocols that trust the front end and give file read or code execution to other hosts.  
  *Steps:*
  1. Scan the web servers for the TCP ports 8009 and 9000, and for other ports found by service detection.
  2. Run the AJP check with nmap against each open port 8009. Look for a reply to a forwarded request.
  3. Run a FastCGI check against each open port 9000. Look for a reply to a begin-request record.
  4. Make sure the AJP connector has a secret set, or is off, and listens only on localhost.
  5. Make sure PHP-FPM and other FastCGI services use a Unix socket or an allow list.
  *Example:* `nmap -sV -p8009,9000 host ; nmap -p8009 --script ajp-headers,ajp-methods host ; cgi-fcgi -bind -connect host:9000 (only with a written approval)`  
  *Expected:* AJP and FastCGI ports are closed to every host except the front-end web server. AJP needs a secret.  
  *Refs:* nist_800_53: CM-7, SC-7; cwe: CWE-306, CWE-923; attack: T1190, T1210; other: A, p, a, c, h, e,  , T, o, m, c, a, t,  , A, J, P,  , c, o, n, n, e, c, t, o, r,  , s, e, c, r, e, t, ;,  , P, H, P, -, F, P, M,  , l, i, s, t, e, n, ., a, l, l, o, w, e, d, _, c, l, i, e, n, t, s  
  *See:* NET-DISC-008


## L2

- [ ] **NET-L2-001** Test that access ports cannot form trunks or reach other VLANs  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds access ports that form a trunk with an attacker and allow VLAN hopping.  
  *Steps:*
  1. List the switch ports that connect to users and printers. Look at the configured mode of each port.
  2. Make sure each access port is fixed as access mode and has trunk negotiation off.
  3. From a test host on one access port, try to form a trunk with a negotiation frame.
  4. Send a frame with a second VLAN tag to a host in another VLAN. Look for a reply.
  5. Make sure no trunk comes up and no frame reaches the other VLAN.
  *Example:* `show interfaces trunk ; show run interface Gi1/0/1 (switchport mode access, switchport nonegotiate) ; scapy: Dot1Q(vlan=1)/Dot1Q(vlan=20)/IP(dst=target)/ICMP()`  
  *Expected:* Every access port is a fixed access port with negotiation off. The test host cannot form a trunk or reach another VLAN.  
  *Refs:* cheatsheet: Network_Segmentation_Cheat_Sheet; nist_800_53: SC-7, AC-4; pci_dss: 1.4.1; cwe: CWE-284; attack: T1599; other: V, L, A, N,  , h, o, p, p, i, n, g,  , b, y,  , s, w, i, t, c, h,  , s, p, o, o, f, i, n, g,  , a, n, d,  , d, o, u, b, l, e,  , t, a, g, g, i, n, g, ;,  , v, e, n, d, o, r,  , h, a, r, d, e, n, i, n, g,  , g, u, i, d, e,  , f, o, r,  , t, h, e,  , s, w, i, t, c, h,  , m, o, d, e, l

- [ ] **NET-L2-002** Check that unused switch ports are off and in a dead-end VLAN  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds open wall and rack ports where an attacker can plug in and join the network.  
  *Steps:*
  1. Get the list of all ports and their state from each access switch.
  2. Compare the list with the port inventory and the patch panel records.
  3. Make sure each unused port is in the shutdown state.
  4. Make sure each unused port is in a VLAN that has no route and no gateway.
  5. Plug a test laptop into one unused port. Make sure it gets no address.
  *Example:* `show interfaces status ; show vlan brief ; show run | section interface`  
  *Expected:* All unused ports are shut down and in a dead-end VLAN. A device on an unused port gets no network access.  
  *Refs:* cheatsheet: Network_Segmentation_Cheat_Sheet; nist_800_53: CM-7, SC-7; pci_dss: 1.4.1; attack: T1200; other: N, E, T, -, D, I, S, C, -, 0, 0, 3,  , f, o, r,  , r, o, g, u, e,  , d, e, v, i, c, e,  , d, e, t, e, c, t, i, o, n  
  *See:* NET-DISC-003

- [ ] **NET-L2-003** Check that the native VLAN is not used for users or management  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds trunks where untagged frames land in a user or management VLAN.  
  *Steps:*
  1. List all trunk ports and the native VLAN of each trunk.
  2. Make sure both ends of each trunk use the same native VLAN.
  3. Make sure the native VLAN is an unused VLAN. No user port and no management interface may be in it.
  4. Make sure each trunk allows only the VLANs it needs.
  5. Make sure VLAN 1 has no user port and no management address.
  *Example:* `show interfaces trunk ; show vlan id 1 ; show run interface Po1 (switchport trunk native vlan 999, switchport trunk allowed vlan ...)`  
  *Expected:* Each trunk uses an unused native VLAN. The allowed VLAN list is limited. No user or management interface is in the native VLAN or VLAN 1.  
  *Refs:* cheatsheet: Network_Segmentation_Cheat_Sheet; nist_800_53: SC-7, CM-7; pci_dss: 1.4.1; other: N, a, t, i, v, e,  , V, L, A, N,  , a, n, d,  , d, o, u, b, l, e, -, t, a, g,  , h, o, p, p, i, n, g, ;,  , v, e, n, d, o, r,  , h, a, r, d, e, n, i, n, g,  , g, u, i, d, e

- [ ] **NET-L2-004** Test that wired ports need 802.1X or MAB before they give access  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds wired ports where an unknown device gets full access without authentication.  
  *Steps:*
  1. Find out which ports are in scope for port-based access control. Get the policy from the NAC team.
  2. Connect an unknown test laptop to a user port. Look at the VLAN and address it gets.
  3. Make sure the laptop gets no access, or only a restricted guest VLAN, before it authenticates.
  4. Connect a laptop with a valid certificate or account. Make sure it gets the right VLAN.
  5. Look at the MAB list. Make sure it holds only approved MAC addresses and the devices are in a limited VLAN.
  *Example:* `show authentication sessions ; show dot1x all ; wpa_supplicant / ip addr on the test laptop`  
  *Expected:* An unknown device gets no access or only guest access. An authenticated device gets the correct VLAN. MAB is limited to listed devices.  
  *Refs:* cheatsheet: Network_Segmentation_Cheat_Sheet; nist_800_53: IA-3, SC-7; pci_dss: 1.4.1; cwe: CWE-306; attack: T1200; other: I, E, E, E,  , 8, 0, 2, ., 1, X, -, 2, 0, 2, 0,  , (, n, a, m, e,  , o, n, l, y, ;,  , t, h, e,  , s, t, a, n, d, a, r, d,  , i, s,  , n, o, t,  , i, n,  , s, o, u, r, c, e, s, )  
  *See:* NET-DISC-003


## RTE

- [ ] **NET-RTE-001** Check that BGP sessions are protected: ACL, TTL security and TCP-AO  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds BGP speakers that accept session packets from unknown or spoofed sources.  
  *Steps:*
  1. List the BGP neighbors from the router configuration.
  2. Make sure an ACL on the control plane allows TCP port 179 only from the listed neighbors.
  3. Make sure each directly connected peering uses TTL security (GTSM). Make sure the TTL check value is set on both ends.
  4. Make sure each peering has TCP-AO, or at least an MD5 key that is not a default value.
  5. Send a TCP SYN to port 179 from an unlisted address. Make sure the router does not answer.
  *Example:* `show ip bgp neighbors | include TTL|MD5|TCP-AO ; show ip access-lists (permit tcp host <peer> any eq 179) ; nmap -Pn -p179 router`  
  *Expected:* Only listed neighbors reach port 179. Direct peerings use GTSM. Each session has TCP-AO or a strong MD5 key.  
  *Refs:* nist_800_53: SC-7, SC-23; capec: CAPEC-584; cwe: CWE-290; attack: T1557; other: R, F, C,  , 7, 4, 5, 4,  , s, e, c, t, i, o, n, s,  , 4, ,,  , 5, ., 1,  , a, n, d,  , 5, ., 2, ;,  , R, F, C,  , 5, 0, 8, 2, ;,  , R, F, C,  , 5, 9, 2, 5, ;,  , h, t, t, p, s, :, /, /, w, w, w, ., r, f, c, -, e, d, i, t, o, r, ., o, r, g, /, r, f, c, /, r, f, c, 7, 4, 5, 4  
  *See:* NET-SEG-006

- [ ] **NET-RTE-002** Check BGP prefix filters and the maximum prefix limit on each peering  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds peerings that accept wrong, bogon or too many routes, which allows route leaks and hijacks.  
  *Steps:*
  1. List the inbound and outbound route policies of each peer.
  2. Make sure customer peers can announce only their own prefixes and AS paths.
  3. Make sure bogon, special-purpose and too-specific prefixes are rejected.
  4. Make sure each peer has a maximum prefix limit with a warning threshold.
  5. Make sure the router does not announce routes learned from one upstream to another upstream.
  *Example:* `show ip bgp neighbors <peer> policy ; show ip prefix-list ; show route-map ; show ip bgp neighbors | include maximum-prefix`  
  *Expected:* Inbound and outbound filters limit each peer to approved prefixes. A maximum prefix limit exists on every peering.  
  *Refs:* nist_800_53: SC-7, CM-7; capec: CAPEC-584; cwe: CWE-923; attack: T1599; other: R, F, C,  , 7, 4, 5, 4,  , s, e, c, t, i, o, n, s,  , 6, ,,  , 8,  , a, n, d,  , 9, ;,  , h, t, t, p, s, :, /, /, w, w, w, ., r, f, c, -, e, d, i, t, o, r, ., o, r, g, /, r, f, c, /, r, f, c, 7, 4, 5, 4

- [ ] **NET-RTE-003** Check that OSPF uses cryptographic authentication and passive interfaces  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds routing domains where an attacker on a user network can inject routes.  
  *Steps:*
  1. List the OSPF interfaces on each router.
  2. Make sure user-facing interfaces are passive, so that they send no hello packets.
  3. Make sure each other interface uses cryptographic authentication with HMAC-SHA. Plain text and null authentication are not allowed.
  4. Make sure keys are not the same on all routers and have a rollover plan.
  5. Connect a test router to a user port. Make sure it does not form an adjacency.
  *Example:* `show ip ospf interface | include Passive|auth ; show ip ospf neighbor ; show run | section router ospf`  
  *Expected:* User-facing interfaces are passive. All adjacencies use HMAC-SHA authentication. A test router forms no adjacency.  
  *Refs:* nist_800_53: SC-7, IA-3; cwe: CWE-306; attack: T1557; other: R, F, C,  , 5, 7, 0, 9, ;,  , R, F, C,  , 9, 0, 9, 9,  , s, e, c, t, i, o, n,  , 2, ., 5, ., 2,  , f, o, r,  , O, S, P, F, v, 3, ;,  , h, t, t, p, s, :, /, /, w, w, w, ., r, f, c, -, e, d, i, t, o, r, ., o, r, g, /, r, f, c, /, r, f, c, 5, 7, 0, 9


## SMTP

- [ ] **NET-SMTP-001** Check that MTA-STS is published and enforced for each mail domain  
  *Severity if fail:* Medium | *Type:* Automated, Config Review  
  *Objective:* Finds mail domains where a downgrade or MX spoof lets an attacker read mail in transit.  
  *Steps:*
  1. Get the TXT record at _mta-sts.<domain>. Make sure one record starts with v=STSv1 and has an id.
  2. Get the policy file from https://mta-sts.<domain>/.well-known/mta-sts.txt.
  3. Make sure the HTTPS certificate is valid for the mta-sts host name.
  4. Make sure the policy has mode enforce and a max_age of at least one week.
  5. Compare the mx lines of the policy with the real MX records of the domain.
  *Example:* `dig +short TXT _mta-sts.example.com ; curl -sv https://mta-sts.example.com/.well-known/mta-sts.txt ; dig +short MX example.com`  
  *Expected:* The TXT record and the policy file exist. The certificate is valid. The mode is enforce. The mx lines match the MX records. The max_age is long.  
  *Refs:* nist_800_53: SC-8; cwe: CWE-319; attack: T1557; other: R, F, C,  , 8, 4, 6, 1,  , s, e, c, t, i, o, n, s,  , 3, ., 1, ,,  , 3, ., 2,  , a, n, d,  , 5, ;,  , h, t, t, p, s, :, /, /, w, w, w, ., r, f, c, -, e, d, i, t, o, r, ., o, r, g, /, r, f, c, /, r, f, c, 8, 4, 6, 1

- [ ] **NET-SMTP-002** Check that a TLS-RPT record is published and the report address works  
  *Severity if fail:* Low | *Type:* Automated, Manual  
  *Objective:* Finds mail domains that cannot see STARTTLS or MTA-STS failures that other senders report.  
  *Steps:*
  1. Get the TXT record at _smtp._tls.<domain>.
  2. Make sure exactly one record starts with v=TLSRPTv1;.
  3. Make sure the rua value is a mailto: or https: address under the control of the domain owner.
  4. Ask the mail team for a TLS-RPT report that arrived in the last 30 days.
  5. Make sure someone reads the reports and acts on policy failures.
  *Example:* `dig +short TXT _smtp._tls.example.com`  
  *Expected:* One valid TLS-RPT record exists. The rua address belongs to the domain owner. Reports arrive and the team reviews them.  
  *Refs:* nist_800_53: SC-8, SI-4; other: R, F, C,  , 8, 4, 6, 0,  , s, e, c, t, i, o, n,  , 3, ;,  , h, t, t, p, s, :, /, /, w, w, w, ., r, f, c, -, e, d, i, t, o, r, ., o, r, g, /, r, f, c, /, r, f, c, 8, 4, 6, 0

- [ ] **NET-SMTP-003** Check DANE TLSA records for the MX hosts of DNSSEC-signed domains  
  *Severity if fail:* Low | *Type:* Automated, Config Review  
  *Objective:* Finds MX hosts where a TLSA record is missing, not signed or does not match the certificate.  
  *Steps:*
  1. Find out if the zone and the MX host zone have DNSSEC. Skip the test if they do not.
  2. Get the TLSA record at _25._tcp.<mx-host> with DNSSEC validation. Make sure the answer is secure.
  3. Make sure the record uses usage 3 or 2. Prefer 3 1 1.
  4. Connect with STARTTLS. Make sure the server certificate matches the TLSA data.
  5. Make sure the TLSA record is updated before each certificate key change.
  *Example:* `dig +dnssec TLSA _25._tcp.mx.example.com ; openssl s_client -starttls smtp -connect mx.example.com:25 -dane -verify 3 -verify_return_error`  
  *Expected:* Each MX host has a DNSSEC-validated TLSA record that matches its certificate. Usage 3 or 2 is in use.  
  *Refs:* nist_800_53: SC-8, SC-12; cwe: CWE-295; attack: T1557; other: R, F, C,  , 7, 6, 7, 2,  , s, e, c, t, i, o, n, s,  , 2, ., 2,  , a, n, d,  , 3, ., 1, ;,  , h, t, t, p, s, :, /, /, w, w, w, ., r, f, c, -, e, d, i, t, o, r, ., o, r, g, /, r, f, c, /, r, f, c, 7, 6, 7, 2

- [ ] **NET-SMTP-004** Test that the mail server does not relay outside-to-outside mail  
  *Severity if fail:* High | *Type:* Manual, Automated  
  *Objective:* Finds open relays that spammers use to hide the origin of mail.  
  *Steps:*
  1. Connect from an outside address to port 25 of the mail server.
  2. Send MAIL FROM and RCPT TO with two external domains that you control.
  3. Make sure the server rejects the RCPT command with a 5yz code.
  4. Try a source-routed forward-path and a RCPT TO with a percent sign in the local part.
  5. Try the same checks on port 587 without authentication.
  *Example:* `nmap -p25 --script smtp-open-relay mail.example.com ; swaks --to a@external-test.example --from b@external-test2.example --server mail.example.com`  
  *Expected:* The server rejects every outside-to-outside recipient. No message is queued. Port 587 needs authentication.  
  *Refs:* nist_800_53: SC-7, CM-7; cwe: CWE-284; attack: T1190; other: R, F, C,  , 5, 3, 2, 1,  , s, e, c, t, i, o, n, s,  , 4, ., 1, ., 1, ., 3,  , a, n, d,  , 7, ., 9, ;,  , h, t, t, p, s, :, /, /, w, w, w, ., r, f, c, -, e, d, i, t, o, r, ., o, r, g, /, r, f, c, /, r, f, c, 5, 3, 2, 1  
  *See:* NET-SVC-014

- [ ] **NET-SMTP-005** Check that VRFY and EXPN do not reveal valid addresses to outsiders  
  *Severity if fail:* Low | *Type:* Automated, Manual  
  *Objective:* Finds mail servers that let outsiders list valid users or members of a mailing list.  
  *Steps:*
  1. Connect to port 25 from an outside address and send EHLO.
  2. Look at the EHLO reply. Make sure EXPN is not listed as an extension.
  3. Send VRFY with a valid local user and with an unknown user.
  4. Send EXPN with a mailing list name.
  5. Compare the replies.
  *Example:* `nmap -p25 --script smtp-commands,smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN} mail.example.com ; printf "VRFY root\r\nEXPN staff\r\nQUIT\r\n" | nc mail.example.com 25`  
  *Expected:* VRFY gives the same 252 reply for valid and unknown users, or needs authentication. EXPN is off for outsiders.  
  *Refs:* nist_800_53: CM-7; cwe: CWE-204; attack: T1589.002; other: R, F, C,  , 5, 3, 2, 1,  , s, e, c, t, i, o, n, s,  , 3, ., 5, ., 2,  , a, n, d,  , 7, ., 3, ;,  , h, t, t, p, s, :, /, /, w, w, w, ., r, f, c, -, e, d, i, t, o, r, ., o, r, g, /, r, f, c, /, r, f, c, 5, 3, 2, 1

- [ ] **NET-SMTP-006** Test that the mail server accepts only CRLF.CRLF as end of data  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds mail servers that treat a bare line feed as end of data, which allows SMTP smuggling.  
  *Steps:*
  1. Send DATA to the mail server from a test client that you control.
  2. Send a message that has the line <LF>.<LF> inside the body, followed by a second MAIL FROM command.
  3. Make sure the server does not end the message at the bare <LF>.<LF>.
  4. Send the same test with <CR>.<CR>.
  5. Look at the delivered mail. Make sure it is one message and not two.
  *Example:* `Use a raw socket script (python3 socket) that sends "\n.\n" inside DATA, then "MAIL FROM:<x@test>" ; read the delivered messages in the test mailbox`  
  *Expected:* The server ends data only at <CRLF>.<CRLF>. A bare line feed or carriage return does not start a new mail transaction.  
  *Refs:* nist_800_53: SC-7; cwe: CWE-444; attack: T1566; other: R, F, C,  , 5, 3, 2, 1,  , s, e, c, t, i, o, n,  , 4, ., 1, ., 1, ., 4, ;,  , h, t, t, p, s, :, /, /, w, w, w, ., r, f, c, -, e, d, i, t, o, r, ., o, r, g, /, r, f, c, /, r, f, c, 5, 3, 2, 1


## V6

- [ ] **NET-V6-001** Test that RA Guard blocks rogue router advertisements, also with extension headers  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds access networks where a rogue router advertisement lets an attacker become the default gateway.  
  *Steps:*
  1. List the access ports. Make sure RA Guard is on for the host-facing ports.
  2. From a test host, send a router advertisement with a different prefix. Do not set a valid router role.
  3. On a second host, look at the routes and the addresses. Make sure the rogue prefix is not there.
  4. Repeat the test with a Destination Options extension header before the ICMPv6 header.
  5. Repeat the test with the packet split into fragments. Make sure the switch logs each drop.
  *Example:* `show ipv6 nd raguard policy ; scapy: Ether()/IPv6(src=fe80::bad)/IPv6ExtHdrDestOpt()/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefix="2001:db8:bad::",prefixlen=64) ; ip -6 route on the victim`  
  *Expected:* The switch drops the rogue router advertisements in all three forms. Hosts show no rogue prefix or router. The drops are logged.  
  *Refs:* nist_800_53: SC-7, SI-4; attack: T1557; cwe: CWE-290; other: R, F, C,  , 6, 1, 0, 5, ;,  , R, F, C,  , 7, 1, 1, 3,  , s, e, c, t, i, o, n,  , 3, ;,  , R, F, C,  , 9, 0, 9, 9,  , s, e, c, t, i, o, n,  , 2, ., 3, ., 2, ., 1, ;,  , h, t, t, p, s, :, /, /, w, w, w, ., r, f, c, -, e, d, i, t, o, r, ., o, r, g, /, r, f, c, /, r, f, c, 7, 1, 1, 3  
  *See:* NET-MITM-003

- [ ] **NET-V6-002** Test that DHCPv6 Shield blocks rogue DHCPv6 servers on access ports  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds access networks where a rogue DHCPv6 server can set DNS servers or addresses for hosts.  
  *Steps:*
  1. Look at the switch configuration. Make sure DHCPv6 server messages are allowed only on trusted ports.
  2. Start a test DHCPv6 server on an access port. Give it a different DNS server address.
  3. Ask for a DHCPv6 lease from a second test host.
  4. Make sure the host does not get an answer from the rogue server.
  5. Look at the switch log. Make sure it shows the dropped server messages.
  *Example:* `show ipv6 dhcp guard policy ; dnsmasq --dhcp-range=::100,::200,constructor:eth0,ra-stateless (lab only) ; dhclient -6 -v eth0`  
  *Expected:* DHCPv6 server messages from access ports are dropped. Hosts use only the approved server. The switch logs the drops.  
  *Refs:* nist_800_53: SC-7, SI-4; attack: T1557; cwe: CWE-290; other: R, F, C,  , 7, 6, 1, 0, ;,  , R, F, C,  , 9, 0, 9, 9,  , s, e, c, t, i, o, n,  , 2, ., 3, ., 3, ;,  , h, t, t, p, s, :, /, /, w, w, w, ., r, f, c, -, e, d, i, t, o, r, ., o, r, g, /, r, f, c, /, r, f, c, 7, 6, 1, 0  
  *See:* NET-MITM-003

- [ ] **NET-V6-003** Check that IPv6 firewall rules match the IPv4 policy  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds networks where IPv6 gives access that the IPv4 firewall blocks.  
  *Steps:*
  1. Find all hosts and edge devices that have IPv6 enabled. Get the IPv4 and IPv6 rulesets.
  2. Compare each IPv4 allow rule with its IPv6 rule. Make sure the IPv6 rules are not wider.
  3. Scan the same hosts from outside over IPv4 and over IPv6. Compare the open ports.
  4. Send IPv6 first fragments that do not hold the full header chain. Make sure the firewall drops them.
  5. Make sure the host firewalls also have IPv6 rules.
  *Example:* `nmap -6 -Pn -p- host6 ; nmap -4 -Pn -p- host4 ; ip6tables -S ; nft list ruleset ; show ipv6 access-list`  
  *Expected:* IPv6 rules are as strict as IPv4 rules. Open ports are the same on both. The firewall drops incomplete first fragments.  
  *Refs:* nist_800_53: SC-7, CM-7; pci_dss: 1.4.1; cwe: CWE-1188; attack: T1046; other: R, F, C,  , 9, 0, 9, 9,  , s, e, c, t, i, o, n, s,  , 2, ., 2, ., 3,  , a, n, d,  , 3, ., 1, ;,  , h, t, t, p, s, :, /, /, w, w, w, ., r, f, c, -, e, d, i, t, o, r, ., o, r, g, /, r, f, c, /, r, f, c, 9, 0, 9, 9


## VOIP

- [ ] **NET-VOIP-001** Check that external SIP signalling uses TLS and not plain text  
  *Severity if fail:* High | *Type:* Manual, Automated  
  *Objective:* Finds SIP servers that send registrations, passwords and call data in clear text.  
  *Steps:*
  1. Scan the SIP servers for UDP and TCP port 5060 and TCP port 5061.
  2. Make sure external users and trunks use TLS on port 5061, or an IPsec tunnel.
  3. Run a TLS scan on port 5061. Make sure the protocol and cipher list is strong.
  4. Make sure the server certificate is valid and names the SIP domain.
  5. Make sure plain port 5060 is closed to outside networks, or only trusted carriers can reach it.
  *Example:* `nmap -sUV -sT -p5060,5061 sip.example.com ; nmap --script ssl-enum-ciphers -p5061 sip.example.com ; openssl s_client -connect sip.example.com:5061 -verify_return_error`  
  *Expected:* External SIP traffic uses TLS with a valid certificate and strong settings. Plain port 5060 is not open to untrusted networks.  
  *Refs:* nist_800_53: SC-8, SC-23; cwe: CWE-319; attack: T1040; other: R, F, C,  , 3, 2, 6, 1,  , s, e, c, t, i, o, n, s,  , 2, 6, ., 2, ., 1, ,,  , 2, 6, ., 3, ., 1,  , a, n, d,  , 2, 6, ., 3, ., 2, ., 1, ;,  , h, t, t, p, s, :, /, /, w, w, w, ., r, f, c, -, e, d, i, t, o, r, ., o, r, g, /, r, f, c, /, r, f, c, 3, 2, 6, 1

- [ ] **NET-VOIP-002** Test that SIP registration needs authentication and limits failed attempts  
  *Severity if fail:* High | *Type:* Manual, Automated  
  *Objective:* Finds SIP registrars where an attacker can hijack an extension or guess passwords without limit.  
  *Steps:*
  1. Send a REGISTER request for a test extension without credentials. Look for a 401 or 407 reply.
  2. Send a REGISTER request with a wrong digest. Make sure the server rejects it.
  3. Send 50 wrong attempts from one address. Look for a block or a delay.
  4. Make sure all extensions use long random passwords and not the extension number.
  5. Make sure the server gives the same error for a known extension and an unknown extension.
  *Example:* `sipvicious: svmap sip.example.com ; svwar -m REGISTER -e 100-110 sip.example.com ; nmap -sU -p5060 --script sip-methods,sip-enum-users sip.example.com`  
  *Expected:* The registrar rejects unauthenticated and wrong REGISTER requests. Repeated failures cause a block or a delay. Error replies do not reveal valid extensions.  
  *Refs:* nist_800_53: IA-2, SC-5; cwe: CWE-287, CWE-307; attack: T1110; other: R, F, C,  , 3, 2, 6, 1,  , s, e, c, t, i, o, n, s,  , 2, 6, ., 1, ., 1, ,,  , 2, 6, ., 3, ., 2, ., 1,  , a, n, d,  , 2, 6, ., 3, ., 2, ., 4, ;,  , h, t, t, p, s, :, /, /, w, w, w, ., r, f, c, -, e, d, i, t, o, r, ., o, r, g, /, r, f, c, /, r, f, c, 3, 2, 6, 1

- [ ] **NET-VOIP-003** Check that voice media uses SRTP with message authentication  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds voice calls that an attacker can hear, change or fill with bogus media packets.  
  *Steps:*
  1. Make a test call between two phones in scope. Capture the media packets on the network.
  2. Look at the capture. Make sure the media uses SRTP and not plain RTP.
  3. Look at the SDP in the signalling. Make sure the crypto line or DTLS setup shows an authentication tag.
  4. Make sure the NULL cipher and the NULL authentication tag are not offered.
  5. Make sure keys are exchanged over the TLS signalling channel or with DTLS-SRTP.
  *Example:* `tshark -i eth0 -Y "rtp || srtp || sip" ; tshark -Y sdp -T fields -e sdp.media -e sdp.crypto.tag ; Wireshark: Telephony > RTP > RTP Streams`  
  *Expected:* All test calls use SRTP with an authentication tag. No plain RTP and no NULL cipher is offered. Keys do not travel in clear text.  
  *Refs:* nist_800_53: SC-8, SC-13; cwe: CWE-319, CWE-345; attack: T1040; other: R, F, C,  , 3, 7, 1, 1,  , s, e, c, t, i, o, n, s,  , 9, ., 3,  , a, n, d,  , 9, ., 5, ., 1, ;,  , h, t, t, p, s, :, /, /, w, w, w, ., r, f, c, -, e, d, i, t, o, r, ., o, r, g, /, r, f, c, /, r, f, c, 3, 7, 1, 1


## WIN

- [ ] **NET-WIN-001** Make sure SMB signing is required on clients and servers  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds Windows hosts that accept unsigned SMB sessions, which an attacker can relay or change in transit.  
  *Steps:*
  1. Read the SMB server setting RequireSecuritySignature on the host.
  2. Read the SMB client setting RequireSecuritySignature on the host.
  3. Read the policies "Microsoft network client/server: Digitally sign communications (always)".
  4. Look for third-party SMB servers that need signing off. Note each one.
  5. Look at the OS version. Windows 11 24H2 and Windows Server 2025 have different defaults.
  *Example:* `Get-SmbServerConfiguration | fl RequireSecuritySignature,EnableSecuritySignature ; Get-SmbClientConfiguration | fl RequireSecuritySignature ; reg query HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v RequireSecuritySignature`  
  *Expected:* RequireSecuritySignature is True on the SMB client and server. The two "always" policies equal 1. No exception exists for guest access.  
  *Refs:* attack: T1557.001; capec: CAPEC-94, CAPEC-644; cwe: CWE-300; nist_800_53: SC-8, SC-23; other: https://learn.microsoft.com/windows-server/storage/file-server/smb-signing, https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows  
  *See:* NET-SVC-001

- [ ] **NET-WIN-002** Make sure domain controllers need LDAP signing and refuse clear-text binds  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds domain controllers that accept unsigned SASL binds or simple binds without TLS.  
  *Steps:*
  1. Read the policy "Domain controller: LDAP server signing requirements" on the domain controllers.
  2. Read the policy "Network security: LDAP client signing requirements" on member hosts.
  3. Look for Directory Service events 2886, 2887, 2888 and 2889.
  4. If event 2887 shows unsigned binds, set LDAP Interface Events to level 2. Read event 2889 for the client list.
  5. Try a simple bind on port 389 with ldp.exe. Do not use a privileged account.
  6. Look at the channel binding setting and events 3039 to 3041 for TLS connections.
  *Example:* `gpresult /h gp.html ; Get-WinEvent -FilterHashtable @{LogName="Directory Service";Id=2886,2887,2888,2889} ; ldp.exe > Connection > Connect (port 389) > Bind > Simple bind ; expected error: Strong Authentication Required`  
  *Expected:* The signing policy is Require signing. Event 2888 appears and 2887 does not. A simple bind on port 389 fails with Strong Authentication Required.  
  *Refs:* attack: T1557; capec: CAPEC-94; cwe: CWE-319; nist_800_53: SC-8, IA-2; other: https://learn.microsoft.com/windows-server/identity/ad-ds/ldap-signing, https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server, https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows  
  *See:* NET-SVC-004

- [ ] **NET-WIN-003** Check that NTLMv1 and LM are off and NTLMv2 is the minimum  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds hosts that still send or accept LM or NTLMv1 responses that an attacker can crack or relay.  
  *Steps:*
  1. Read the policy "Network security: LAN Manager authentication level".
  2. Read the policy "Do not store LAN Manager hash value on next password change".
  3. Read the NTLM SSP minimum session security for clients and servers.
  4. Read "Configure encryption types allowed for Kerberos".
  5. Look for NTLM audit or restriction policies and for NTLM events on the domain controllers.
  *Example:* `reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LmCompatibilityLevel ; reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v NoLMHash ; reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 /v NtlmMinClientSec /v NtlmMinServerSec`  
  *Expected:* LmCompatibilityLevel is 5 (NTLMv2 only, refuse LM and NTLM). NoLMHash is 1. NTLM minimum session security is 537395200 for clients and servers.  
  *Refs:* attack: T1557.001, T1550.002; capec: CAPEC-644; cwe: CWE-327, CWE-328; nist_800_53: IA-5, SC-13; other: https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows, Related: EPA on HTTP endpoints, see NET-ADCS-007  
  *See:* NET-ADCS-007

- [ ] **NET-WIN-004** Check that LSA protection runs LSASS as a protected process  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds hosts where a tool can inject code into LSASS to read credentials.  
  *Steps:*
  1. Read the RunAsPPL value in the Lsa registry key.
  2. Look at the CodeIntegrity operational log for events 3033, 3063, 3065 and 3066.
  3. Note each LSA plug-in or driver that fails to load as a protected process.
  4. Look at the AuditLevel value under the LSASS.exe image options key, if LSA protection is not yet on.
  5. Make sure Smart App Control does not hide the audit events.
  *Example:* `reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL ; reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel ; Get-WinEvent -LogName Microsoft-Windows-CodeIntegrity/Operational`  
  *Expected:* RunAsPPL is set (1 or 2) and the host runs LSASS as a protected process. No unsigned plug-in is in the failure events.  
  *Refs:* attack: T1003.001, T1003.004; capec: CAPEC-645; cwe: CWE-522; nist_800_53: SC-39, SI-7; other: https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

- [ ] **NET-WIN-005** Check that Credential Guard is running  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds hosts that keep NTLM hashes and Kerberos secrets in LSASS memory.  
  *Steps:*
  1. Open System Information. Look at Virtualization-based Security Services Running.
  2. Read SecurityServicesRunning from Win32_DeviceGuard.
  3. Read the registry values EnableVirtualizationBasedSecurity and LsaCfgFlags.
  4. Look at the group policy "Turn On Virtualization Based Security" and the Credential Guard option.
  5. Note hosts where hardware or a legacy application blocks Credential Guard.
  *Example:* `msinfo32.exe ; (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning ; reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LsaCfgFlags`  
  *Expected:* SecurityServicesRunning includes the value 1. LsaCfgFlags is 1 or 2. The host shows Credential Guard as running.  
  *Refs:* attack: T1003.001, T1550.002; capec: CAPEC-644, CAPEC-645; cwe: CWE-522; nist_800_53: SC-39, SC-28; other: https://learn.microsoft.com/windows/security/identity-protection/credential-guard/configure

- [ ] **NET-WIN-006** Check that WDigest does not keep clear-text passwords  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds hosts where WDigest stores clear-text credentials in memory.  
  *Steps:*
  1. Read the UseLogonCredential value under the WDigest key.
  2. Read the policy "WDigest Authentication" in the security baseline.
  3. Look at the OS version and the KB2871997 update level on older hosts.
  *Example:* `reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential`  
  *Expected:* WDigest Authentication is disabled (UseLogonCredential is 0 or missing on a patched host).  
  *Refs:* attack: T1003.001; cwe: CWE-257, CWE-522; nist_800_53: IA-5, SC-28; other: https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows

- [ ] **NET-WIN-007** Check the number of cached domain logons  
  *Severity if fail:* Low | *Type:* Config Review, Manual  
  *Objective:* Finds hosts that keep many cached domain logon verifiers that an attacker can crack offline.  
  *Steps:*
  1. Read the policy "Interactive logon: Number of previous logons to cache".
  2. Compare the value with 1 to 4.
  3. Set a lower value for servers that always reach a domain controller.
  *Example:* `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount`  
  *Expected:* The cached logon count is in the range 1 to 4 on laptops. It is 0 on servers that always reach a domain controller.  
  *Refs:* attack: T1003.005; cwe: CWE-522; nist_800_53: IA-5; other: https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows

- [ ] **NET-WIN-008** Check that App Control or AppLocker enforces rules on servers  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds hosts where any program or script can run, so malware runs without a block.  
  *Steps:*
  1. List the active App Control policies and AppLocker rule collections on the host.
  2. Look at the policy mode. Note any policy in audit mode.
  3. Look for rules that allow user-writable paths.
  4. Look for App Control events 8028 and 8029 for audited and blocked scripts.
  5. Look at the process that updates the list of authorized software.
  *Example:* `Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard | fl CodeIntegrityPolicyEnforcementStatus,UsermodeCodeIntegrityPolicyEnforcementStatus ; Get-AppLockerPolicy -Effective -Xml ; Get-WinEvent -LogName "Microsoft-Windows-AppLocker/MSI and Script"`  
  *Expected:* An allow-by-exception policy runs in enforce mode on servers and admin hosts. No rule allows a user-writable path.  
  *Refs:* attack: T1059.001; cwe: CWE-250; nist_800_53: CM-7, CM-7(2), CM-7(5); other: https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/appcontrol, https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/script-enforcement  
  *See:* NET-SVC-017

- [ ] **NET-WIN-009** Check PowerShell logging and language mode on servers and admin hosts  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds hosts where PowerShell runs in full language mode without script logs.  
  *Steps:*
  1. Read the policy "Turn on PowerShell Script Block Logging".
  2. Look at the policy "Turn on PowerShell Transcription" and note its state.
  3. Open a PowerShell session as a normal user. Read the language mode.
  4. Look at the PowerShell event log for script block events.
  5. Look at whether the App Control policy puts untrusted scripts in ConstrainedLanguage mode.
  *Example:* `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging ; $ExecutionContext.SessionState.LanguageMode ; Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational";Id=4104} -MaxEvents 5`  
  *Expected:* Script block logging is on. A normal user session runs in ConstrainedLanguage mode on hosts under an enforced App Control policy.  
  *Refs:* attack: T1059.001; nist_800_53: CM-7, AU-12; other: https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows, https://learn.microsoft.com/powershell/scripting/security/app-control/how-to-use-app-control

- [ ] **NET-WIN-010** Check that AlwaysInstallElevated is off in both registry hives  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds hosts where a standard user can install any MSI package with SYSTEM rights.  
  *Steps:*
  1. Read AlwaysInstallElevated under HKLM Software Policies Microsoft Windows Installer.
  2. Read the same value under HKCU for a standard user.
  3. Note that the value 1 in both hives gives SYSTEM rights to every MSI.
  4. Read the policy "Always install with elevated privileges" in the computer and user policy.
  *Example:* `reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated ; reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`  
  *Expected:* AlwaysInstallElevated does not exist or equals 0 in both hives.  
  *Refs:* attack: T1068; capec: CAPEC-233; cwe: CWE-269, CWE-250; nist_800_53: CM-6, AC-6; other: https://learn.microsoft.com/windows/win32/msi/alwaysinstallelevated, https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows, CCE-37490-0

- [ ] **NET-WIN-011** Look for writable service binaries, service keys and unquoted service paths  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds services that a standard user can change to run code as SYSTEM.  
  *Steps:*
  1. List the services with their binary path and run-as account.
  2. Note each path that has spaces and no quotation marks.
  3. Read the ACL of each service binary and its folder. Look for write rights for Users or Everyone.
  4. Read the ACL of each service registry key. Look for write rights for non-admin groups.
  5. Note the services that run as LocalSystem.
  *Example:* `Get-CimInstance Win32_Service | Select Name,StartName,PathName ; icacls "<service binary path>" ; (Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\<name>").Access`  
  *Expected:* No service binary, its folder or its registry key allows write access to non-admin users. All paths with spaces use quotation marks.  
  *Refs:* attack: T1574.010, T1574.011, T1574.009, T1543.003; cwe: CWE-732, CWE-276, CWE-428; nist_800_53: AC-6, CM-6; other: CWE-732, CWE-276, CWE-428 definitions in sources/cwe/cwec_latest.xml.zip. Thin source: no Microsoft page for service ACL checks.

- [ ] **NET-WIN-012** Look for writable autorun and scheduled task targets  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds startup items and tasks that run as a privileged user from a folder that standard users can write to.  
  *Steps:*
  1. List the Run and RunOnce keys for the machine and the startup folder for all users.
  2. List the scheduled tasks that run as SYSTEM or an admin.
  3. Read the ACL of each target file and folder.
  4. Note any target that standard users can write to or replace.
  *Example:* `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run ; Get-ScheduledTask | % { $_.Actions.Execute } ; icacls "<target path>"`  
  *Expected:* Every autorun and scheduled task target is in a folder that only administrators and SYSTEM can write to.  
  *Refs:* attack: T1547.001, T1053.005; cwe: CWE-732, CWE-276; nist_800_53: AC-6, CM-6; other: CWE-732 and CWE-276 in sources/cwe/cwec_latest.xml.zip. Thin source.

- [ ] **NET-WIN-013** Check sensitive user rights: debug, impersonate and log on  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds accounts that hold rights that allow token theft or privilege escalation.  
  *Steps:*
  1. Read the user right "Debug programs".
  2. Read the user right "Impersonate a client after authentication".
  3. Read "Access Credential Manager as a trusted caller" and "Allow log on locally".
  4. List the services that run as an account with the impersonate right and that a user can reach.
  *Example:* `secedit /export /cfg sec.inf /areas USER_RIGHTS ; findstr "SeDebugPrivilege SeImpersonatePrivilege SeTrustedCredManAccessPrivilege SeInteractiveLogonRight" sec.inf`  
  *Expected:* Debug programs is limited to Administrators. Impersonate is limited to Administrators, Service, Local Service and Network Service. Credential Manager trust is held by no one.  
  *Refs:* attack: T1134, T1134.001; capec: CAPEC-233; cwe: CWE-269; nist_800_53: AC-6, AC-6(1); other: https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows

- [ ] **NET-WIN-014** Check that User Account Control uses Admin Approval Mode for admins  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds hosts where admin tokens run without a prompt or on a non-secure desktop.  
  *Steps:*
  1. Read "Run all administrators in Admin Approval Mode".
  2. Read "Admin Approval Mode for the Built-in Administrator account".
  3. Read the elevation prompt behavior for administrators and standard users.
  4. Read "Switch to the secure desktop when prompting for elevation".
  5. Read "Only elevate UIAccess applications that are installed in secure locations".
  *Example:* `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /v FilterAdministratorToken /v ConsentPromptBehaviorAdmin /v ConsentPromptBehaviorUser /v PromptOnSecureDesktop`  
  *Expected:* Admin Approval Mode is on for all admins. The prompt for administrators is 2 and the prompt for standard users is 0. The secure desktop is on.  
  *Refs:* attack: T1068; cwe: CWE-250; nist_800_53: AC-6, CM-6; other: https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows


## WRMT

- [ ] **NET-WRMT-001** Check WinRM for Basic authentication, clear-text traffic and stored credentials  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds WinRM settings that allow weak or clear-text authentication.  
  *Steps:*
  1. Read the WinRM client and service setting "Allow Basic authentication".
  2. Read the setting "Allow unencrypted traffic" for the client and the service.
  3. Read the setting "Disallow Digest authentication".
  4. Read the setting "Disallow WinRM from storing RunAs credentials".
  5. List the WinRM listeners. Make sure each listener uses HTTPS or an encrypted transport.
  *Example:* `winrm get winrm/config ; winrm enumerate winrm/config/listener ; reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service /v AllowBasic /v AllowUnencryptedTraffic`  
  *Expected:* Basic authentication is off, unencrypted traffic is off, Digest is off and RunAs credentials are not stored. No listener sends clear text.  
  *Refs:* attack: T1021.006; cwe: CWE-319; nist_800_53: AC-17, SC-8, IA-2; other: https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows

- [ ] **NET-WRMT-002** Check RDP settings: NLA, encryption level, saved passwords, log on rights  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds RDP hosts that skip Network Level Authentication or allow broad access.  
  *Steps:*
  1. Read the setting "Require user authentication for remote connections by using Network Level Authentication".
  2. Read "Set client connection encryption level" and "Always prompt for password upon connection".
  3. Read "Do not allow passwords to be saved" and "Do not allow drive redirection".
  4. Read the user right "Allow log on through Remote Desktop Services". List the members.
  5. Look for the policy "Remote host allows delegation of non-exportable credentials" for Remote Credential Guard.
  *Example:* `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /v MinEncryptionLevel ; reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"`  
  *Expected:* NLA is on. The encryption level is High. A password prompt is required. Only Administrators and Remote Desktop Users can log on. Passwords are not saved.  
  *Refs:* attack: T1021.001; cwe: CWE-287; nist_800_53: AC-17, IA-2; other: https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows  
  *See:* NET-SVC-002

- [ ] **NET-WRMT-003** Check that local and guest accounts cannot log on from the network  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds hosts where guest and local accounts can sign in over SMB or RPC.  
  *Steps:*
  1. Read the user right "Deny access to this computer from the network".
  2. Make sure the right includes Guests. Note any other denied group.
  3. Read the user rights "Deny log on as a batch job", "as a service" and "locally".
  4. Read the setting "Sharing and security model for local accounts".
  5. Read "Limit local account use of blank passwords to console logon only".
  *Example:* `secedit /export /cfg sec.inf /areas USER_RIGHTS ; findstr "SeDenyNetworkLogonRight SeDenyBatchLogonRight SeDenyServiceLogonRight SeDenyInteractiveLogonRight" sec.inf`  
  *Expected:* The deny network logon right includes Guests. The sharing model for local accounts is Classic. Blank passwords work at the console only.  
  *Refs:* attack: T1078.003; cwe: CWE-287; nist_800_53: AC-17, AC-6, AC-2; other: https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows, Remote UAC token filtering is not in the sources read. See notes-gap3B.md.


## LOG

- [ ] **NET-LOG-001** Review firewall, router and IDS logs for blocked and unusual traffic  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds attacks, misconfigurations and compromised hosts that the logs show but nobody acts on.  
  *Steps:*
  1. Get the logs of firewalls, routers, IDS or IPS and authentication servers for a set period.
  2. Look for unauthorized connection attempts and traffic that the rules should block.
  3. Look for outbound connections from internal hosts to unknown destinations.
  4. Look for repeated failed logins and for account changes.
  5. Write down each event that nobody investigated.
  *Example:* `grep -E "DENY|DROP|REJECT" /var/log/firewall.log | awk "{print \$<src-col>}" | sort | uniq -c | sort -rn | head ; zeek-cut id.orig_h id.resp_h < conn.log`  
  *Expected:* The logs show the events that the logging policy requires. Each unusual event has an investigation record, and no log shows traffic that the rules should block.  
  *Refs:* cheatsheet: Logging_Cheat_Sheet; owasp_top10: A09:2025; cwe: CWE-778; nist_800_53: AU-6, SI-4; pci_dss: 10.4.1; other: NIST SP 800-115 section 3.2 (log review)  
  *See:* WEB-LOG-014

- [ ] **NET-LOG-002** Check that devices send logs securely to a central server  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds devices whose logs stay on the device, where an attacker can delete them.  
  *Steps:*
  1. List all firewalls, routers, switches, IDS and servers in scope.
  2. Read the log destination on each device.
  3. Make sure the destination is a separate central log server.
  4. Make sure the transport is secure, for example syslog over TLS.
  5. Generate a test event on a device and find it on the log server.
  *Example:* `show logging | include host ; logger -p auth.notice "net-log-test" ; grep net-log-test /var/log/central/*.log`  
  *Expected:* Every device sends its logs promptly to a central log server on a separate system, over a secure channel. The test event arrives on the server.  
  *Refs:* cheatsheet: Logging_Cheat_Sheet, Network_Segmentation_Cheat_Sheet; nist_800_53: AU-9, AU-9(2), AU-12; pci_dss: 10.3.3, 10.2.1  
  *See:* WEB-LOG-013

- [ ] **NET-LOG-003** Check that devices share one time source and keep logs long enough  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds logs that cannot be matched across devices, or that are gone when needed.  
  *Steps:*
  1. Compare the clocks of a sample of devices and servers with the time source.
  2. Look at the time zone and the time format in the log entries.
  3. Read the retention settings of the log server.
  4. Make sure logs of the last 12 months exist.
  5. Make sure logs of the last three months are ready for analysis.
  *Example:* `chronyc tracking ; ntpq -p ; show clock detail ; ls -l /var/log/central/ | head`  
  *Expected:* All devices follow one time source and log in a common time format. Logs are kept for at least 12 months, with the last three months ready for analysis.  
  *Refs:* cheatsheet: Logging_Cheat_Sheet; nist_800_53: SC-45, AU-8; pci_dss: 10.6.1, 10.5.1  
  *See:* WEB-LOG-003

- [ ] **NET-LOG-004** Check that a port scan and failed logins create logs and alerts  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds monitoring that does not see common attack steps on the network.  
  *Steps:*
  1. Tell the contact in the plan about the source address of the test.
  2. Run a port scan from an external test host.
  3. Send a small number of failed logins to a test account on a remote service.
  4. Look at the firewall, IDS and authentication logs for both actions.
  5. Look at the alerts and the time until a responder reads them.
  *Example:* `nmap -Pn -sS -p 1-1024 <target> ; hydra -l testuser -p wrong-password -t 1 ssh://<target> ; check SIEM search for the test source address`  
  *Expected:* Both actions appear in the logs of the right devices. The monitoring raises an alert and a responder reads it in the agreed time.  
  *Refs:* cheatsheet: Logging_Cheat_Sheet; owasp_top10: A09:2025; cwe: CWE-778; nist_800_53: SI-4, AU-6, CA-8; pci_dss: 11.5.1, 12.10.5; other: NIST SP 800-115 sections 4.2 and 5.2 (compare logs with scans; defenders ability to detect)  
  *See:* WEB-LOG-014

- [ ] **NET-LOG-005** Check that logins and configuration changes on network devices are logged  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds devices where an attacker or admin can change settings without a record.  
  *Steps:*
  1. Make sure the device logs successful and failed administrator logins.
  2. Change a harmless setting on a test device.
  3. Look at the device log and the central log server for the change.
  4. Make sure the entry shows who, when and from where.
  *Example:* `show logging | include (LOGIN|CONFIG) ; journalctl -u sshd --since "10 min ago" ; grep "config" /var/log/central/*.log`  
  *Expected:* Logins and configuration changes appear in the logs with the user, the time and the source address. Logs do not hold passwords.  
  *Refs:* cheatsheet: Logging_Cheat_Sheet; cwe: CWE-778, CWE-532; nist_800_53: AU-2, AU-3, AU-12; pci_dss: 10.2.1  
  *See:* WEB-LOG-007


## MAIL

- [ ] **NET-MAIL-001** Check SPF, DKIM and DMARC records for each mail domain  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds domains where other parties can send mail that looks like it came from the organization.  
  *Steps:*
  1. List all domains and subdomains that send or receive mail.
  2. Query the SPF, DKIM and DMARC records of each domain.
  3. Compare the SPF sources with the mail servers that the organization owns.
  4. Look for SPF mechanisms that match addresses of removed or taken-over hosts.
  5. Read the DMARC aggregate reports and look for senders that the organization did not start.
  *Example:* `dig TXT example.com +short ; dig TXT _dmarc.example.com +short ; dig TXT <selector>._domainkey.example.com +short ; dnsrecon -d example.com -t std`  
  *Expected:* Each mail domain has SPF, DKIM and DMARC records. They list only the senders that the organization owns, and DMARC reports show no unknown sender.  
  *Refs:* cheatsheet: Subdomain_Takeover_Prevention_Cheat_Sheet; nist_800_53: SC-20, SI-4  
  *See:* NET-SVC-014


## MITM

- [ ] **NET-MITM-001** Test whether ARP poisoning is blocked or detected on the LAN  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds segments where an attacker can put a host between two others and read or change their traffic.  
  *Steps:*
  1. Put a test client, a test server and an attacker host on the same segment.
  2. Send spoofed ARP replies from the attacker host to the client and to the server.
  3. Look at the ARP table of the client and the server.
  4. Look at the traffic that the attacker host can see.
  5. Look at the switch and monitoring alerts for the ARP packets.
  *Example:* `arpspoof -i eth0 -t <client> <server> ; ettercap -T -M arp:remote /<client>// /<server>// ; arp -a ; Wireshark filter arp`  
  *Expected:* The network drops the spoofed ARP packets or raises an alert. The attacker host cannot see the traffic between client and server.  
  *Refs:* attack: T1557, T1557.002; capec: CAPEC-94, CAPEC-158; cheatsheet: Denial_of_Service_Cheat_Sheet; nist_800_53: SC-7, SI-4

- [ ] **NET-MITM-002** Test whether switches resist MAC flooding  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds switches that send all traffic to all ports when the MAC table is full.  
  *Steps:*
  1. Put a sniffer host on a port of the test switch.
  2. Send frames with many different source MAC addresses from the attacker host.
  3. Send traffic between two other hosts on the switch.
  4. Look at the sniffer to see if it receives the traffic of the other hosts.
  5. Look at the switch for port security alerts or port shutdown.
  *Example:* `macof -i eth0 -n 100000 ; show mac address-table count ; Wireshark on the sniffer port`  
  *Expected:* The switch limits the MAC addresses on each port or blocks the port. It never forwards the traffic of other hosts to the sniffer.  
  *Refs:* cheatsheet: Denial_of_Service_Cheat_Sheet; capec: CAPEC-158; cwe: CWE-770; nist_800_53: SC-5, SC-7

- [ ] **NET-MITM-003** Test whether rogue DHCP servers are blocked on the access network  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds networks where a rogue host can give clients false addresses, gateways or DNS servers.  
  *Steps:*
  1. Get the list of approved DHCP servers.
  2. Start a test DHCP server on a host in a test segment.
  3. Connect a test client and look at the lease that it gets.
  4. Look at the switch and monitoring alerts for the rogue server.
  *Example:* `dnsmasq --no-daemon --dhcp-range=192.0.2.100,192.0.2.150 (test segment only) ; nmap --script broadcast-dhcp-discover ; Wireshark filter bootp`  
  *Expected:* The test client gets a lease only from an approved server. The network drops the replies of the rogue server and raises an alert.  
  *Refs:* attack: T1557, T1557.003; capec: CAPEC-94; nist_800_53: SC-7, SI-4, CM-8

- [ ] **NET-MITM-004** Look for broadcast name resolution that an attacker can answer  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds clients that ask the local network for names and accept replies from any host.  
  *Steps:*
  1. Capture the traffic of a client segment for a business cycle.
  2. Look for multicast and broadcast name queries, and for NetBIOS name queries.
  3. On a test segment, answer one query from a test host with a test address.
  4. Look at what the client sends to the test host.
  *Example:* `tshark -r seg.pcap -Y "llmnr || nbns || mdns" ; Responder -I eth0 -A (analyze mode only) ; Wireshark filter nbns`  
  *Expected:* Clients do not use broadcast or multicast name resolution for company names. Clients send no credentials to a host that answers a query.  
  *Refs:* attack: T1557, T1557.001; capec: CAPEC-94; nist_800_53: SC-7, CM-7; other: NIST SP 800-115 sections 3.5 and 5.2.1 (network sniffing and NetBIOS enumeration)


## PEN

- [ ] **NET-PEN-001** Run an external penetration test with a defined methodology  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds attack paths from the internet that scans alone do not show.  
  *Steps:*
  1. Plan the test with the rules of engagement and the goals.
  2. Collect host names, addresses, services and versions of the external perimeter.
  3. Compare the services with vulnerability databases and with the scan results.
  4. Try to exploit each confirmed vulnerability to prove that it works.
  5. Try to use each success to reach more systems, and go back to the discovery step.
  6. Write the report with the evidence, the risk rating and the fix advice.
  *Example:* `nmap -sV -oX ext.xml <range> ; searchsploit --nmap ext.xml ; msfconsole (exploit modules) ; Wireshark to record the test traffic`  
  *Expected:* The test finds no exploitable path to critical systems. Any finding has a risk rating and a fix, and the test repeats after the fix.  
  *Refs:* attack: T1190, T1210; capec: CAPEC-310; nist_800_53: CA-8, CA-8(1); pci_dss: 11.4.1, 11.4.3, 11.4.4; other: NIST SP 800-115 section 5.2 (penetration testing phases)

- [ ] **NET-PEN-002** Run an internal penetration test from a user network position  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds paths from a normal internal host to critical systems and data.  
  *Steps:*
  1. Connect a test host to a user network, as a normal employee or visitor would.
  2. Find hosts, services and shares with passive and active discovery.
  3. Look for misconfigurations, default accounts and weak passwords on the hosts found.
  4. Try to exploit confirmed weaknesses and to move to more systems.
  5. Record each step with time and evidence.
  6. Stop and tell the contact if you find an intruder or a real incident.
  *Example:* `nmap -sV -p- --open <internal-range> ; crackmapexec smb <range> ; Responder -A ; msfconsole`  
  *Expected:* The test host cannot reach critical systems or sensitive data. The security team detects the test activity from the agreed source addresses.  
  *Refs:* attack: T1210, T1021, T1078.001; nist_800_53: CA-8, CA-8(1); pci_dss: 11.4.2, 11.4.4; other: NIST SP 800-115 section 5.2 (penetration testing and attack phase categories)

- [ ] **NET-PEN-003** Check that exploitable findings are corrected and tested again  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds penetration test findings that stay open or that return after a fix.  
  *Steps:*
  1. Get the report of the last penetration test and the fix tickets.
  2. Compare the risk rating of each finding with the time that the team needed to fix it.
  3. Repeat the exploit steps for each finding that the team closed.
  4. Reopen each finding that still works.
  *Example:* `Repeat the exploit from the report, for example: msfconsole -x "use <module>; set RHOSTS <host>; check" ; compare with the first nmap -sV output`  
  *Expected:* Each exploitable finding is fixed in the time that its rating sets. A new test shows that the fix works.  
  *Refs:* nist_800_53: CA-8, RA-5, SI-2; pci_dss: 11.4.4, 6.3.1; other: NIST SP 800-115 section 8.3 (remediation and mitigation)


## PLAN

- [ ] **NET-PLAN-001** Check that the assessment plan defines scope, exclusions and authorization  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds network tests that start without written approval or with unclear target lists.  
  *Steps:*
  1. Get the assessment plan or the rules of engagement.
  2. Look at the list of authorized systems, IP ranges and test types.
  3. Look at the list of systems that the test must not touch.
  4. Look for the written consent of third-party network owners and shared hosting providers.
  5. Compare the target list with the asset inventory.
  *Example:* `Compare the plan with the inventory: nmap -sL -n 10.10.0.0/24 (list targets only, no packets sent to the hosts)`  
  *Expected:* The signed plan names every authorized system and test type. It lists excluded systems by IP address. Third-party owners have given written consent.  
  *Refs:* nist_800_53: CA-2, CA-8; pci_dss: 12.5.2; other: NIST SP 800-115 sections 5.2 and 6.5 (assessment plan and rules of engagement)

- [ ] **NET-PLAN-002** Check that the plan defines incident handling and tester source addresses  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds plans that leave testers and staff without rules for real intruders and test alerts.  
  *Steps:*
  1. Look in the plan for the primary and alternate contacts of the testers and the security group.
  2. Look for the rule that says what happens if the tester finds a real intruder.
  3. Look for the list of IP addresses that the testers use.
  4. Look for the rule that prevents test alerts from going to external parties.
  *Example:* `Check the tester source address list against the firewall and IDS logs after the test: grep <tester-ip> /var/log/firewall.log`  
  *Expected:* The plan names contacts, source IP addresses and the stop rule for real incidents. The plan also says who may restart the test.  
  *Refs:* nist_800_53: CA-2; pci_dss: 12.10.5; other: NIST SP 800-115 section 6.5 (incident handling in the plan)

- [ ] **NET-PLAN-003** Check that test data is stored, sent and removed safely  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds scan results, captures and cracked passwords that testers keep without protection.  
  *Steps:*
  1. Look in the plan for the rules on storage of test data on the tester systems.
  2. Look for the rules on the transmission of reports and captures over networks.
  3. Look for the rules on the removal of data at the end of the test.
  4. Look at one tester system and one report to see if the rules are in use.
  *Example:* `Look for unencrypted captures and hash files: find /data/assessment -name "*.pcap" -o -name "*.hash" ; lsblk -f`  
  *Expected:* Test data is stored on encrypted media, sent only over encrypted channels, and removed at the end of the test as the plan says.  
  *Refs:* nist_800_53: SC-28; other: NIST SP 800-115 sections 6.5 and 7.4 (data handling)

- [ ] **NET-PLAN-004** Check that the assessment policy sets roles and a test schedule  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds organizations that do not scan or test their networks on a fixed schedule.  
  *Steps:*
  1. Get the security assessment policy.
  2. Look for the roles that approve and run the assessments.
  3. Look for the frequency of internal and external vulnerability scans and penetration tests.
  4. Look for the date of the last review of the policy.
  5. Look at the reports of the last scans and tests to see if the dates follow the policy.
  *Example:* `Compare report dates with the policy, for example: ls -l --time-style=long-iso reports/*.nessus reports/*.xml`  
  *Expected:* The policy names roles and a fixed schedule. It was reviewed in the last 12 months. Scan and test reports exist for each scheduled period.  
  *Refs:* nist_800_53: CA-8, RA-5; pci_dss: 11.3.1, 11.3.2, 11.4.1; other: NIST SP 800-115 sections 6.1 and 6.2 (assessment policy and scheduling)


## REV

- [ ] **NET-REV-001** Review network and data-flow diagrams and the list of allowed ports  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds networks where the documents do not match the real system or list no approved services.  
  *Steps:*
  1. Get the network diagram, the data-flow diagram and the list of allowed services, protocols and ports.
  2. Make sure each allowed port has a business reason and an approver.
  3. Compare the diagram with the results of a host and port scan.
  4. Write down each host or flow that is not in the documents.
  *Example:* `nmap -sn -oX hosts.xml 10.10.0.0/24 ; compare hosts.xml with the diagram and the asset inventory`  
  *Expected:* The diagrams are current. Every open port and every data flow in the network is in the documents with a business reason and an approval.  
  *Refs:* wstg: WSTG-CONF-01; nist_800_53: CM-8, CM-7; pci_dss: 1.2.3, 1.2.4, 1.2.5; other: NIST SP 800-115 section 3.1 (documentation review)

- [ ] **NET-REV-002** Review firewall and router rulesets for deny by default and least privilege  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds rules that are too wide, old, temporary or in the wrong order.  
  *Steps:*
  1. Export the rulesets of each firewall and the access control lists of each router.
  2. Make sure the last rule denies all traffic that is not allowed.
  3. Look for rules that use any as a source, a destination or a port.
  4. Look for temporary rules that are still active and for rules that nobody needs.
  5. Make sure specific rules come before general rules.
  6. Make sure no rule lets traffic go around other security controls.
  *Example:* `show running-config | section access-list ; iptables -S ; nft list ruleset ; Wireshark capture behind the firewall to see which traffic passes`  
  *Expected:* The ruleset denies all traffic by default and allows only listed sources, destinations and ports. Each rule has an owner and a reason, and no old rule remains.  
  *Refs:* wstg: WSTG-CONF-01; cheatsheet: Network_Segmentation_Cheat_Sheet; cwe: CWE-284, CWE-668; nist_800_53: SC-7, CM-6; pci_dss: 1.2.1, 1.2.7, 1.3.1, 1.4.2; other: NIST SP 800-115 section 3.3 (ruleset review)

- [ ] **NET-REV-003** Review host-based firewall rules and IDS or IPS rulesets  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds host rules that allow backdoors and monitoring rules that are off or out of date.  
  *Steps:*
  1. Export the host-based firewall rules of a sample of servers.
  2. Look for rules that allow prohibited applications or unknown listeners.
  3. Export the IDS or IPS signature list and the date of the last update.
  4. Make sure the needed signatures are on and the unneeded signatures are off.
  5. Make sure the IDS or IPS monitors the perimeter and the critical segments.
  *Example:* `iptables -S ; netstat -tulpn ; ufw status verbose ; Get-NetFirewallRule -Enabled True -Direction Inbound`  
  *Expected:* Host rules allow only approved applications. Needed IDS or IPS signatures are on and current. Traffic at the perimeter and at critical segments is monitored.  
  *Refs:* nist_800_53: SI-4, SC-7; pci_dss: 11.5.1, 1.5.1; other: NIST SP 800-115 section 3.3 (ruleset review)

- [ ] **NET-REV-004** Review the system configuration of network hosts against a hardening standard  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds unneeded services, weak account settings and wrong log and backup settings.  
  *Steps:*
  1. Get the hardening standard or checklist that the organization uses.
  2. Export the settings of a sample of servers, routers and switches.
  3. Compare each setting with the standard.
  4. Make sure each deviation has an approval and a reason.
  5. Run an automated check tool where one exists, and check the rest by hand.
  *Example:* `oscap xccdf eval --profile <profile> --results r.xml <benchmark>.xml ; lynis audit system`  
  *Expected:* Each setting matches the hardening standard, or the deviation is approved and documented. No unneeded service runs.  
  *Refs:* wstg: WSTG-CONF-01; cheatsheet: Attack_Surface_Analysis_Cheat_Sheet; cwe: CWE-1188; nist_800_53: CM-6, CM-7; pci_dss: 2.2.1, 2.2.4; other: NIST SP 800-115 section 3.4 (system configuration review)

- [ ] **NET-REV-005** Capture network traffic and look for clear-text protocols and credentials  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds protocols that send passwords or data in clear text on a network segment.  
  *Steps:*
  1. Connect the sniffer to a tap or a mirror port on the segment.
  2. Capture traffic for a defined time.
  3. Filter the capture for telnet, FTP, HTTP, SNMP, LDAP and other clear-text protocols.
  4. Look for user names, passwords and sensitive data in the packets.
  5. Write down each unauthorized or clear-text protocol and the hosts that use it.
  *Example:* `tshark -i eth1 -a duration:600 -w seg.pcap ; tshark -r seg.pcap -Y "telnet || ftp || http.authorization || snmp" -T fields -e ip.src -e ip.dst -e frame.protocols`  
  *Expected:* The capture shows no clear-text credentials and no clear-text sensitive data. Only approved encrypted protocols carry management and login traffic.  
  *Refs:* attack: T1040; capec: CAPEC-158; cwe: CWE-319; nist_800_53: SC-8; pci_dss: 4.2.1; other: NIST SP 800-115 section 3.5 (network sniffing)

- [ ] **NET-REV-006** Check that file integrity monitoring covers critical system and device files  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds hosts and devices where changes to critical files go unseen.  
  *Steps:*
  1. Get the list of critical files that the file integrity tool guards.
  2. Make sure the tool compares files at least once each week.
  3. Change a test file in the guarded list.
  4. Make sure the tool sends an alert for the change.
  5. Make sure the reference database is stored offline or in a protected place.
  *Example:* `aide --check ; tripwire --check ; echo test >> /etc/<guarded-file> (use a test copy and restore it)`  
  *Expected:* The tool guards the critical files, compares them at least weekly and alerts on each change. Attackers cannot change the reference database.  
  *Refs:* nist_800_53: SI-7; pci_dss: 11.5.2; other: NIST SP 800-115 section 3.6 (file integrity checking)


## SEG

- [ ] **NET-SEG-001** Check that the network has frontend, middleware and backend security zones  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds flat networks where one compromised web server gives access to databases and directories.  
  *Steps:*
  1. Get the network diagram and the VLAN and subnet list.
  2. Look at the placement of load balancers, web servers, application servers, databases and directory servers.
  3. Make sure public-facing components are in a separate zone from internal applications.
  4. Make sure databases, directory services, key storage and file servers are in a backend zone.
  5. Make sure a firewall controls the traffic between the zones.
  *Example:* `Review of diagram and switch/firewall config: show vlan brief ; show ip route ; Wireshark capture on each zone border`  
  *Expected:* Public-facing components, applications and data stores are in separate zones. A firewall with an explicit ruleset controls each zone border.  
  *Refs:* cheatsheet: Network_Segmentation_Cheat_Sheet; cwe: CWE-668; nist_800_53: SC-7, SC-32; pci_dss: 1.4.1; other: SC-7(21) isolation of system components; SC-7(29) separate subnets (control text read in the catalog)

- [ ] **NET-SEG-002** Make sure databases and backend systems are not reachable from untrusted networks  
  *Severity if fail:* Critical | *Type:* Automated  
  *Objective:* Finds data stores that an attacker on the internet or a web server can reach directly.  
  *Steps:*
  1. Scan the backend hosts from an untrusted external network.
  2. Scan the backend hosts from a host in the frontend zone.
  3. Try to connect to the database and directory ports that answer.
  4. Compare the result with the zone rules.
  *Example:* `nmap -Pn -p 1433,1521,3306,5432,27017,6379,389,636,445 <backend-range> -oA seg-db ; nc -vz <db-host> 5432`  
  *Expected:* Backend systems do not answer from untrusted networks. Only the application servers can reach the database ports.  
  *Refs:* wstg: WSTG-CONF-01; cheatsheet: Network_Segmentation_Cheat_Sheet; cwe: CWE-668, CWE-284; nist_800_53: SC-7, AC-4; pci_dss: 1.4.4, 1.4.2; other: WSTG-CONF-01 VPC and subnet isolation row

- [ ] **NET-SEG-003** Make sure information systems cannot reach the zones of other systems  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds paths from one system to the frontend, middleware or backend of another system.  
  *Steps:*
  1. Get the network security policy and the list of allowed interservice flows.
  2. Scan the frontend and middleware zones of system B from a host in system A.
  3. Scan the backend zone of system B from the middleware zone of system A.
  4. Compare the result with the list of allowed flows.
  *Example:* `nmap -Pn -p- --open <system-B-range> -oA a-to-b ; nc -vz <system-B-db> 5432`  
  *Expected:* Only the documented flows between systems work. A middleware host cannot reach the database of another system and goes through the application server.  
  *Refs:* cheatsheet: Network_Segmentation_Cheat_Sheet; cwe: CWE-668; nist_800_53: SC-7, AC-4; pci_dss: 1.4.1; other: SC-7(5) deny by default (control text read in the catalog)

- [ ] **NET-SEG-004** Check that outbound traffic from servers is limited to what is needed  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds servers that can connect to any internet host, so a compromised server can reach a control server.  
  *Steps:*
  1. Get the list of outbound flows that each server zone needs.
  2. From a test host in each zone, try to open connections to an external host that you control.
  3. Try common ports, such as 22, 53, 80, 443 and 3389, and an uncommon port.
  4. Compare the result with the egress rules.
  *Example:* `nmap -Pn -p 22,25,53,80,443,3389,8080,4444 <external-test-host> ; curl -m 5 https://<external-test-host>/`  
  *Expected:* Servers reach only the destinations and ports on the allowed list. Other outbound connections are denied and logged.  
  *Refs:* cheatsheet: Network_Segmentation_Cheat_Sheet; attack: T1048; nist_800_53: SC-7, SI-4; pci_dss: 1.3.2; other: SC-7(9) restrict threatening outgoing traffic (control text read in the catalog)

- [ ] **NET-SEG-005** Test the segmentation controls with a penetration test  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds segmentation that exists on paper but does not stop traffic between zones.  
  *Steps:*
  1. Get the list of all segmentation methods in use, such as firewalls, VLANs and access lists.
  2. Test each method from the less trusted side to the more trusted side.
  3. Test again after each change to the segmentation controls.
  4. Record each path that crosses a zone border without approval.
  *Example:* `nmap -Pn -sS -sU -p- <protected-range> from each out-of-scope segment ; hping3 for crafted packets`  
  *Expected:* Traffic from out-of-scope networks cannot reach the protected zone. The test ran in the last 12 months and after each change.  
  *Refs:* nist_800_53: SC-7, CA-8; pci_dss: 11.4.5; other: NIST SP 800-115 section 5.2 (penetration testing)

- [ ] **NET-SEG-006** Check that edge routers drop packets with forged source addresses  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds networks that accept spoofed source addresses, which helps to go around block lists.  
  *Steps:*
  1. Read the ingress filter rules on the edge routers.
  2. Send a packet from outside with a source address of the internal range.
  3. Send a packet from outside with a private or loopback source address.
  4. Look on an internal sniffer to see if the packets arrive.
  *Example:* `hping3 -S -a 10.0.0.5 -p 80 <public-host> ; Wireshark on the internal segment with filter ip.src==10.0.0.5`  
  *Expected:* The router drops the packets with a forged source address before they enter the trusted network.  
  *Refs:* cheatsheet: Denial_of_Service_Cheat_Sheet; cwe: CWE-345; nist_800_53: SC-7; pci_dss: 1.4.3; other: RFC 2267 ingress filtering as named in the Denial of Service Cheat Sheet

- [ ] **NET-SEG-007** Check that internal IP addresses and routes are not shown to outsiders  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds devices that tell untrusted parties about the internal network layout.  
  *Steps:*
  1. Look at the routing protocol settings on the edge routers.
  2. Look at ICMP replies, traceroute output and error messages seen from outside.
  3. Look for internal addresses in DNS answers and in public headers.
  4. Make sure routing updates go only to approved neighbors.
  *Example:* `traceroute -n <public-host> ; dig +short @<public-ns> <name> ; curl -sI https://<site> | grep -i "via\|x-forwarded"`  
  *Expected:* Outside parties see no internal IP address and no internal route. Routing updates go only to approved neighbors.  
  *Refs:* attack: T1590.004, T1590.005; cwe: CWE-200; nist_800_53: SC-7; pci_dss: 1.4.5; other: SC-7(16) prevent discovery of system components (control text read in the catalog)

- [ ] **NET-SEG-008** Review cloud security groups, route tables and network policies for exposure  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds cloud rules that open management or database ports to the internet.  
  *Steps:*
  1. List all security group or firewall rules in the account.
  2. Find each inbound rule with a source of 0.0.0.0/0 or any.
  3. Look at the ports of those rules, mainly SSH, RDP and database ports.
  4. Read the route tables and subnet layout to see which subnets have a route to the internet.
  5. Scan the public addresses to confirm which ports really answer.
  *Example:* `aws ec2 describe-security-groups ; aws ec2 describe-route-tables ; az network nsg rule list --nsg-name <nsg> -g <rg> ; prowler ; ScoutSuite ; nmap -Pn -p- <public-ip>`  
  *Expected:* No security group opens SSH, RDP or database ports to 0.0.0.0/0. Backend subnets have no route from the internet.  
  *Refs:* wstg: WSTG-CONF-01; owasp_top10: A02:2025; cwe: CWE-1327; nist_800_53: SC-7, CM-7; pci_dss: 1.3.1, 1.4.2  
  *See:* WEB-CONF-001

- [ ] **NET-SEG-009** Check that a written network security policy exists and matches the rules  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds firewall rules that no policy approves, and policies that no rule enforces.  
  *Steps:*
  1. Get the network security policy that lists the allowed flows.
  2. Take a sample of firewall rules from the main zone borders.
  3. Look for a policy line for each sampled rule.
  4. Look for a rule for each policy line about a main flow, such as logs, monitoring and CI/CD.
  *Example:* `Compare the policy with the export of rules: show access-lists ; nft list ruleset ; manual sample of 20 rules`  
  *Expected:* Each sampled rule has a policy line, and each main policy line has a rule. The policy is current and approved.  
  *Refs:* cheatsheet: Network_Segmentation_Cheat_Sheet; nist_800_53: SC-7, CM-6; pci_dss: 1.2.1, 1.2.2

- [ ] **NET-SEG-010** Scan infrastructure code for open network rules before deployment  
  *Severity if fail:* Medium | *Type:* Code Review  
  *Objective:* Finds open security group rules and weak network settings before they reach production.  
  *Steps:*
  1. Find the repositories that define networks, firewalls and security groups as code.
  2. Run a static analysis tool on the code.
  3. Look for rules with any source, any port or public addresses.
  4. Make sure the pipeline runs the tool on each change and blocks high findings.
  *Example:* `checkov -d infra/ ; tfsec infra/ ; kubescape scan . ; grep -rn "0.0.0.0/0" infra/`  
  *Expected:* The code defines no open rule that the policy does not allow. The pipeline blocks changes with high findings.  
  *Refs:* cheatsheet: Infrastructure_as_Code_Security_Cheat_Sheet; owasp_top10: A02:2025; cwe: CWE-1327; nist_800_53: CM-3, CM-6, SC-7  
  *See:* WEB-CONF-001


## SOC

- [ ] **NET-SOC-001** Run an approved phishing test and count users who give out data  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds how many users follow fake mails that ask for passwords or open attachments.  
  *Steps:*
  1. Define the target group and the message with management and HR.
  2. Send the test mails from a controlled domain to the target group.
  3. Count the users who open the mail, follow the link or give data on the test page.
  4. Count the users who report the mail to the security team.
  5. Tell the users the result in a way that does not name or blame single persons.
  *Example:* `gophish campaign with a landing page that records the click and discards entered data ; check the mail gateway logs for the sender domain`  
  *Expected:* Few users give out data, and most users report the mail. Mail controls block or mark the test messages.  
  *Refs:* nist_800_53: SI-4; pci_dss: 12.6.1, 12.6.3; other: NIST SP 800-115 section 5.3 (social engineering and phishing)

- [ ] **NET-SOC-002** Test phone or in-person requests for passwords or network access  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds staff who give credentials or access to a caller or a visitor who has no right to them.  
  *Steps:*
  1. Write a short script for a call or a visit, such as an IT help desk request.
  2. Make the calls or visits to a sample of staff and the help desk.
  3. Record whether the person follows the identity check procedure.
  4. Record whether the person gives data or access.
  5. Write a report with the successful and the failed tactics.
  *Example:* `Call script and a log sheet with fields: time, role called, request, identity check done (yes/no), data given (yes/no)`  
  *Expected:* Staff follow the identity check procedure and refuse the request. The help desk reports the try to the security team.  
  *Refs:* nist_800_53: IA-5; pci_dss: 12.6.1, 12.6.3; other: NIST SP 800-115 section 5.3 (social engineering)


## SVC

- [ ] **NET-SVC-001** Make sure SMB and NetBIOS services give no access to untrusted networks  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds file-sharing services with anonymous access, open shares or exposure to the internet.  
  *Steps:*
  1. Scan the hosts from an untrusted network for the SMB and NetBIOS ports.
  2. Scan the hosts from the user network for the same ports.
  3. Try to list shares, users and system information with no credentials.
  4. Try to read and write the shares that the hosts show.
  5. Write down each host and share that answers.
  *Example:* `nmap -Pn -p 137-139,445 --script smb-os-discovery,smb-enum-shares <host> ; enum4linux -a <host> ; smbclient -L //<host> -N ; smbmap -H <host>`  
  *Expected:* SMB and NetBIOS do not answer from untrusted networks. Anonymous sessions give no list of shares, users or system data.  
  *Refs:* attack: T1021.002, T1135, T1210; cwe: CWE-306, CWE-668; nist_800_53: CM-7, SC-7; pci_dss: 2.2.4, 1.4.2; other: NIST SP 800-115 section 5.2.1 (NetBIOS enumeration in the discovery phase)

- [ ] **NET-SVC-002** Make sure remote desktop and VNC are not open to the internet  
  *Severity if fail:* Critical | *Type:* Automated  
  *Objective:* Finds remote desktop services that attackers can reach and attack with stolen or guessed passwords.  
  *Steps:*
  1. Scan the public address ranges for RDP, VNC and other remote desktop ports.
  2. Scan the internal ranges for the same ports from the user network.
  3. Read the rules that allow remote desktop access.
  4. Make sure remote access goes through a managed access point such as a VPN or a jump host.
  5. Make sure multi-factor authentication is required for remote access.
  *Example:* `nmap -Pn -p 3389,5900-5902,5985,5986 -sV <range> ; nmap --script rdp-enum-encryption -p 3389 <host>`  
  *Expected:* Remote desktop ports do not answer from the internet. Access goes through a managed access point with multi-factor authentication.  
  *Refs:* wstg: WSTG-CONF-01; attack: T1021.001, T1021.005, T1133; cwe: CWE-1327; nist_800_53: AC-17, SC-7; pci_dss: 8.4.3, 1.4.2  
  *See:* NET-ADM-001

- [ ] **NET-SVC-003** Check SNMP for default community strings and write access  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds devices that give configuration data or control to anyone who knows a default string.  
  *Steps:*
  1. Scan for SNMP on UDP port 161 in the ranges in scope.
  2. Try the default community strings of the vendors on each device that answers.
  3. Walk the data that the device returns and look for configuration, user and network data.
  4. Try a set operation on a test object, if the plan allows it.
  5. Make sure SNMP answers only to the management hosts.
  *Example:* `nmap -sU -p 161 --script snmp-info,snmp-brute <range> ; onesixtyone -c community.txt -i hosts.txt ; snmpwalk -v2c -c <string> <host>`  
  *Expected:* SNMP answers only to management hosts. No default community string works and no string gives write access. SNMP uses authentication and encryption.  
  *Refs:* attack: T1602, T1602.002; cwe: CWE-1188, CWE-306; nist_800_53: CM-6, IA-5, SC-8; pci_dss: 2.3.1, 2.2.7; other: PCI DSS 2.3.1 names SNMP defaults; NIST SP 800-115 appendix lists Net-SNMP for remote access testing

- [ ] **NET-SVC-004** Check directory services for anonymous access and clear-text binds  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds directory services that give user data without a login or accept clear-text passwords.  
  *Steps:*
  1. Scan for directory ports from untrusted networks and from the application zone.
  2. Try an anonymous bind and read the base data.
  3. Capture a normal bind and make sure the password is not in clear text.
  4. Make sure only authorized hosts can reach the directory.
  *Example:* `nmap -Pn -p 389,636,3268,3269 --script ldap-rootdse <host> ; ldapsearch -x -H ldap://<host> -b "" -s base ; ldapsearch -x -H ldap://<host> -b "dc=example,dc=com"`  
  *Expected:* Directory servers are in the backend zone. An anonymous bind returns no user data. Binds use an encrypted channel.  
  *Refs:* cheatsheet: Network_Segmentation_Cheat_Sheet; cwe: CWE-306, CWE-319; nist_800_53: SC-7, SC-8, AC-3; pci_dss: 8.3.2

- [ ] **NET-SVC-005** Check NTP servers for outside access and clock synchronization  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds time servers that attackers can use for amplification, and hosts with wrong clocks.  
  *Steps:*
  1. Find hosts that answer on UDP port 123.
  2. From an external host, send status and monitor queries to each time server.
  3. Look at the answer size compared to the query size.
  4. Compare the clocks of a sample of hosts and devices with the authoritative time source.
  *Example:* `nmap -sU -p 123 --script ntp-info,ntp-monlist <range> ; ntpq -c rv <host> ; chronyc sources`  
  *Expected:* Time servers do not answer status and monitor queries from untrusted hosts. All clocks follow the same authoritative time source.  
  *Refs:* cheatsheet: Denial_of_Service_Cheat_Sheet; attack: T1498.002; capec: CAPEC-490; nist_800_53: SC-45, SC-5; pci_dss: 10.6.1

- [ ] **NET-SVC-006** Check database listeners for network binding and authentication  
  *Severity if fail:* Critical | *Type:* Automated  
  *Objective:* Finds databases that listen on all interfaces or accept connections with no login.  
  *Steps:*
  1. Scan the hosts for common database ports from the application zone and from other zones.
  2. Read the bind address in the database configuration.
  3. Try to connect with no password and with the vendor default account.
  4. Make sure only the application servers can reach the listener.
  *Example:* `nmap -Pn -p 1433,1521,3306,5432,6379,9200,11211,27017 -sV <range> ; ss -tlnp | grep -E "3306|5432|6379|27017" ; redis-cli -h <host> ping`  
  *Expected:* Databases listen only on the addresses that they need. Each connection needs authentication and only the application servers can connect.  
  *Refs:* owasp_top10: A02:2025; wstg: WSTG-CONF-01; cwe: CWE-1327, CWE-306, CWE-1188; nist_800_53: CM-7, SC-7, AC-3; pci_dss: 1.4.4, 2.2.2

- [ ] **NET-SVC-007** Make sure the container daemon API is not exposed on the network  
  *Severity if fail:* Critical | *Type:* Automated  
  *Objective:* Finds hosts where a network client can control containers and get root on the host.  
  *Steps:*
  1. Scan the hosts for the container daemon TCP ports.
  2. Read the daemon start options and look for a TCP listen address.
  3. Look for containers that mount the daemon socket.
  4. Try an unauthenticated API request to each port that answers.
  *Example:* `nmap -Pn -p 2375,2376 <range> ; curl -s http://<host>:2375/version ; ps aux | grep dockerd ; docker ps --format "{{.Names}} {{.Mounts}}"`  
  *Expected:* The daemon does not listen on an unprotected TCP port. No container mounts the daemon socket.  
  *Refs:* cheatsheet: Docker_Security_Cheat_Sheet; cwe: CWE-306, CWE-1327; nist_800_53: CM-7, SC-7


## TLS

- [ ] **NET-TLS-001** Scan every TLS service on the network, not only HTTPS  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds mail, directory, database and management services with old protocols or weak ciphers.  
  *Steps:*
  1. Use the open-port results to list all ports that speak TLS or offer STARTTLS.
  2. Scan each TLS port for the supported protocol versions and cipher suites.
  3. Compare the result with the TLS standard of the organization.
  4. Write down each service that allows TLS 1.0, TLS 1.1, null, anonymous, export or non-forward-secrecy ciphers.
  *Example:* `testssl.sh --starttls smtp <host>:25 ; testssl.sh <host>:636 ; sslyze --regular <host>:8443 ; nmap --script ssl-enum-ciphers -p <ports> <host>`  
  *Expected:* Every TLS service supports only TLS 1.2 and TLS 1.3 with strong AEAD ciphers. Null, anonymous, export and static key exchange suites are off.  
  *Refs:* wstg: WSTG-CONF-01; cheatsheet: Transport_Layer_Security_Cheat_Sheet; cwe: CWE-326, CWE-327; nist_800_53: SC-8, SC-13; pci_dss: 4.2.1  
  *See:* WEB-TLS-001, WEB-TLS-002

- [ ] **NET-TLS-002** Make sure TLS compression is off on all TLS services  
  *Severity if fail:* Low | *Type:* Automated  
  *Objective:* Finds services where TLS compression lets an attacker recover secrets from sessions.  
  *Steps:*
  1. Scan each TLS service for the compression setting.
  2. Write down each service that accepts TLS compression.
  *Example:* `testssl.sh --crime <host>:<port> ; sslyze --compression <host>:<port>`  
  *Expected:* No TLS service accepts TLS compression.  
  *Refs:* cheatsheet: Transport_Layer_Security_Cheat_Sheet; cwe: CWE-327; nist_800_53: SC-8, SC-13

- [ ] **NET-TLS-003** Check TLS libraries for known flaws such as Heartbleed  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds services that use old cryptographic libraries with known flaws.  
  *Steps:*
  1. List the TLS library and version used by each service.
  2. Scan each TLS service for known library flaws.
  3. Compare the library version with the vendor advisories.
  4. Write down each service that uses an old or vulnerable library.
  *Example:* `testssl.sh --heartbleed <host>:<port> ; nmap --script ssl-heartbleed -p <port> <host> ; sslyze --heartbleed <host>:<port>`  
  *Expected:* No TLS service is open to known library flaws. The libraries are at a supported version with current fixes.  
  *Refs:* cheatsheet: Transport_Layer_Security_Cheat_Sheet; cwe: CWE-1395; nist_800_53: SI-2, RA-5

- [ ] **NET-TLS-004** Check that legacy TLS clients use a separate endpoint with fallback protection  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds primary endpoints that were weakened for old clients, or that allow protocol downgrade.  
  *Steps:*
  1. Ask the owner if old clients need weak protocols.
  2. Look for a separate endpoint for old clients with no access to sensitive data.
  3. Make sure the primary endpoint does not allow TLS 1.0 or TLS 1.1.
  4. Check that the TLS_FALLBACK_SCSV extension is on.
  *Example:* `testssl.sh --fallback <host>:<port> ; sslyze --fallback <host>:<port>`  
  *Expected:* Weak protocols run only on a separate endpoint without sensitive data. The primary endpoint refuses them and TLS_FALLBACK_SCSV is on.  
  *Refs:* cheatsheet: Transport_Layer_Security_Cheat_Sheet; cwe: CWE-326; nist_800_53: SC-8; pci_dss: 4.2.1

- [ ] **NET-TLS-005** Check certificates on internal services and management interfaces  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds expired, self-signed, weak or wrong-name certificates on devices and internal services.  
  *Steps:*
  1. List the TLS certificates of all services found by the port scan.
  2. Look at the expiry date, the issuer, the key size and the hash algorithm.
  3. Look at the subject alternative names and compare them with the host name.
  4. Look at the permissions of the private key files where you have access.
  5. Write down each default, self-signed, expired or weak certificate.
  *Example:* `nmap --script ssl-cert -p <ports> <range> ; testssl.sh --server-defaults <host>:<port> ; openssl x509 -in cert.pem -noout -text`  
  *Expected:* Certificates are valid and not expired, use RSA keys of at least 2048 bits and SHA-256, and match the host name. Private keys are not readable by other users.  
  *Refs:* cheatsheet: Transport_Layer_Security_Cheat_Sheet; cwe: CWE-295, CWE-326; nist_800_53: SC-17, SC-12; pci_dss: 4.2.1  
  *See:* WEB-TLS-003, WEB-TLS-004


## VULN

- [ ] **NET-VULN-001** Run an authenticated network vulnerability scan with current signatures  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds missing patches, old software and misconfigurations that a scan without login misses.  
  *Steps:*
  1. Update the vulnerability database of the scanner and write down the update date.
  2. Set up scan accounts with read access on the hosts in scope.
  3. Run the scan against the hosts from the internal viewpoint.
  4. Run a scan without login from the external viewpoint.
  5. Save the reports in a standard format.
  *Example:* `OpenVAS/GVM: gvm-cli ... create_task with a scan config "Full and fast" and credentials ; nmap -sV --script vuln <host>`  
  *Expected:* The scan covers all hosts in scope with a database of the last few days. The reports list all findings, missing patches and misconfigurations.  
  *Refs:* attack: T1595.002; capec: CAPEC-310; nist_800_53: RA-5; pci_dss: 11.3.1, 11.3.2; other: NIST SP 800-115 section 4.3 (vulnerability scanning)

- [ ] **NET-VULN-002** Validate each high scanner finding and remove false positives  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds scanner results that are wrong, so that teams fix real problems only.  
  *Steps:*
  1. Take each Critical and High finding from the scan reports.
  2. Look at the evidence of the finding, such as the banner, the version or the response.
  3. Confirm the finding with a second tool or by a manual check.
  4. Mark each finding as confirmed, false positive or not known.
  5. Record the evidence for each confirmed finding.
  *Example:* `nmap -sV --script <vuln-script> -p <port> <host> ; curl -sv telnet://<host>:<port> ; compare OpenVAS result with a second scanner`  
  *Expected:* Each high finding is confirmed or marked as a false positive with evidence. No unconfirmed finding stays in the report as a fact.  
  *Refs:* wstg: WSTG-CONF-01; nist_800_53: RA-5; other: NIST SP 800-115 sections 4.3 and 5.2 (false positives and exploit validation)

- [ ] **NET-VULN-003** Rate scanner findings by real risk and combine related findings  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds findings that the scanner rates too low or too high for the real environment.  
  *Steps:*
  1. Get the risk rating method of the organization.
  2. Compare the scanner rating of each finding with the organization rating.
  3. Look at the exposure and the data of each affected host.
  4. Look for low findings on one host or path that together give a higher risk.
  5. Record the final rating and the reason.
  *Example:* `Group findings per host: openvas-report --format csv | sort -t, -k<host-col> ; check reachability from untrusted networks with nmap`  
  *Expected:* Each finding has an organization rating with a reason. Findings that combine into a higher risk are listed together.  
  *Refs:* cwe: CWE-693; nist_800_53: RA-5, RA-3; pci_dss: 6.3.1; other: NIST SP 800-115 section 4.3 (scanner risk levels and combined vulnerabilities)

- [ ] **NET-VULN-004** Check that patches for network systems are installed within the set time  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds hosts and devices that stay unpatched after the fix is out.  
  *Steps:*
  1. Get the patch policy and the time limits for each risk level.
  2. Get the scan reports and the patch status from at least two scan periods.
  3. Find each Critical and High finding and its first scan date.
  4. Compare the first scan date with the time limit.
  5. Include network devices, firmware and security appliances in the list.
  *Example:* `Compare reports: gvm-cli ... get_reports ; nmap -sV --script vulners <host> ; list installed patches: apt list --upgradable ; Get-HotFix`  
  *Expected:* Critical patches are installed within one month of release. Other patches are installed within the time set in the policy.  
  *Refs:* owasp_top10: A02:2025; cheatsheet: Vulnerable_Dependency_Management_Cheat_Sheet; cwe: CWE-1104, CWE-1395; nist_800_53: SI-2, RA-5; pci_dss: 6.3.3; other: NIST SP 800-115 sections 4.3 and 8.3 (mitigation and remediation)  
  *See:* WEB-DEP-001

- [ ] **NET-VULN-005** Check that a virtual patch exists where no fix is possible  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds known vulnerabilities that stay open with no fix and no other protection.  
  *Steps:*
  1. List the open vulnerabilities that have no vendor fix or no scheduled fix.
  2. Look for a virtual patch or other control for each of them.
  3. Send the known exploit pattern to a test system that has the same protection.
  4. Send variants of the pattern to look for bypasses.
  5. Make sure the virtual patch is tracked in a change ticket and is reviewed again.
  *Example:* `curl -s "https://<test-host>/<vulnerable-path>?<exploit-pattern>" -o /dev/null -w "%{http_code}\n" ; ZAP or curl for variants`  
  *Expected:* The WAF or IPS blocks the exploit pattern and its variants. The virtual patch is tracked in a ticket and reviewed after the real fix.  
  *Refs:* cheatsheet: Virtual_Patching_Cheat_Sheet; nist_800_53: SI-2, SC-7; other: NIST SP 800-115 section 4.3 (mitigation)

- [ ] **NET-VULN-006** Rescan after remediation and confirm that the finding is closed  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds fixes that were not applied or that did not remove the vulnerability.  
  *Steps:*
  1. Take each finding that the team marked as fixed.
  2. Run a rescan of the affected host and port.
  3. Compare the result with the first report.
  4. Reopen each finding that still appears.
  5. Keep the old and new reports together.
  *Example:* `nmap -sV --script <vuln-script> -p <port> <host> ; OpenVAS: create a task with the same config and compare the reports`  
  *Expected:* The rescan shows no Critical or High finding that was marked as fixed. Each closed finding has a rescan report as evidence.  
  *Refs:* nist_800_53: RA-5, SI-2; pci_dss: 11.3.1; other: NIST SP 800-115 section 8.3 (remediation) and PCI DSS 11.3.1 (rescans)

- [ ] **NET-VULN-007** Make sure no unsupported software runs on the network  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds hosts and devices that run software without security fixes.  
  *Steps:*
  1. Use the service and version scan results of the network.
  2. Compare each product and version with the vendor support dates.
  3. List each end-of-life operating system, firmware and service.
  4. Check if each item has a replacement plan or an approved exception.
  *Example:* `nmap -sV -O -oX inv.xml <range> ; xsltproc inv.xml -o inv.html`  
  *Expected:* No unsupported software runs on the network. Any exception has an owner, an end date and a compensating control.  
  *Refs:* owasp_top10: A02:2025; cwe: CWE-1104, CWE-1329; nist_800_53: SI-2, CM-8; other: NIST SP 800-115 section 4.2 (version scanning)


## WIFI

- [ ] **NET-WIFI-001** Scan passively for rogue access points and unauthorized wireless networks  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds access points and ad hoc networks that the organization did not approve.  
  *Steps:*
  1. Get the inventory of authorized access points with MAC addresses and SSIDs.
  2. Walk the site slowly with a wireless analyzer in passive mode on all channels.
  3. Record the SSID, channel, MAC address, vendor and signal strength of each network.
  4. Compare the list with the inventory and find unknown MAC addresses, vendors and SSIDs.
  5. Use the signal strength to find the location of each unknown device.
  6. Repeat the scan at least each three months.
  *Example:* `airodump-ng wlan0mon --band abg -w site-scan ; kismet -c wlan0mon ; Wireshark with monitor mode and filter wlan.fc.type_subtype==8`  
  *Expected:* Every access point in range is in the inventory. Unknown devices are found, located and handled by the rogue device process.  
  *Refs:* attack: T1016.002, T1557.004; nist_800_53: AC-18, SI-4, CM-8; pci_dss: 11.2.1; other: NIST SP 800-115 sections 4.4.1 and 4.4.3 (passive scanning and device location)

- [ ] **NET-WIFI-002** Check the authentication and encryption settings of authorized wireless networks  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds company wireless networks with weak or no authentication and encryption.  
  *Steps:*
  1. Look at the beacon of each authorized SSID for the authentication and encryption mode.
  2. Look at the wireless configuration standard of the organization.
  3. Try to join each network with no credentials and with a guest account.
  4. Make sure the access point uses a strong key or per-user authentication.
  5. Make sure the administration interface of the access point is not open to the wireless clients.
  *Example:* `airodump-ng wlan0mon --essid <ssid> ; iw dev wlan0 scan | grep -E "SSID|RSN|WPA" ; nmap -Pn -p 22,23,80,443,161 <ap-ip>`  
  *Expected:* Each network needs authentication and uses strong encryption as the standard says. Open networks give no access to internal systems.  
  *Refs:* nist_800_53: AC-18, SC-40; pci_dss: 4.2.1.2, 2.3.1; other: NIST SP 800-115 section 4.4.2 (active wireless scanning)

- [ ] **NET-WIFI-003** Check wireless vendor defaults and the change of wireless keys  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds access points that keep vendor keys, admin passwords or SNMP defaults.  
  *Steps:*
  1. List the access point models in use.
  2. Try the vendor default wireless key and the default admin account on each model.
  3. Look for default SNMP community strings on the access points.
  4. Look at the key management documents to see when the wireless keys change.
  *Example:* `nmap -sU -p 161 --script snmp-info <ap-ip> ; hydra -C ap-defaults.txt <ap-ip> http-get / ; onesixtyone -c community.txt <ap-ip>`  
  *Expected:* No vendor default key, password or SNMP community works. Wireless keys change as the key management process says.  
  *Refs:* attack: T1078.001; capec: CAPEC-70; cwe: CWE-1188; nist_800_53: IA-5, CM-6; pci_dss: 2.3.1, 2.3.2

- [ ] **NET-WIFI-004** Make sure a firewall separates wireless networks from internal and sensitive networks  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds wireless networks that have direct access to servers or the cardholder data zone.  
  *Steps:*
  1. Join each wireless network with a test client.
  2. Scan the internal and sensitive ranges from the test client.
  3. Compare the result with the firewall rules between the wireless network and the other zones.
  *Example:* `nmap -Pn -sS -p- --open <internal-range> from the wireless test client ; traceroute -n <internal-host>`  
  *Expected:* A firewall sits between each wireless network and the sensitive zone. All traffic from wireless to the sensitive zone is denied by default.  
  *Refs:* cheatsheet: Network_Segmentation_Cheat_Sheet; nist_800_53: SC-7, AC-18; pci_dss: 1.3.3

- [ ] **NET-WIFI-005** Check that wireless intrusion detection finds rogue devices and sends alerts  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds sites where a rogue access point or an evil twin goes unseen.  
  *Steps:*
  1. Tell the wireless administrators about the test time.
  2. Start a test access point with a new SSID in the authorized area.
  3. Start a second test access point with the SSID of an authorized network.
  4. Look at the wireless intrusion detection console and alerts.
  5. Stop the test access points at the end of the test.
  *Example:* `hostapd with a test config ; Wireshark/Kismet to see the beacons ; check the WIDPS alert log`  
  *Expected:* The system detects both test access points, finds their location and sends an alert to the responders in the agreed time.  
  *Refs:* attack: T1557.004; nist_800_53: SI-4; pci_dss: 11.2.1; other: NIST SP 800-115 section 4.4.2 (monitoring WIDPS during active scans)

- [ ] **NET-WIFI-006** Scan for Bluetooth devices and check the security mode of company devices  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds rogue or weak Bluetooth devices and access points.  
  *Steps:*
  1. Scan passively for Bluetooth devices in public areas and in a sample of other areas.
  2. Repeat the scan at different times of the day.
  3. Compare the devices with the inventory.
  4. Try an active scan only on devices that the organization owns.
  5. Look at the security mode, the PIN strength and the power setting of those devices.
  *Example:* `hcitool scan ; bluetoothctl scan on ; btscanner`  
  *Expected:* Only approved Bluetooth devices are present. Company devices use a strong security mode and PIN, and the lowest power setting that works.  
  *Refs:* nist_800_53: AC-18, CM-8; other: NIST SP 800-115 section 4.4.4 (Bluetooth scanning)
