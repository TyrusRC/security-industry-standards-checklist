# PCI-DSS security test cases

80 tests. Tick the box when the test passes.


## ACC

- [ ] **PCI-ACC-001** Check that privileges are approved by authorized personnel  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Find access rights that no authorized person approved.  
  *Steps:*
  1. Pick ten users with access to systems or data in scope, including three privileged users.
  2. Find the access request and the approval for each user.
  3. Make sure the approver is authorized and is not the requester.
  4. Compare the approved privileges with the privileges that are set on the system.
  5. Look for privileges that were not approved.
  *Example:* `Compare identity governance requests with the group memberships in the directory`  
  *Expected:* Each user privilege has an approval from an authorized person. The privileges on the system match the approval.  
  *Refs:* pci_dss: 7.2.3; nist_800_53: AC-2, AC-6

- [ ] **PCI-ACC-002** Check the six-month review of user accounts and access rights  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Find accounts and rights that stay after the role changed or the person left.  
  *Steps:*
  1. Ask for the account review procedure.
  2. Find the records of the last two reviews. Make sure they are less than six months apart.
  3. Make sure the review covers all user accounts, third-party and vendor accounts and their rights.
  4. Make sure management confirmed that access is still right and removed access is closed.
  5. Compare a sample of accounts with the HR and contract records.
  *Example:* `User access review reports; directory export compared to the HR list`  
  *Expected:* A review of all user accounts and rights runs at least every six months. Management confirms access and inappropriate access is removed.  
  *Refs:* pci_dss: 7.2.4; nist_800_53: AC-2

- [ ] **PCI-ACC-003** Check the periodic review of application and system account access  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Find application and system accounts with rights that no one reviews.  
  *Steps:*
  1. Ask for the review process for application and system accounts.
  2. Make sure the review frequency comes from the targeted risk analysis.
  3. Find the records of the last review.
  4. Make sure the rights follow least privilege.
  5. Make sure management confirmed the access and that removed rights are closed.
  *Example:* `Service account lists; database grants; cloud role assignments; review records`  
  *Expected:* Application and system accounts are reviewed at a risk-based frequency. Rights follow least privilege and management confirms them.  
  *Refs:* pci_dss: 7.2.5.1, 7.2.5; nist_800_53: AC-2, AC-6

- [ ] **PCI-ACC-004** Check that users query cardholder data only through controlled applications  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find direct access to data stores with cardholder data that bypasses application controls.  
  *Steps:*
  1. List the repositories of stored cardholder data, such as databases and files.
  2. List the users and groups with direct query access.
  3. Make sure only the responsible administrators can query the repository directly.
  4. Make sure all other access goes through applications with role-based, least-privilege actions.
  5. Try a direct database login with an ordinary user account.
  *Example:* `SELECT grantee, privilege_type FROM information_schema.table_privileges; psql -h db -U appuser`  
  *Expected:* Only the responsible administrators can query repositories directly. Other users reach cardholder data through applications with role limits.  
  *Refs:* pci_dss: 7.2.6; nist_800_53: AC-3, AC-6


## AUTH

- [ ] **PCI-AUTH-001** Check that every user has a unique ID before access is allowed  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find users who share an ID or whose actions cannot be linked to one person.  
  *Steps:*
  1. Export the user list of each system and application in scope.
  2. Look for IDs that two or more people use, such as admin, root or team names.
  3. Interview two users of each system. Ask whether they use their own ID.
  4. Pick five events in the audit logs. Link each one to one named person.
  5. Look for access that needs no ID.
  *Example:* `getent passwd; SELECT username FROM users; compare with the HR list; follow five log entries to a person`  
  *Expected:* Each user has a unique ID before access is allowed. Every logged action can be linked to one person.  
  *Refs:* pci_dss: 8.2.1; nist_800_53: IA-2, IA-4

- [ ] **PCI-AUTH-002** Check that shared and generic IDs are rare and controlled  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find group, shared or generic IDs that are used without a need or without individual accountability.  
  *Steps:*
  1. List all group, shared and generic IDs and shared credentials, including service and vendor IDs.
  2. Make sure each has a written business reason and management approval.
  3. Make sure use is blocked by default and open only for the time of the exception.
  4. Make sure the system confirms the identity of the person before the use of the account.
  5. Pick one recent use. Make sure the log links each action to one person.
  *Example:* `Privileged access management check-out log; vault session records; sudo log`  
  *Expected:* Shared and generic IDs are used only by exception, with approval, a time limit, identity confirmation and individual accountability.  
  *Refs:* pci_dss: 8.2.2; nist_800_53: AC-2, IA-2

- [ ] **PCI-AUTH-003** Check that remote access factors are unique for each customer  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find service providers that reuse one credential for remote access to several customers.  
  *Steps:*
  1. Ask for the list of customers that the provider can reach with remote access.
  2. Examine the authentication factors that are used for each customer environment.
  3. Look for factors that two or more customer environments share.
  4. Make sure the remote access tool stores the factors per customer.
  5. Make sure a leak of one factor opens only one customer environment.
  *Example:* `Remote support tool configuration; vault entries per customer`  
  *Expected:* Each customer premises has its own authentication factors. No factor works on more than one customer environment.  
  *Refs:* pci_dss: 8.2.3; nist_800_53: IA-5

- [ ] **PCI-AUTH-004** Check that access of terminated users is revoked at once  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find accounts of former staff and contractors that still work.  
  *Steps:*
  1. Get the list of users who left in the last 90 days.
  2. Look for each user in the local, remote, VPN, application and database accounts.
  3. Compare the leave date with the date the access ended.
  4. Make sure the access ended at once, in the same working day.
  5. Try to log in with one disabled account on a test system.
  *Example:* `Compare the HR leaver list with: ldapsearch, lastlog, aws iam list-users, VPN user list`  
  *Expected:* Every account of a terminated user is removed or disabled at once on every system, for local and remote access.  
  *Refs:* pci_dss: 8.2.5; nist_800_53: PS-4, AC-2

- [ ] **PCI-AUTH-005** Check that inactive accounts are removed or disabled within 90 days  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find user accounts that stay active after 90 days with no use.  
  *Steps:*
  1. Export last-login dates for all user accounts of each system in scope.
  2. Find accounts with no use for more than 90 days.
  3. Make sure each such account is removed or disabled.
  4. Make sure an automatic job or a documented process does this.
  5. Make sure the reason is on file for any exception.
  *Example:* `lastlog; SELECT last_login FROM users; aws iam generate-credential-report; Get-ADUser -Filter {LastLogonDate -lt $d}`  
  *Expected:* No user account is active after 90 days of inactivity. A process removes or disables inactive accounts.  
  *Refs:* pci_dss: 8.2.6; nist_800_53: AC-2

- [ ] **PCI-AUTH-006** Check that third-party remote access accounts are limited and monitored  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find vendor accounts that stay enabled all the time or run with no monitoring.  
  *Steps:*
  1. List all accounts that third parties use for remote access.
  2. Make sure each account is disabled when not in use.
  3. Make sure the account is open only for the time needed, with approval.
  4. Look at the logs of the last vendor session. Make sure it was monitored for unexpected activity.
  5. Try to log in with a vendor account outside an approved period.
  *Example:* `VPN account list; vendor access schedule; session recording of the last vendor session`  
  *Expected:* Third-party remote accounts are enabled only for the needed period and disabled otherwise. Their use is monitored.  
  *Refs:* pci_dss: 8.2.7; nist_800_53: AC-17, MA-4

- [ ] **PCI-AUTH-007** Check that sessions need new authentication after 15 minutes of idle time  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find terminals and sessions that stay open for more than 15 minutes with no activity.  
  *Steps:*
  1. Find the idle timeout settings for each application, operating system and remote access tool in scope.
  2. Make sure each value is 15 minutes or less.
  3. Log in to a test system and stay idle for 16 minutes.
  4. Try to use the session. Make sure the system asks for authentication again.
  5. Try the same on a session that the user locked, and on a remote desktop session.
  *Example:* `Application session timeout setting; Windows screen lock policy; sshd ClientAliveInterval; TMOUT`  
  *Expected:* A session that is idle for more than 15 minutes needs authentication again. All in-scope systems have a timeout of 15 minutes or less.  
  *Refs:* pci_dss: 8.2.8; nist_800_53: AC-11, AC-12

- [ ] **PCI-AUTH-008** Check the lockout limit and duration for invalid logins  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find login functions that allow more than 10 invalid attempts or unlock too early.  
  *Steps:*
  1. Find the lockout settings for each login function in scope.
  2. Make sure the lockout starts after no more than 10 invalid attempts.
  3. Send 10 wrong passwords to a test account. Then send the correct password.
  4. Make sure the account stays locked for at least 30 minutes or until an administrator confirms the user.
  5. Try the same on the API and on remote access.
  *Example:* `Active Directory account lockout policy; application lockout setting; hydra against a test account`  
  *Expected:* An account locks after no more than 10 invalid attempts. It stays locked for at least 30 minutes or until the identity is confirmed.  
  *Refs:* pci_dss: 8.3.4; cwe: CWE-307; nist_800_53: AC-7

- [ ] **PCI-AUTH-009** Check the password length and character type rules against PCI DSS  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find password settings that allow fewer than 12 characters or no mix of numbers and letters.  
  *Steps:*
  1. Find the password settings for each system and application that uses passwords as a factor.
  2. Make sure the minimum length is 12 characters, or 8 where the system cannot support 12.
  3. Try to set a password of 11 characters. Make sure the system refuses it.
  4. Try to set a password of only letters and one of only digits. Make sure the system refuses both.
  5. Make sure the rule is enforced on the server.
  *Example:* `Active Directory password policy; /etc/security/pwquality.conf; the application password rule`  
  *Expected:* Passwords need at least 12 characters, or 8 where 12 is not supported, and contain both numbers and letters.  
  *Refs:* pci_dss: 8.3.6; cwe: CWE-521; nist_800_53: IA-5

- [ ] **PCI-AUTH-010** Check that a new password differs from the last four passwords  
  *Severity if fail:* Low | *Type:* Manual, Config Review  
  *Objective:* Find systems that allow users to reuse a recent password.  
  *Steps:*
  1. Find the password history setting for each system in scope.
  2. Make sure the history size is at least four.
  3. Change the password of a test account five times.
  4. Try to set the second password again. Make sure the system refuses it.
  5. Try to set the first password. Make sure the system accepts it only after four changes.
  *Example:* `net accounts; /etc/pam.d/common-password remember=4; application password history table`  
  *Expected:* A user cannot set a new password that matches any of the last four passwords.  
  *Refs:* pci_dss: 8.3.7; nist_800_53: IA-5

- [ ] **PCI-AUTH-011** Check that single-factor passwords change every 90 days or get dynamic analysis  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find accounts that use a password as the only factor and keep it more than 90 days with no risk analysis.  
  *Steps:*
  1. List the systems where a password is the only authentication factor.
  2. Find the password age rule of each. Make sure it is 90 days or less.
  3. If the system uses dynamic analysis, examine how it decides on access in real time.
  4. Examine the posture signals that the analysis uses.
  5. Look for accounts with a password older than 90 days and no dynamic analysis.
  *Example:* `Active Directory maxPwdAge; account password last set date; risk-based access policy export`  
  *Expected:* Single-factor passwords change at least every 90 days, or the posture of the account is analyzed and access is set in real time.  
  *Refs:* pci_dss: 8.3.9; nist_800_53: IA-5

- [ ] **PCI-AUTH-012** Check that a service provider guides customers on single-factor passwords  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Find customer password guidance that omits change timing and the conditions for a change.  
  *Steps:*
  1. Find out if customer users can reach cardholder data with a password as the only factor.
  2. Ask for the guidance that the provider gives to these users.
  3. Make sure the guidance tells users when and how often to change the password.
  4. Make sure it states the conditions for a password change.
  5. Or make sure the provider uses dynamic analysis of the account posture instead (see 8.3.10.1).
  *Example:* `Customer onboarding documents; portal help pages; password policy of the customer portal`  
  *Expected:* The provider gives customer users guidance on password change timing and conditions. Passwords change every 90 days or accounts are analyzed dynamically.  
  *Refs:* pci_dss: 8.3.10, 8.3.10.1; nist_800_53: IA-5

- [ ] **PCI-AUTH-013** Check that tokens, smart cards and certificates belong to one user  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find authentication tokens that several people share or that others can use.  
  *Steps:*
  1. List the physical and logical tokens, smart cards and certificates in use.
  2. Compare each with the user it is assigned to.
  3. Look for tokens or certificates that more than one person uses.
  4. Make sure a PIN, a biometric or another control stops others from using the factor.
  5. Look for client certificates and keys saved in shared folders.
  *Example:* `Token inventory; certificate subject check; PIN policy; keystore file search`  
  *Expected:* Each token, smart card or certificate is assigned to one user. Controls stop other persons from using the factor.  
  *Refs:* pci_dss: 8.3.11; nist_800_53: IA-5

- [ ] **PCI-AUTH-014** Check that interactive use of application and system accounts is limited  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find service accounts that people use to log in with no need, approval or attribution.  
  *Steps:*
  1. List application and system accounts that can log in interactively.
  2. Make sure interactive login is blocked unless an exceptional circumstance needs it.
  3. Make sure each exception has a business reason and management approval.
  4. Make sure use is limited in time and the identity of the person is confirmed before access.
  5. Pick one recent use. Make sure the log links each action to one person.
  *Example:* `grep -v nologin /etc/passwd; service account shell and logon type audit; vault check-out log`  
  *Expected:* Interactive use of application and system accounts is blocked by default. Exceptions are approved, time limited and attributable to a person.  
  *Refs:* pci_dss: 8.6.1; nist_800_53: AC-2, IA-2


## CFG

- [ ] **PCI-CFG-001** Check that each server has one primary function or isolated security levels  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find systems that run functions with different security needs without separation.  
  *Steps:*
  1. List the primary function of each system in scope, such as web server, database server and DNS server.
  2. Find systems that run more than one primary function.
  3. For each, make sure the functions are isolated in virtual machines, containers or separate processes with different privileges.
  4. Make sure the functions on one system need the same security level.
  5. Try to reach the data of the more sensitive function from the less sensitive one.
  *Example:* `docker ps; systemctl list-units --type=service; hypervisor VM list; compare with the configuration standard`  
  *Expected:* Each system has one primary function, or functions with different security needs are isolated from each other.  
  *Refs:* pci_dss: 2.2.3; nist_800_53: SC-2, CM-7


## CHG

- [ ] **PCI-CHG-001** Check that production changes follow the change control procedure  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Find changes to production systems that skip reason, security impact, approval, testing or a back-out plan.  
  *Steps:*
  1. Ask for the change control procedure.
  2. Pick ten recent changes to production systems and software.
  3. Make sure each change has a reason, a description, a security impact record and an approval by authorized parties.
  4. Make sure each change has a test record that shows no negative security impact. For bespoke software, make sure the tests cover 6.2.4.
  5. Make sure each change has a procedure to return to a secure state.
  *Example:* `Change tickets; pipeline approval records; test reports; roll-back plans`  
  *Expected:* Every change has a reason, a security impact record, an authorized approval, a test result and a way to return to a secure state.  
  *Refs:* pci_dss: 6.5.1; nist_800_53: CM-3, CM-4

- [ ] **PCI-CHG-002** Check that PCI DSS controls are confirmed after significant changes  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Find new or changed systems that go live with no check of the PCI DSS controls.  
  *Steps:*
  1. Ask for the definition of a significant change.
  2. Pick two significant changes from the last 12 months.
  3. Find the record that confirms that the applicable PCI DSS requirements are in place on the new or changed systems.
  4. Make sure the scope, the network and data flow diagrams and the inventories were updated.
  5. Make sure the change closed only after the confirmation.
  *Example:* `Post-change review checklist; updated data flow diagram; scan and test results after the change`  
  *Expected:* After each significant change, the applicable requirements are confirmed in place and the documentation is updated.  
  *Refs:* pci_dss: 6.5.2; nist_800_53: CM-3, CA-6

- [ ] **PCI-CHG-003** Check that access control enforces the split of pre-production and production  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find pre-production systems that reach or share accounts with production.  
  *Steps:*
  1. List the pre-production and production environments.
  2. Examine the network rules between them. Make sure they allow only approved flows.
  3. Make sure the accounts, keys and secrets of the two environments are different.
  4. Log in with a pre-production account. Try to reach a production system and its data.
  5. Examine the access control lists of each environment.
  *Example:* `Network and cloud account review; try an SSH or API call from a staging host to production`  
  *Expected:* Access controls enforce the split. Pre-production accounts and credentials cannot reach production.  
  *Refs:* pci_dss: 6.5.3; nist_800_53: CM-2, SC-7

- [ ] **PCI-CHG-004** Check that live PANs are not in pre-production environments  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find real card numbers in test and development data.  
  *Steps:*
  1. Ask whether any pre-production environment is part of the cardholder data environment.
  2. If not, search the test databases, files, logs and backups for PAN values that pass a Luhn check.
  3. Check each hit against known test card ranges.
  4. Ask how the test data is made. Make sure no live data is copied from production.
  5. Make sure a process removes found live PANs.
  *Example:* `PAN discovery tool run on the staging database; compare BIN ranges with the test card list`  
  *Expected:* No live PAN exists in pre-production unless that environment is in the cardholder data environment and fully protected.  
  *Refs:* pci_dss: 6.5.5; cwe: CWE-359; nist_800_53: SA-3

- [ ] **PCI-CHG-005** Check that test data and test accounts are removed before go-live  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find test accounts, test data and test code that stay in production.  
  *Steps:*
  1. Ask for the process that removes test data and test accounts before a system goes live.
  2. List all accounts on a new production system. Find test, demo and vendor accounts.
  3. Search the production database for test records and test card numbers.
  4. Look at the last release record for a clean-up step.
  5. Try to log in with known test credentials on a test copy of the release.
  *Example:* `SELECT user FROM users WHERE name LIKE 'test%'; check for demo and qa accounts in the identity provider`  
  *Expected:* No test account, test data or test card number exists on a production system. A release step removes them.  
  *Refs:* pci_dss: 6.5.6; cwe: CWE-489


## DATA

- [ ] **PCI-DATA-001** Check that stored account data is limited by retention and disposal rules  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find account data that is kept longer than the business need or the documented retention period.  
  *Steps:*
  1. Ask for the data retention and disposal policy for account data.
  2. Make sure the policy sets a retention period and a business reason for each data store.
  3. Search each data store for account data that is older than the retention period.
  4. Make sure a job or process removes or overwrites expired data on a schedule.
  5. Make sure the quarterly process finds stored account data that is not in the policy.
  *Example:* `SELECT count(*) FROM payments WHERE created_at < now() - interval '13 months'; scan file shares with a PAN discovery tool`  
  *Expected:* Account data is kept only for the documented period and need. Expired data is removed in a secure way, and a quarterly process finds unknown copies.  
  *Refs:* pci_dss: 3.2.1; cwe: CWE-312

- [ ] **PCI-DATA-002** Check that sensitive authentication data is unrecoverable after authorization  
  *Severity if fail:* Critical | *Type:* Manual, Config Review  
  *Objective:* Find sensitive authentication data that stays on a system after the authorization process ends.  
  *Steps:*
  1. Ask which systems receive sensitive authentication data and how long it stays on them.
  2. Examine the documented process that removes this data after authorization.
  3. Make an authorized test transaction with a test card on the test system.
  4. Search databases, files, logs, queues, caches and memory dumps for the test values after authorization.
  5. Make sure the secure deletion method makes the data unrecoverable.
  *Example:* `grep -r <test track or CVV value> /var/log /data; strings core.dump | grep <test PAN>`  
  *Expected:* No sensitive authentication data remains after authorization, even in encrypted form. The deletion method makes the data unrecoverable.  
  *Refs:* pci_dss: 3.3.1; cwe: CWE-312

- [ ] **PCI-DATA-003** Check that full track data is not stored after authorization  
  *Severity if fail:* Critical | *Type:* Manual, Config Review  
  *Objective:* Find full magnetic-stripe or chip track data that is kept after the authorization process ends.  
  *Steps:*
  1. Make a test transaction with a test card on the test system.
  2. Look at the payment application files, databases and logs for the track 1 and track 2 format.
  3. Search for the sentinel patterns of track data, for example a leading % or ; and an = separator.
  4. Look at debug output, crash dumps, backups and error reports for the same patterns.
  5. Examine the capture code or configuration for fields that keep track data.
  *Example:* `grep -rE '%B[0-9]{13,19}\^|;[0-9]{13,19}=' /data /var/log`  
  *Expected:* No data store, log, backup or dump holds the full contents of any track after authorization is complete.  
  *Refs:* pci_dss: 3.3.1.1; cwe: CWE-312

- [ ] **PCI-DATA-004** Check that the card verification code is not stored after authorization  
  *Severity if fail:* Critical | *Type:* Manual, Config Review  
  *Objective:* Find CVV, CVC or similar card verification values that stay after the authorization process ends.  
  *Steps:*
  1. Make a test transaction with a known test card verification code.
  2. Search database columns, files, logs and message queues for the test code.
  3. Look at the request logs, the proxy logs and the browser or app crash reports for the code.
  4. Examine the application code and the log filters for fields called cvv, cvc, cid or security code.
  5. Look at backups and replicas of the data stores.
  *Example:* `grep -rn -i -E 'cvv|cvc|cid|security_code' /data /var/log; search for the test value in database dumps`  
  *Expected:* No data store, log, backup or report holds the card verification code after authorization is complete.  
  *Refs:* pci_dss: 3.3.1.2; cwe: CWE-312, CWE-532

- [ ] **PCI-DATA-005** Check that PIN and PIN block data is not kept after authorization  
  *Severity if fail:* Critical | *Type:* Manual, Config Review  
  *Objective:* Find PIN or PIN block data that stays after the authorization process ends.  
  *Steps:*
  1. Ask whether the system receives PIN or PIN block data.
  2. Make a test PIN transaction on the test system if the system supports it.
  3. Search databases, files, logs, queues and dumps for the encrypted PIN block and for PIN fields.
  4. Examine the application code and the log filters for fields called pin or pinblock.
  5. Look at backups and replicas of the data stores.
  *Example:* `grep -rn -i -E 'pin_?block|pinblock|\bpin\b' /data /var/log; search database dumps for the test PIN block`  
  *Expected:* No data store, log, backup or report holds a PIN or a PIN block after authorization is complete.  
  *Refs:* pci_dss: 3.3.1.3; cwe: CWE-312

- [ ] **PCI-DATA-006** Check that sensitive authentication data is encrypted before authorization ends  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find sensitive authentication data that waits in clear text on a system before the authorization is complete.  
  *Steps:*
  1. Ask where sensitive authentication data is stored before authorization is complete.
  2. Make a test transaction and stop it before the authorization response.
  3. Look at the data stores, queues, files and swap space for the test values in clear text.
  4. Examine the encryption algorithm and key length against current industry guidance.
  5. Make sure the stored data is deleted when the authorization is complete.
  *Example:* `Pause the test transaction at the gateway; inspect the queue and database; run strings on the swap file`  
  *Expected:* All sensitive authentication data that is stored before authorization is complete is encrypted with strong cryptography.  
  *Refs:* pci_dss: 3.3.2; cwe: CWE-311, CWE-312

- [ ] **PCI-DATA-007** Check that displayed PANs show only the BIN and last four digits  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Find screens, reports, exports and receipts that show more PAN digits than the business need allows.  
  *Steps:*
  1. Ask for the list of roles that need to see more than the BIN and the last four digits.
  2. Make sure each role on the list has a documented business need.
  3. Log in as a role that is not on the list. Open each screen, report and export that shows a PAN.
  4. Count the visible digits. Make sure only the BIN and the last four digits show.
  5. Look at the API responses and the page source for the full PAN.
  6. Log in as a listed role and make sure the full PAN shows only where the business need exists.
  *Example:* `Compare the API response to the screen; curl -s /api/orders/123 | grep -E '[0-9]{13,19}'`  
  *Expected:* Roles with no documented need see at most the BIN and the last four digits. The full PAN is not in any response sent to those roles.  
  *Refs:* pci_dss: 3.4.1; cwe: CWE-200, CWE-359

- [ ] **PCI-DATA-008** Check that remote access tools block copy and move of the PAN  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find remote sessions that allow a user to copy or move PAN data to a local device.  
  *Steps:*
  1. List the remote-access technologies that reach systems with account data.
  2. Ask for the list of users with documented authorization to copy or move PAN.
  3. Open a remote session as a user who is not on the list.
  4. Try to copy PAN text, drag a file out, map a local drive and use the clipboard and print functions.
  5. Make sure the technical controls block each action and log the try.
  *Example:* `RDP: check drive, clipboard and printer redirection policy; Citrix: check client drive mapping and clipboard policy`  
  *Expected:* Technical controls block copy and move of PAN in remote sessions. Only users with documented authorization and a defined business need can do it.  
  *Refs:* pci_dss: 3.4.2; cwe: CWE-200

- [ ] **PCI-DATA-009** Check that the PAN is unreadable in every place it is stored  
  *Severity if fail:* Critical | *Type:* Manual, Config Review  
  *Objective:* Find stored PAN in clear text in databases, files, logs, backups, caches and temporary files.  
  *Steps:*
  1. Ask for the documentation of the method that makes the PAN unreadable.
  2. Make sure the method is a keyed hash, truncation, an index token or strong cryptography with key management.
  3. Insert a test PAN. Search databases, files, logs, queues, caches and backups for the test value.
  4. Search the payment application logs and the debug output for PAN patterns that pass a Luhn check.
  5. Make sure the algorithm and key length meet current industry guidance.
  *Example:* `grep -rE '\b[3-6][0-9]{12,18}\b' /data /var/log then run a Luhn check; use a data discovery tool such as a PAN scanner`  
  *Expected:* The PAN is unreadable everywhere it is stored, including logs, backups and temporary files. The method is hash, truncation, token or strong cryptography.  
  *Refs:* pci_dss: 3.5.1; cwe: CWE-312, CWE-311, CWE-532; nist_800_53: SC-28

- [ ] **PCI-DATA-010** Check that hashed and truncated copies of one PAN cannot be correlated  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find environments where a hash and a truncated value of the same PAN let a person rebuild the PAN.  
  *Steps:*
  1. Find out if the same PAN is stored in both a hashed form and a truncated form.
  2. Ask for the controls that stop the correlation of these two forms.
  3. Try to join the hashed records and the truncated records to rebuild the PAN.
  4. Make sure the access rights to the two data sets are separate.
  5. Make sure the hash does not replace the truncated part of the PAN.
  *Example:* `Join test records on the last four digits and the BIN; try a brute force of the missing digits against the hash`  
  *Expected:* No user or process can rebuild the original PAN from the hashed and truncated copies. Access to the two forms is separate.  
  *Refs:* pci_dss: 3.5.1; cwe: CWE-328

- [ ] **PCI-DATA-011** Check that PAN hashes are keyed cryptographic hashes of the whole PAN  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find PAN hashes that use no key, a weak hash function or only part of the PAN.  
  *Steps:*
  1. Find the code or the database function that hashes the PAN.
  2. Make sure the hash is a keyed hash such as HMAC-SHA-256 and covers the entire PAN.
  3. Make sure the key is not in the code or in the same data store as the hashes.
  4. Compute a plain SHA-256 of a test PAN. Make sure it does not match the stored hash.
  5. Examine the key management process for the hash key.
  *Example:* `echo -n <test PAN> | sha256sum; compare to the stored value; search the source for the HMAC key`  
  *Expected:* PAN hashes are keyed hashes of the entire PAN. The key is managed under the key management rules and a plain hash does not match.  
  *Refs:* pci_dss: 3.5.1.1; cwe: CWE-328, CWE-759

- [ ] **PCI-DATA-012** Check that disk or partition encryption alone does not protect stored PAN  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Find non-removable storage where only disk-level or partition-level encryption protects the PAN.  
  *Steps:*
  1. List the storage that holds PAN and the encryption method on each volume.
  2. Find volumes that use only disk-level or partition-level encryption.
  3. Make sure these volumes are removable media.
  4. For non-removable volumes, make sure file-level, column-level or field-level encryption also protects the PAN.
  5. Mount a volume on a running system and read a PAN file as a normal user.
  *Example:* `lsblk -f; cryptsetup status <volume>; SELECT column-level encryption settings in the database`  
  *Expected:* Disk-level or partition-level encryption is used alone only on removable media. Other storage also has file, column or field-level protection.  
  *Refs:* pci_dss: 3.5.1.2; cwe: CWE-311; nist_800_53: SC-28

- [ ] **PCI-DATA-013** Check the management of disk and partition encryption for PAN  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Find disk encryption where the operating system login or a user account unlocks the data.  
  *Steps:*
  1. Find the access control for the disk encryption product.
  2. Make sure logical access is managed apart from the operating system login and access control.
  3. Make sure the decryption keys are not tied to user accounts.
  4. Find where the unlock passphrase or key is stored. Make sure the storage is secure.
  5. Log in as an operating system administrator. Try to read the data without the separate unlock factor.
  *Example:* `cryptsetup luksDump <device>; check the key slots; check the TPM and key escrow settings`  
  *Expected:* Access to the decryption is separate from the operating system accounts. Keys are not tied to user accounts and unlock factors are stored securely.  
  *Refs:* pci_dss: 3.5.1.3; cwe: CWE-311, CWE-522


## KEY

- [ ] **PCI-KEY-001** Check that keys for stored account data resist disclosure and misuse  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find keys that protect stored account data and that people or processes can read or use without a need.  
  *Steps:*
  1. Ask for the procedures that protect the keys used to encrypt stored account data.
  2. List all data-encrypting keys and key-encrypting keys with their owners and uses.
  3. Examine who and what can read each key and who and what can call it for decrypt operations.
  4. Make sure each key has one purpose and the application can use it only through its own identity.
  5. Look at the key use logs for calls from unknown identities.
  *Example:* `aws kms get-key-policy; vault policy read; openssl list key stores; review HSM partition roles`  
  *Expected:* The procedures protect the keys against disclosure and misuse. Only named identities with a need can use or read each key.  
  *Refs:* pci_dss: 3.6.1; cwe: CWE-522; nist_800_53: SC-12

- [ ] **PCI-KEY-002** Check the cryptographic architecture document of the service provider  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Find service providers with no current description of the cryptography that protects account data.  
  *Steps:*
  1. Ask for the cryptographic architecture document.
  2. Make sure it lists the algorithms, protocols, key strengths and the key expiry date.
  3. Make sure it names each key with its purpose and where it is used.
  4. Make sure it lists each hardware security module and other secure cryptographic device.
  5. Compare five entries with the real systems.
  *Example:* `Document review; compare with the cryptographic inventory and the key store export`  
  *Expected:* A current document describes the algorithms, protocols, key strengths, key uses, expiry dates and secure devices. The document matches the real systems.  
  *Refs:* pci_dss: 3.6.1.1; nist_800_53: SC-12

- [ ] **PCI-KEY-003** Check that secret and private keys are stored only in approved forms  
  *Severity if fail:* Critical | *Type:* Manual, Config Review  
  *Objective:* Find data-encrypting keys that are stored in clear text next to the data they protect.  
  *Steps:*
  1. List where each secret and private key for account data is stored.
  2. Make sure each key has a key-encrypting key, a secure cryptographic device or split key components.
  3. Make sure the key-encrypting key is at least as strong as the key it protects.
  4. Make sure the key-encrypting key is stored apart from the data-encrypting key.
  5. Search configuration files, code and environment variables for a clear-text key.
  *Example:* `grep -rE 'BEGIN (RSA |EC )?PRIVATE KEY' /app /etc; check the HSM or KMS key wrapping settings`  
  *Expected:* Every secret and private key exists only as an encrypted key, in a secure cryptographic device, or as split components. The key-encrypting key is separate.  
  *Refs:* pci_dss: 3.6.1.2, 3.7.3; cwe: CWE-321, CWE-312; nist_800_53: SC-12

- [ ] **PCI-KEY-004** Check that few custodians can access clear-text key components  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Find clear-text key components that too many people can reach.  
  *Steps:*
  1. Ask for the list of key custodians and the key components each person holds.
  2. Compare the list with the key ceremony records and the access list of the key store.
  3. Make sure no person has access to a full clear-text key unless the process needs it.
  4. Make sure each custodian has a documented role and a business need.
  5. Look for custodians who changed role or left the company.
  *Example:* `Review the key custodian list, the HSM smart card holders and the key ceremony logs`  
  *Expected:* Only the fewest necessary custodians can access clear-text key components. Each custodian has a documented need and the list is current.  
  *Refs:* pci_dss: 3.6.1.3; nist_800_53: SC-12

- [ ] **PCI-KEY-005** Check that keys exist in the fewest possible places  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find copies of cryptographic keys in extra places such as backups, build servers and developer systems.  
  *Steps:*
  1. Ask for the list of approved key storage locations.
  2. Search the production hosts, the backup media, the code repositories and the build servers for key files.
  3. Search developer systems and shared drives for exported keys.
  4. Compare the result with the approved list.
  5. Make sure each extra copy has a documented reason.
  *Example:* `find / -name '*.pem' -o -name '*.key' -o -name '*.p12' -o -name '*.jks' 2>/dev/null; gitleaks detect`  
  *Expected:* Keys exist only in the approved locations. No unneeded copy exists in backups, code repositories or on developer systems.  
  *Refs:* pci_dss: 3.6.1.4; cwe: CWE-321; nist_800_53: SC-12

- [ ] **PCI-KEY-006** Check that strong keys are generated for account data protection  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find keys that are weak, predictable or made with a poor random source.  
  *Steps:*
  1. Ask for the key generation procedure.
  2. Make sure the keys come from a validated random number generator in a hardware module or a vetted library.
  3. Make sure the key length meets current industry guidance for the algorithm.
  4. Generate a test key by the procedure and examine the algorithm and length.
  5. Search for keys that came from a password or a fixed seed.
  *Example:* `openssl rand -hex 32; aws kms describe-key; pkcs11-tool --list-mechanisms`  
  *Expected:* Keys are made with a validated random source in a secure device or vetted library. Key lengths meet current industry guidance.  
  *Refs:* pci_dss: 3.7.1; cwe: CWE-326, CWE-330; nist_800_53: SC-12

- [ ] **PCI-KEY-007** Check that keys are distributed in a secure way  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find key distribution that sends keys in clear text or over open channels.  
  *Steps:*
  1. Ask for the key distribution procedure.
  2. Follow one key from the generation point to the system that uses it.
  3. Look at each hop. Make sure the key is wrapped or split during transfer.
  4. Search e-mail, chat, tickets and shared drives for clear-text keys.
  5. Make sure only the intended recipient can unwrap the key.
  *Example:* `Trace a key import into the HSM; capture the transfer; search the ticket system for 'BEGIN PRIVATE KEY'`  
  *Expected:* Keys move only in encrypted or split form between authorized systems and custodians. No key travels in clear text.  
  *Refs:* pci_dss: 3.7.2; cwe: CWE-319; nist_800_53: SC-12

- [ ] **PCI-KEY-008** Check that keys change at the end of their cryptoperiod  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find keys that stay in use after the end of the defined cryptoperiod.  
  *Steps:*
  1. Ask for the cryptoperiod of each key type and the reason for its length.
  2. Look at the creation date and last rotation date of each key.
  3. Find keys that are older than their cryptoperiod.
  4. Make sure the process also changes a key when a compromise is suspected.
  5. Do a test rotation. Make sure the application still reads the old data.
  *Example:* `aws kms list-keys --query ... ; vault read transit/keys/<name>; compare the creation date to the policy`  
  *Expected:* Each key changes at the end of its defined cryptoperiod or at a suspected compromise. No key is older than its cryptoperiod.  
  *Refs:* pci_dss: 3.7.4; cwe: CWE-324; nist_800_53: SC-12

- [ ] **PCI-KEY-009** Check that retired keys are destroyed or archived under protection  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find old keys that stay active, readable or unprotected after they are retired.  
  *Steps:*
  1. Ask for the procedure to retire, replace or destroy keys.
  2. Pick five retired keys from the key log.
  3. Make sure each key is destroyed, or kept only for decryption of old data in a protected archive.
  4. Make sure keys with known or suspected weakness are replaced.
  5. Make sure a retired key cannot encrypt new data.
  *Example:* `Check the key state in the KMS (disabled, pending deletion); search backups for the retired key files`  
  *Expected:* Retired and replaced keys are destroyed or archived under protection. A retired key cannot protect new data.  
  *Refs:* pci_dss: 3.7.5; nist_800_53: SC-12

- [ ] **PCI-KEY-010** Check split knowledge and dual control for manual clear-text key operations  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Find manual key operations that one person can do alone.  
  *Steps:*
  1. Find all manual operations on clear-text keys, such as load, export and import.
  2. Ask for the procedure for each operation.
  3. Make sure the procedure uses split knowledge and dual control.
  4. Look at the records of the last two key ceremonies for two named custodians.
  5. Make sure one custodian alone cannot complete the operation.
  *Example:* `Review the HSM quorum settings (M of N); review the key ceremony records`  
  *Expected:* Each manual clear-text key operation needs split knowledge and dual control. One person cannot complete it alone.  
  *Refs:* pci_dss: 3.7.6; nist_800_53: SC-12

- [ ] **PCI-KEY-011** Check that nobody can replace a key without approval  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find ways to put an unauthorized key in place of a valid key.  
  *Steps:*
  1. Ask for the controls that prevent unauthorized key substitution.
  2. Examine who can import, replace or alias a key in the key store.
  3. Try to replace a test key as a user without the key administrator role.
  4. Make sure the key store logs each import, replace and alias change.
  5. Make sure a person other than the requester must approve the change.
  *Example:* `aws kms update-alias test; vault write transit/keys/test/import; check the audit log for the event`  
  *Expected:* Only authorized key administrators can replace a key. Each change needs approval and creates a log entry.  
  *Refs:* pci_dss: 3.7.7; cwe: CWE-494; nist_800_53: SC-12

- [ ] **PCI-KEY-012** Check that a service provider documents key sharing with its customers  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Find service providers that share keys with customers without guidance on how to handle the keys.  
  *Steps:*
  1. Find out if the provider shares keys with customers for transmission or storage of account data.
  2. Ask for the key management guidance that the provider gives to the customers.
  3. Make sure the guidance covers secure transmission, storage and update of the shared keys.
  4. Make sure it follows the key management rules for generation, distribution, storage, change and retirement.
  5. Compare the guidance with how the provider shares a real key.
  *Example:* `Document review of the customer onboarding and key exchange procedure`  
  *Expected:* The provider gives customers guidance on how to handle shared keys. The guidance covers the full key lifecycle.  
  *Refs:* pci_dss: 3.7.9; nist_800_53: SC-12


## LOG

- [ ] **PCI-LOG-001** Check that audit logs record all individual access to cardholder data  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find reads and changes of cardholder data that leave no audit record.  
  *Steps:*
  1. List the applications and data stores that hold cardholder data.
  2. Log in as a test user. View, export, change and delete a test cardholder record.
  3. Look at the audit log for one entry for each action.
  4. Make sure each entry names the user and the record.
  5. Do the same through the API and by a direct database query.
  *Example:* `Application audit trail query; database audit log (pgaudit, Oracle audit, SQL Server audit); API gateway logs`  
  *Expected:* Each individual access to cardholder data creates an audit log entry that names the user, action and record.  
  *Refs:* pci_dss: 10.2.1.1; cwe: CWE-778; nist_800_53: AU-2, AU-12

- [ ] **PCI-LOG-002** Check that audit logs record all actions of administrative users  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find administrative actions, including interactive use of service accounts, that leave no record.  
  *Steps:*
  1. List the administrative roles and the accounts with administrative access.
  2. Log in as an administrator on a test system. Change a setting, add a user and run a privileged command.
  3. Do the same with a service account if interactive use is possible.
  4. Look at the logs for one entry for each action.
  5. Make sure the entry shows the person behind a shared or service account.
  *Example:* `sudo log; auditd rules for execve by uid 0; cloud audit trail; database admin audit`  
  *Expected:* Every action of an administrative user is logged, including interactive use of application and system accounts.  
  *Refs:* pci_dss: 10.2.1.2; cwe: CWE-778; nist_800_53: AU-2, AU-12

- [ ] **PCI-LOG-003** Check that audit logs record all access to the audit logs  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find reads and changes of the audit logs that leave no record.  
  *Steps:*
  1. Find where the audit logs are stored and who can reach them.
  2. As a test user with log access, open a log file or query the log platform.
  3. Try to change a setting of the log platform.
  4. Look at the audit trail of the log system for one entry for each action.
  5. Make sure the entry names the user.
  *Example:* `Log platform audit trail; file access auditing on the log directory; object store access logs`  
  *Expected:* All access to the audit logs creates an entry that names the user and the action.  
  *Refs:* pci_dss: 10.2.1.3; cwe: CWE-778; nist_800_53: AU-9, AU-12

- [ ] **PCI-LOG-004** Check that audit logs record changes to credentials and authentication factors  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find changes to identities, factors and privileges that leave no record.  
  *Steps:*
  1. Use a test account to create an ID, change a password and enrol a factor. Remove a factor and change a privilege.
  2. Look at the audit log for one entry for each action.
  3. Make sure the entry names the person who made the change and the affected account.
  4. Make sure the entry never holds the password or the secret.
  5. Include elevation of privilege and add or change of administrator rights.
  *Example:* `Directory service event IDs 4720, 4723, 4724, 4728; application audit trail; identity provider event log`  
  *Expected:* Each addition, change or deletion of an identity or an authentication factor and each privilege elevation is logged without secrets.  
  *Refs:* pci_dss: 10.2.1.5; cwe: CWE-778, CWE-532; nist_800_53: AU-2, IA-5

- [ ] **PCI-LOG-005** Check that audit logs record the start, stop and pause of logging  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find ways to stop or pause logging without a record.  
  *Steps:*
  1. Find the logging agents and log services on a test system.
  2. Stop the logging service, then start it again.
  3. Pause or change the audit configuration if the system allows it.
  4. Look in the central log system for an entry for each of these events.
  5. Make sure a new log file or new log source also creates an entry.
  *Example:* `systemctl stop auditd; auditctl -e 0; Windows event 1100 and 1102; check the central log`  
  *Expected:* Every start, stop, pause and initialization of an audit log creates a log entry that is stored in a protected place.  
  *Refs:* pci_dss: 10.2.1.6; cwe: CWE-778; nist_800_53: AU-2, AU-5, AU-12

- [ ] **PCI-LOG-006** Check that audit logs record creation and deletion of system-level objects  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find system-level objects that appear or vanish with no record.  
  *Steps:*
  1. List the system-level objects of the platform, such as database tables, stored procedures, scheduled jobs and services.
  2. On a test system, create a scheduled job, a database object and a service. Then delete them.
  3. Look at the audit log for one entry for each action.
  4. Make sure the entry names the user and the object.
  5. Include object creation by a cloud API.
  *Example:* `auditd watch rules; SQL DDL audit; Windows event 4698 and 7045; cloud audit trail for resource creation`  
  *Expected:* The creation and deletion of each system-level object creates an audit log entry with the user and the object name.  
  *Refs:* pci_dss: 10.2.1.7; cwe: CWE-778; nist_800_53: AU-2, AU-12

- [ ] **PCI-LOG-007** Check that file integrity or change detection alerts on audit log changes  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find audit log changes that raise no alert.  
  *Steps:*
  1. Find the file integrity monitoring or change-detection tool that covers the audit logs.
  2. Make sure it covers all log locations, including the central log store.
  3. On a test system, change an old entry in a log file. Delete a log file.
  4. Make sure the tool raises an alert in the agreed time.
  5. Make sure normal appends of new entries do not raise an alert.
  *Example:* `AIDE or Tripwire configuration; OSSEC syscheck; object lock plus hash chain; echo test >> old.log`  
  *Expected:* A tool alerts personnel when existing log data is changed or deleted. Normal additions do not raise an alert.  
  *Refs:* pci_dss: 10.3.4; cwe: CWE-778; nist_800_53: AU-9, SI-7

- [ ] **PCI-LOG-008** Check the daily review of security and cardholder data system logs  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Find security event logs and critical system logs that no one reviews every day.  
  *Steps:*
  1. Ask for the list of logs that need a daily review and the review procedure.
  2. Make sure it covers security events, systems that handle cardholder data, critical systems and security functions.
  3. Pick seven days in the last 30 days. Find the review record for each day.
  4. Make sure the record shows who reviewed the logs.
  5. Make sure the review covers each log on the list.
  *Example:* `SIEM dashboard review records; ticket log; shift handover notes`  
  *Expected:* All security events and logs of in-scope and critical systems are reviewed at least once a day, with a record.  
  *Refs:* pci_dss: 10.4.1; nist_800_53: AU-6

- [ ] **PCI-LOG-009** Check that automated mechanisms do the log review  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find log review that depends on manual work only.  
  *Steps:*
  1. Find the automated mechanisms that review logs, such as a SIEM or log analysis tool.
  2. Make sure the mechanisms cover the logs that need a daily review.
  3. Send a test event that should match a rule.
  4. Make sure the mechanism raises an alert or a finding.
  5. Examine the rules and the update dates.
  *Example:* `SIEM correlation rules; alert history; use case list`  
  *Expected:* Automated mechanisms review the required logs. They raise findings for test events and the rules are current.  
  *Refs:* pci_dss: 10.4.1.1; nist_800_53: AU-6, SI-4

- [ ] **PCI-LOG-010** Check the periodic review of other system component logs  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Find logs of other components that no one reviews, or a review frequency with no risk analysis.  
  *Steps:*
  1. Ask for the list of the other system components that are not in the daily review.
  2. Find the targeted risk analysis that sets the review frequency.
  3. Make sure the frequency in the procedure matches the analysis.
  4. Find the review records for the last period.
  5. Make sure all components on the list have records.
  *Example:* `Targeted risk analysis document; review schedule; review tickets`  
  *Expected:* The logs of other components are reviewed at the frequency in the targeted risk analysis. Records exist for each component.  
  *Refs:* pci_dss: 10.4.2, 10.4.2.1; nist_800_53: AU-6

- [ ] **PCI-LOG-011** Check that exceptions found in log reviews are addressed  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Find anomalies from log reviews that nobody handles.  
  *Steps:*
  1. Pick five anomalies or exceptions that log reviews found in the last 90 days.
  2. Find the ticket or incident for each one.
  3. Make sure each was investigated and resolved or accepted by an authorized person.
  4. Compare the time to resolve with the procedure.
  5. Look for reviews that found nothing for a long time and ask why.
  *Example:* `Ticket system; incident log; SIEM case history`  
  *Expected:* Each exception and anomaly from a log review is investigated and closed or accepted, with a record.  
  *Refs:* pci_dss: 10.4.3; nist_800_53: AU-6, IR-4

- [ ] **PCI-LOG-012** Check that audit logs are kept 12 months, with 3 months online  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find audit logs that are kept too short or that need a long restore to read.  
  *Steps:*
  1. Ask for the log retention policy.
  2. Make sure it states at least 12 months of history.
  3. Look at the oldest log record in the log store. Make sure it is at least 12 months old.
  4. Run a search for the last three months. Make sure the result comes back at once.
  5. Restore a record from an older period and make sure it is complete.
  *Example:* `SIEM retention setting; S3 lifecycle rule; log index list; query the date range`  
  *Expected:* Audit log history for at least 12 months exists. The most recent three months are immediately available for analysis.  
  *Refs:* pci_dss: 10.5.1; cwe: CWE-778; nist_800_53: AU-11

- [ ] **PCI-LOG-013** Check that systems use trusted time sources and the same time  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find systems that take time from an untrusted source or drift apart.  
  *Steps:*
  1. Find the time sources of each class of system in scope.
  2. Make sure systems use designated central time servers, and those servers use industry-accepted time sources.
  3. Make sure the time servers accept time only from the approved sources.
  4. Compare the clock offset of ten systems.
  5. Make sure systems peer with each other only through the designated time servers.
  *Example:* `chronyc sources -v; ntpq -p; w32tm /query /status; compare date -u across hosts`  
  *Expected:* Systems get time from designated central servers with industry-accepted sources. The clocks on all systems are consistent.  
  *Refs:* pci_dss: 10.6.2; nist_800_53: AU-8, SC-45

- [ ] **PCI-LOG-014** Check that time settings and time data are protected  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find time settings that unauthorized persons can read or change.  
  *Steps:*
  1. List who can read and change the time settings and the time data on critical systems.
  2. Make sure access is limited to personnel with a business need.
  3. On a test system, change the time as an ordinary user. Make sure it fails.
  4. Change a time setting as an administrator. Make sure it creates a log entry.
  5. Make sure the log entry is monitored and reviewed.
  *Example:* `chrony.conf permissions; Windows event 4616; auditd rule for settimeofday and clock_settime`  
  *Expected:* Only personnel with a business need can reach time data. Changes to time settings on critical systems are logged, monitored and reviewed.  
  *Refs:* pci_dss: 10.6.3; cwe: CWE-778; nist_800_53: AU-8, AU-9

- [ ] **PCI-LOG-015** Check that failures of critical security controls raise alerts  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find control failures that no one notices.  
  *Steps:*
  1. List the critical security control systems: network controls, IDS or IPS, change detection, anti-malware, access control and audit logging.
  2. Include audit log review tools, segmentation controls and automated security test tools if used.
  3. On a test system, stop one control. Make sure an alert reaches the response team in the agreed time.
  4. Repeat for each type of control on the list.
  5. Look at the last alert history for real failures.
  *Example:* `Stop the agent or service on a test system; check the monitoring alert; heartbeat monitor configuration`  
  *Expected:* A failure of each critical security control creates an alert that reaches personnel promptly.  
  *Refs:* pci_dss: 10.7.2, 10.7.1; nist_800_53: SI-4, AU-5

- [ ] **PCI-LOG-016** Check the response to failures of critical security controls  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Find control failures that stay open or have no cause analysis.  
  *Steps:*
  1. Pick three real failures of critical security controls from the last 12 months.
  2. Make sure each control was restored.
  3. Make sure the record shows the cause, the duration and the security gap during the failure.
  4. Make sure the record shows that the team looked for new risks and fixed the cause.
  5. Make sure the monitoring resumed and the failure was recorded.
  *Example:* `Incident tickets; post-incident reviews; control uptime reports`  
  *Expected:* Each failure is answered with a restore of the control, a root cause record, a check for security issues and a fix.  
  *Refs:* pci_dss: 10.7.3; nist_800_53: IR-4, SI-4


## RISK

- [ ] **PCI-RISK-001** Check the targeted risk analysis behind flexible requirement frequencies  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Find requirements with a risk-based frequency that has no documented analysis.  
  *Steps:*
  1. List the requirements where the entity sets its own frequency, such as log review and password change.
  2. Ask for the targeted risk analysis document for each one.
  3. Make sure each document names the assets, the threats, the likelihood and the review date.
  4. Make sure each document sets the frequency and the reason.
  5. Make sure a person reviewed the analysis in the last 12 months.
  *Example:* `Targeted risk analysis records; compare the frequency in the procedure with the analysis`  
  *Expected:* A current targeted risk analysis supports every risk-based frequency. Each analysis states the threats, the reason for the frequency and the review date.  
  *Refs:* pci_dss: 12.3.1; nist_800_53: RA-3


## SCAN

- [ ] **PCI-SCAN-001** Check scans after a significant change and rescans of fixed findings  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find significant changes that go live with no vulnerability scan.  
  *Steps:*
  1. Ask for the definition of a significant change.
  2. Pick two significant changes from the last 12 months.
  3. Find an internal and an external vulnerability scan after each change.
  4. Make sure high-risk and critical findings were fixed and rescanned.
  5. Make sure the scan was done by qualified persons who are independent of the change.
  *Example:* `Change record; scan report dates; rescan reports`  
  *Expected:* Internal and external scans run after each significant change. High-risk and critical findings are fixed and rescanned.  
  *Refs:* pci_dss: 11.3.1.3, 11.3.2.1; nist_800_53: RA-5, CM-4

- [ ] **PCI-SCAN-002** Check that approved scanning vendor scans pass every quarter  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Find external scans that are missing, not from an approved vendor, or not passing.  
  *Steps:*
  1. Ask for the ASV scan reports of the last 12 months.
  2. Make sure at least one scan exists for each three-month period.
  3. Make sure each scan came from a PCI SSC approved scanning vendor.
  4. Make sure the scan has a passing status or the failed findings were fixed and rescanned.
  5. Compare the scanned addresses with the list of public addresses in scope.
  *Example:* `ASV attestation of scan compliance; scan scope list compared to the external address inventory`  
  *Expected:* An approved scanning vendor scanned every in-scope public address once every three months. The latest scans pass.  
  *Refs:* pci_dss: 11.3.2; nist_800_53: RA-5


## SWDEV

- [ ] **PCI-SWDEV-001** Check that bespoke software follows a secure development process  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Find development processes that ignore industry standards, PCI DSS needs or security in the life cycle phases.  
  *Steps:*
  1. Ask for the secure development procedures for bespoke and custom software.
  2. Make sure they follow an industry standard or best practice for secure development.
  3. Make sure they cover PCI DSS needs such as secure authentication and logging.
  4. Make sure each phase of the life cycle has a security task.
  5. Pick one recent release and find the records of each security task.
  *Example:* `Compare the procedure with OWASP SAMM or NIST SSDF; examine tickets, design reviews and test reports of one release`  
  *Expected:* The procedures follow an industry standard and PCI DSS. Each life cycle phase has a security task and the last release has the records.  
  *Refs:* pci_dss: 6.2.1; nist_800_53: SA-3, SA-8

- [ ] **PCI-SWDEV-002** Check that code is reviewed before release and findings are fixed  
  *Severity if fail:* High | *Type:* Manual, Code Review  
  *Objective:* Find releases of bespoke software that reach production without a code review for vulnerabilities.  
  *Steps:*
  1. Ask for the code review procedure for bespoke and custom software.
  2. Make sure it requires review against secure coding guidelines before each release.
  3. Make sure the review looks for both existing and new types of software vulnerabilities.
  4. Pick five recent releases. Find the review record for each one.
  5. Make sure each finding was corrected before the release.
  *Example:* `Pull request history; SAST reports; ticket links between the findings and the fix commits`  
  *Expected:* Every release has a completed code review against the secure coding guidelines. Findings are corrected before release.  
  *Refs:* pci_dss: 6.2.3; nist_800_53: SA-11

- [ ] **PCI-SWDEV-003** Check that manual code reviews use independent reviewers and approval  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find manual code reviews done by the author or released without management approval.  
  *Steps:*
  1. Ask who does manual code reviews and what skills they have.
  2. Pick five reviews. Make sure the reviewer is not the author.
  3. Make sure the reviewers know code review methods and secure coding practices.
  4. Make sure management reviewed and approved the results before release.
  5. Try to merge a change with no approval on a test copy.
  *Example:* `Branch protection settings; pull request approval rules; review checklist`  
  *Expected:* Reviewers know the methods, are not the author, and management approves the results before each release.  
  *Refs:* pci_dss: 6.2.3.1

- [ ] **PCI-SWDEV-004** Check the documented methods that prevent each common software attack  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Find attack classes that have no defined technique for prevention in the development procedure.  
  *Steps:*
  1. Ask for the documented techniques for bespoke software developers.
  2. Make sure they cover injection attacks, attacks on data and data structures, and attacks on cryptography use.
  3. Make sure they cover attacks on business logic, attacks on access control and other high-risk vulnerabilities.
  4. Interview two developers. Ask how they prevent an injection attack and a broken access control.
  5. Run the existing tests for each attack class and record the result.
  *Example:* `Compare the procedure to the sheet tests WEB-INJ, WEB-XSS, WEB-CRYPTO, WEB-BIZ and WEB-AUTHZ`  
  *Expected:* Defined methods cover each attack class. Developers can name and use them, and the test results show they work.  
  *Refs:* pci_dss: 6.2.4

- [ ] **PCI-SWDEV-005** Check that security vulnerabilities are found and ranked by risk  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Find missing sources of vulnerability data or missing risk ranking for high-risk vulnerabilities.  
  *Steps:*
  1. Ask for the process that finds new security vulnerabilities.
  2. Make sure it uses industry-recognized sources, including alerts from national and international CERTs.
  3. Make sure each vulnerability gets a risk rank by industry practice and potential impact.
  4. Make sure the ranks identify at least all high-risk and critical vulnerabilities.
  5. Make sure the process covers bespoke software and third-party software such as operating systems and databases.
  *Example:* `Examine the vulnerability tracker; look at the CVSS and local risk fields; examine the subscription list of advisory feeds`  
  *Expected:* New vulnerabilities come from recognized sources. Each one gets a risk rank, and high-risk and critical items are identified for bespoke and third-party software.  
  *Refs:* pci_dss: 6.3.1; nist_800_53: RA-5, RA-3

- [ ] **PCI-SWDEV-006** Check the inventory of bespoke software and third-party components  
  *Severity if fail:* Medium | *Type:* Manual, Automated  
  *Objective:* Find software and components that are not in the inventory, so no one patches them.  
  *Steps:*
  1. Ask for the inventory of bespoke and custom software and the third-party components in it.
  2. Compare the inventory with the build files, lock files and deployed packages of two applications.
  3. Make sure each entry shows version and owner.
  4. Pick one recent advisory. Find the affected component in the inventory within one hour.
  5. Make sure the inventory is updated when components change.
  *Example:* `SBOM in CycloneDX or SPDX format; npm ls, pip freeze, mvn dependency:tree compared to the inventory`  
  *Expected:* A current inventory lists all bespoke software and third-party components with versions. The team uses it to find and fix vulnerabilities.  
  *Refs:* pci_dss: 6.3.2; nist_800_53: CM-8, SA-15

- [ ] **PCI-SWDEV-007** Check the method that addresses new threats on public web applications  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find public web applications with no ongoing review for new threats and vulnerabilities.  
  *Steps:*
  1. List the public-facing web applications.
  2. Find out which method is used: a vulnerability assessment or an automated technical solution.
  3. For an assessment, make sure it runs at least every 12 months and after significant changes.
  4. Make sure the assessment uses tools or manual methods that find the current attacks, and that fixes are made.
  5. For an automated solution, make sure the test of the web application firewall settings is on file.
  *Example:* `Application assessment reports and dates; DAST scan schedule; manual penetration test report`  
  *Expected:* Every public web application has a defined method for new threats. Assessments are recent, cover current attacks and lead to fixes.  
  *Refs:* pci_dss: 6.4.1; nist_800_53: RA-5, SI-4

- [ ] **PCI-SWDEV-008** Check that an automated solution detects and blocks web attacks  
  *Severity if fail:* High | *Type:* Manual, Automated  
  *Objective:* Find public web applications with no web application firewall or one that is in log-only mode with no review.  
  *Steps:*
  1. List the public-facing web applications and the web attack solution in front of each.
  2. Make sure the solution is in front of the application and in block mode, or alerts are reviewed at once.
  3. Make sure the rule sets and signatures are up to date.
  4. Send a test SQL injection and a test XSS string. Make sure the solution blocks or alerts.
  5. Make sure the solution writes audit logs and personnel review the alerts.
  *Example:* `curl 'https://app.example/?q=<script>alert(1)</script>' ; curl "https://app.example/?id=1' OR '1'='1" ; review WAF logs`  
  *Expected:* A maintained solution sits in front of each public web application and writes audit logs. It blocks attacks, or an alert is investigated at once.  
  *Refs:* pci_dss: 6.4.2; nist_800_53: SI-4, SC-7

- [ ] **PCI-SWDEV-009** Check that payment page scripts are authorized and protected from tampering  
  *Severity if fail:* High | *Type:* Manual, Automated  
  *Objective:* Find scripts on the payment page that are not authorized, not checked for integrity or not in the inventory.  
  *Steps:*
  1. Open the payment page in a browser. List all scripts that load, including third-party and fourth-party scripts.
  2. Compare the list with the inventory of payment page scripts.
  3. Make sure each script has a written business or technical reason and an authorization record.
  4. Make sure each script has an integrity control such as Subresource Integrity or a Content-Security-Policy with hashes or nonces.
  5. Change a script on a test copy. Make sure the page blocks or reports the change.
  *Example:* `Browser developer tools network tab; Content-Security-Policy header review; integrity attribute check; compare the script list with the inventory`  
  *Expected:* Every payment page script is in the inventory with a reason and an authorization. An integrity control blocks or reports a changed script.  
  *Refs:* pci_dss: 6.4.3; cwe: CWE-829, CWE-494; nist_800_53: SI-7, CM-8

- [ ] **PCI-SWDEV-010** Check that tamper detection watches payment page headers and scripts  
  *Severity if fail:* High | *Type:* Manual, Automated  
  *Objective:* Find payment pages where a change to the HTTP headers or scripts raises no alert.  
  *Steps:*
  1. Find the change- and tamper-detection mechanism for the payment pages.
  2. Make sure it evaluates the headers and the scripts as the consumer browser receives them.
  3. Make sure it runs at least weekly, or at the frequency in the targeted risk analysis.
  4. Change a security header and a script on a test copy. Make sure the mechanism alerts personnel.
  5. Look at the alert record. Make sure personnel investigated the alert.
  *Example:* `Monitor that fetches the page with a headless browser and compares header and script hashes; review the alert log`  
  *Expected:* A mechanism checks the received headers and scripts at least weekly. It alerts personnel to unauthorized changes, additions and deletions.  
  *Refs:* pci_dss: 11.6.1; cwe: CWE-829; nist_800_53: SI-7


## TRANS

- [ ] **PCI-TRANS-001** Check the inventory of trusted keys and certificates for PAN transmission  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find certificates and keys that protect PAN in transit and that no one tracks.  
  *Steps:*
  1. Ask for the inventory of trusted keys and certificates used to protect PAN in transit.
  2. Scan the public and internal endpoints that carry PAN. Compare each certificate with the inventory.
  3. Make sure each entry has an owner, an issuer and an expiry date.
  4. Find certificates that expire within 30 days.
  5. Make sure a process updates the inventory when a certificate changes.
  *Example:* `nmap --script ssl-cert -p443 <host>; certificate lifecycle tool export; compare to the inventory`  
  *Expected:* A current inventory lists all trusted keys and certificates for PAN in transit. Each has an owner and an expiry date, and none is missing.  
  *Refs:* pci_dss: 4.2.1.1; nist_800_53: SC-12, SC-17

- [ ] **PCI-TRANS-002** Check that PAN sent through messaging tools is protected or blocked  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Find PAN in clear text in e-mail, chat, SMS or other end-user messaging.  
  *Steps:*
  1. Ask whether policy allows PAN in end-user messaging.
  2. Make sure the policy forbids unprotected PAN, or requires strong cryptography.
  3. Send a test message that holds a test PAN on each channel in use.
  4. Make sure a data loss control blocks the message or encrypts it.
  5. Search sent mail and chat archives for PAN patterns.
  *Example:* `Mail gateway DLP rule test with 4111111111111111; chat DLP policy review`  
  *Expected:* A control blocks PAN in end-user messaging or requires strong cryptography. No unprotected PAN is in messaging archives.  
  *Refs:* pci_dss: 4.2.2; cwe: CWE-319; nist_800_53: SC-8, SI-12
