# NIST security test cases

29 tests. Tick the box when the test passes.


## AC

- [ ] **NIST-AC-001** Review the account lifecycle from creation to removal  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds accounts that stay active after the person or service no longer needs them.  
  *Steps:*
  1. List the account types: individual, group, role, service, guest, temporary and emergency.
  2. Read the rules for who may approve, create, change and remove each account type.
  3. Create a test account and follow the approval steps.
  4. Change the roles of the test account and disable it.
  5. Remove the test account and look for left-over sessions, tokens, keys and shared objects.
  *Example:* `Compare the account export with the HR or ticket list: aws iam generate-credential-report; ldapsearch -b DC=corp -s sub '(objectClass=user)' lastLogon`  
  *Expected:* Each account has an owner and an approval record. Disabled accounts cannot log in, and their tokens and sessions stop working at once.  
  *Refs:* nist_800_53: AC-2, AC-2(1), AC-2(3), AC-2(9), IA-4; cwe: CWE-284

- [ ] **NIST-AC-002** Check that temporary, emergency and inactive accounts end by themselves  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds accounts and grants that never expire because only a person can remove them.  
  *Steps:*
  1. Find the accounts and grants that have a set end date.
  2. Create a temporary account with a short life and wait until it ends.
  3. Try to log in with the temporary account after the end time.
  4. List accounts with no logon for the period that the policy sets.
  5. Make sure the system disables each inactive account within the policy time.
  *Example:* `Check last logon: aws iam get-credential-report; Get-ADUser -Filter * -Properties LastLogonDate; psql -c 'select rolname,rolvaliduntil from pg_roles'`  
  *Expected:* Temporary and emergency accounts stop working at the end time. Inactive accounts are disabled within the policy time and the system records the change.  
  *Refs:* nist_800_53: AC-2(2), AC-2(3), AC-2(5)

- [ ] **NIST-AC-003** Check that every account management action is written to the audit log  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds account changes that leave no record, so misuse cannot be traced.  
  *Steps:*
  1. Create, change, enable, disable and remove a test account.
  2. Add and remove a role of the test account.
  3. Read the audit log for each of the actions.
  4. Make sure each record names the actor, the target account, the time and the result.
  *Example:* `Search the audit log for the test account name; for example grep -i TESTUSER /var/log/audit/audit.log; aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=TESTUSER`  
  *Expected:* Each account management action has one audit record with the actor, the target, the time and the result.  
  *Refs:* nist_800_53: AC-2(4), AU-2, AU-12, AC-6(9); cwe: CWE-778

- [ ] **NIST-AC-004** Review how privileged roles are assigned, watched and revoked  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds privileged accounts with no owner, no review or no alert on role changes.  
  *Steps:*
  1. List all accounts that hold a privileged or security role.
  2. Compare the list with the approved list of people for each role.
  3. Add a test account to a privileged role.
  4. Look for an alert or a record of the role change.
  5. Remove the role and make sure the access ends.
  *Example:* `kubectl get clusterrolebindings -o wide; aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess; net localgroup administrators`  
  *Expected:* Only approved people hold privileged roles. Each role change creates a record and an alert, and a removed role ends the access at once.  
  *Refs:* nist_800_53: AC-2(7), AC-5, AC-6(1), AC-6(5); cwe: CWE-269

- [ ] **NIST-AC-005** Check that each process and service runs with least privilege  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds services that run as root or administrator or hold more rights than their task needs.  
  *Steps:*
  1. List the processes and services of the system and the account of each.
  2. Read the file, network and system rights of each account.
  3. Find rights that the documented task does not need.
  4. Run a function that needs a high right as an ordinary user.
  5. Make sure the system refuses the function.
  *Example:* `ps -eo user,pid,cmd | grep -v '^root' ; sc qc SERVICE; systemd-analyze security UNIT; getcap -r / 2>/dev/null`  
  *Expected:* No process runs with more rights than its task needs. Ordinary users cannot start privileged functions or raise their own privilege.  
  *Refs:* nist_800_53: AC-6, AC-6(2), AC-6(8), AC-6(10), SA-8(14); cwe: CWE-250

- [ ] **NIST-AC-006** Check the logon failure limit and the way to unlock an account  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds logons that allow unlimited guesses, or a lockout that an attacker can use to block users.  
  *Steps:*
  1. Read the failed logon limit and the lockout or delay rule for each logon interface.
  2. Send wrong passwords for one test account until the limit is reached.
  3. Send the correct password after the limit and look at the response.
  4. Try the alternate factor or the unlock path that the system offers.
  5. Make sure the unlock path has its own limit of tries.
  *Example:* `hydra -l TESTUSER -P short.txt -t 1 https://HOST/login; check Retry-After headers and the lockout events in the log`  
  *Expected:* The system limits consecutive failed logons and then delays or locks the account. The unlock path has a limit and a record.  
  *Refs:* nist_800_53: AC-7, AC-7(4), IA-5(1); cwe: CWE-307

- [ ] **NIST-AC-007** Check the system use notice before logon  
  *Severity if fail:* Low | *Type:* Config Review, Manual  
  *Objective:* Finds logon screens that show no required legal, privacy or monitoring notice.  
  *Steps:*
  1. Find the notice text that the policy requires for each logon interface.
  2. Open each interface: web, console, SSH, API portal and admin tool.
  3. Look for the notice before the credential fields.
  4. Make sure the user must accept the notice, or can read it, before access starts.
  *Example:* `ssh -v HOST (look for Banner text); curl -s https://HOST/login | grep -i notice; sshd_config: Banner /etc/issue.net`  
  *Expected:* Each logon interface shows the approved notice before access. The text is the same as the approved text.  
  *Refs:* nist_800_53: AC-8

- [ ] **NIST-AC-008** Check that the user sees the last logon date and time  
  *Severity if fail:* Low | *Type:* Config Review, Manual  
  *Objective:* Finds systems that cannot show a user that someone else used the account.  
  *Steps:*
  1. Log in with a test account and note the time.
  2. Log out and log in again.
  3. Look for the time and the place of the last successful logon on screen.
  4. Look for the count of failed logons since the last success.
  5. Make sure the data is correct when you log in from a second device.
  *Example:* `SSH: PrintLastLog yes in sshd_config; web: look at the account security page; Windows: policy DisplayLastLogonInfo`  
  *Expected:* After logon the user sees the correct time and place of the last logon. The user can see failed logons since then.  
  *Refs:* nist_800_53: AC-9, AC-2(12)

- [ ] **NIST-AC-009** Check the session lock and that it hides the screen content  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds sessions that stay open on an unattended device and show data to other people.  
  *Steps:*
  1. Read the idle time after which the session must lock.
  2. Leave a test session idle until the lock starts.
  3. Look at the screen and make sure it shows no application data.
  4. Try to use the session without new credentials.
  5. Unlock with valid credentials and make sure the work state is kept.
  *Example:* `Windows: InactivityTimeoutSecs; Linux: gsettings get org.gnome.desktop.session idle-delay; web client: leave tab idle and send a request`  
  *Expected:* The session locks after the set idle time and hides the content. Access returns only after the user proves identity again.  
  *Refs:* nist_800_53: AC-11, AC-11(1), AC-12

- [ ] **NIST-AC-010** Check the timeout warning and the logout message  
  *Severity if fail:* Low | *Type:* Config Review, Manual  
  *Objective:* Finds sessions that end without a warning or leave the user unsure if the session is closed.  
  *Steps:*
  1. Read the idle limit and the overall limit of the session.
  2. Use a test session and wait for the warning time.
  3. Look for a message that tells the user when the session ends.
  4. Let the session end and look for an explicit logout message.
  5. Log out with the logout button and look for the same message.
  *Example:* `Browser: wait for the idle limit with the developer tools open; look for a 401 response and the logout page text`  
  *Expected:* The user gets a warning before the session ends and an explicit message when it ends. The session cannot be used after that.  
  *Refs:* nist_800_53: AC-12, AC-12(1), AC-12(2), AC-12(3)

- [ ] **NIST-AC-011** Check the audited emergency override of access control  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds break-glass paths that bypass access control with no approval, limit or record.  
  *Steps:*
  1. Find the break-glass or emergency access paths of the system.
  2. Read who may start each path and under which condition.
  3. Start the path with a test case.
  4. Make sure the system limits the time and the scope of the override.
  5. Look for audit records and an alert for the start and the end.
  *Example:* `Check break-glass accounts in the IdP; kubectl auth can-i --list --as=EMERGENCY-USER; read the vault emergency policy`  
  *Expected:* Only named people can start the override. It ends by itself, and the system records and reports each use.  
  *Refs:* nist_800_53: AC-3(10), AC-2(2), AC-6(9)

- [ ] **NIST-AC-012** Check that sharing and delegation of access follows the policy  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds users who can pass access to other people or change access rules for their own objects without limit.  
  *Steps:*
  1. List the functions that let a user share an object or grant rights to others.
  2. Share a test object with a second test user.
  3. Try to share the object with a user outside the allowed group.
  4. Let the second user share the object again.
  5. Look for audit records of the sharing and the changes of rights.
  *Example:* `Test share links and ACL changes: curl -X POST https://HOST/api/files/ID/share -d '{"user":"OUTSIDER"}'`  
  *Expected:* Users share only inside the limits of the policy. The system records each grant and each change, and the owner can revoke it.  
  *Refs:* nist_800_53: AC-3(4), AC-2(11); cwe: CWE-284


## AU

- [ ] **NIST-AU-001** Check who can change which events the system logs  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds logging settings that any admin or process can lower without a record.  
  *Steps:*
  1. Read the list of event types that the policy requires the system to log.
  2. Compare the list with the active logging settings of each component.
  3. List the roles that can change the logging settings.
  4. Change one logging setting with a test account and look at the audit log.
  5. Make sure a role without the right cannot change the setting.
  *Example:* `auditctl -l; kubectl get cm audit-policy -o yaml; aws cloudtrail get-event-selectors --trail-name TRAIL`  
  *Expected:* Active logging covers all required event types. Only named roles can change the settings, and each change creates an audit record.  
  *Refs:* nist_800_53: AU-12, AU-12(3), AU-2, AU-9(4); cheatsheet: Logging_Cheat_Sheet; cwe: CWE-778

- [ ] **NIST-AU-002** Check the audit log storage size and the capacity warning  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds logs that fill the disk and stop, or that lose old records with no warning.  
  *Steps:*
  1. Read the space set aside for audit logs and the rate of new records.
  2. Calculate how long the space lasts at the peak rate.
  3. Read the warning level for the storage and the receiver of the warning.
  4. Fill a test log volume to the warning level and look for the alert.
  5. Make sure the retention time still holds when the volume is full.
  *Example:* `df -h /var/log; journalctl --disk-usage; check Elasticsearch disk watermark settings and alert rules`  
  *Expected:* The storage holds the retention time at peak load. A warning reaches the named receiver before the storage is full.  
  *Refs:* nist_800_53: AU-4, AU-5(1), AU-11; cheatsheet: Logging_Cheat_Sheet

- [ ] **NIST-AU-003** Check the response when audit logging fails  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds systems that go on with no audit trail, or stop in a way that is easy to abuse, when logging fails.  
  *Steps:*
  1. Read the rule for what the system does when it cannot write audit records.
  2. Stop the log agent or block the log target on a test system.
  3. Do a security-relevant action and see if the system works as the rule says.
  4. Look for an alert about the logging failure.
  5. Restore logging and look for a gap record or a backlog.
  *Example:* `systemctl stop auditd; iptables -A OUTPUT -p tcp --dport 514 -j DROP; then look at the alert channel and the buffer`  
  *Expected:* A logging failure creates an alert at once. The system follows the written rule and keeps a buffer, and no records are lost silently.  
  *Refs:* nist_800_53: AU-5, AU-5(2), AU-12, SI-4(5); cheatsheet: Logging_Cheat_Sheet; cwe: CWE-778

- [ ] **NIST-AU-004** Check audit record search and that reports keep the originals  
  *Severity if fail:* Low | *Type:* Config Review, Manual  
  *Objective:* Finds logs that cannot be searched for an incident, or reports that change the original records.  
  *Steps:*
  1. Pick a test event from the last day and note its time and actor.
  2. Search the audit records for the event by user, time and event type.
  3. Create a report from the search result.
  4. Compare the original record before and after the report.
  5. Make sure the time order of the original records is unchanged.
  *Example:* `Search in SIEM: user=TESTUSER AND action=login earliest=-24h; sha256sum the raw log file before and after the report`  
  *Expected:* The reviewer finds the test event with the search fields. Report tools read the records and do not change their content or order.  
  *Refs:* nist_800_53: AU-7, AU-7(1), AU-6


## CM

- [ ] **NIST-CM-001** Check the security impact analysis before a change  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds changes that go live without an analysis of their effect on security.  
  *Steps:*
  1. Pick five recent changes: one each of code, settings, infrastructure, dependency and access.
  2. Find the change record of each change.
  3. Look for a written security impact review with an approver.
  4. Look for the test result that shows the security controls still work.
  5. Look for a back-out plan.
  *Example:* `Compare the change tickets with the deploy log; read the pull request checklist for security impact`  
  *Expected:* Each change has a security impact review before approval. The record shows a test of the controls and a back-out plan.  
  *Refs:* nist_800_53: CM-4, CM-3, CM-3(2)


## IA

- [ ] **NIST-IA-001** Review the authenticator lifecycle for issue, reset, revoke and expiry  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds authenticators that are given with no identity check or that stay valid after loss or change of role.  
  *Steps:*
  1. List the authenticator types: password, key, token, certificate and API key.
  2. Request a test authenticator and look at the identity check before issue.
  3. Check that the first value must be changed or is single use.
  4. Report the test authenticator as lost and make sure it stops working.
  5. Look at the expiry date of each authenticator type.
  *Example:* `Test the activation link twice; revoke an API key and call the API with it; openssl x509 -noout -enddate -in CERT`  
  *Expected:* The system checks identity before issue. Lost or changed authenticators stop working at once, and every authenticator has an owner and an end date.  
  *Refs:* nist_800_53: IA-5, IA-5(6), IA-12, AC-2; cwe: CWE-798

- [ ] **NIST-IA-002** Check that login names differ from public identifiers  
  *Severity if fail:* Low | *Type:* Config Review, Manual  
  *Objective:* Finds accounts whose login name is the public email or display name, which helps guessing attacks.  
  *Steps:*
  1. List the places where the system shows a user name, email or ID to other people.
  2. Compare each public value with the login name of the test account.
  3. Try to log in with the public value of another test account.
  4. Look at how new identifiers are assigned and whether they are reused.
  *Example:* `Compare the public profile page and API response with the login name; try login with the display name`  
  *Expected:* The login name is not shown to other users. The system never reuses an identifier, and the public value does not log in.  
  *Refs:* nist_800_53: IA-4, IA-4(1)


## SA

- [ ] **NIST-SA-001** Check the security flaw tracking tool and its link to the build  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds security flaws that are found but never tracked, assigned or fixed.  
  *Steps:*
  1. Find the tool that tracks security flaws for the system.
  2. Pick five flaws from scans and reviews of the last quarter.
  3. Look for each flaw in the tool with an owner, a severity and a status.
  4. Make sure the build or release step can see open flaws.
  5. Look for flaws that passed the fix time with no decision.
  *Example:* `Compare scanner exports with the ticket system: jira JQL labels = security AND status != Done; defectdojo findings list`  
  *Expected:* Each flaw has a record with an owner, a severity and a due date. The release step checks open flaws, and late flaws need a recorded decision.  
  *Refs:* nist_800_53: SA-15(2), SA-15, SA-11, SI-2

- [ ] **NIST-SA-002** Check the dynamic and interactive security tests in the development process  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds releases that only get static scans and never run tests on the running application.  
  *Steps:*
  1. Read the pipeline and find the dynamic analysis and interactive test steps.
  2. Look at the last three runs and the code and API coverage.
  3. Make sure the test target is a running build, not a mock.
  4. Open the findings and check that the results are stored.
  5. Check that high findings stop the release or need a signed exception.
  *Example:* `Look at ZAP, Burp or IAST agent runs in the pipeline logs; check agent coverage reports and the exception list`  
  *Expected:* Each release runs dynamic or interactive tests on a running build. The results are stored, and high findings block the release.  
  *Refs:* nist_800_53: SA-11(9), SA-11(8), SA-11(1), SA-15(7)


## SC

- [ ] **NIST-SC-001** Review the lifecycle of cryptographic keys from creation to destruction  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds keys that are made weak, kept in clear text, never rotated or never destroyed.  
  *Steps:*
  1. List all keys: TLS, signing, data encryption, token and backup keys.
  2. Read where each key is created, who can read it and where it is stored.
  3. Look at the rotation date of each key.
  4. Revoke or rotate one test key and make sure the system keeps working.
  5. Check how the system gets back data if a user key is lost.
  *Example:* `aws kms list-keys; aws kms get-key-rotation-status --key-id ID; vault read sys/keys/encryption; keytool -list -v`  
  *Expected:* Each key has an owner, a rotation date and protected storage. Rotation and revoke work, and the loss of a key does not cause data loss.  
  *Refs:* nist_800_53: SC-12, SC-12(1), SC-28(3), IA-13(1); cheatsheet: Key_Management_Cheat_Sheet

- [ ] **NIST-SC-002** Check that the system fails to a safe state when security fails  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds systems that open access or lose protection when a security function or boundary device fails.  
  *Steps:*
  1. List the security functions: authentication, authorization, filtering, logging and encryption.
  2. Stop or break one security function on a test system.
  3. Send a request that the function normally blocks.
  4. Make sure the system denies the request or stops, and does not allow it.
  5. Look for an alert, restore the function and make sure it works again.
  *Example:* `Stop the authorization service and call a protected API; stop the WAF or firewall rule engine; block the policy server`  
  *Expected:* When a security function fails the system denies access or stops in a known state. It sends an alert and keeps data safe.  
  *Refs:* nist_800_53: SC-24, SC-7(18), SI-17, SA-8(24); cwe: CWE-636

- [ ] **NIST-SC-003** Check that monitoring tools can see encrypted traffic where policy needs it  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds encrypted paths where attack tools and data loss tools are blind.  
  *Steps:*
  1. Read which traffic the policy says the monitoring tools must inspect.
  2. List where the system encrypts this traffic and who holds the keys.
  3. Send a test payload that the monitor must detect through the encrypted path.
  4. Look for the alert, or for the log of the decrypting proxy or host agent.
  5. Make sure the decrypting point is protected and logs access.
  *Example:* `Send the EICAR test string over HTTPS through the proxy; compare the IDS alerts with and without TLS inspection`  
  *Expected:* The test payload raises an alert on every required path. The point that decrypts traffic is protected and audited.  
  *Refs:* nist_800_53: SI-4(10), SC-8, SI-4(4)


## SI

- [ ] **NIST-SI-001** Check that old software versions are removed after an update  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds old vulnerable versions that stay on the system and can be started after an update.  
  *Steps:*
  1. Update a test component to the new version with the normal process.
  2. List the installed versions of the component, images and packages.
  3. Look for old binaries, libraries, containers and rollback copies.
  4. Try to start the old version.
  5. Read the rule that sets how long a rollback copy may stay.
  *Example:* `dpkg -l | grep PKG; docker images; find / -name 'libssl*' 2>/dev/null; kubectl get rs -A`  
  *Expected:* After the update only the new version stays active. Old copies are removed or locked after the set rollback time.  
  *Refs:* nist_800_53: SI-2(6), SI-2, SA-22; cwe: CWE-1104

- [ ] **NIST-SI-002** Check that integrity violations create an audit record and a response  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds changed files or software that raise no alert and start no action.  
  *Steps:*
  1. List the files, packages and settings that the integrity tool watches.
  2. Change one watched test file on a test system.
  3. Look for an audit record with the actor, the time and the file.
  4. Look for the alert and the automatic action that the policy sets.
  5. Restore the file and make sure the tool reports the clean state.
  *Example:* `aide --check; tripwire --check; auditctl -w /etc/TESTFILE -p wa; sigcheck -h FILE`  
  *Expected:* The tool detects the change and records it. It sends an alert, and the set response, such as restore or isolate, starts.  
  *Refs:* nist_800_53: SI-7(8), SI-7(5), SI-7, AU-2

- [ ] **NIST-SI-003** Check the manual override of input validation  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds override functions that let a user skip validation without a limit or a record.  
  *Steps:*
  1. Search the system for functions that skip or relax input validation.
  2. List the roles that can use each override.
  3. Use an override with a test account that has the right.
  4. Try the same override with an ordinary account.
  5. Look for an audit record of each use.
  *Example:* `Search the code and settings for validate=false, skip_validation, force and import-without-check options`  
  *Expected:* Only named roles can use an override. Each use is limited to defined inputs and creates an audit record.  
  *Refs:* nist_800_53: SI-10(1), SI-10, AU-12; cwe: CWE-20

- [ ] **NIST-SI-004** Check the self-test of security functions at start-up and on a schedule  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds security functions that fail silently, such as a broken filter or a stopped log agent.  
  *Steps:*
  1. List the security functions that need a regular test, such as logging, filtering and encryption.
  2. Read when the system tests them and who gets the result.
  3. Break one function on a test system.
  4. Wait for the next test run and look for the alert.
  5. Make sure the result is stored and reported.
  *Example:* `Stop the antivirus service; remove a firewall rule; look at the health check and the alert in the monitoring tool`  
  *Expected:* The system finds a failed security function in the set time. It alerts the named receiver and keeps the test result.  
  *Refs:* nist_800_53: SI-6, SI-4(5), SA-11

- [ ] **NIST-SI-005** Check malicious code protection at the entry and exit points  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds paths where files or messages enter or leave with no malware scan.  
  *Steps:*
  1. List the entry and exit points: upload, email, API, download and removable media.
  2. Send the EICAR test file through each entry point.
  3. Look for the block, the quarantine and the alert.
  4. Check the date of the last signature or rule update of each scanner.
  5. Make sure the update runs by itself.
  *Example:* `curl -F file=@eicar.com https://HOST/upload; clamscan eicar.com; check the scanner update log`  
  *Expected:* Every entry and exit point blocks or quarantines the test file and raises an alert. Scanners update by themselves.  
  *Refs:* nist_800_53: SI-3, SI-4(5); cwe: CWE-434
