# PRIVACY security test cases

100 tests. Tick the box when the test passes.


## BREACH

- [ ] **PRIV-BREACH-001** Review the incident response plan for personal data breaches  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds response plans that skip privacy incidents.  
  *Steps:*
  1. Ask for the incident response plan.
  2. Look for privacy incident steps, owners and contacts.
  3. Look for the 72 hour notice step to the authority.
  4. Ask for the last test record of the plan.
  *Example:* `Document review: plan, test protocol, contact list; check for a tabletop exercise in the last two years.`  
  *Expected:* The plan names owners and steps for privacy incidents. It is tested and records of tests exist.  
  *Refs:* privacy_top10: P3; other: GDPR Art. 33, GDPR Art. 34

- [ ] **PRIV-BREACH-002** Check that the breach register holds the required facts  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds breaches that are not documented.  
  *Steps:*
  1. Ask for the breach register.
  2. Check each entry for facts, effects and remedial action.
  3. Check entries that were not reported and the reason.
  4. Compare with the incident tickets.
  *Example:* `Compare register entries with the security incident tracker of the last year.`  
  *Expected:* Every breach has an entry with facts, effects and action. The register allows the authority to check compliance.  
  *Refs:* privacy_top10: P3; other: GDPR Art. 33

- [ ] **PRIV-BREACH-003** Check the draft user notice for a breach  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds notices that are late, unclear or incomplete.  
  *Steps:*
  1. Ask for the notice template.
  2. Check for nature of the breach, contact point, likely effects and measures.
  3. Check that the language is clear and plain.
  4. Check the channel for fast delivery to all affected users.
  *Example:* `Template review; send a test notice to a test group and measure the time.`  
  *Expected:* The template has all required parts in plain language. The service can reach affected users without undue delay.  
  *Refs:* privacy_top10: P3; other: GDPR Art. 34

- [ ] **PRIV-BREACH-004** Check that monitoring detects personal data leaks  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds leaks that stay unseen because no monitoring covers them.  
  *Steps:*
  1. List the monitoring rules for bulk data access and data export.
  2. Create a test export of many records.
  3. Check that an alert starts.
  4. Check the response time of the team.
  *Example:* `Run a bulk export in a test environment; check SIEM alert and ticket.`  
  *Expected:* A bulk read or export raises an alert. The team starts triage within the agreed time.  
  *Refs:* privacy_top10: P3, P2; other: GDPR Art. 32, GDPR Art. 33; cheatsheet: Logging_Cheat_Sheet  
  *See:* WEB-LOG-014

- [ ] **PRIV-BREACH-005** Check that processors tell the controller about a breach without delay  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds contracts and channels that delay the breach message.  
  *Steps:*
  1. Ask for the processor contracts.
  2. Look for the breach notice clause and the contact.
  3. Check the contact channel with a test message.
  4. Check that the processor has a response plan.
  *Example:* `Send a test alert to the processor breach contact and note the reply time.`  
  *Expected:* Each processor must tell the controller without undue delay. The test message reaches a staffed contact.  
  *Refs:* privacy_top10: P3; other: GDPR Art. 28, GDPR Art. 33


## CONSENT

- [ ] **PRIV-CONSENT-001** Check that consent is collected separately for each purpose  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds consent that is bundled for several purposes, such as service use and advertising profiling.  
  *Steps:*
  1. List all processing purposes in the privacy notice and the consent records.
  2. Open the sign-up flow and the consent dialogs.
  3. Count the consent choices shown for each purpose.
  4. Try to finish sign-up while you refuse every optional purpose.
  *Example:* `Evidence: screenshots of each consent dialog, consent database schema, list of purposes and legal bases.`  
  *Expected:* Each purpose has its own consent choice. The user can refuse optional purposes and still use the core service.  
  *Refs:* privacy_top10: P4; other: GDPR Art. 6, GDPR Art. 7

- [ ] **PRIV-CONSENT-002** Check that optional consent is off by default  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds pre-ticked boxes and opt-out defaults for purposes that the service does not need.  
  *Steps:*
  1. Create a new account with default settings.
  2. Look at every consent switch, tick box and cookie setting.
  3. Look at the stored consent values after sign-up.
  4. Record each optional purpose that is on without a user action.
  *Example:* `Compare the consent table after a fresh sign-up with the list of necessary purposes.`  
  *Expected:* All consent switches for optional purposes are off until the user acts. The stored value shows no consent.  
  *Refs:* privacy_top10: P4, P10; other: GDPR Art. 7, GDPR Art. 25

- [ ] **PRIV-CONSENT-003** Make sure users can withdraw consent as easily as they give it  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds consent that is easy to give but hard to withdraw.  
  *Steps:*
  1. Count the clicks that give consent.
  2. Count the clicks that withdraw the same consent.
  3. Withdraw one consent and look at the stored consent record.
  4. Watch network traffic for trackers after the withdrawal.
  *Example:* `Burp Suite or browser developer tools: compare requests before and after withdrawal; check the consent log row.`  
  *Expected:* Withdrawal needs no more steps than consent. Processing and tracker calls for that purpose stop after withdrawal.  
  *Refs:* privacy_top10: P4; other: GDPR Art. 7

- [ ] **PRIV-CONSENT-004** Make sure the service keeps proof of consent and its version  
  *Severity if fail:* Low | *Type:* Config Review, Manual  
  *Objective:* Finds services that cannot show who agreed to which text and when.  
  *Steps:*
  1. Ask for the consent log of one test user.
  2. Look for the timestamp, the purpose and the text version in each record.
  3. Change the policy text and look for a new consent request.
  4. Check that old records keep their original text version.
  *Example:* `Document review: consent table export with user ID, purpose, version, timestamp, source.`  
  *Expected:* Each consent record shows the user, purpose, text version and time. Users accept new versions of changed terms.  
  *Refs:* privacy_top10: P4, P5; other: GDPR Art. 7

- [ ] **PRIV-CONSENT-005** Check that consent is voluntary and not a condition for unrelated service  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds services that block use unless the user agrees to processing that the service does not need.  
  *Steps:*
  1. List the data fields and purposes that the service needs for its core function.
  2. Refuse every optional consent in the sign-up flow.
  3. Try to use the core service.
  4. Record any blocked feature and the reason that the service shows.
  *Example:* `Walk through the flow with all optional consents refused; note any "accept to continue" wall.`  
  *Expected:* The core service works when the user refuses consent for data that the service does not need.  
  *Refs:* privacy_top10: P4; other: GDPR Art. 7


## DSR

- [ ] **PRIV-DSR-001** Test the access request process and the content of the answer  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds access requests that fail, come late or leave out data.  
  *Steps:*
  1. Submit an access request as a test user.
  2. Note the identity checks that the service asks for.
  3. Compare the answer with the data in the database.
  4. Check the answer for purposes, recipients, retention and source.
  *Example:* `Measure days from request to answer. Compare export with a database dump for the test user.`  
  *Expected:* The answer arrives within one month and holds a copy of all data plus purposes, recipients, storage period and rights.  
  *Refs:* privacy_top10: P9; other: GDPR Art. 12, GDPR Art. 15

- [ ] **PRIV-DSR-002** Make sure access requests do not expose data to another person  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds access processes that give data to the wrong person.  
  *Steps:*
  1. Submit an access request for user A while you use a different e-mail address.
  2. Try to change the user identifier in the request.
  3. Check that the service checks identity before it sends data.
  4. Check the channel that carries the export.
  *Example:* `Burp Repeater on the export request; change the user ID parameter.`  
  *Expected:* The service refuses requests that it cannot link to the data subject. The export goes only to the verified owner on a protected channel.  
  *Refs:* privacy_top10: P9, P2; other: GDPR Art. 12, GDPR Art. 15; cwe: CWE-359, CWE-863

- [ ] **PRIV-DSR-003** Test the rectification of personal data and its spread to recipients  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds data that users cannot correct or that stays wrong at third parties.  
  *Steps:*
  1. Change a data field in the account.
  2. Check that the new value shows in all features.
  3. Check recipients and sub-systems for the old value.
  4. Check the update process for critical actions.
  *Example:* `Change a name or address; search downstream systems and exports for the old value.`  
  *Expected:* Users can correct their data. The change reaches all systems and recipients.  
  *Refs:* privacy_top10: P7, P9; other: GDPR Art. 5, GDPR Art. 16, GDPR Art. 19

- [ ] **PRIV-DSR-004** Test the portability export format  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds exports that are incomplete or that use a format that others cannot read.  
  *Steps:*
  1. Request an export of data that you provided.
  2. Open the file.
  3. Compare the content with the data in the account.
  4. Check the format for structure and machine readability.
  *Example:* `Check for JSON or CSV with a documented schema; compare field counts with the profile.`  
  *Expected:* The export holds all data that the user provided in a structured, common, machine-readable format.  
  *Refs:* privacy_top10: P9; other: GDPR Art. 20  
  *See:* MOB-PRIV-014

- [ ] **PRIV-DSR-005** Test the objection and the marketing opt-out  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds marketing that continues after an objection.  
  *Steps:*
  1. Subscribe a test user to marketing.
  2. Use the opt-out link and the account setting.
  3. Look for the stop of messages and profiling.
  4. Check that the record shows the objection.
  *Example:* `Check mail headers for a working unsubscribe link; check the marketing list for the user after 48 hours.`  
  *Expected:* Marketing and related profiling stop after the objection. The objection stays on record.  
  *Refs:* privacy_top10: P4, P9; other: GDPR Art. 21

- [ ] **PRIV-DSR-006** Check that rights requests have an owner, a tracker and a deadline  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds missing process for the data subject requests.  
  *Steps:*
  1. Ask for the request procedure.
  2. Look at the request log of the last year.
  3. Calculate the time to answer for each request.
  4. Check for refusal records with reasons.
  *Example:* `Document review: request tracker export; deadline of one month with a documented extension rule.`  
  *Expected:* All requests are tracked. Answers or reasons for refusal go out within one month, or the extension is told to the user.  
  *Refs:* privacy_top10: P9, P3; other: GDPR Art. 12


## GOV

- [ ] **PRIV-GOV-001** Check that a record of processing activities exists and is current  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds processing that nobody documented.  
  *Steps:*
  1. Ask for the record of processing activities.
  2. Check for controller, purposes, categories, recipients, transfers and time limits.
  3. Compare with the data inventory and with traffic.
  4. Check the date of the last update.
  *Example:* `Document review; compare record rows with the systems list.`  
  *Expected:* The record has all required fields for every processing activity and was updated after the last change.  
  *Refs:* privacy_top10: P5, P10; other: GDPR Art. 30

- [ ] **PRIV-GOV-002** Check that a data protection impact assessment exists for high-risk processing  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds high-risk processing with no impact assessment.  
  *Steps:*
  1. List processing that uses profiling, large-scale sensitive data or monitoring.
  2. Ask for the assessment for each item.
  3. Check the assessment for description, necessity, risks and measures.
  4. Check the review date after changes.
  *Example:* `Document review: DPIA register with dates and owners.`  
  *Expected:* Each high-risk processing has an assessment made before the start. It was reviewed after the last change.  
  *Refs:* privacy_top10: P1, P10; other: GDPR Art. 35

- [ ] **PRIV-GOV-003** Check that privacy by design is part of development  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds projects that add privacy late or never.  
  *Steps:*
  1. Ask for the privacy requirements of the latest release.
  2. Check design records for data minimisation and default settings.
  3. Check for a privacy step in change control.
  4. Check the privacy tests in the release checklist.
  *Example:* `Document review: design review notes, release checklist, threat model with privacy threats.`  
  *Expected:* Privacy requirements exist from the start. Change control includes a privacy impact check.  
  *Refs:* privacy_top10: P1, P10; other: GDPR Art. 25; cheatsheet: Secure_Product_Design_Cheat_Sheet

- [ ] **PRIV-GOV-004** Check the data quality controls for stored personal data  
  *Severity if fail:* Low | *Type:* Manual, Config Review  
  *Objective:* Finds old, wrong or duplicate personal data.  
  *Steps:*
  1. Ask how the service keeps data up to date.
  2. Look for periodic checks or prompts to the user.
  3. Find duplicate or conflicting records in a sample.
  4. Check that updates reach all copies.
  *Example:* `SQL duplicate check on a sample; review of the reminder process.`  
  *Expected:* The service has a process to keep data accurate. Old and wrong data is corrected or removed.  
  *Refs:* privacy_top10: P7; other: GDPR Art. 5, GDPR Art. 16

- [ ] **PRIV-GOV-005** Check the privacy of automated decisions and profiling  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds profiling with legal or similar effect that has no human review or explanation.  
  *Steps:*
  1. List automated decisions that affect users.
  2. Check the notice for the logic and its effect.
  3. Check for a human review path.
  4. Check that users can object.
  *Example:* `Document review: decision logic description, review procedure.`  
  *Expected:* Automated decisions with significant effect have a notice, a human review path and an objection path.  
  *Refs:* privacy_top10: P4, P5; other: GDPR Art. 13, GDPR Art. 22


## MINIM

- [ ] **PRIV-MINIM-001** Compare the collected personal data with the documented purposes  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds fields and telemetry that the stated purposes do not need.  
  *Steps:*
  1. Ask for the list of purposes and the data inventory.
  2. Open each form and API request that collects data.
  3. List each field and map it to one purpose.
  4. Mark each field with no purpose.
  *Example:* `Data map: field, purpose, legal basis, retention. Tools: Burp Suite, API schema review.`  
  *Expected:* Every collected field maps to a documented purpose. No field exists only in case it is useful later.  
  *Refs:* privacy_top10: P10; other: GDPR Art. 5, GDPR Art. 25

- [ ] **PRIV-MINIM-002** Make sure the server accepts forms with only needed fields  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds required fields that the service does not need.  
  *Steps:*
  1. Open each registration and profile form.
  2. Send the form with only the fields that the interface marks as required.
  3. Send the form again with each required field removed one by one.
  4. Check that the server accepts the minimum set.
  *Example:* `Burp Repeater: remove one parameter at a time and compare responses.`  
  *Expected:* The server accepts a request that has only the data needed for the purpose. Each field shows its reason.  
  *Refs:* privacy_top10: P10; other: GDPR Art. 5, GDPR Art. 25

- [ ] **PRIV-MINIM-003** Check that a new data purpose needs a new notice  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds reuse of data for new purposes, such as marketing, without notice or consent.  
  *Steps:*
  1. Ask for the list of data uses that were added after launch.
  2. Compare the list with the purposes in the notice.
  3. Look for a change record that shows a notice or consent step.
  4. Check that users were told before the new use.
  *Example:* `Document review: change log, DPIA update, notice versions.`  
  *Expected:* Each new use of data has a documented purpose, a legal basis and a notice to the users before it starts.  
  *Refs:* privacy_top10: P10, P4; other: GDPR Art. 5, GDPR Art. 6, GDPR Art. 13

- [ ] **PRIV-MINIM-004** Check that test and analytics systems hold no clear personal data  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds real personal data in test, analytics and marketing copies.  
  *Steps:*
  1. List all systems that hold copies of production data.
  2. Look at a sample of rows in each test and analytics system.
  3. Look for names, e-mail addresses and identifiers in clear form.
  4. Check the masking or pseudonymisation job and who holds the key.
  *Example:* `Database sample query; masking tool configuration; key access list.`  
  *Expected:* Test and analytics systems hold masked or pseudonymised data. The re-identification key is kept apart with limited access.  
  *Refs:* privacy_top10: P2, P10; other: GDPR Art. 25, GDPR Art. 32; cwe: CWE-359

- [ ] **PRIV-MINIM-005** Check that the default settings collect the least data  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds privacy-invasive defaults for tracking, profiling and visibility.  
  *Steps:*
  1. Create a new account.
  2. List all privacy-relevant settings and their defaults.
  3. Look at profile visibility and data sharing defaults.
  4. Record each setting that is more open than the purpose needs.
  *Example:* `Screenshot every settings page after fresh sign-up.`  
  *Expected:* Defaults collect and share the minimum data. Personalised advertising and public profile visibility are off.  
  *Refs:* privacy_top10: P10, P4; other: GDPR Art. 25  
  *See:* MOB-PRIV-011


## NOTICE

- [ ] **PRIV-NOTICE-001** Check that the privacy notice lists all required information  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds privacy notices that miss controller identity, purposes, recipients, retention or rights.  
  *Steps:*
  1. Find the privacy notice from the sign-up page and from the footer.
  2. Make a list of the items in the notice.
  3. Compare the list with the items in the checklist.
  4. Mark each missing item.
  *Example:* `Checklist items: controller and contact, purposes and legal basis, recipients, third-country transfers, retention period, data subject rights, right to complain, automated decisions.`  
  *Expected:* The notice is easy to find and contains every required item. It is shown when the data is collected.  
  *Refs:* privacy_top10: P5; other: GDPR Art. 12, GDPR Art. 13

- [ ] **PRIV-NOTICE-002** Check that the privacy notice matches the real data flows  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds processing, recipients and trackers that the notice does not mention.  
  *Steps:*
  1. Record all requests of the application with a proxy during a normal session.
  2. List all third-party hosts that receive data.
  3. Compare the hosts and data types with the notice.
  4. Report each recipient that the notice does not list.
  *Example:* `Burp Suite or mitmproxy HAR export; compare hosts with the recipient list in the notice.`  
  *Expected:* Every recipient and data category seen in traffic is named in the privacy notice.  
  *Refs:* privacy_top10: P5, P10; other: GDPR Art. 5, GDPR Art. 13

- [ ] **PRIV-NOTICE-003** Check that the notice is readable and available in the user language  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds notices that non-lawyers cannot read or that exist only in one language.  
  *Steps:*
  1. Open the notice in each supported user language.
  2. Check for a short summary and a long version.
  3. Run a readability score tool on the text.
  4. Look for a change history and a record of the version that each user accepted.
  *Example:* `Readability score tool; compare language list of the product with the language list of the notice.`  
  *Expected:* The notice is short, plain and in the user language. A change history and a per-user accepted version exist.  
  *Refs:* privacy_top10: P5; other: GDPR Art. 12

- [ ] **PRIV-NOTICE-004** Check the cookie list, its purposes and the opt-out  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds sites that set cookies and trackers without a list or an opt-out.  
  *Steps:*
  1. Open the site with a clean browser profile.
  2. List all cookies and storage entries before any consent action.
  3. Compare the list with the cookie list in the notice.
  4. Use the opt-out control and list the entries again.
  *Example:* `Browser developer tools Application tab; clear site data between steps.`  
  *Expected:* Only necessary cookies exist before consent. The cookie list names each cookie and its purpose. The opt-out removes the others.  
  *Refs:* privacy_top10: P5, P4; other: GDPR Art. 7, GDPR Art. 13


## RET

- [ ] **PRIV-RET-001** Review the retention and deletion policy for each data category  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds data categories that have no retention period or no deletion process.  
  *Steps:*
  1. Ask for the retention schedule.
  2. Compare it with the data inventory.
  3. Mark each data category with no period.
  4. Check that the period is in the privacy notice.
  *Example:* `Document review: retention schedule, deletion concept, privacy notice section on storage period.`  
  *Expected:* Each data category has a retention period and a deletion process. The periods are in the privacy notice.  
  *Refs:* privacy_top10: P6; other: GDPR Art. 5, GDPR Art. 13  
  *See:* WEB-DATA-008

- [ ] **PRIV-RET-002** Make sure data is deleted when the retention period ends  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds data that stays after its period, such as inactive accounts and old logs.  
  *Steps:*
  1. Find records older than the retention period in the database.
  2. Look at backups and archives for the same records.
  3. Run the deletion job on a test set.
  4. Check that the records are gone from all stores.
  *Example:* `SQL count of rows older than the period; list of stores: database, search index, cache, object store, backup.`  
  *Expected:* No record exists beyond its period in any active store. Backups have an expiry that follows the policy.  
  *Refs:* privacy_top10: P6; other: GDPR Art. 5  
  *See:* WEB-DATA-008

- [ ] **PRIV-RET-003** Make sure account deletion removes data in all systems and at processors  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds deleted accounts that stay in search indexes, caches, analytics or third-party systems.  
  *Steps:*
  1. Create a test account with data in every feature.
  2. Request deletion of the account.
  3. Search for the test data in the database, indexes, logs and analytics after the deletion period.
  4. Ask each processor to confirm deletion.
  *Example:* `Use a unique marker string in the test data and search for it everywhere.`  
  *Expected:* The marker string is not found in any active store or processor system after the stated deletion time.  
  *Refs:* privacy_top10: P6, P9; other: GDPR Art. 17

- [ ] **PRIV-RET-004** Check that deletion also covers backups, copies and shared data  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds personal data that deletion leaves in backups, exports or third-party copies.  
  *Steps:*
  1. Ask for the backup retention and restore procedure.
  2. Check that a restore applies earlier deletion requests.
  3. Look for exports and file shares that hold copies.
  4. Check the process to tell recipients about an erasure.
  *Example:* `Document review: backup policy, restore runbook, list of recipients with erasure notice process.`  
  *Expected:* Backups expire on a set schedule. A restore re-applies deletion requests. Recipients get erasure notices.  
  *Refs:* privacy_top10: P6; other: GDPR Art. 17, GDPR Art. 19

- [ ] **PRIV-RET-005** Check that the service keeps an erasure record without the deleted data  
  *Severity if fail:* Low | *Type:* Config Review, Manual  
  *Objective:* Finds services that cannot prove a deletion.  
  *Steps:*
  1. Request deletion of a test account.
  2. Ask for the deletion protocol of the request.
  3. Check that the protocol shows date, scope and result.
  4. Check that the protocol holds no more personal data than needed.
  *Example:* `Deletion log row with request ID, time, systems cleaned, operator.`  
  *Expected:* A deletion record exists. It shows what was deleted and when, and it holds no deleted personal data.  
  *Refs:* privacy_top10: P6; other: GDPR Art. 5, GDPR Art. 17


## SEC

- [ ] **PRIV-SEC-001** Make sure URLs, logs and analytics hold no personal data  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds personal data in places that many people and systems can read.  
  *Steps:*
  1. Use the application with a test user that has unique data values.
  2. Search access logs, application logs and analytics events for the unique values.
  3. Look for personal data in URLs and query strings.
  4. Check log access rights.
  *Example:* `grep -r 'test.user@example.com' /var/log; compare analytics event payloads with the data map.`  
  *Expected:* Logs, URLs and analytics events hold no clear personal data. Identifiers are masked or hashed.  
  *Refs:* privacy_top10: P2, P1; other: GDPR Art. 5, GDPR Art. 32; cwe: CWE-532, CWE-598, CWE-359; cheatsheet: Logging_Cheat_Sheet  
  *See:* WEB-LOG-006, WEB-DATA-002

- [ ] **PRIV-SEC-002** Check encryption of personal data at rest and the key separation  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds personal data stored in clear form or with keys next to the data.  
  *Steps:*
  1. List the stores that hold personal data.
  2. Check the encryption setting of each store and each backup.
  3. Find where the keys are kept.
  4. Check who can read both keys and data.
  *Example:* `Cloud console storage settings; database encryption status; key vault access policy.`  
  *Expected:* All stores and backups are encrypted. Keys are kept in a separate key service with limited access.  
  *Refs:* privacy_top10: P2; other: GDPR Art. 32; cwe: CWE-311, CWE-312; cheatsheet: Cryptographic_Storage_Cheat_Sheet  
  *See:* WEB-DATA-013

- [ ] **PRIV-SEC-003** Check that access to personal data follows need-to-know  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds staff and service accounts that can read more personal data than their role needs.  
  *Steps:*
  1. Ask for the role list and the access matrix for personal data.
  2. List the accounts with read access to the main data store.
  3. Compare the list with the roles.
  4. Check that access to personal data is logged.
  *Example:* `Database grants export; IAM policy review; audit log sample.`  
  *Expected:* Only needed roles can read personal data. Each access to bulk data is logged and reviewed.  
  *Refs:* privacy_top10: P2; other: GDPR Art. 5, GDPR Art. 32; cwe: CWE-359, CWE-862; cheatsheet: Secure_Product_Design_Cheat_Sheet

- [ ] **PRIV-SEC-004** Check that personal data is encrypted in transit on every channel  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds clear-text transfers of personal data, including internal and partner links.  
  *Steps:*
  1. List all channels that carry personal data.
  2. Capture traffic on each channel.
  3. Look for clear-text protocols.
  4. Check the TLS version and certificate checks.
  *Example:* `Wireshark capture; nmap --script ssl-enum-ciphers -p 443 host.`  
  *Expected:* Every channel uses current TLS with certificate checks. No personal data goes in clear text.  
  *Refs:* privacy_top10: P2, P1; other: GDPR Art. 32; cwe: CWE-319; cheatsheet: User_Privacy_Protection_Cheat_Sheet  
  *See:* WEB-TLS-006

- [ ] **PRIV-SEC-005** Check that sessions end after inactivity and at logout  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds sessions that stay open and let the service keep collecting data without user awareness.  
  *Steps:*
  1. Log in and leave the session idle.
  2. Check that the session ends at the documented time.
  3. Log out and replay the old session token.
  4. Check for a logout button on all pages.
  *Example:* `Burp Repeater: replay the old cookie after logout and after the timeout.`  
  *Expected:* The session ends at the idle limit and at logout. The old token is rejected. Tracking stops with the session.  
  *Refs:* privacy_top10: P8; other: GDPR Art. 5, GDPR Art. 32  
  *See:* WEB-SESS-019, WEB-SESS-017, WEB-SESS-016

- [ ] **PRIV-SEC-006** Check that users can see and end open sessions  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds services that give users no control over open sessions.  
  *Steps:*
  1. Log in on two devices.
  2. Open the session list in the account.
  3. End the other session from the first device.
  4. Check that the second device lost access.
  *Example:* `Two browsers; confirm the second token returns 401 after revocation.`  
  *Expected:* The user sees all open sessions and can end them. Ended sessions stop at once.  
  *Refs:* privacy_top10: P8; other: GDPR Art. 32; cheatsheet: User_Privacy_Protection_Cheat_Sheet  
  *See:* WEB-SESS-024

- [ ] **PRIV-SEC-007** Check that the privacy assessment covers the web application vulnerabilities  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds privacy reviews that ignore technical flaws such as injection and broken access control.  
  *Steps:*
  1. Ask for the last penetration test and scan reports.
  2. Check that the scope includes personal data stores.
  3. Check the fix status of high findings.
  4. Check the patch process for components.
  *Example:* `Document review: pen test report, SAST/DAST results, patch SLA.`  
  *Expected:* Regular tests cover personal data paths. High findings have a fix with evidence. Patches follow a set time frame.  
  *Refs:* privacy_top10: P1; other: GDPR Art. 32; cwe: CWE-1395  
  *See:* WEB-DEP-001


## SHARE

- [ ] **PRIV-SHARE-001** Find all third parties that receive personal data in application traffic  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds trackers, widgets and SDKs that send data to third parties without notice.  
  *Steps:*
  1. Start a clean browser profile and a proxy.
  2. Load the main pages and log in.
  3. List every third-party host in the traffic.
  4. Look at the parameters sent to each host.
  *Example:* `Burp Suite HTTP history filtered by host; browser developer tools Network tab; look for e-mail, user ID, location in parameters.`  
  *Expected:* Only documented recipients receive data. No personal data goes to a tracker before consent.  
  *Refs:* privacy_top10: P1, P2, P4; other: GDPR Art. 6, GDPR Art. 7, GDPR Art. 13; cwe: CWE-359, CWE-201; cheatsheet: Third_Party_Javascript_Management_Cheat_Sheet  
  *See:* WEB-DATA-004, MOB-PRIV-005

- [ ] **PRIV-SHARE-002** Make sure no tracker fires before consent or after refusal  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds trackers that run without the required consent.  
  *Steps:*
  1. Open the site with a clean profile and do not click the banner.
  2. Record all requests.
  3. Refuse optional cookies and reload.
  4. Record the requests again and compare.
  *Example:* `Browser developer tools Network tab with preserve log; compare host list before and after the consent action.`  
  *Expected:* No analytics or advertising request exists before consent or after refusal.  
  *Refs:* privacy_top10: P4, P10; other: GDPR Art. 6, GDPR Art. 7

- [ ] **PRIV-SHARE-003** Check processor contracts and the list of sub-processors  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds processors that have no contract terms for security and instructions.  
  *Steps:*
  1. Ask for the list of processors.
  2. Ask for the contract of each processor.
  3. Check that each contract has the required terms.
  4. Check the notice process for new sub-processors.
  *Example:* `Document review: contract clauses on instructions, security measures, sub-processors, deletion, audit.`  
  *Expected:* Each processor has a contract with the required terms. Changes of sub-processors need prior authorisation.  
  *Refs:* privacy_top10: P2; other: GDPR Art. 28, GDPR Art. 30

- [ ] **PRIV-SHARE-004** Check that partner data feeds are minimised and pseudonymised  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds partner feeds that hold more data than the partner needs.  
  *Steps:*
  1. List the data feeds to partners.
  2. Look at a sample payload of each feed.
  3. Compare the fields with the contract purpose.
  4. Check for pseudonymisation of identifiers.
  *Example:* `Sample payload review; field list against the data processing agreement.`  
  *Expected:* Each feed carries only the fields that the partner needs. Identifiers are pseudonymised where the purpose allows.  
  *Refs:* privacy_top10: P2, P10; other: GDPR Art. 25, GDPR Art. 28

- [ ] **PRIV-SHARE-005** Make sure external content does not leak the IP address  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds third-party images and scripts that disclose the user IP address or page URL.  
  *Steps:*
  1. List all external images, fonts and scripts on user pages.
  2. Look at the Referer header sent to each host.
  3. Check if users can block external content.
  4. Check that user-supplied URLs are not loaded without a proxy.
  *Example:* `Browser developer tools Network tab; check the Referrer-Policy header.`  
  *Expected:* The application loads external content only from documented hosts. Referrer data is limited. Users can block external content.  
  *Refs:* privacy_top10: P2; other: GDPR Art. 5, GDPR Art. 25; cheatsheet: User_Privacy_Protection_Cheat_Sheet


## VNAUTO

- [ ] **PRIV-VNAUTO-001** Check the notice and consent for automated profiling  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds profiling that the user does not know about.  
  *Steps:*
  1. List the systems that score, rank or predict habits, behaviour, interests or position of a user.
  2. Look for the notice and consent for each system.
  3. Check that the user can object to the profiling.
  4. Check the effect on the user.
  *Example:* `Review the model inventory and the notice text. Test the opt-out as a user.`  
  *Expected:* Users know about profiling and consent to it. An opt-out exists and the controller can show the purpose.  
  *Refs:* privacy_top10: P5, P4; other: Vietnam Decree 13/2023/ND-CP Art. 2, Vietnam Decree 13/2023/ND-CP Art. 9, Vietnam Decree 13/2023/ND-CP Art. 11, Vietnam Decree 13/2023/ND-CP Art. 13, Vietnam PDP Law 91/2025/QH15 Art. 30  
  *See:* PRIV-GOV-005

- [ ] **PRIV-VNAUTO-002** Check AI risk classification and purpose limits for personal data  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds AI systems that use personal data beyond the stated purpose or with no risk class.  
  *Steps:*
  1. List AI systems that process personal data.
  2. Find the risk class for each system.
  3. Check that the safeguards match the class.
  4. Check the training data sources and the purposes.
  5. Check that the system is not used to harm other people.
  *Example:* `Review the AI inventory and the risk register. Compare training data fields with the purpose list.`  
  *Expected:* Each AI system that uses personal data has a risk class and safeguards that match it. It uses data only within the stated purpose.  
  *Refs:* privacy_top10: P10, P2; other: Vietnam PDP Law 91/2025/QH15 Art. 30  
  *See:* PRIV-MINIM-001


## VNBREACH

- [ ] **PRIV-VNBREACH-001** Check that the breach process meets the 72-hour limit  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds breach processes that cannot notify the authority in time.  
  *Steps:*
  1. Read the breach procedure for the Vietnamese authority.
  2. Find the step that starts the 72-hour clock.
  3. Run a table-top case and record the time to notify.
  4. Check that a late notice has the reason for the delay.
  *Example:* `Table-top: simulate the leak of 1000 records. Use form Mau so 03 of the Decree.`  
  *Expected:* The procedure notifies the authority within 72 hours. A late notice includes the reason for the delay.  
  *Refs:* privacy_top10: P3; other: Vietnam Decree 13/2023/ND-CP Art. 23, Vietnam PDP Law 91/2025/QH15 Art. 23  
  *See:* PRIV-BREACH-001

- [ ] **PRIV-VNBREACH-002** Check the content of the breach notice to the authority  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds breach notices that omit required facts.  
  *Steps:*
  1. Get the template or a sample notice.
  2. Look for the time, place, act, parties, data types and amount of data.
  3. Look for the contact of the person in charge of data protection.
  4. Look for the possible effects and the steps taken.
  5. Check that the process allows a notice in stages.
  *Example:* `Use the four groups of Decree Art. 23(3) and form Mau so 03 as a checklist.`  
  *Expected:* The notice has all required facts. The process allows a first notice and then more details in stages.  
  *Refs:* privacy_top10: P3; other: Vietnam Decree 13/2023/ND-CP Art. 23, Vietnam PDP Law 91/2025/QH15 Art. 23  
  *See:* PRIV-BREACH-002

- [ ] **PRIV-VNBREACH-003** Check that processors report breaches to the controller fast  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds processors that delay the breach report.  
  *Steps:*
  1. Read the contract with the processor.
  2. Find the duty and the time limit to report a breach.
  3. Ask the processor to run a test report.
  4. Record the time from detection to the message to the controller.
  *Example:* `Send a test incident alert to the processor contact and measure the response.`  
  *Expected:* The processor tells the controller of a breach as soon as possible. The contact and channel are tested.  
  *Refs:* privacy_top10: P3; other: Vietnam Decree 13/2023/ND-CP Art. 23, Vietnam PDP Law 91/2025/QH15 Art. 23  
  *See:* PRIV-BREACH-005

- [ ] **PRIV-VNBREACH-004** Check the breach record and the reports of other violations  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds breaches with no signed record or with no report of other violations.  
  *Steps:*
  1. Find the record of each past breach.
  2. Check that the record confirms the breach and the work with the authority.
  3. Check the process to report unlawful processing, wrong purpose and failed rights.
  4. Check who can send these reports.
  *Example:* `Document review of the breach register and the report log.`  
  *Expected:* A record exists for each breach. The organisation reports misuse of data and failures to meet data subject rights.  
  *Refs:* privacy_top10: P3; other: Vietnam Decree 13/2023/ND-CP Art. 23, Vietnam PDP Law 91/2025/QH15 Art. 23  
  *See:* PRIV-BREACH-002

- [ ] **PRIV-VNBREACH-005** Check the notice to users after a bank or credit data leak  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds finance firms that do not tell users about a leak of account data.  
  *Steps:*
  1. Read the user notice process for leaks of bank, financial and credit data.
  2. Find who approves and sends the notice.
  3. Run a test case and measure the time.
  4. Check the notice text.
  *Example:* `Table-top: leak of account numbers. Review the notice template.`  
  *Expected:* The firm tells affected users about a leak of bank, financial or credit data.  
  *Refs:* privacy_top10: P3; other: Vietnam PDP Law 91/2025/QH15 Art. 27, Vietnam Decree 13/2023/ND-CP Art. 2  
  *See:* PRIV-BREACH-003


## VNCONSENT

- [ ] **PRIV-VNCONSENT-001** Check that the consent screen shows the four required facts  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds consent that is not informed because required facts are missing.  
  *Steps:*
  1. Open each form or screen that asks for consent.
  2. Look for the types of personal data to be processed.
  3. Look for the purpose, the name of the controller or other organisation, and the rights and duties of the user.
  4. Compare the facts with the real processing.
  *Example:* `Screenshot each consent screen and list the four facts in a table.`  
  *Expected:* Each consent request shows data types, purpose, the organisation that processes the data, and the rights and duties of the data subject.  
  *Refs:* privacy_top10: P5, P4; other: Vietnam Decree 13/2023/ND-CP Art. 11, Vietnam PDP Law 91/2025/QH15 Art. 9  
  *See:* PRIV-NOTICE-001, PRIV-CONSENT-001

- [ ] **PRIV-VNCONSENT-002** Check that consent is clear, per purpose and never implied  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds pre-ticked boxes, silent consent and bundled purposes.  
  *Steps:*
  1. Open each consent form and look at the default state of each box.
  2. Send the form with no choice and see what the service stores.
  3. Accept one purpose and refuse the others, then examine the stored choices.
  4. Try to give consent for part of the data or with a condition.
  5. Look for consent that is a condition of service for an unrelated purpose.
  *Example:* `Intercept the consent request and look for a consent flag per purpose. Burp Repeater: remove the consent field.`  
  *Expected:* Consent is a clear action for each purpose. Silence is not consent. The service accepts partial consent and does not bundle unrelated purposes.  
  *Refs:* privacy_top10: P4; other: Vietnam Decree 13/2023/ND-CP Art. 11, Vietnam PDP Law 91/2025/QH15 Art. 9  
  *See:* PRIV-CONSENT-001, PRIV-CONSENT-002, PRIV-CONSENT-005

- [ ] **PRIV-VNCONSENT-003** Check the consent record and the proof of consent  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds consent that the controller cannot prove in a dispute.  
  *Steps:*
  1. Give consent as a test user and note the time, version and text shown.
  2. Find the consent record in the data store.
  3. Make sure the record can be printed or copied in a readable format.
  4. Change the consent text and check that old records keep the old version.
  5. Ask for the proof of consent for the test user.
  *Example:* `Export the consent log for the test user. Check fields: timestamp, purpose, text version, channel, user ID.`  
  *Expected:* The service keeps a verifiable record for each consent. The controller can show it and can print or copy it.  
  *Refs:* privacy_top10: P4, P5; other: Vietnam Decree 13/2023/ND-CP Art. 11, Vietnam PDP Law 91/2025/QH15 Art. 9  
  *See:* PRIV-CONSENT-004

- [ ] **PRIV-VNCONSENT-004** Test the withdrawal of consent and its spread to processors  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds withdrawals that do not stop processing at the controller or at processors.  
  *Steps:*
  1. Withdraw consent for one purpose as a test user.
  2. Check that the service tells the user about the possible results of the withdrawal.
  3. Check that the service stops the processing for that purpose.
  4. Check that processors and third parties receive the withdrawal.
  5. Check that data from before the withdrawal stays valid as history.
  *Example:* `Look at processor API calls, queue messages and batch jobs after the withdrawal. Compare the data flow before and after.`  
  *Expected:* The service accepts a withdrawal in a recordable format and tells the user the results. The controller, processors and third parties stop the processing.  
  *Refs:* privacy_top10: P4; other: Vietnam Decree 13/2023/ND-CP Art. 12, Vietnam Decree 13/2023/ND-CP Art. 9, Vietnam PDP Law 91/2025/QH15 Art. 10, Vietnam PDP Law 91/2025/QH15 Art. 4  
  *See:* PRIV-CONSENT-003

- [ ] **PRIV-VNCONSENT-005** Check the processing notice before the first processing  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds processing that starts with no notice or with an incomplete notice.  
  *Steps:*
  1. Open the first data collection step as a new user.
  2. Look for a notice before the service collects data.
  3. Look for purpose, data types, method, other parties, possible harm, and start and end time.
  4. Check that the notice is in a form that can be saved or printed.
  5. Check the exception when the user already knows and agrees with all items.
  *Example:* `Capture the notice text and compare it with the six items in the list. Check the timing against the first network request that carries data.`  
  *Expected:* The user gets one complete notice before processing starts. The notice can be saved or printed.  
  *Refs:* privacy_top10: P5; other: Vietnam Decree 13/2023/ND-CP Art. 13, Vietnam PDP Law 91/2025/QH15 Art. 4  
  *See:* PRIV-NOTICE-001, PRIV-NOTICE-002

- [ ] **PRIV-VNCONSENT-006** Check the legal basis for processing without consent  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds processing without consent that has no documented legal exception.  
  *Steps:*
  1. List the processing activities that run without consent.
  2. Find the legal ground for each activity in the register.
  3. Check that the controller can show the emergency or the legal duty.
  4. Look for the oversight process: rules, risk checks, periodic audit and a complaint channel.
  *Example:* `Document review: register of processing with a column for legal ground and a column for owner.`  
  *Expected:* Each processing without consent has a named legal ground and an owner. The controller can prove an urgent case, and an oversight process exists.  
  *Refs:* privacy_top10: P4, P10; other: Vietnam Decree 13/2023/ND-CP Art. 17, Vietnam PDP Law 91/2025/QH15 Art. 19  
  *See:* PRIV-GOV-001


## VNDPIA

- [ ] **PRIV-VNDPIA-001** Review the controller dossier for the impact of processing  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds dossiers with missing items or no dossier.  
  *Steps:*
  1. Get the dossier of the controller.
  2. Check the details of the controller and the data protection staff.
  3. Check the purpose, data types, recipients (also foreign ones), transfers and the storage period.
  4. Check the description of the safeguards and the impact assessment with the risk reduction steps.
  5. Check that a legal document holds the dossier.
  *Example:* `Use the nine items of Decree Art. 24(1) as a table. Compare the dossier with the real data flows.`  
  *Expected:* The dossier exists from the first day of processing and holds all required items. It matches the real data flows.  
  *Refs:* privacy_top10: P5; other: Vietnam Decree 13/2023/ND-CP Art. 24, Vietnam PDP Law 91/2025/QH15 Art. 21  
  *See:* PRIV-GOV-002, PRIV-GOV-001

- [ ] **PRIV-VNDPIA-002** Review the processor dossier for contracted processing  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds processors that keep no impact dossier of their own.  
  *Steps:*
  1. Get the dossier of each processor.
  2. Check the contact details of the processor and its staff.
  3. Check the description of processing and data types in the contract.
  4. Check the storage period, transfers, safeguards and the risk list.
  *Example:* `Document review of the processor dossier against the processor contract.`  
  *Expected:* Each processor keeps a dossier that matches the contract and lists safeguards and risks.  
  *Refs:* privacy_top10: P2, P5; other: Vietnam Decree 13/2023/ND-CP Art. 24, Vietnam PDP Law 91/2025/QH15 Art. 21  
  *See:* PRIV-SHARE-003

- [ ] **PRIV-VNDPIA-003** Check the 60-day filing and the updates of the dossier  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds dossiers that were not filed or that are out of date.  
  *Steps:*
  1. Find the date of the first processing.
  2. Check the filing receipt for an original dossier within 60 days.
  3. Compare the dossier with the current system and vendors.
  4. Check the change notices and the review dates.
  *Example:* `Document review: filing receipt, change notices, system change log. Law: update every 6 months on change.`  
  *Expected:* The dossier is filed in 60 days and updated when the system or business changes. The date of the last review is on record.  
  *Refs:* privacy_top10: P3; other: Vietnam Decree 13/2023/ND-CP Art. 24, Vietnam PDP Law 91/2025/QH15 Art. 21, Vietnam PDP Law 91/2025/QH15 Art. 22  
  *See:* PRIV-GOV-002


## VNMKT

- [ ] **PRIV-VNMKT-001** Check consent for marketing and proof of its use  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds marketing that uses data with no consent or with no proof.  
  *Steps:*
  1. Sign up as a test customer without marketing consent.
  2. Check that no marketing message arrives.
  3. Check that the consent states content, method, form and frequency.
  4. Ask the marketing team for proof of consent for the test user.
  *Example:* `Review the sign-up flow and the campaign tool segments. Check against the consent log.`  
  *Expected:* Marketing uses personal data only with consent that names content, method, form and frequency. The team can prove it.  
  *Refs:* privacy_top10: P4, P10; other: Vietnam Decree 13/2023/ND-CP Art. 21, Vietnam PDP Law 91/2025/QH15 Art. 28  
  *See:* PRIV-CONSENT-001, PRIV-CONSENT-005

- [ ] **PRIV-VNMKT-002** Test the way to refuse advertising and the stop of it  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds advertising that continues after a refusal.  
  *Steps:*
  1. Find the way to refuse advertising in the product and in each message.
  2. Use it as a test user.
  3. Record the time until the advertising stops.
  4. Check that partners stop to use the data.
  *Example:* `Click the unsubscribe link. Check the suppression list and partner sync.`  
  *Expected:* The user can refuse advertising at any time. The service stops it at once and tells the partners.  
  *Refs:* privacy_top10: P4; other: Vietnam PDP Law 91/2025/QH15 Art. 28, Vietnam Decree 13/2023/ND-CP Art. 9  
  *See:* PRIV-DSR-005, PRIV-VNRIGHTS-007

- [ ] **PRIV-VNMKT-003** Check consent and controls for behavioural advertising and tracking  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds tracking for advertising with no consent, no refusal or no storage limit.  
  *Steps:*
  1. Open the site in a new browser with no consent.
  2. Check for tracking cookies and SDK calls before the choice.
  3. Refuse tracking and check that tracking stops.
  4. Look for a do-not-track option.
  5. Check the storage time of the profile data and its deletion.
  *Example:* `Browser developer tools network and storage tabs. Compare with the cookie list in the notice.`  
  *Expected:* The service tracks behaviour only after consent, offers a refusal and a do-not-track option, and sets a storage time with deletion.  
  *Refs:* privacy_top10: P4, P5; other: Vietnam PDP Law 91/2025/QH15 Art. 11, Vietnam PDP Law 91/2025/QH15 Art. 28, Vietnam PDP Law 91/2025/QH15 Art. 29, Vietnam Decree 13/2023/ND-CP Art. 11  
  *See:* PRIV-SHARE-002, PRIV-NOTICE-004, WEB-CLIENT-009

- [ ] **PRIV-VNMKT-004** Check account verification and tracking rules for social platforms  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds platforms that ask for ID images, read messages or collect beyond the agreement.  
  *Steps:*
  1. Register an account on the platform as a test user.
  2. Check the verification step and whether it asks for an image of an ID document.
  3. Check app permissions for call, SMS and microphone access.
  4. Look for the privacy settings, the way to report a violation and the privacy policy.
  *Example:* `Walk through registration. Review the permissions in the mobile manifest.`  
  *Expected:* The platform does not ask for an ID image for verification. It does not read calls or messages without consent and it offers privacy settings and reports.  
  *Refs:* privacy_top10: P10, P5; other: Vietnam PDP Law 91/2025/QH15 Art. 29  
  *See:* MOB-PRIV-004


## VNPROC

- [ ] **PRIV-VNPROC-001** Check that a processor contract exists before data transfer  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds processors that receive data with no contract.  
  *Steps:*
  1. List all processors and the date of first data transfer.
  2. Find the signed contract for each processor.
  3. Check that the date of the contract is before the first transfer.
  4. Check that the contract states the rights, duties and security measures.
  *Example:* `Compare the processor list with the contract register and the date of first API call.`  
  *Expected:* Each processor has a signed contract that is older than the first transfer. The contract states the duties and the measures.  
  *Refs:* privacy_top10: P2; other: Vietnam Decree 13/2023/ND-CP Art. 38, Vietnam Decree 13/2023/ND-CP Art. 39, Vietnam PDP Law 91/2025/QH15 Art. 37  
  *See:* PRIV-SHARE-003

- [ ] **PRIV-VNPROC-002** Check that processors return or delete data when the work ends  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds processors that keep data after the contract ends.  
  *Steps:*
  1. Read the exit clause of the contract.
  2. Close a test project with the processor.
  3. Ask for proof of deletion or return of the test data.
  4. Look in the processor systems for the test data.
  *Example:* `Request a deletion certificate. Look at storage buckets and backups at the processor.`  
  *Expected:* The processor deletes or returns all personal data at the end of the work and gives proof.  
  *Refs:* privacy_top10: P6; other: Vietnam Decree 13/2023/ND-CP Art. 39, Vietnam PDP Law 91/2025/QH15 Art. 14, Vietnam PDP Law 91/2025/QH15 Art. 37  
  *See:* PRIV-RET-003

- [ ] **PRIV-VNPROC-003** Check the consent for data given to another organisation  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds data that goes to third parties without consent.  
  *Steps:*
  1. List the third parties that get personal data.
  2. Find the consent or other ground for each flow.
  3. Run a test user flow and look at the outgoing traffic.
  4. Check the notice to users for the same parties.
  *Example:* `Proxy capture on a test user session. Compare with the consent log.`  
  *Expected:* Data goes to third parties only with consent of the data subject or another ground in law. The notice names the parties.  
  *Refs:* privacy_top10: P2, P4; other: Vietnam Decree 13/2023/ND-CP Art. 14, Vietnam Decree 13/2023/ND-CP Art. 13, Vietnam PDP Law 91/2025/QH15 Art. 15, Vietnam PDP Law 91/2025/QH15 Art. 17  
  *See:* PRIV-SHARE-001, PRIV-SHARE-002


## VNRIGHTS

- [ ] **PRIV-VNRIGHTS-001** Test that a data access request gets an answer within 72 hours  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds access (provision) requests that are late, incomplete or hard to submit.  
  *Steps:*
  1. Send an access request for the test user through each channel the service offers.
  2. Use the fields of the Vietnam form: name, identity number, data requested, format, purpose.
  3. Record the time from the request to the answer.
  4. Read the answer for the cost, place, format and period of delivery.
  5. Compare the delivered data with the data in the database.
  *Example:* `Request form fields follow Mau so 01 (individual) and Mau so 02 (organisation) in the Decree annex. Use a stopwatch or ticket timestamps.`  
  *Expected:* The service answers a valid request within 72 hours and delivers the data in the stated format. It states any cost and the delivery details.  
  *Refs:* privacy_top10: P9; other: Vietnam Decree 13/2023/ND-CP Art. 9, Vietnam Decree 13/2023/ND-CP Art. 14, Vietnam PDP Law 91/2025/QH15 Art. 4, Vietnam PDP Law 91/2025/QH15 Art. 15  
  *See:* PRIV-DSR-001, PRIV-DSR-002, PRIV-DSR-006

- [ ] **PRIV-VNRIGHTS-002** Check requests from a representative and requests to third parties  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds service that hands data to a wrong representative or gives it to others without consent.  
  *Steps:*
  1. Send an access request for the test user from an authorised representative with a written authorisation.
  2. Send the same request with no written authorisation.
  3. Ask the service to send the test user data to another organisation. Try with and without consent.
  4. Check that the service refuses each request that has no consent or authorisation.
  *Example:* `Use a signed authorisation letter and an unsigned copy. Check the audit record of each request.`  
  *Expected:* The service acts for a representative only with written authorisation. It gives data to another party only with the consent of the data subject.  
  *Refs:* privacy_top10: P9, P2; other: Vietnam Decree 13/2023/ND-CP Art. 11, Vietnam Decree 13/2023/ND-CP Art. 14, Vietnam PDP Law 91/2025/QH15 Art. 15  
  *See:* PRIV-DSR-002

- [ ] **PRIV-VNRIGHTS-003** Test the correction of personal data and the 72-hour answer  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds correction requests that fail, come late or do not reach other recipients.  
  *Steps:*
  1. Change a field in the test user profile with the self-service function.
  2. Send a correction request for a field that the user cannot change directly.
  3. Record the time until the service corrects the field or gives a refusal.
  4. Check that processors and third parties hold the corrected value.
  5. Check that the refusal states a valid reason.
  *Example:* `Compare the field in the web application, the database and the processor export before and after the request.`  
  *Expected:* The service corrects the data as soon as possible or tells the user of the refusal within 72 hours. Recipients receive the correction.  
  *Refs:* privacy_top10: P9, P7; other: Vietnam Decree 13/2023/ND-CP Art. 9, Vietnam Decree 13/2023/ND-CP Art. 15, Vietnam PDP Law 91/2025/QH15 Art. 4, Vietnam PDP Law 91/2025/QH15 Art. 13  
  *See:* PRIV-DSR-003

- [ ] **PRIV-VNRIGHTS-004** Test the deletion request and the 72-hour limit  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds deletion requests that are late, partial or refused with no reason.  
  *Steps:*
  1. Send a deletion request for the test user for data that is no longer needed.
  2. Record the time until the service deletes the data.
  3. Look for the data in the database, the search index, the file store and the processor systems.
  4. Send a deletion request for data that the service must keep by law.
  5. Check that the service tells the user why it did not delete.
  *Example:* `Use the grounds in Decree Art. 16(1): no longer needed, consent withdrawn, objection, unlawful processing.`  
  *Expected:* The service deletes all copies of the requested data within 72 hours. It states the legal ground when it refuses.  
  *Refs:* privacy_top10: P6; other: Vietnam Decree 13/2023/ND-CP Art. 9, Vietnam Decree 13/2023/ND-CP Art. 16, Vietnam PDP Law 91/2025/QH15 Art. 4, Vietnam PDP Law 91/2025/QH15 Art. 14  
  *See:* PRIV-RET-003, PRIV-RET-004, PRIV-RET-005

- [ ] **PRIV-VNRIGHTS-005** Check that deletion is irrecoverable and covers old devices  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds deleted data that an attacker can restore, or old media that still hold data.  
  *Steps:*
  1. Delete a test record and then look for it in backups, snapshots and replicas.
  2. Look for recovery tools or an undelete function in the application.
  3. Review the way the organisation destroys disks and devices that held personal data.
  4. Look at the record of the security check made before a device is wiped or destroyed.
  *Example:* `Review the media destruction records and the retention schedule of backups. Try a database undelete or point-in-time restore on a test copy.`  
  *Expected:* Deleted data cannot be restored by normal means. The organisation checks the security of a system before it wipes or destroys devices.  
  *Refs:* privacy_top10: P6; other: Vietnam Decree 13/2023/ND-CP Art. 16, Vietnam Decree 13/2023/ND-CP Art. 27, Vietnam PDP Law 91/2025/QH15 Art. 14  
  *See:* PRIV-RET-002, PRIV-RET-004

- [ ] **PRIV-VNRIGHTS-006** Test the restriction of processing within 72 hours  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds requests to restrict processing that the service ignores or does late.  
  *Steps:*
  1. Send a restriction request for chosen data of the test user.
  2. Record the time until the service applies the restriction.
  3. Check that analytics, e-mail and batch jobs do not use the restricted data.
  4. Check that processors receive the restriction.
  5. Check that the user can lift the restriction.
  *Example:* `Look for a restriction flag in the data model. Run the marketing and reporting jobs and check their output.`  
  *Expected:* The service restricts all requested data within 72 hours and stops all use except storage. Processors apply the restriction.  
  *Refs:* privacy_top10: P9; other: Vietnam Decree 13/2023/ND-CP Art. 9, Vietnam PDP Law 91/2025/QH15 Art. 4, Vietnam PDP Law 91/2025/QH15 Art. 10  
  *See:* PRIV-DSR-006

- [ ] **PRIV-VNRIGHTS-007** Test the objection to disclosure and marketing within 72 hours  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds objections that the service does not apply, or applies late.  
  *Steps:*
  1. Send an objection to use for advertising and marketing for the test user.
  2. Send an objection to disclosure of the personal data to others.
  3. Record the time until the service applies each objection.
  4. Send a marketing e-mail campaign and check that the test user is not in it.
  5. Check that partners stop to use the data.
  *Example:* `Use the in-product opt-out and a written request. Check the suppression list.`  
  *Expected:* The service applies the objection within 72 hours. The user gets no marketing and the data is not disclosed.  
  *Refs:* privacy_top10: P9, P4; other: Vietnam Decree 13/2023/ND-CP Art. 9, Vietnam PDP Law 91/2025/QH15 Art. 4, Vietnam PDP Law 91/2025/QH15 Art. 28  
  *See:* PRIV-DSR-005, PRIV-VNMKT-002


## VNSEC

- [ ] **PRIV-VNSEC-001** Check the security measures for personal data across its life  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds processing with no managed and technical protection from the start.  
  *Steps:*
  1. Read the data protection rules of the organisation.
  2. Check the list of managed and technical measures for each system.
  3. Check that measures exist from the start of the project and are reviewed.
  4. Check that standard-based controls are in use.
  *Example:* `Review the policy, the control list and the last review date. Match with the security tests in the sheets SEC and WEB-DATA.`  
  *Expected:* Managed and technical measures exist from the start and through the whole processing. The organisation reviews and updates them.  
  *Refs:* privacy_top10: P2, P1; other: Vietnam Decree 13/2023/ND-CP Art. 3, Vietnam Decree 13/2023/ND-CP Art. 26, Vietnam Decree 13/2023/ND-CP Art. 27, Vietnam PDP Law 91/2025/QH15 Art. 37  
  *See:* PRIV-SEC-007, PRIV-GOV-003

- [ ] **PRIV-VNSEC-002** Check the system log of personal data processing  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds processing that leaves no trace for audit.  
  *Steps:*
  1. Read the log design for systems that process personal data.
  2. Do a read, change and delete action on a test record.
  3. Find the log entries for each action.
  4. Check the retention and protection of the log.
  *Example:* `Search the log store by test user ID. Check the fields: who, when, what.`  
  *Expected:* The system logs the processing of personal data and keeps the log. The log holds no clear personal data that it does not need.  
  *Refs:* privacy_top10: P2; other: Vietnam Decree 13/2023/ND-CP Art. 38  
  *See:* WEB-LOG-002, WEB-LOG-006, WEB-LOG-012

- [ ] **PRIV-VNSEC-003** Test the system against unlawful collection of personal data  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds interfaces that allow bulk scraping of personal data.  
  *Steps:*
  1. List public pages and API endpoints that return personal data.
  2. Send many requests for different user IDs from one client.
  3. Check for rate limits, authentication and bot controls.
  4. Check that the response shows only needed fields.
  *Example:* `Burp Intruder or a script with 500 requests. Look at status codes and alerts.`  
  *Expected:* The service blocks bulk collection of personal data from its systems and shows only needed fields.  
  *Refs:* privacy_top10: P2, P1; other: Vietnam Decree 13/2023/ND-CP Art. 22, Vietnam PDP Law 91/2025/QH15 Art. 37  
  *See:* WEB-BOT-001, WEB-IDOR-001, WEB-DATA-007

- [ ] **PRIV-VNSEC-004** Check that partner data feeds are not a sale of data  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds partner feeds that count as a purchase or sale of personal data.  
  *Steps:*
  1. List the partner feeds and the data they carry.
  2. Read the contracts for payment or exchange of personal data.
  3. Check the legal ground and the consent for each feed.
  4. Check that data is not offered for sale in any other channel.
  *Example:* `Document review of partner contracts and the data catalogue. grep the code for export jobs.`  
  *Expected:* No feed sells or buys personal data. Each transfer to a third party has a legal ground.  
  *Refs:* privacy_top10: P2, P10; other: Vietnam Decree 13/2023/ND-CP Art. 3, Vietnam Decree 13/2023/ND-CP Art. 22, Vietnam PDP Law 91/2025/QH15 Art. 7, Vietnam PDP Law 91/2025/QH15 Art. 17  
  *See:* PRIV-SHARE-004, PRIV-SHARE-001

- [ ] **PRIV-VNSEC-005** Check that de-identified data cannot be traced back  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds de-identified data sets that a party can link back to a person.  
  *Steps:*
  1. Read the method to de-identify data.
  2. Try to link the de-identified set with other sets that the organisation holds.
  3. Check who holds the key or the mapping table.
  4. Check the controls over the de-identification process.
  *Example:* `Try a join on quasi-identifiers: date of birth, postcode, device ID. Review the key store.`  
  *Expected:* A party cannot link de-identified data to a person. The process has access control and monitoring, and nobody re-identifies the data.  
  *Refs:* privacy_top10: P2, P10; other: Vietnam PDP Law 91/2025/QH15 Art. 2, Vietnam PDP Law 91/2025/QH15 Art. 14  
  *See:* PRIV-MINIM-004, PRIV-SHARE-004

- [ ] **PRIV-VNSEC-006** Check access control and identity for AI, big data and cloud systems  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds systems with weak authentication or roles around personal data.  
  *Steps:*
  1. List the AI, big data, cloud and blockchain systems that use personal data.
  2. Check the authentication method and the roles.
  3. Check that the system uses personal data only for its stated purpose.
  4. Check that the system has security measures built in.
  *Example:* `Review the role matrix and the identity settings. Link to the sheets CLD, LLM and PRIV-SEC.`  
  *Expected:* The system uses suitable authentication and role-based access for personal data, and it keeps within the stated purpose.  
  *Refs:* privacy_top10: P2, P10; other: Vietnam PDP Law 91/2025/QH15 Art. 12, Vietnam PDP Law 91/2025/QH15 Art. 30  
  *See:* PRIV-SEC-003, PRIV-SEC-002


## VNSENS

- [ ] **PRIV-VNSENS-001** Find sensitive personal data in the data inventory  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds sensitive data that the inventory does not mark and therefore misses extra controls.  
  *Steps:*
  1. Read the data inventory and the database schema.
  2. Mark fields that fit the sensitive categories: health, biometric, location, bank and account data, race, religion, politics.
  3. Look for such data in logs, files and analytics events.
  4. Check that the inventory shows each sensitive field.
  *Example:* `grep the schema for health, biometric, geo, account and card terms. Compare with the inventory.`  
  *Expected:* All sensitive fields are in the inventory and are marked. No sensitive field is hidden in free text, logs or analytics.  
  *Refs:* privacy_top10: P2, P10; other: Vietnam Decree 13/2023/ND-CP Art. 2, Vietnam PDP Law 91/2025/QH15 Art. 2  
  *See:* PRIV-MINIM-001, WEB-DATA-001

- [ ] **PRIV-VNSENS-002** Check that the user is told when sensitive data is processed  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds sensitive data processing that the user does not know about.  
  *Steps:*
  1. Open each form that collects sensitive data.
  2. Look for a clear message that the data is sensitive personal data.
  3. Look for the same message in the consent text.
  4. Check that the controller has a department or person named for data protection.
  *Example:* `Screenshot the form and the consent text. Look for the notice before submit.`  
  *Expected:* The user sees a notice that the data is sensitive before the service processes it. A data protection department or person is named.  
  *Refs:* privacy_top10: P5; other: Vietnam Decree 13/2023/ND-CP Art. 11, Vietnam Decree 13/2023/ND-CP Art. 28, Vietnam PDP Law 91/2025/QH15 Art. 33  
  *See:* PRIV-NOTICE-001

- [ ] **PRIV-VNSENS-003** Test the age check and the parent consent for child data  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds child data processing that starts with no age check or parent consent.  
  *Steps:*
  1. Register as a user who states an age under 16 and one who states age 7 to 15.
  2. Look for an age check before the service processes data.
  3. Check that consent comes from the parent or guardian and, for age 7 or older, from the child as well.
  4. Try to skip the parent step.
  *Example:* `Burp Repeater: change the age or the consent flag in the registration request. Look at server-side checks.`  
  *Expected:* The service checks the age before it processes data of a child. It needs consent of the guardian, and of the child from age 7.  
  *Refs:* privacy_top10: P4, P5; other: Vietnam Decree 13/2023/ND-CP Art. 20, Vietnam PDP Law 91/2025/QH15 Art. 24

- [ ] **PRIV-VNSENS-004** Test the stop and deletion of child data on request  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds child data that stays after a guardian withdraws consent or an authority asks.  
  *Steps:*
  1. Withdraw the consent of the guardian for a test child account.
  2. Check that the service stops the processing.
  3. Check that the service deletes the child data in a way that cannot be restored.
  4. Check the process for a written request from an authority.
  *Example:* `Look at the child account, backups and processor copies after the withdrawal.`  
  *Expected:* The service stops processing child data and deletes it when the guardian withdraws consent or the purpose ends. It acts on a valid authority order.  
  *Refs:* privacy_top10: P6; other: Vietnam Decree 13/2023/ND-CP Art. 20, Vietnam PDP Law 91/2025/QH15 Art. 24  
  *See:* PRIV-RET-003

- [ ] **PRIV-VNSENS-005** Check the handling of location data  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds tracking of position with no consent or with access by other parties.  
  *Steps:*
  1. Install the mobile application or open the web page that uses position.
  2. Look for a notice about the use of location data.
  3. Look for an option to switch tracking off.
  4. Check network traffic for location sent to parties not related to the service.
  *Example:* `Use a proxy to inspect traffic for latitude, longitude or Wi-Fi data. Check the OS permission prompt.`  
  *Expected:* The service tracks position only with consent or by legal order. It tells the user, offers options and sends location to no unrelated party.  
  *Refs:* privacy_top10: P10, P2; other: Vietnam Decree 13/2023/ND-CP Art. 2, Vietnam PDP Law 91/2025/QH15 Art. 31  
  *See:* MOB-PRIV-004, MOB-PRIV-005

- [ ] **PRIV-VNSENS-006** Check the protection of biometric data  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds biometric data that is stored or sent with weak physical, access or monitoring controls.  
  *Steps:*
  1. List the places that store or send biometric data.
  2. Check the physical security of the storage and the transport devices.
  3. Check that only needed roles can read the data.
  4. Look for monitoring and alerts on access to the data.
  5. Check the notice to the user after harm.
  *Example:* `Review the access list and the monitoring rules. Look for templates, images and raw samples.`  
  *Expected:* The organisation limits access to biometric data, protects the storage devices and watches for abuse. It tells the user when harm occurs.  
  *Refs:* privacy_top10: P2; other: Vietnam Decree 13/2023/ND-CP Art. 2, Vietnam PDP Law 91/2025/QH15 Art. 31  
  *See:* PRIV-SEC-003

- [ ] **PRIV-VNSENS-007** Check the limits on sharing of health and insurance data  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds health data that goes to insurers or care providers with no written request.  
  *Steps:*
  1. List the recipients of health data.
  2. Look for the legal ground or the written request of the user for each recipient.
  3. Try to send data to an insurer without the request.
  4. Check the contract clauses for reinsurance transfers.
  *Example:* `Review data sharing agreements and interface logs between the health service and insurance partners.`  
  *Expected:* Health data goes to care or insurance providers only after a written request of the user or an emergency. Reinsurance transfers are in the customer contract.  
  *Refs:* privacy_top10: P2, P10; other: Vietnam PDP Law 91/2025/QH15 Art. 26, Vietnam Decree 13/2023/ND-CP Art. 2  
  *See:* PRIV-SHARE-004

- [ ] **PRIV-VNSENS-008** Check the notice and retention of audio and video recordings  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds recording with no notice or with data kept too long.  
  *Steps:*
  1. Find the places and systems that record audio or video of people.
  2. Look for a sign or notice that tells people about the recording.
  3. Read the retention rule and the deletion job for the recordings.
  4. Check that the use of the recordings fits the purpose.
  *Example:* `Photograph the notice at the camera. Compare the oldest recording with the retention rule.`  
  *Expected:* People can see that recording takes place. The system keeps recordings only as long as needed and deletes them after that.  
  *Refs:* privacy_top10: P5, P6; other: Vietnam Decree 13/2023/ND-CP Art. 18, Vietnam PDP Law 91/2025/QH15 Art. 32  
  *See:* PRIV-RET-001

- [ ] **PRIV-VNSENS-009** Check recruitment data and the monitoring of employees  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds candidate data that is kept after the process, and secret monitoring of staff.  
  *Steps:*
  1. Look at the data fields that the recruitment form requires.
  2. Check that the data of rejected candidates is deleted, unless the candidate agreed to keep it.
  3. Check that the service deletes employee data when the contract ends, unless the law or an agreement says otherwise.
  4. Look for technical monitoring of staff and the notice to staff.
  *Example:* `Review the HR system retention jobs and the staff notice. Compare the form fields with the job purpose.`  
  *Expected:* The organisation asks only for data that the job needs and deletes it on time. Staff know about technical monitoring.  
  *Refs:* privacy_top10: P10, P6, P5; other: Vietnam PDP Law 91/2025/QH15 Art. 25, Vietnam Decree 13/2023/ND-CP Art. 9  
  *See:* PRIV-RET-001


## VNXFER

- [ ] **PRIV-VNXFER-001** Find all flows of data of Vietnamese citizens to other countries  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds cross-border flows that are not on record.  
  *Steps:*
  1. List the systems, cloud regions and platforms that process data collected in Vietnam.
  2. Mark each system outside Vietnam, including remote access and remote support.
  3. Use traffic capture to find data sent to foreign hosts.
  4. Compare the result with the transfer register.
  *Example:* `Use DNS and TLS SNI logs, cloud region settings and a proxy capture. Mark data of Vietnamese citizens by country code of the user.`  
  *Expected:* The transfer register lists every flow of data of Vietnamese citizens to a place outside Vietnam, including foreign platforms that process the data.  
  *Refs:* privacy_top10: P2; other: Vietnam Decree 13/2023/ND-CP Art. 2, Vietnam Decree 13/2023/ND-CP Art. 25, Vietnam PDP Law 91/2025/QH15 Art. 20  
  *See:* PRIV-XFER-001, PRIV-XFER-003

- [ ] **PRIV-VNXFER-002** Review the content of the cross-border transfer impact assessment  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds transfer assessments that miss required items.  
  *Steps:*
  1. Get the transfer impact assessment dossier.
  2. Check the details and contacts of the exporter and the importer.
  3. Check the purpose, the data types, the safeguards and the risk assessment.
  4. Check the consent of the data subject and the complaint process.
  5. Check the written agreement between the exporter and the importer.
  *Example:* `Use the six-item checklist from Decree Art. 25(2) as a table.`  
  *Expected:* The dossier has all required items, including the written agreement of the exporter and the importer and the consent with a complaint process.  
  *Refs:* privacy_top10: P5; other: Vietnam Decree 13/2023/ND-CP Art. 25, Vietnam PDP Law 91/2025/QH15 Art. 20  
  *See:* PRIV-XFER-002, PRIV-GOV-002

- [ ] **PRIV-VNXFER-003** Check the filing of the transfer dossier and the update schedule  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds transfers that start with no filing or whose dossier is out of date.  
  *Steps:*
  1. Find the date of the first transfer.
  2. Check that the authority received an original dossier within 60 days of that date.
  3. Check the update records after each change of the dossier content.
  4. Look for a notice to the authority after the first transfer.
  *Example:* `Document review: filing receipt, dossier version history, change log.`  
  *Expected:* The dossier is filed within 60 days of the first transfer and each change is filed. The dossier is always ready for inspection.  
  *Refs:* privacy_top10: P3; other: Vietnam Decree 13/2023/ND-CP Art. 25, Vietnam PDP Law 91/2025/QH15 Art. 20, Vietnam PDP Law 91/2025/QH15 Art. 22  
  *See:* PRIV-GOV-002

- [ ] **PRIV-VNXFER-004** Check that the service can stop a transfer on order  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds transfers that the operator cannot stop quickly when the authority orders it.  
  *Steps:*
  1. Find the technical controls that start and stop each transfer.
  2. Ask who can stop the transfer and how long it takes.
  3. Try the stop on a test flow in the test environment.
  4. Check that the operator keeps contact details for the authority and the responsible person.
  *Example:* `Run the stop in the test environment: disable the export job, revoke the key or block the egress rule.`  
  *Expected:* The operator can stop each cross-border transfer quickly on order and knows who does it.  
  *Refs:* privacy_top10: P2; other: Vietnam Decree 13/2023/ND-CP Art. 25, Vietnam PDP Law 91/2025/QH15 Art. 20

- [ ] **PRIV-VNXFER-005** Check the cloud and platform settings for data of Vietnamese citizens  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds cloud and SaaS tenants that send data abroad with no assessment.  
  *Steps:*
  1. List the cloud and SaaS tenants that hold data of Vietnamese citizens.
  2. Read the region and replication settings.
  3. Check support access and logging exports.
  4. Match each setting to the transfer dossier.
  *Example:* `Cloud console region view, replication rules, log export targets.`  
  *Expected:* Each tenant setting matches the transfer dossier. No replica or log copy leaves the stated location.  
  *Refs:* privacy_top10: P2; other: Vietnam Decree 13/2023/ND-CP Art. 2, Vietnam Decree 13/2023/ND-CP Art. 25, Vietnam PDP Law 91/2025/QH15 Art. 20  
  *See:* PRIV-XFER-003


## XFER

- [ ] **PRIV-XFER-001** Find all places where personal data leaves the legal region  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds data transfers to other countries that nobody documented.  
  *Steps:*
  1. List the regions of all hosts, backups, support tools and processors.
  2. Check DNS and IP data of the hosts in application traffic.
  3. Compare with the record of processing.
  4. Mark each unrecorded transfer.
  *Example:* `Cloud console region list; whois/geoip for hosts in the proxy log; record of processing activities.`  
  *Expected:* All storage and processing locations are known. Each transfer outside the region is recorded.  
  *Refs:* privacy_top10: P2; other: GDPR Art. 30, GDPR Art. 44

- [ ] **PRIV-XFER-002** Check the legal mechanism for each transfer to a third country  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds transfers with no adequacy decision or safeguard.  
  *Steps:*
  1. List each third country and recipient.
  2. Find the mechanism: adequacy decision, standard clauses or binding corporate rules.
  3. Check the documents exist and are current.
  4. Check the user notice names the safeguard.
  *Example:* `Document review: transfer register with mechanism, date, contract reference.`  
  *Expected:* Each transfer has a valid mechanism that is on record and named in the notice.  
  *Refs:* privacy_top10: P2, P5; other: GDPR Art. 44, GDPR Art. 45, GDPR Art. 46, GDPR Art. 47, GDPR Art. 49, GDPR Art. 13

- [ ] **PRIV-XFER-003** Check the region settings of cloud and SaaS services  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds services set to the wrong region or with global replication.  
  *Steps:*
  1. Open the region and replication settings of each data store.
  2. Check support and log tools for data copies in other regions.
  3. Check that the settings match the record.
  4. Check the infrastructure code for the same values.
  *Example:* `Terraform or console review; look for global replication or default region values.`  
  *Expected:* Region and replication settings match the recorded location. No uncontrolled copies exist elsewhere.  
  *Refs:* privacy_top10: P2; other: GDPR Art. 44, GDPR Art. 30
