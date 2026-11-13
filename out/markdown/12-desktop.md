# DESKTOP security test cases

47 tests. Tick the box when the test passes.


## AUTH

- [ ] **DESK-AUTH-001** Test the login for bypass by changing client state  
  *Severity if fail:* Critical | *Type:* Manual  
  *Objective:* Finds checks that only run in the client and that a user can change or skip.  
  *Steps:*
  1. Find where the client decides that a user is logged in.
  2. Change the local flag, config value or return value with a debugger.
  3. Try to open a protected screen.
  4. Send the server calls without the login step.
  *Example:* `dnSpy breakpoint on the login method; Burp Suite replay of API calls with no token.`  
  *Expected:* The server decides on access. A changed client flag does not give access to protected data or functions.  
  *Refs:* cwe: CWE-306, CWE-285; asvs: V2.2.2; desktop_top10: DA2, DA5

- [ ] **DESK-AUTH-002** Check that sessions end at logout, timeout and lock  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds sessions and tokens that stay valid after the user leaves.  
  *Steps:*
  1. Log in and note the session token or ticket.
  2. Log out and replay the token against the server.
  3. Leave the client idle and test again after the timeout.
  4. Check the token files on disk after logout.
  *Example:* `Burp Repeater or curl with the old token; Procmon on the profile folder.`  
  *Expected:* The server rejects the old token. The client deletes local tokens. The idle timeout locks the client.  
  *Refs:* asvs: V7.3.1; desktop_top10: DA2  
  *See:* WEB-SESS-017, WEB-SESS-019

- [ ] **DESK-AUTH-003** Check hardware logins for a second factor  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds RFID, smart card or USB key logins that work without a PIN.  
  *Steps:*
  1. List the hardware factors that the client accepts.
  2. Present a copied or lost device in a test setup.
  3. Check if the client asks for a PIN or password.
  4. Check the lock-out rules after wrong PINs.
  *Example:* `Test device in a lab; check client logs for the PIN prompt and the count of failed tries.`  
  *Expected:* A hardware device alone does not give access. The client asks for a PIN or password and locks after repeated failures.  
  *Refs:* cwe: CWE-306; desktop_top10: DA2

- [ ] **DESK-AUTH-004** Check kiosk and shared-device modes for authentication gaps  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds public or emergency modes that skip login and give too much access.  
  *Steps:*
  1. List the modes that run without login.
  2. Try to leave the kiosk shell with keys and dialogs.
  3. Open file dialogs and help links.
  4. List the data and functions reachable in each mode.
  *Example:* `Keyboard shortcuts such as Alt+Tab and Ctrl+Alt+Del on a test machine; record each escape path.`  
  *Expected:* Modes with no login expose only the planned functions. The user cannot reach the OS shell, files or admin functions.  
  *Refs:* desktop_top10: DA2, DA6

- [ ] **DESK-AUTH-005** Check stored credentials and the remember-me feature  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds saved passwords and tokens that others can read.  
  *Steps:*
  1. Turn on remember me and log in.
  2. Search the profile folder, registry and credential store for the secret.
  3. Check file and key access rights.
  4. Check the token life time.
  *Example:* `Procmon filter on the client process; reg query HKCU\Software\Vendor; strings on profile files.`  
  *Expected:* The client stores only a short-lived token in the OS credential store. It stores no password in clear or reversible form.  
  *Refs:* cwe: CWE-522, CWE-256, CWE-257; cheatsheet: Password_Storage_Cheat_Sheet; desktop_top10: DA2, DA3


## AUTHZ

- [ ] **DESK-AUTHZ-001** Check install folders and config files for weak permissions  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds files that low-privilege users can change.  
  *Steps:*
  1. List the install folders and the data folders.
  2. Read the access rights with icacls or ls -l.
  3. Look for write rights for Users, Everyone or other.
  4. Try to change a config file and a binary as a normal user.
  *Example:* `icacls "C:\Program Files\Vendor" /T; accesschk.exe -uwdqs Users; find / -perm -o+w on Linux.`  
  *Expected:* Only administrators can change program files. User data folders are readable only by the owner.  
  *Refs:* cwe: CWE-276, CWE-732; wstg: WSTG-CONF-09; desktop_top10: DA5

- [ ] **DESK-AUTHZ-002** Check the privilege level of the client and its services  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds processes that run as administrator, root or SYSTEM without need.  
  *Steps:*
  1. List all processes and services that the product installs.
  2. Read the account of each process.
  3. Check for setuid or setgid bits on Linux binaries.
  4. Find which functions need elevation.
  *Example:* `Process Explorer user column; sc qc service; find / -perm -4000 -user root.`  
  *Expected:* Each process runs with the lowest rights it needs. No binary has setuid or setgid without need.  
  *Refs:* cwe: CWE-250, CWE-269; cheatsheet: Secure_Product_Design_Cheat_Sheet; desktop_top10: DA5

- [ ] **DESK-AUTHZ-003** Check registry keys and settings that carry security decisions  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds registry values or policy files that a normal user can change to bypass controls.  
  *Steps:*
  1. List the registry keys that the product reads and writes.
  2. Check the access rights of each key.
  3. Change a security setting as a normal user.
  4. Restart the product and look at the effect.
  *Example:* `Procmon filter on Registry operations; accesschk.exe -kvuqsw HKLM\Software\Vendor.`  
  *Expected:* Only administrators can change security settings. A changed user-level value does not lower protection.  
  *Refs:* cwe: CWE-732, CWE-269; desktop_top10: DA5, DA6

- [ ] **DESK-AUTHZ-004** Test admin functions of the client for vertical privilege change  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds admin functions that the server allows for normal users.  
  *Steps:*
  1. Log in as a normal user and as an admin.
  2. Record the API calls for admin functions.
  3. Replay them with the normal user token.
  4. Show hidden menu items with a UI inspection tool.
  *Example:* `Burp Suite Autorize extension; Snoop or Inspect.exe for hidden controls.`  
  *Expected:* The server rejects admin calls from normal users. Hidden controls do not give access.  
  *Refs:* cwe: CWE-862, CWE-863; desktop_top10: DA5


## CODE

- [ ] **DESK-CODE-001** Check code signing of the installer, binaries and libraries  
  *Severity if fail:* Medium | *Type:* Manual, Automated  
  *Objective:* Finds unsigned or wrongly signed files.  
  *Steps:*
  1. List all executables and DLL files in the install.
  2. Check the signature of each file.
  3. Check that the certificate chain and time stamp are valid.
  4. Change one file and start the product.
  *Example:* `sigcheck.exe -u -e -s "C:\Program Files\Vendor"; Get-AuthenticodeSignature; codesign -v on macOS.`  
  *Expected:* All shipped code has a valid signature from the vendor. A changed file is rejected by the installer or loader.  
  *Refs:* cwe: CWE-494, CWE-345; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet; desktop_top10: DA8

- [ ] **DESK-CODE-002** Test for DLL search order hijacking and untrusted load paths  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds loads of libraries from folders that a user can write.  
  *Steps:*
  1. Run the product with Process Monitor.
  2. Filter on NAME NOT FOUND for DLL loads.
  3. Check the write rights of the searched folders.
  4. Place a harmless test library in a writable searched folder.
  *Example:* `Procmon filter: Result is NAME NOT FOUND and Path ends with .dll. Use a benign test DLL that writes a marker file.`  
  *Expected:* The product loads libraries from fixed trusted paths. No searched folder is writable by normal users.  
  *Refs:* cwe: CWE-426, CWE-427; cheatsheet: DotNet_Security_Cheat_Sheet; desktop_top10: DA8, DA5

- [ ] **DESK-CODE-003** Test temporary files and update steps for race conditions  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds time-of-check time-of-use gaps in file handling.  
  *Steps:*
  1. Find the temporary files and folders the product makes.
  2. Check the names and the access rights.
  3. Replace the file between check and use in a test setup.
  4. Check that the product checks the file again.
  *Example:* `Procmon file events; script that swaps a test file in a lab.`  
  *Expected:* Temporary files have random names in a private folder. The product opens each file once and keeps the handle.  
  *Refs:* cwe: CWE-367, CWE-378; desktop_top10: DA8

- [ ] **DESK-CODE-004** Check binary hardening flags and memory safety of native code  
  *Severity if fail:* Medium | *Type:* Automated, Manual  
  *Objective:* Finds missing ASLR, DEP and stack protection and unsafe functions.  
  *Steps:*
  1. List native binaries in the install.
  2. Read the hardening flags of each.
  3. Search for unsafe copy functions in the code or symbols.
  4. Send over-long input to parsers in a test lab.
  *Example:* `winchecksec; checksec --file on Linux; dumpbin /headers; fuzz parsers with a lab fuzzer.`  
  *Expected:* All native binaries use ASLR, DEP and stack protection. Parsers check lengths and fail safely on long input.  
  *Refs:* cwe: CWE-120, CWE-787, CWE-125, CWE-416; asvs: V1.4.1; desktop_top10: DA8

- [ ] **DESK-CODE-005** Check the release build for debug code and test data  
  *Severity if fail:* Low | *Type:* Manual, Code Review  
  *Objective:* Finds dead code, test accounts and debug switches in the release.  
  *Steps:*
  1. Decompile the release build.
  2. Search for debug flags, test accounts and test URLs.
  3. Look for debug symbols and verbose log switches.
  4. Start the client with a debug argument.
  *Example:* `ILSpy; strings; command line flags such as --debug or environment variables in the code.`  
  *Expected:* The release has no debug mode, test accounts or test data. Debug switches do not change security.  
  *Refs:* cwe: CWE-489, CWE-215; asvs: V13.4.2; desktop_top10: DA8

- [ ] **DESK-CODE-006** Check that critical decisions do not depend on tamper detection alone  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds license and admin checks that a debugger or hook can change.  
  *Steps:*
  1. Attach a debugger to the client in a lab.
  2. Hook the license or admin check with Frida.
  3. Change the return value.
  4. Check that the server confirms the result.
  *Example:* `Frida script that only logs and changes one boolean in a test copy.`  
  *Expected:* Critical decisions are made on the server. Hooking the client does not give paid or admin functions.  
  *Refs:* cwe: CWE-693; desktop_top10: DA8


## COMM

- [ ] **DESK-COMM-001** Capture client traffic and find clear-text protocols  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds HTTP, FTP, Telnet, MQTT or plain database traffic.  
  *Steps:*
  1. Start Wireshark on the client interface.
  2. Use all main functions.
  3. List all protocols and ports in the capture.
  4. Look for credentials and data in clear text.
  *Example:* `Wireshark display filter !tls && !ssh; tshark -r cap.pcap -q -z conv,tcp.`  
  *Expected:* All client traffic uses TLS or another encrypted protocol. No credentials or data appear in clear text.  
  *Refs:* cwe: CWE-319; cheatsheet: Transport_Layer_Security_Cheat_Sheet; asvs: V12.3.1; wstg: WSTG-CRYP-03; desktop_top10: DA7  
  *See:* WEB-TLS-006, WEB-TLS-005

- [ ] **DESK-COMM-002** Check TLS versions and cipher suites of all client endpoints  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds old protocol versions and weak ciphers.  
  *Steps:*
  1. List all server hosts and ports from the capture.
  2. Scan each endpoint for protocol versions and ciphers.
  3. Check the database connection for TLS.
  4. Compare with the approved list.
  *Example:* `nmap --script ssl-enum-ciphers -p 443,1433 host; testssl.sh host:port.`  
  *Expected:* All endpoints accept only TLS 1.2 and TLS 1.3 with strong ciphers.  
  *Refs:* cwe: CWE-327; cheatsheet: Transport_Layer_Security_Cheat_Sheet; asvs: V12.1.1; desktop_top10: DA7  
  *See:* WEB-TLS-001, WEB-TLS-002

- [ ] **DESK-COMM-003** Test certificate validation in the client with an untrusted certificate  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds clients that accept wrong, expired or self-signed certificates.  
  *Steps:*
  1. Route the client through a proxy with its own CA.
  2. Start the client without the CA in the trust store.
  3. Watch if the client connects.
  4. Repeat with an expired certificate and a wrong host name.
  *Example:* `Burp Suite or mitmproxy with a fresh CA; look for certificate errors in the client log.`  
  *Expected:* The client refuses all untrusted, expired and wrong-host certificates and sends no data.  
  *Refs:* cwe: CWE-295, CWE-297; cheatsheet: Pinning_Cheat_Sheet, Transport_Layer_Security_Cheat_Sheet; asvs: V12.3.2; desktop_top10: DA7  
  *See:* WEB-TLS-010

- [ ] **DESK-COMM-004** Check certificate pinning for critical hosts  
  *Severity if fail:* Medium | *Type:* Manual, Code Review  
  *Objective:* Finds high-risk clients without a pin for the update or API host.  
  *Steps:*
  1. Find the hosts that carry updates and credentials.
  2. Look in the code for pin checks or custom validation callbacks.
  3. Install a trusted proxy CA and try to read the traffic.
  4. Make sure no callback returns true for all.
  *Example:* `ILSpy search for ServerCertificateValidationCallback that returns true; Electron setCertificateVerifyProc.`  
  *Expected:* The client pins keys for critical hosts or validates the full chain. No callback accepts every certificate.  
  *Refs:* cwe: CWE-295; cheatsheet: Pinning_Cheat_Sheet; desktop_top10: DA7

- [ ] **DESK-COMM-005** Check database connections for encryption and least privilege  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds clients that use a shared database account over a plain channel.  
  *Steps:*
  1. Find the connection string in the config or code.
  2. Capture the database traffic.
  3. Look for TLS in the handshake.
  4. Check the rights of the database account.
  *Example:* `Wireshark on port 1433, 3306 or 5432; SQL: SELECT * FROM fn_my_permissions(NULL,NULL).`  
  *Expected:* The connection uses TLS. Each user or the service has an account with the least rights. The client holds no admin database account.  
  *Refs:* cwe: CWE-319, CWE-250; asvs: V13.2.2; desktop_top10: DA7, DA3, DA5


## CONF

- [ ] **DESK-CONF-001** Check named pipes, local ports and IPC for access control  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds local interfaces that any user or any host can use.  
  *Steps:*
  1. List named pipes, sockets and listening ports of the product.
  2. Check the access rights of each pipe.
  3. Check the bind address of each port.
  4. Send a request as another local user.
  *Example:* `pipelist.exe; accesschk.exe \pipe\name; netstat -ano; nmap -p- from a second host.`  
  *Expected:* IPC objects allow only the needed accounts. Local services bind to loopback and need authentication.  
  *Refs:* cwe: CWE-732, CWE-306; cheatsheet: Attack_Surface_Analysis_Cheat_Sheet; desktop_top10: DA6

- [ ] **DESK-CONF-002** Check Windows services for unquoted paths and weak folder rights  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds services that a user can hijack through the service path.  
  *Steps:*
  1. List the services that the product installs.
  2. Read the image path of each service.
  3. Look for spaces in unquoted paths.
  4. Check the write rights of each parent folder.
  *Example:* `wmic service get name,pathname; sc qc; icacls on each folder in the path.`  
  *Expected:* Service paths are quoted. No folder in the path is writable by normal users.  
  *Refs:* cwe: CWE-428, CWE-732; desktop_top10: DA6, DA5

- [ ] **DESK-CONF-003** Check file open and import functions for type and content checks  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds file handlers that accept any file or parse unsafe content.  
  *Steps:*
  1. List the file types the client opens or imports.
  2. Open files with a wrong type and a wrong content.
  3. Open files with an odd size and a long name.
  4. Watch the client for crashes and file writes.
  *Example:* `Procmon; WinDbg crash notes; test file set with a changed header.`  
  *Expected:* The client checks file type and content before it parses the file. Bad files give a clear error and no crash.  
  *Refs:* cwe: CWE-120; desktop_top10: DA6, DA8

- [ ] **DESK-CONF-004** Check back-end services of the client for default credentials  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds databases, queues and directory services with default accounts.  
  *Steps:*
  1. List the back-end services that the client uses.
  2. Read the connection settings in the config.
  3. Try the vendor default account on a test instance.
  4. Check the network rules around each service.
  *Example:* `Look in the config for sa, root and admin accounts; nmap -sV on the service host.`  
  *Expected:* Back-end services have no default accounts and allow access only from the client network.  
  *Refs:* cwe: CWE-1392, CWE-1188; asvs: V13.2.3; desktop_top10: DA6

- [ ] **DESK-CONF-005** Check local-only features for exposure over the network  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds services meant for the same machine that listen on all interfaces.  
  *Steps:*
  1. List all listening sockets of the product.
  2. Read the local address of each.
  3. Connect from a second host.
  4. Check the firewall rules that the installer adds.
  *Example:* `netstat -ano | findstr LISTENING; Test-NetConnection from another host.`  
  *Expected:* Local-only features bind to 127.0.0.1. The installer adds no inbound allow rule for them.  
  *Refs:* cwe: CWE-1188; desktop_top10: DA6


## CRYPTO

- [ ] **DESK-CRYPTO-001** Find weak or custom cryptography in the client  
  *Severity if fail:* Medium | *Type:* Code Review, Manual  
  *Objective:* Finds weak algorithms, weak modes and home-made crypto code.  
  *Steps:*
  1. Search the code for MD5, SHA1, DES, RC4, ECB and custom cipher classes.
  2. List the calls to the crypto library.
  3. Check the algorithm, key size and mode for each use.
  4. Check that passwords use a password hashing function.
  *Example:* `ILSpy search; grep for MD5, SHA1, DES and ECB; keyword list from WSTG-CRYP-04.`  
  *Expected:* The client uses approved algorithms and modes and a maintained library. It uses no custom algorithm.  
  *Refs:* cwe: CWE-327, CWE-326; cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V11.4.1; wstg: WSTG-CRYP-04; desktop_top10: DA4  
  *See:* WEB-CRYPTO-009, WEB-CRYPTO-012

- [ ] **DESK-CRYPTO-002** Check that keys and salts are unique per installation  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds keys, IVs and salts that are the same on every install.  
  *Steps:*
  1. Install the client on two clean systems.
  2. Compare the key files, key values and salts.
  3. Find the code that makes keys and IVs.
  4. Check the random source.
  *Example:* `Binary diff of the two profile folders; ILSpy review for System.Random use.`  
  *Expected:* Each install has its own keys from a secure random source. The client never reuses an IV or nonce with one key.  
  *Refs:* cwe: CWE-321, CWE-330, CWE-338, CWE-1204; cheatsheet: Cryptographic_Storage_Cheat_Sheet; asvs: V11.5.1; desktop_top10: DA4, DA3  
  *See:* WEB-CRYPTO-014

- [ ] **DESK-CRYPTO-003** Check key storage in the OS key store  
  *Severity if fail:* High | *Type:* Code Review, Manual  
  *Objective:* Finds keys stored in clear form or in files next to the data.  
  *Steps:*
  1. Find where the client keeps its keys.
  2. Check if it uses DPAPI, the OS credential store or a hardware module.
  3. Check the DPAPI scope, user or machine.
  4. Check if the key and the data are in separate places.
  *Example:* `ILSpy search for ProtectedData.Protect and DataProtectionScope.LocalMachine.`  
  *Expected:* Keys are in an OS key store or hardware module with user scope. Keys are not next to the data in clear form.  
  *Refs:* cwe: CWE-922, CWE-312; cheatsheet: DotNet_Security_Cheat_Sheet, Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; desktop_top10: DA3, DA4

- [ ] **DESK-CRYPTO-004** Check integrity protection of trusted local data  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds files and license data that a user can change without detection.  
  *Steps:*
  1. Find the local files that the client trusts.
  2. Change one value in a test copy of the file.
  3. Start the client.
  4. Check that the client detects and rejects the change.
  *Example:* `Hex editor on a test copy; compare the client behaviour with and without an HMAC.`  
  *Expected:* The client protects trusted local data with a signature or HMAC and rejects a changed file.  
  *Refs:* cwe: CWE-345, CWE-353; cheatsheet: Cryptographic_Storage_Cheat_Sheet; desktop_top10: DA4, DA8


## DATA

- [ ] **DESK-DATA-001** Search binaries and config files for hard-coded secrets  
  *Severity if fail:* High | *Type:* Automated, Manual  
  *Objective:* Finds keys, passwords and connection strings inside the installer and files.  
  *Steps:*
  1. Install the client in a clean virtual machine.
  2. Run strings and a secret scanner over all installed files.
  3. Decompile managed code and search for keys and connection strings.
  4. Test each found value for use.
  *Example:* `strings -n 8 app.dll | grep -iE "pass|key|secret|conn"; gitleaks or trufflehog directory scan; ILSpy.`  
  *Expected:* No secret is in any binary, config or resource. Each install gets its own credentials from a secret store.  
  *Refs:* cwe: CWE-798, CWE-321, CWE-259; cheatsheet: Secrets_Management_Cheat_Sheet, Key_Management_Cheat_Sheet; asvs: V13.3.1; desktop_top10: DA3, DA8  
  *See:* WEB-CRYPTO-018

- [ ] **DESK-DATA-002** Check data at rest for clear text and weak access rights  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds databases, caches and temporary files that hold sensitive data in clear form.  
  *Steps:*
  1. Use the client with test data in each feature.
  2. Watch file and registry writes with Procmon.
  3. Open each written file and look for the test data.
  4. Check the file permissions and the temporary folders.
  *Example:* `Procmon filter Operation is WriteFile; icacls on the data folder; sqlite3 .dump on local databases.`  
  *Expected:* Sensitive data is encrypted with a key that is not in the files. Only the user and the app can read the files.  
  *Refs:* cwe: CWE-312, CWE-922, CWE-378; cheatsheet: Cryptographic_Storage_Cheat_Sheet, DotNet_Security_Cheat_Sheet; desktop_top10: DA3, DA5  
  *See:* WEB-DATA-013

- [ ] **DESK-DATA-003** Check process memory after logout for sensitive data  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds secrets and personal data that stay in memory after the session ends.  
  *Steps:*
  1. Log in and open sensitive records.
  2. Log out or lock the client.
  3. Make a memory dump of the client process.
  4. Search the dump for the test values and tokens.
  *Example:* `procdump -ma app.exe dump.dmp; strings -el dump.dmp | grep -i testvalue; Frida memory scan on a lab host.`  
  *Expected:* Secrets and sensitive records are cleared after use or logout. The dump does not hold them in readable form.  
  *Refs:* cwe: CWE-312; cheatsheet: Secrets_Management_Cheat_Sheet, Key_Management_Cheat_Sheet; desktop_top10: DA3

- [ ] **DESK-DATA-004** Check logs, crash dumps and debug output for sensitive data  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds tokens, passwords and personal data in logs and dumps.  
  *Steps:*
  1. Use all main functions with default logging.
  2. Cause an error and a crash.
  3. Search log files, dump files and the event log for test values.
  4. Check the folders and access rights.
  *Example:* `Search the client log folder for password and token strings; Windows Event Viewer; Windows Error Reporting dump folder.`  
  *Expected:* Logs and dumps hold no secrets or personal data. Debug output is off in the release.  
  *Refs:* cwe: CWE-532, CWE-215, CWE-489; cheatsheet: Logging_Cheat_Sheet; asvs: V16.2.5, V13.4.2; desktop_top10: DA3, DA10  
  *See:* WEB-LOG-006

- [ ] **DESK-DATA-005** Check clipboard and recent-file lists for leaks  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds sensitive data that the client copies to shared OS areas.  
  *Steps:*
  1. Copy a sensitive field in the client.
  2. Read the clipboard and the clipboard history.
  3. Look at the recent-file lists and the thumbnails.
  4. Look at the task switcher preview.
  *Example:* `Windows clipboard history (Win+V); Get-Clipboard in PowerShell; recent items folder.`  
  *Expected:* The client clears or limits clipboard data for secrets. Sensitive views are hidden in previews where the OS allows it.  
  *Refs:* desktop_top10: DA3


## DEP

- [ ] **DESK-DEP-001** Build a component inventory and find known vulnerable versions  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds outdated libraries, runtimes and frameworks.  
  *Steps:*
  1. List all libraries, runtimes and frameworks in the install.
  2. Make a software bill of materials.
  3. Check each version against vulnerability databases.
  4. Include transitive dependencies.
  *Example:* `syft dir:. -o cyclonedx-json; grype sbom:./sbom.json; dependency-check; NVD search.`  
  *Expected:* The inventory is complete. No component has a known high or critical vulnerability without a fix plan.  
  *Refs:* cwe: CWE-1395, CWE-1104; cheatsheet: Vulnerable_Dependency_Management_Cheat_Sheet, Dependency_Graph_SBOM_Cheat_Sheet; asvs: V15.1.2; desktop_top10: DA9  
  *See:* WEB-DEP-002, WEB-DEP-003

- [ ] **DESK-DEP-002** Check bundled Electron, Chromium and runtime versions  
  *Severity if fail:* Medium | *Type:* Automated, Manual  
  *Objective:* Finds bundled engines that miss security fixes.  
  *Steps:*
  1. Find the bundled runtime and web engine versions.
  2. Compare them with the current supported versions.
  3. Check the update process for engines.
  4. Look for unsupported components.
  *Example:* `About dialog; package.json; file properties of the runtime DLLs.`  
  *Expected:* Bundled engines and runtimes are supported versions with current patches.  
  *Refs:* cwe: CWE-1104, CWE-1395; cheatsheet: Vulnerable_Dependency_Management_Cheat_Sheet; desktop_top10: DA9

- [ ] **DESK-DEP-003** Test the update mechanism for signed packages on a secure channel  
  *Severity if fail:* Critical | *Type:* Manual  
  *Objective:* Finds updates that a network attacker can replace.  
  *Steps:*
  1. Find the update URL and the update file format.
  2. Capture an update check.
  3. Check that the channel uses TLS with certificate checks.
  4. Serve a changed package from a lab server and look at the result.
  *Example:* `mitmproxy in a lab; look for a signature check in the code before install.`  
  *Expected:* The client installs only packages with a valid vendor signature. A changed package is rejected.  
  *Refs:* cwe: CWE-494, CWE-347; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet; desktop_top10: DA9, DA8  
  *See:* WEB-DEP-005

- [ ] **DESK-DEP-004** Review the supported platforms and the patch policy of the vendor  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds clients that need an unsupported OS or old runtime.  
  *Steps:*
  1. Read the system requirements.
  2. Find any OS or runtime that is out of support.
  3. Ask for the patch time frames.
  4. Look for an end-of-support notice for the product.
  *Example:* `Document review: support matrix and patch policy.`  
  *Expected:* The product runs on supported platforms. A patch policy with time frames exists.  
  *Refs:* cwe: CWE-1104; cheatsheet: Vulnerable_Dependency_Management_Cheat_Sheet; desktop_top10: DA9  
  *See:* WEB-DEP-001


## INJ

- [ ] **DESK-INJ-001** Test client input fields for SQL injection  
  *Severity if fail:* High | *Type:* Manual, Automated  
  *Objective:* Finds queries that the client builds from user input.  
  *Steps:*
  1. List all input fields and file imports that reach a database.
  2. Capture the database traffic or turn on the query log.
  3. Send a single quote and a boolean test value in each field.
  4. Compare the query text with the input.
  *Example:* `Procmon or Wireshark on the database port; database general query log; sqlmap only against in-scope back ends.`  
  *Expected:* The client uses parameterized queries. Special characters in input never change the query structure.  
  *Refs:* cwe: CWE-89; cheatsheet: DotNet_Security_Cheat_Sheet; asvs: V1.2.5; desktop_top10: DA1

- [ ] **DESK-INJ-002** Find OS command execution that uses user input  
  *Severity if fail:* Critical | *Type:* Code Review, Manual  
  *Objective:* Finds calls to a shell or a process with input that the user controls.  
  *Steps:*
  1. Search the code or decompiled code for process start calls.
  2. Trace each call to its input source.
  3. Send shell separators in the matching fields on a test system.
  4. Watch child processes with Process Monitor.
  *Example:* `ILSpy or dnSpy: search for Process.Start and ProcessStartInfo; Procmon filter on Process Create.`  
  *Expected:* The client starts programs with a fixed path and separate arguments. No user value reaches a command interpreter.  
  *Refs:* cwe: CWE-78, CWE-77; cheatsheet: OS_Command_Injection_Defense_Cheat_Sheet, DotNet_Security_Cheat_Sheet; asvs: V1.2.5; desktop_top10: DA1

- [ ] **DESK-INJ-003** Check XML and import file parsers for external entities  
  *Severity if fail:* High | *Type:* Manual, Code Review  
  *Objective:* Finds parsers that resolve external entities in untrusted files.  
  *Steps:*
  1. List the file types and XML settings that the client reads.
  2. Search the code for the parser settings.
  3. Open a test file with an external entity that points to a canary file.
  4. Look for an outbound request or a file read.
  *Example:* `Canary file with a unique string; Procmon to watch file reads by the client process.`  
  *Expected:* The parser turns off DTD and external entity resolution. Untrusted files cause an error and no file or network access.  
  *Refs:* cwe: CWE-611; cheatsheet: XML_External_Entity_Prevention_Cheat_Sheet, DotNet_Security_Cheat_Sheet; desktop_top10: DA1, DA6

- [ ] **DESK-INJ-004** Check embedded HTML views for script injection  
  *Severity if fail:* High | *Type:* Manual, Code Review  
  *Objective:* Finds web views and mail views that run script from untrusted content.  
  *Steps:*
  1. Find the components that render HTML.
  2. Load content with a harmless script marker in a test record.
  3. Check if the marker runs.
  4. Read the web view settings for script and file access.
  *Example:* `Marker that only changes the page title; Electron or WebView2 settings review for nodeIntegration and contextIsolation.`  
  *Expected:* Untrusted HTML is encoded or sanitized. The view runs no script and has no access to local files or system APIs.  
  *Refs:* cwe: CWE-79; cheatsheet: DotNet_Security_Cheat_Sheet, JavaScript_and_TypeScript_Security_Cheat_Sheet; desktop_top10: DA1

- [ ] **DESK-INJ-005** Check deserialization of files, messages and update data  
  *Severity if fail:* Critical | *Type:* Code Review, Manual  
  *Objective:* Finds unsafe serializers that read data an attacker can change.  
  *Steps:*
  1. Search the code for BinaryFormatter, ObjectInputStream and type name settings.
  2. Find the data source of each call.
  3. Look for serialized blobs in files and traffic.
  4. Check the type allowlist or the signature check.
  *Example:* `ILSpy search for BinaryFormatter and TypeNameHandling; look for the Base64 prefix AAEAAAD///// in saved files.`  
  *Expected:* The client uses a data-only format such as JSON. It does not read objects whose type comes from the data stream.  
  *Refs:* cwe: CWE-502; cheatsheet: Deserialization_Cheat_Sheet, DotNet_Security_Cheat_Sheet, Java_Security_Cheat_Sheet; asvs: V1.5.2; desktop_top10: DA1, DA8  
  *See:* WEB-DEP-006


## LOG

- [ ] **DESK-LOG-001** Check that security events are logged with who, when, where and what  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds missing audit logs for login, access denial and admin actions.  
  *Steps:*
  1. List the security events of the product.
  2. Cause a failed login, a denied action and a config change.
  3. Find the log entries.
  4. Check each entry for user, time, source and action.
  *Example:* `Windows Event Viewer; client log folder; event list from the Logging Cheat Sheet.`  
  *Expected:* Each security event creates a log entry with user, time, source and action.  
  *Refs:* cwe: CWE-778; cheatsheet: Logging_Cheat_Sheet; asvs: V16.2.1, V16.3.1, V16.3.2; desktop_top10: DA10  
  *See:* WEB-LOG-007, WEB-LOG-002

- [ ] **DESK-LOG-002** Check access rights on log files and the audit trail  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds logs that normal users can read or change.  
  *Steps:*
  1. Find the log folders and files.
  2. Read the access rights.
  3. Try to edit and delete a log entry as a normal user.
  4. Check for forwarding to a central system.
  *Example:* `icacls on the log folder; compare local logs with the central copy.`  
  *Expected:* Normal users cannot read or change audit logs. Logs go to a central system.  
  *Refs:* cwe: CWE-732, CWE-538; cheatsheet: Logging_Cheat_Sheet; desktop_top10: DA10, DA5  
  *See:* WEB-LOG-012, WEB-LOG-013

- [ ] **DESK-LOG-003** Test log injection through user-supplied values  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds log entries that a user can forge.  
  *Steps:*
  1. Find input values that the client writes to logs.
  2. Send a value with a line break and a made-up log entry.
  3. Open the log file.
  4. Check that the log shows the value as one encoded field.
  *Example:* `Test value: a name followed by a line break and a made-up entry text.`  
  *Expected:* Log writers encode or remove control characters. A user value cannot make a new log entry.  
  *Refs:* cwe: CWE-117; cheatsheet: Logging_Cheat_Sheet; asvs: V16.4.1; desktop_top10: DA10  
  *See:* WEB-LOG-011

- [ ] **DESK-LOG-004** Check that monitoring raises alerts for client abuse  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds missing detection for repeated failed logins and tamper events.  
  *Steps:*
  1. List the alert rules for the client and its back end.
  2. Make 10 failed logins in a test.
  3. Change a protected file in a test.
  4. Check that alerts reach the responders.
  *Example:* `SIEM rule list; test alert timestamps.`  
  *Expected:* Abuse events create alerts that the responders receive within the agreed time.  
  *Refs:* cwe: CWE-778; cheatsheet: Logging_Cheat_Sheet; desktop_top10: DA10  
  *See:* WEB-LOG-014
