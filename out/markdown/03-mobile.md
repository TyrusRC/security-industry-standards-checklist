# MOBILE security test cases

131 tests. Tick the box when the test passes.


## AUTH

- [ ] **MOB-AUTH-001** Check that biometric authentication is bound to a key or Keychain item  
  *Severity if fail:* Medium | *Type:* Manual, Code Review | *Level:* MASVS L2  
  *Objective:* Finds local authentication that depends only on a success callback that an attacker can bypass with hooking.  
  *Steps:*
  1. Android: Search for BiometricPrompt.authenticate calls and see if they pass a CryptoObject.
  2. Android: Search for keys generated with setUserAuthenticationRequired(true) that the protected operation uses.
  3. iOS: Search for LAContext.evaluatePolicy and SecAccessControlCreateWithFlags with user presence or biometry flags.
  4. iOS: Hook both APIs at run time and use every flow that the biometric check protects.
  5. Hook the callback or evaluatePolicy reply to return success and try to open the protected resource.
  6. Find sensitive resources that open after the forced success without a key operation.
  *Example:* `jadx -d src app.apk; grep -rn "BiometricPrompt\|CryptoObject\|setUserAuthenticationRequired" src/; frida -U -f <package> -l bypass-biometric.js (objection: android ui biometrics_bypass); r2 -qc "aaa; axt sym.imp.SecAccessControlCreateWithFlags" Payload/App.app/App; objection -g <bundle> explore -> ios ui biometrics_bypass; frida-trace -U -f <bundle> -m "-[LAContext evaluatePolicy:localizedReason:reply:]" -i SecAccessControlCreateWithFlags`  
  *Expected:* Each sensitive resource is protected by a Keystore key or Keychain item that needs authentication. A forced success callback does not open it.  
  *Refs:* mobile_top10: M3:2024; masvs: MASVS-AUTH-2; mastg: MASTG-TEST-0327, MASTG-TEST-0266, MASTG-TEST-0267; maswe: MASWE-0020; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-285, CWE-287, CWE-312, CWE-319, CWE-326, CWE-602, CWE-603, CWE-863, CWE-922

- [ ] **MOB-AUTH-002** Check for fallback to device credentials on sensitive actions  
  *Severity if fail:* Low | *Type:* Code Review, Manual | *Level:* MASVS L2  
  *Objective:* Finds sensitive actions that accept the weaker device PIN, pattern or passcode instead of a biometric.  
  *Steps:*
  1. Android: Search for BiometricPrompt, setAllowedAuthenticators and setDeviceCredentialAllowed.
  2. Android: Flag the DEVICE_CREDENTIAL constant, alone or combined with a biometric constant.
  3. iOS: Search for SecAccessControlCreateWithFlags and flag kSecAccessControlUserPresence and kSecAccessControlDevicePasscode.
  4. iOS: Hook SecAccessControlCreateWithFlags at run time and list the flags that the app uses.
  5. Decide for each sensitive resource if a fallback fits the risk level of the app.
  *Example:* `jadx -d src app.apk; grep -rnE "DEVICE_CREDENTIAL|setDeviceCredentialAllowed|setAllowedAuthenticators" src/; r2 -qc "aaa; axt sym.imp.SecAccessControlCreateWithFlags" Payload/App.app/App; frida-trace -U -f <bundle> -i SecAccessControlCreateWithFlags`  
  *Expected:* High-risk actions need biometrics alone, without fallback to the device credential, or the team accepts and documents the risk.  
  *Refs:* mobile_top10: M3:2024; masvs: MASVS-AUTH-2; mastg: MASTG-TEST-0326, MASTG-TEST-0268, MASTG-TEST-0269; maswe: MASWE-0021; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-288, CWE-287

- [ ] **MOB-AUTH-003** Check that biometric keys become invalid when new biometrics are enrolled  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS L2  
  *Objective:* Finds protected keys and Keychain items that a newly enrolled fingerprint or face can unlock.  
  *Steps:*
  1. Android: Search KeyGenParameterSpec.Builder for setInvalidatedByBiometricEnrollment and flag the value false.
  2. iOS: Search SecAccessControlCreateWithFlags and flag items that do not use kSecAccessControlBiometryCurrentSet.
  3. iOS: Hook SecAccessControlCreateWithFlags at run time and list the flags.
  4. Set up the biometric protection in the app, then enroll a new fingerprint or face on the test device.
  5. Try to open the protected resource with the new biometric.
  *Example:* `jadx -d src app.apk; grep -rn "setInvalidatedByBiometricEnrollment" src/; r2 -qc "aaa; axt sym.imp.SecAccessControlCreateWithFlags" Payload/App.app/App; frida-trace -U -f <bundle> -i SecAccessControlCreateWithFlags (look for biometryCurrentSet)`  
  *Expected:* The key or item becomes unusable after a new biometric enrollment. The user must authenticate again with the app credentials.  
  *Refs:* mobile_top10: M3:2024; masvs: MASVS-AUTH-2, MASVS-CRYPTO-2; mastg: MASTG-TEST-0328, MASTG-TEST-0270, MASTG-TEST-0271; maswe: MASWE-0022; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-287, CWE-522

- [ ] **MOB-AUTH-004** Check that Android biometric prompts need explicit user confirmation  
  *Severity if fail:* Low | *Type:* Code Review, Manual | *Level:* MASVS L2  
  *Objective:* Finds sensitive actions that a passive biometric, such as face recognition, approves without a user action.  
  *Steps:*
  1. Search the code for BiometricPrompt.PromptInfo.Builder and setConfirmationRequired.
  2. Flag every call that sets the value to false.
  3. Check if the call protects a sensitive action such as a payment or data access.
  4. Run the action with face recognition and see if it completes without a tap.
  *Example:* `jadx -d src app.apk; grep -rn "setConfirmationRequired" src/`  
  *Expected:* Sensitive actions use setConfirmationRequired(true) or the default value, so the user confirms the action explicitly.  
  *Refs:* mobile_top10: M3:2024; masvs: MASVS-AUTH-2; mastg: MASTG-TEST-0329; maswe: MASWE-0020; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-285, CWE-287, CWE-312, CWE-319, CWE-326, CWE-602, CWE-603, CWE-863, CWE-922

- [ ] **MOB-AUTH-005** Check the validity time of Android keys that biometrics unlock  
  *Severity if fail:* Low | *Type:* Code Review, Manual | *Level:* MASVS L2  
  *Objective:* Finds keys that stay usable for minutes or hours after one biometric authentication.  
  *Steps:*
  1. Search for setUserAuthenticationParameters and setUserAuthenticationValidityDurationSeconds in key generation code.
  2. Note the duration value for each key.
  3. Flag every key for a sensitive action that has a duration above zero.
  4. Authenticate once, then run the sensitive operation again inside the validity window.
  5. See if the operation succeeds without a new authentication.
  *Example:* `jadx -d src app.apk; grep -rnE "setUserAuthenticationParameters|setUserAuthenticationValidityDurationSeconds" src/`  
  *Expected:* Keys for sensitive operations need authentication for every use (duration 0), or the validity is only a few seconds and the team accepts it.  
  *Refs:* mobile_top10: M3:2024; masvs: MASVS-AUTH-2; mastg: MASTG-TEST-0330; maswe: MASWE-0020; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-285, CWE-287, CWE-312, CWE-319, CWE-326, CWE-602, CWE-603, CWE-863, CWE-922

- [ ] **MOB-AUTH-006** Check that a custom app PIN or password resists guessing  
  *Severity if fail:* Medium | *Type:* Manual, Code Review | *Level:* MASVS L2  
  *Objective:* Finds app-defined PINs and passwords that the code compares in plain text or that allow unlimited guesses.  
  *Steps:*
  1. Find the screens and code where the app asks for its own PIN or password.
  2. Search the code for a plain string comparison against a stored or hardcoded value.
  3. Enter wrong values many times and see if the app limits or delays the attempts.
  4. Restart the app and clear its data between attempts to see if the counter resets.
  5. Check that the app binds the secret to key material from the Keystore or Keychain.
  6. Check that the app rejects short PINs, such as 4 digits.
  *Example:* `jadx -d src app.apk; grep -rnE "equals\(.*(pin|passcode)|compareTo" src/; frida-trace -U -f <package> -j "java.lang.String!equals"; objection: android keystore list; ios keychain dump`  
  *Expected:* The app has no plain comparison and no hardcoded PIN. It limits wrong guesses and ties the secret to hardware-backed key material.  
  *Refs:* mobile_top10: M3:2024; masvs: MASVS-AUTH-2; maswe: MASWE-0020; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-285, CWE-287, CWE-312, CWE-319, CWE-326, CWE-602, CWE-603, CWE-863, CWE-922  
  *See:* WEB-AUTHN-002

- [ ] **MOB-AUTH-007** Check that the backend enforces authentication for app requests  
  *Severity if fail:* High | *Type:* Manual | *Level:* MASVS L2  
  *Objective:* Finds backend functions that the app can call without a valid token, which local checks cannot protect.  
  *Steps:*
  1. Record the requests that the app sends for each protected function with an interception proxy.
  2. Replay each request without the token or session cookie.
  3. Replay each request with the token of a different user.
  4. Hook the local authentication result to success and check what the backend still requires.
  5. Search the app for user roles or permissions that it sends to the backend.
  *Example:* `mitmproxy -s save_flows.py; burp: Repeater (delete the Authorization header, then replay); frida -U -f <package> -l bypass-local-auth.js; curl -i https://api.example.com/v1/me (no token)`  
  *Expected:* The backend rejects requests without a valid token. A local bypass gives no access to server data, and the server decides roles and permissions.  
  *Refs:* mobile_top10: M3:2024; masvs: MASVS-AUTH-1, MASVS-AUTH-2; maswe: MASWE-0020; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-285, CWE-287, CWE-312, CWE-319, CWE-326, CWE-602, CWE-603, CWE-863, CWE-922  
  *See:* WEB-AUTHN-009, WEB-SESS-004

- [ ] **MOB-AUTH-008** Check that the app uses system flows for OAuth and third-party login  
  *Severity if fail:* High | *Type:* Manual | *Level:* MASVS L1  
  *Objective:* Finds logins in embedded WebViews, OAuth without PKCE and tokens that the app accepts without checks.  
  *Steps:*
  1. Find all login flows that use OAuth, OpenID Connect or a third-party identity provider.
  2. Check if the app opens the login page in the system browser, a custom tab or ASWebAuthenticationSession.
  3. Flag logins that load the identity provider in an embedded WebView.
  4. Capture the authorization request and see if it carries a state value and a PKCE code challenge.
  5. Open the app deep links with a changed authorization response and see if the app accepts it.
  6. Check that the app validates the token signature, issuer, audience and expiry, or that the backend does.
  *Example:* `mitmproxy; burp: look for code_challenge, state, redirect_uri; adb shell am start -a android.intent.action.VIEW -d "app://callback?code=attacker" <package>; xcrun simctl openurl booted "app://callback?code=attacker"; grep -rn "ASWebAuthenticationSession\|CustomTabsIntent\|WebView" src/`  
  *Expected:* The app signs in users with system browser flows and PKCE. It rejects forged or replayed responses and accepts only validated tokens.  
  *Refs:* mobile_top10: M3:2024; masvs: MASVS-AUTH-1; maswe: MASWE-0018; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-306, CWE-749, CWE-862, CWE-863, CWE-923, CWE-926, CWE-939, CWE-940  
  *See:* WEB-OAUTH-003, WEB-OAUTH-011, WEB-OAUTH-015

- [ ] **MOB-AUTH-009** Check that login fields support password managers and one-time code fill  
  *Severity if fail:* Info | *Type:* Manual | *Level:* MASVS L1  
  *Objective:* Finds login screens that block password managers and so push users to weak or reused passwords.  
  *Steps:*
  1. Open the login screen and try to fill the credentials with the system password manager.
  2. Check the autofill hints on Android and the textContentType values on iOS for the credential fields.
  3. Check that one-time code fields support code autofill.
  4. Check that the app is linked to its website with website association files.
  5. Check if the app offers passkeys where the service supports them.
  *Example:* `jadx -d src app.apk; grep -rn "autofillHints\|importantForAutofill" src/res/layout; plutil -p Payload/App.app/Info.plist | grep -i associated; grep -r "textContentType" Payload/ (storyboard or code); curl -s https://example.com/.well-known/assetlinks.json`  
  *Expected:* Credential and code fields accept autofill. The app is linked to its domain and offers passkeys where possible.  
  *Refs:* mobile_top10: M3:2024; masvs: MASVS-AUTH-1, MASVS-AUTH-3; maswe: MASWE-0019; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-287, CWE-522

- [ ] **MOB-AUTH-010** Check that sensitive actions need step-up authentication  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* MASVS L2  
  *Objective:* Finds high-risk actions that need no fresh authentication, or whose approval can be reused for another action.  
  *Steps:*
  1. Make a list of the high-risk actions, such as payments, password changes and display of sensitive data.
  2. Run each action in a signed-in session and see if the app asks for a new factor.
  3. Replay the approval request with changed amount or target and see if the server accepts it.
  4. Skip the step-up screen in the client and call the server API directly.
  5. See if the approval is tied to the specific transaction.
  *Example:* `burp: Repeater (change the amount in the approved request and replay it); frida -U -f <package> -l skip-stepup.js; mitmproxy`  
  *Expected:* The server demands a fresh factor for each high-risk action and ties the approval to that action. The client alone cannot skip the step.  
  *Refs:* mobile_top10: M3:2024; masvs: MASVS-AUTH-3; maswe: MASWE-0023; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-306  
  *See:* WEB-SESS-026, WEB-SESS-025

- [ ] **MOB-AUTH-011** Check that logout and timeout end the session and clear local data  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* MASVS L2  
  *Objective:* Finds sessions that stay valid on the server, or tokens and personal data that stay on the device after logout.  
  *Steps:*
  1. Sign in and note the access and refresh tokens that the app uses.
  2. Log out in the app and replay the old tokens against the API.
  3. Copy the app data directory and search for tokens, cached personal data and the user profile.
  4. Wait for the inactivity timeout and see if the app asks for a new login.
  5. Send the app to the background and bring it back after a sensitive flow. See if it asks for a new login.
  *Example:* `mitmproxy; curl -H "Authorization: Bearer <old-token>" https://api.example.com/v1/me; objection -g <package> explore -> env; adb pull /data/data/<package>; grep -rniE "token|session" data/; objection: ios keychain dump`  
  *Expected:* The server rejects old tokens after logout and timeout. The device holds no tokens or cached personal data of the ended session.  
  *Refs:* mobile_top10: M3:2024; masvs: MASVS-AUTH-3; maswe: MASWE-0024; cheatsheet: Mobile_Application_Security_Cheat_Sheet, Session_Management_Cheat_Sheet; cwe: CWE-285, CWE-287  
  *See:* WEB-SESS-017, WEB-SESS-019, WEB-SESS-020, WEB-SESS-029

- [ ] **MOB-AUTH-012** Check that critical actions give signed proof of user approval  
  *Severity if fail:* Low | *Type:* Manual, Code Review | *Level:* MASVS L2  
  *Objective:* Finds critical actions that the user can later deny, or that a tampered app can show differently from what it runs.  
  *Steps:*
  1. List the critical actions, such as money transfers and legal consent.
  2. Check if the app shows a confirmation that is tied to the exact data of the action.
  3. Check if the confirmation produces a signature from a hardware-backed, user-authenticated key.
  4. Check that the server validates the signature and the key attestation, and keeps the signature as evidence.
  5. Change the displayed data in a hooked app and see if the server detects the change.
  *Example:* `jadx -d src app.apk; grep -rn "setAttestationChallenge\|Signature" src/; frida -U -f <package> -l change-amount.js; burp: Repeater`  
  *Expected:* Each critical action carries a hardware-backed signature over the exact approved data. The server checks it and keeps it as evidence.  
  *Refs:* mobile_top10: M3:2024; masvs: MASVS-AUTH-3; maswe: MASWE-0025; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-451, CWE-778


## CODE

- [ ] **MOB-CODE-001** Check the minimum platform version that the app supports  
  *Severity if fail:* Low | *Type:* Config Review, Code Review | *Level:* MASVS L2  
  *Objective:* Finds apps that run on old OS versions that lack current security patches and features.  
  *Steps:*
  1. Android: Read minSdkVersion in the AndroidManifest.xml.
  2. iOS: Read MinimumOSVersion in the Info.plist.
  3. Compare the value with the platform versions that still get security updates.
  4. Android: Search the code for Build.VERSION.SDK_INT checks and the sensitive features that they protect.
  5. Make sure the app refuses or limits sensitive features on unsupported platform versions.
  *Example:* `aapt2 d badging app.apk | grep -E "sdkVersion|targetSdkVersion" ; plutil -p Payload/App.app/Info.plist | grep MinimumOSVersion ; grep -rn "Build.VERSION.SDK_INT" out/`  
  *Expected:* The app sets a minimum platform version that still gets security updates. It limits sensitive features on older versions.  
  *Refs:* masvs: MASVS-CODE-1; mastg: MASTG-TEST-0245; maswe: MASWE-0041; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-451, CWE-693, CWE-1104, CWE-1357

- [ ] **MOB-CODE-002** Check that the app targets the latest platform version  
  *Severity if fail:* Low | *Type:* Config Review | *Level:* MASVS L1  
  *Objective:* Finds apps that miss platform protections because they target an old SDK.  
  *Steps:*
  1. Android: Read targetSdkVersion in the AndroidManifest.xml.
  2. Android: Compare it with the current Google Play target API requirement.
  3. iOS: Find the Xcode and SDK version that built the app, and compare it with the current App Store requirement.
  4. Look for legacy behavior that works only because of the old target, such as broad storage access.
  *Example:* `aapt2 d badging app.apk | grep targetSdkVersion ; plutil -p Payload/App.app/Info.plist | grep -E "DTSDKName|DTXcode"`  
  *Expected:* The app targets the latest platform version that the store requires. It does not depend on legacy compatibility behavior.  
  *Refs:* masvs: MASVS-CODE-1; maswe: MASWE-0042; cwe: CWE-693, CWE-1357

- [ ] **MOB-CODE-003** Check that the app can force users to update  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS L2  
  *Objective:* Finds apps that cannot block old, vulnerable versions after a security fix.  
  *Steps:*
  1. Android: Search the code for AppUpdateManager, getAppUpdateInfo and startUpdateFlowForResult.
  2. iOS: Search the binary for CFBundleShortVersionString, the iTunes lookup URL and a minimum version policy.
  3. Check that the version check runs before access to protected functions and cannot be skipped.
  4. Check that the app uses an immediate update or a screen that the user cannot dismiss.
  5. Run the app with a version below the minimum. Capture the traffic and hook the update calls.
  6. Make sure the app blocks use until the user updates.
  *Example:* `grep -rn "AppUpdateManager\|startUpdateFlowForResult\|BuildConfig.VERSION" out/ ; frida -U -f <pkg> -l hook_update.js ; r2 -A <app_binary> ; izz~itunes.apple.com/lookup ; Burp: change the version in the request or the response`  
  *Expected:* The app checks its version at start. It blocks use of an outdated version with a non-dismissible update flow.  
  *Refs:* mobile_top10: M2:2024; masvs: MASVS-CODE-2; mastg: MASTG-TEST-0392, MASTG-TEST-0382, MASTG-TEST-0383, MASTG-TEST-0384; maswe: MASWE-0043; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-602, CWE-693

- [ ] **MOB-CODE-004** Scan app dependencies for known vulnerabilities  
  *Severity if fail:* High | *Type:* Automated, Config Review | *Level:* MASVS L1  
  *Objective:* Finds third-party libraries and SDKs with public vulnerabilities.  
  *Steps:*
  1. Android: Run a Software Composition Analysis scan on the Gradle build, or create a CycloneDX SBOM.
  2. iOS: Collect Package.resolved, Podfile.lock and Cartfile.resolved. Scan them, or create a CycloneDX SBOM.
  3. Upload each SBOM to a vulnerability tool such as Dependency-Track.
  4. List dependencies with CVE identifiers. Include transitive dependencies and bundled native libraries.
  5. Check the exploitability and the exposure of each finding in the app.
  6. Check that a process updates or replaces vulnerable libraries.
  *Example:* `./gradlew dependencyCheckAnalyze ; cdxgen -t java -o sbom.json ; cdxgen -o sbom.json (iOS project) ; dependency-check --enableExperimental -f SARIF -s Podfile.lock ; upload sbom.json to Dependency-Track`  
  *Expected:* The app has no dependency with a known high-impact vulnerability. A process finds and fixes new vulnerable dependencies.  
  *Refs:* mobile_top10: M2:2024; masvs: MASVS-CODE-3; mastg: MASTG-TEST-0272, MASTG-TEST-0274, MASTG-TEST-0273, MASTG-TEST-0275; maswe: MASWE-0044; cheatsheet: Vulnerable_Dependency_Management_Cheat_Sheet, Dependency_Graph_SBOM_Cheat_Sheet, Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-1395, CWE-1357

- [ ] **MOB-CODE-005** Check native binaries for compiler security features  
  *Severity if fail:* Low | *Type:* Automated, Config Review | *Level:* MASVS L2  
  *Objective:* Finds native code built without PIE, stack canaries or ARC, which makes memory bugs easier to use.  
  *Steps:*
  1. Android: Extract the native libraries from the APK.
  2. Android: Read the canary and pic values of each library.
  3. iOS: Extract the main binary and list the bundled libraries and frameworks.
  4. iOS: Check the main binary and each library for pic, stack canary symbols and ARC symbols.
  5. Flag a library that mixes Objective-C or C code with no canary symbols.
  6. Check false positives, such as memory-safe code, with the source code and the build flags.
  *Example:* `unzip -o app.apk "lib/*" -d app ; rabin2 -I app/lib/arm64-v8a/lib.so | grep -E "canary|pic" ; r2 -A <app_binary> ; i~canary,pic ; is~release,retain`  
  *Expected:* All native libraries use position independent code and stack canaries. iOS code that is not Swift-only uses ARC.  
  *Refs:* mobile_top10: M7:2024; masvs: MASVS-CODE-3, MASVS-CODE-4; mastg: MASTG-TEST-0222, MASTG-TEST-0223, MASTG-TEST-0228, MASTG-TEST-0229, MASTG-TEST-0230; maswe: MASWE-0045

- [ ] **MOB-CODE-006** Check the app for deprecated APIs in security functions  
  *Severity if fail:* Low | *Type:* Code Review | *Level:* MASVS L2  
  *Objective:* Finds use of deprecated APIs that lack fixes or have safer replacements.  
  *Steps:*
  1. Build the app with deprecation warnings on. List the warnings.
  2. Find deprecated keystore, crypto, networking and authentication APIs in the code.
  3. Check the release notes of each supported platform version for removed or changed features.
  4. Check that the team tracks the move off each deprecated security API.
  5. Run the app on all supported platform versions.
  *Example:* `./gradlew build --warning-mode all ; xcodebuild build 2>&1 | grep -i deprecated ; grep -rn "@Deprecated\|deprecated" out/ | head`  
  *Expected:* Security-relevant code uses no deprecated APIs, and the team treats deprecation warnings as work items.  
  *Refs:* masvs: MASVS-CODE-3; maswe: MASWE-0046; cwe: CWE-327, CWE-477, CWE-522

- [ ] **MOB-CODE-007** Check that security functions use platform APIs and vetted libraries  
  *Severity if fail:* Medium | *Type:* Code Review | *Level:* MASVS L1  
  *Objective:* Finds custom crypto, TLS, DNS or authentication code that is likely to have flaws.  
  *Steps:*
  1. Search the code for custom cryptographic algorithms, custom TLS stacks and custom DNS resolvers.
  2. Search for custom authentication flows next to the platform credential APIs.
  3. List third-party security libraries. Check the release date and the maintenance state of each.
  4. Compare the libraries with standards such as FIPS 140-2 or 140-3 where the app must follow them.
  *Example:* `jadx -d out app.apk ; grep -rn "implements X509TrustManager\|MessageDigest\|Cipher.getInstance\|new Socket(" out/ ; list libraries with cdxgen -t java`  
  *Expected:* The app uses platform APIs or vetted, maintained libraries for crypto, networking, DNS and authentication. It has no home-made security code.  
  *Refs:* masvs: MASVS-CODE-3; maswe: MASWE-0047; cwe: CWE-287, CWE-326, CWE-327, CWE-1240

- [ ] **MOB-CODE-008** Check the app supply chain for malicious or unexpected code  
  *Severity if fail:* High | *Type:* Manual, Config Review | *Level:* MASVS L1  
  *Objective:* Finds trojanized SDKs, build changes or hidden features that ship in the app.  
  *Steps:*
  1. Compare the SBOM of the release with the declared dependencies. List components that are not declared.
  2. Check that the build pins dependency versions with a lockfile and takes packages from a controlled repository.
  3. Check that code review and strong sign-in protect the source repository and the build system.
  4. Scan the release binary for unexpected code, permissions, secrets and network endpoints.
  5. Run the release build and look for unexpected network traffic.
  6. Check that the signing keys are protected and that releases carry a signature.
  *Example:* `cdxgen -o sbom.json ; apksigner verify --print-certs app.apk ; mitmproxy to capture the first start traffic ; grep -rn "http" out/resources | sort -u`  
  *Expected:* The release contains only reviewed and declared components. The build pins dependencies and protects signing keys, and the release shows no unexpected behavior.  
  *Refs:* mobile_top10: M2:2024; masvs: MASVS-CODE-3; maswe: MASWE-0048; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet, Dependency_Graph_SBOM_Cheat_Sheet, Mobile_Application_Security_Cheat_Sheet; cwe: CWE-506, CWE-507, CWE-511

- [ ] **MOB-CODE-009** Check the app for unsafe dynamic code loading  
  *Severity if fail:* High | *Type:* Code Review | *Level:* MASVS L2  
  *Objective:* Finds code that the app loads at runtime from places that attackers control.  
  *Steps:*
  1. Android: Search for DexClassLoader, PathClassLoader, System.load and System.loadLibrary with a path.
  2. iOS: Search for dlopen and downloaded scripts or plugins.
  3. Find the folder that the loaded code comes from. Check if it is writable or on external storage.
  4. Check that the app verifies a signature on downloaded code against a pinned key.
  5. Check that the code arrives over a secure channel.
  *Example:* `grep -rn "DexClassLoader\|PathClassLoader\|System.load" out/ ; r2 -A <app_binary> ; afl~dlopen`  
  *Expected:* The app loads no code from writable or external folders. Downloaded code is signed and the app checks the signature before it runs the code.  
  *Refs:* mobile_top10: M4:2024; masvs: MASVS-CODE-4; maswe: MASWE-0049; cwe: CWE-494

- [ ] **MOB-CODE-010** Check input validation on all entry points of the app  
  *Severity if fail:* High | *Type:* Code Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds input from the UI, IPC, files or network that reaches a sensitive sink unchecked.  
  *Steps:*
  1. List the entry points: UI fields, deep links, IPC, files, the clipboard and network data.
  2. Follow the data from each entry point to its sinks, such as SQL, file paths, WebViews and parsers.
  3. Check that the code validates type, length, range and format against an allowlist.
  4. Check that validation runs on the server too, as client checks are easy to bypass.
  5. Send malformed, oversized and malicious values to each entry point. Look for crashes and injection.
  6. Check that the parsers limit size and nesting depth.
  *Example:* `semgrep --config <rules> out/ ; mobsf: upload the APK or IPA for the static scan ; adb shell monkey -p <pkg> 5000 ; Burp Suite Intruder on the API calls of the app`  
  *Expected:* The app treats all outside data as untrusted. It validates data against allowlists before use, and malformed input causes no crash or injection.  
  *Refs:* mobile_top10: M4:2024; masvs: MASVS-CODE-4; maswe: MASWE-0050; cheatsheet: Input_Validation_Cheat_Sheet, Mobile_Application_Security_Cheat_Sheet; cwe: CWE-20, CWE-22, CWE-73, CWE-89, CWE-116


## CRYPTO

- [ ] **MOB-CRYPTO-001** Check that the app uses no broken symmetric encryption algorithms  
  *Severity if fail:* Medium | *Type:* Code Review, Automated | *Level:* MASVS L1  
  *Objective:* Finds use of DES, 3DES, RC2, RC4, Blowfish and other broken ciphers in the app or its libraries.  
  *Steps:*
  1. Android: Decompile the app and search for Cipher.getInstance, SecretKeyFactory.getInstance and KeyGenerator.getInstance.
  2. iOS: Extract the binaries and search for CCCrypt and the algorithm constants kCCAlgorithmDES, 3DES, RC4, RC2, CAST and Blowfish.
  3. Search bundled libraries such as OpenSSL, BoringSSL and libsodium for the same algorithms.
  4. Look at the code at each hit and find the algorithm and the data that it protects.
  5. Compare the algorithms with the current NIST and BSI guidance.
  *Example:* `jadx -d src app.apk; grep -rnE "Cipher.getInstance\(\"(DES|DESede|RC2|RC4|Blowfish|ARC4)" src/; semgrep --config p/mobsfscan src/; mobsf scan (static analyzer); unzip app.ipa; r2 -qc "aaa; afl~CCCrypt; axt sym.imp.CCCrypt" Payload/App.app/App; strings Payload/App.app/App | grep -iE "rc4|des-|blowfish"`  
  *Expected:* The app uses no DES, 3DES, RC2, RC4 or Blowfish for sensitive data. It uses AES-GCM or ChaCha20-Poly1305 instead.  
  *Refs:* mobile_top10: M10:2024; masvs: MASVS-CRYPTO-1; mastg: MASTG-TEST-0221, MASTG-TEST-0210; maswe: MASWE-0007; cheatsheet: Cryptographic_Storage_Cheat_Sheet, Mobile_Application_Security_Cheat_Sheet; cwe: CWE-208, CWE-323, CWE-325, CWE-326, CWE-327, CWE-329, CWE-780  
  *See:* WEB-CRYPTO-009

- [ ] **MOB-CRYPTO-002** Check that the app uses no broken block modes such as ECB  
  *Severity if fail:* Medium | *Type:* Code Review, Automated, Manual | *Level:* MASVS L1  
  *Objective:* Finds symmetric encryption in ECB mode that leaks patterns in the data.  
  *Steps:*
  1. Android: Decompile the app and list all Cipher.getInstance transformation strings.
  2. Android: Mark the strings "AES", AES/ECB/NoPadding, AES/ECB/PKCS5Padding and AES/ECB/ISO10126Padding. Ignore RSA/ECB strings.
  3. iOS: Search the binary for CCCrypt calls and look for kCCOptionECBMode (value 2) in the options argument.
  4. Hook Cipher.getInstance or CCCrypt at run time and use every workflow of the app with sensitive data.
  5. Use the backtraces to see if the encrypted data is sensitive.
  *Example:* `jadx -d src app.apk; grep -rnE "Cipher.getInstance\(\"[A-Za-z0-9]+(/ECB/[A-Za-z0-9]+)?\"\)" src/; frida-trace -U -f <package> -j "javax.crypto.Cipher!getInstance"; r2 -qc "aaa; axt sym.imp.CCCrypt" Payload/App.app/App; frida-trace -U -f <bundle> -i CCCrypt`  
  *Expected:* The app does not use ECB for sensitive data. It uses an authenticated mode such as GCM.  
  *Refs:* mobile_top10: M10:2024; masvs: MASVS-CRYPTO-1; mastg: MASTG-TEST-0232, MASTG-TEST-0350, MASTG-TEST-0317; maswe: MASWE-0007; cheatsheet: Cryptographic_Storage_Cheat_Sheet, Mobile_Application_Security_Cheat_Sheet; cwe: CWE-208, CWE-323, CWE-325, CWE-326, CWE-327, CWE-329, CWE-780  
  *See:* WEB-CRYPTO-008

- [ ] **MOB-CRYPTO-003** Check that security-relevant values come from a secure random generator  
  *Severity if fail:* Medium | *Type:* Code Review, Automated, Manual | *Level:* MASVS L1  
  *Objective:* Finds tokens, keys, IVs and nonces that come from a predictable random number generator or from the clock.  
  *Steps:*
  1. Android: Search the code for java.util.Random, Math.random, SecureRandom with a fixed seed, and Date().getTime or Calendar.MILLISECOND as value sources.
  2. iOS: Search the binary for rand, random, srand and the *rand48 functions.
  3. Hook these APIs at run time and use every workflow of the app.
  4. Look at the backtraces and the code to find what the value is used for.
  5. Flag keys, IVs, nonces, tokens, session IDs, passwords and PINs.
  6. Ignore uses that are not security-relevant, such as UI effects or game logic.
  *Example:* `jadx -d src app.apk; grep -rnE "java\.util\.Random|Math\.random|new SecureRandom\(|getTime\(\)" src/; frida-trace -U -f <package> -j "java.util.Random!*"; r2 -qc "aaa; afl~rand" Payload/App.app/App; frida-trace -U -f <bundle> -i rand -i random -i arc4random`  
  *Expected:* The app uses SecureRandom (Android) or SecRandomCopyBytes and arc4random (iOS) for all security-relevant values. Seeds are not fixed.  
  *Refs:* mobile_top10: M10:2024; masvs: MASVS-CRYPTO-1; mastg: MASTG-TEST-0204, MASTG-TEST-0205, MASTG-TEST-0311, MASTG-TEST-0349; maswe: MASWE-0012; cheatsheet: Cryptographic_Storage_Cheat_Sheet; cwe: CWE-332, CWE-337, CWE-338  
  *See:* WEB-CRYPTO-014

- [ ] **MOB-CRYPTO-004** Check that cryptographic keys have a sufficient size  
  *Severity if fail:* Medium | *Type:* Code Review | *Level:* MASVS L1  
  *Objective:* Finds symmetric and asymmetric keys that are too short for current guidance.  
  *Steps:*
  1. Android: Search for KeyGenerator.init, KeyPairGenerator.initialize and key sizes in KeyGenParameterSpec.
  2. iOS: Search for CCCrypt key length arguments and for SecKeyCreateRandomKey with kSecAttrKeyType and kSecAttrKeySizeInBits.
  3. Write down the algorithm and the key size at each location.
  4. Compare the sizes with the current NIST guidance, for example RSA 2048 bits or more and AES 256 bits.
  5. Flag RSA keys of 1024 bits and AES keys of 128 bits or less for the product policy.
  *Example:* `jadx -d src app.apk; grep -rnE "KeyGenerator|KeyPairGenerator|\.init\([0-9]+\)|\.initialize\([0-9]+\)" src/; r2 -qc "aaa; axt sym.imp.SecKeyCreateRandomKey" Payload/App.app/App; frida-trace -U -f <bundle> -i SecKeyCreateRandomKey`  
  *Expected:* Every key meets the current size guidance for its algorithm. The app uses no RSA 1024 bit keys and no keys shorter than the policy allows.  
  *Refs:* mobile_top10: M10:2024; masvs: MASVS-CRYPTO-2; mastg: MASTG-TEST-0208, MASTG-TEST-0209; maswe: MASWE-0013; cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; cwe: CWE-331, CWE-326, CWE-337, CWE-338, CWE-522  
  *See:* WEB-CRYPTO-005

- [ ] **MOB-CRYPTO-005** Check that no cryptographic keys are hardcoded in code or files  
  *Severity if fail:* High | *Type:* Code Review, Automated | *Level:* MASVS L1  
  *Objective:* Finds symmetric keys, private keys and key files that ship inside the app.  
  *Steps:*
  1. Android: Search the decompiled code for SecretKeySpec and other calls that take raw key bytes or strings.
  2. iOS: Search for SecKeyCreateWithData, CCCrypt with a literal key and CryptoKit init(rawRepresentation:) calls.
  3. Search resources and bundle files for .key, .pem, .p12, .der and .cer files and for BEGIN PRIVATE KEY markers.
  4. Search plist and JSON files for Base64 or hex strings next to names such as key, secret or privateKey.
  5. Look at each hit to see if it is a real key that protects data or authenticates a user.
  *Example:* `jadx -d src app.apk; grep -rn "SecretKeySpec" src/; find out/ ipa/ -name "*.pem" -o -name "*.p12" -o -name "*.key" -o -name "*.der"; grep -rl "BEGIN .*PRIVATE KEY" out/ ipa/; strings -n 16 Payload/App.app/App | grep -E "^[A-Za-z0-9+/=]{24,}$"; r2 -qc "aaa; axt sym.imp.SecKeyCreateWithData" Payload/App.app/App; trufflehog filesystem out ipa`  
  *Expected:* The app contains no hardcoded keys. The app creates keys on the device or gets them from a backend and stores them in the Keystore or Keychain.  
  *Refs:* mobile_top10: M1:2024, M10:2024; masvs: MASVS-CRYPTO-2, MASVS-STORAGE-1; mastg: MASTG-TEST-0212, MASTG-TEST-0213, MASTG-TEST-0214; maswe: MASWE-0003; cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; cwe: CWE-312, CWE-318, CWE-321  
  *See:* WEB-CRYPTO-018

- [ ] **MOB-CRYPTO-006** Check that keys live only in the platform keystore  
  *Severity if fail:* High | *Type:* Manual, Code Review | *Level:* MASVS L1  
  *Objective:* Finds cryptographic keys that the app stores in preferences, files or code instead of the Android Keystore or iOS Keychain.  
  *Steps:*
  1. List all keys, key pairs and secrets that the app creates, imports or receives.
  2. Android: Look for KeyStore.getInstance("AndroidKeyStore") and for keys written to files or SharedPreferences.
  3. iOS: Look for SecKeyCreateRandomKey with kSecAttrTokenIDSecureEnclave and for keys in UserDefaults or files.
  4. Compare the app data directory before and after use, and search for key material.
  5. Check how the app imports keys and see if it wraps them before import.
  *Example:* `jadx -d src app.apk; grep -rnE "AndroidKeyStore|KeyGenParameterSpec|setIsStrongBoxBacked" src/; objection -g <package> explore -> android keystore list; objection: ios keychain dump; grep -rE "[A-Za-z0-9+/=]{32,}" data/shared_prefs/`  
  *Expected:* The app keeps all keys in the Android Keystore or iOS Keychain. Key material never sits in preferences, plain files or code.  
  *Refs:* mobile_top10: M10:2024; masvs: MASVS-CRYPTO-2, MASVS-STORAGE-1; maswe: MASWE-0003; cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet, Mobile_Application_Security_Cheat_Sheet; cwe: CWE-312, CWE-318, CWE-321

- [ ] **MOB-CRYPTO-007** Check that Android asymmetric key pairs have one purpose  
  *Severity if fail:* Low | *Type:* Code Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds key pairs that the app uses for more than one role, such as encryption and signing.  
  *Steps:*
  1. Search the code for KeyGenParameterSpec.Builder and note the purposes argument.
  2. Decode the purposes bitmask: 1 encrypt, 2 decrypt, 4 sign, 8 signature check, 32 wrap key.
  3. Flag every purposes value that mixes encryption, signing and wrapping roles.
  4. Hook Cipher.init, Signature.initSign and Signature.initVerify and use every workflow of the app.
  5. Check that no key is used in more than one group of operations.
  *Example:* `jadx -d src app.apk; grep -rn "KeyGenParameterSpec" src/; frida-trace -U -f <package> -j "javax.crypto.Cipher!init" -j "java.security.Signature!initSign" -j "java.security.Signature!initVerify"`  
  *Expected:* Each key pair has exactly one role: encryption, signing or key wrapping. The value 15 or any mixed value does not appear.  
  *Refs:* mobile_top10: M10:2024; masvs: MASVS-CRYPTO-1; mastg: MASTG-TEST-0307, MASTG-TEST-0308; maswe: MASWE-0007; cheatsheet: Key_Management_Cheat_Sheet; cwe: CWE-208, CWE-323, CWE-325, CWE-326, CWE-327, CWE-329, CWE-780

- [ ] **MOB-CRYPTO-008** Check that Android crypto calls use no explicit security provider  
  *Severity if fail:* Low | *Type:* Code Review | *Level:* MASVS L1  
  *Objective:* Finds getInstance calls that name a provider other than the default Conscrypt provider.  
  *Steps:*
  1. Search the decompiled code for getInstance calls with a second provider argument.
  2. Note the provider names, such as Crypto, BC or BouncyCastle.
  3. Flag every provider except AndroidKeyStore in KeyStore.getInstance calls.
  4. Check the targetSdkVersion, because apps for Android 9 and higher fail when they name a provider.
  *Example:* `jadx -d src app.apk; grep -rnE "getInstance\([^)]*,\s*\"(BC|Crypto|SC|SunJCE)\"" src/; grep -rn "Security.addProvider\|BouncyCastleProvider" src/; aapt2 d badging app.apk | grep targetSdkVersion`  
  *Expected:* No getInstance call names a provider other than the default. Only KeyStore calls name AndroidKeyStore.  
  *Refs:* mobile_top10: M10:2024; masvs: MASVS-CRYPTO-1; mastg: MASTG-TEST-0312; maswe: MASWE-0007; cwe: CWE-208, CWE-323, CWE-325, CWE-326, CWE-327, CWE-329, CWE-780

- [ ] **MOB-CRYPTO-009** Check that the app uses no broken hash functions  
  *Severity if fail:* Medium | *Type:* Code Review, Automated | *Level:* MASVS L1  
  *Objective:* Finds MD5 and SHA-1 in security-relevant uses such as signatures, integrity checks and fingerprints.  
  *Steps:*
  1. Android: Search the decompiled code for MessageDigest.getInstance with MD5, MD2, MD4 or SHA-1.
  2. iOS: Search the binary for CC_MD2, CC_MD4, CC_MD5, CC_SHA1 and CryptoKit Insecure.MD5 and Insecure.SHA1.
  3. Look at the code at each hit and note what the hash protects.
  4. Check that the app does not hash passwords or passphrases with a fast hash. A password KDF is needed.
  5. Check that digests are not truncated below the security strength that the use case needs.
  *Example:* `jadx -d src app.apk; grep -rnE "MessageDigest.getInstance\(\"(MD5|MD2|MD4|SHA-?1)\"" src/; r2 -qc "aaa; afl~CC_MD5; afl~CC_SHA1" Payload/App.app/App; strings Payload/App.app/App | grep -E "Insecure.*(MD5|SHA1)"`  
  *Expected:* The app uses SHA-256 or stronger for security purposes. MD5 and SHA-1 appear only in non-security uses.  
  *Refs:* mobile_top10: M10:2024; masvs: MASVS-CRYPTO-1; mastg: MASTG-TEST-0211; maswe: MASWE-0008; cheatsheet: Cryptographic_Storage_Cheat_Sheet; cwe: CWE-328  
  *See:* WEB-CRYPTO-012

- [ ] **MOB-CRYPTO-010** Check that the app uses MACs correctly  
  *Severity if fail:* Medium | *Type:* Code Review | *Level:* MASVS L1  
  *Objective:* Finds missing, weak or reused message authentication codes.  
  *Steps:*
  1. List the places where the app must protect the integrity of data, such as stored files, messages and tokens.
  2. Search the code for Mac, HMAC, CCHmac, CRC32 and hash(key + message) constructions.
  3. Flag CRC checksums, MD5 or SHA-1 based MACs and plain hash(key || message) patterns.
  4. Check the key source, the key reuse, the tag length and the order of encryption and MAC.
  5. Check that the app compares tags in constant time and rejects replayed messages.
  *Example:* `jadx -d src app.apk; grep -rnE "javax.crypto.Mac|HmacMD5|HmacSHA1|CRC32" src/; r2 -qc "aaa; afl~CCHmac" Payload/App.app/App; frida-trace -U -f <package> -j "javax.crypto.Mac!*"`  
  *Expected:* The app uses HMAC with SHA-256 or stronger, or an AEAD mode. Keys have one purpose, tags are full length and replays fail.  
  *Refs:* mobile_top10: M10:2024; masvs: MASVS-CRYPTO-1, MASVS-CRYPTO-2; maswe: MASWE-0009; cheatsheet: Cryptographic_Storage_Cheat_Sheet; cwe: CWE-208, CWE-323, CWE-327, CWE-354, CWE-807  
  *See:* WEB-CRYPTO-010, WEB-CRYPTO-006

- [ ] **MOB-CRYPTO-011** Check how the app generates cryptographic signatures  
  *Severity if fail:* Medium | *Type:* Code Review | *Level:* MASVS L1  
  *Objective:* Finds weak signature algorithms, short signing keys and weak nonces.  
  *Steps:*
  1. Search the code for Signature.getInstance, SecKeyCreateSignature and CryptoKit signing calls.
  2. Note the signature algorithm and digest, for example SHA1withRSA.
  3. Note the key length of each signing key.
  4. Check that (EC)DSA nonces come from a secure random generator or use a deterministic scheme.
  5. Check that signing keys are not used for encryption or key agreement.
  *Example:* `jadx -d src app.apk; grep -rn "Signature.getInstance" src/; r2 -qc "aaa; axt sym.imp.SecKeyCreateSignature" Payload/App.app/App; frida-trace -U -f <package> -j "java.security.Signature!getInstance"`  
  *Expected:* The app uses ECDSA, RSA-PSS or EdDSA with approved digests and key lengths. Nonces are unpredictable and signing keys have one purpose.  
  *Refs:* mobile_top10: M10:2024; masvs: MASVS-CRYPTO-1, MASVS-CRYPTO-2; maswe: MASWE-0010; cheatsheet: Cryptographic_Storage_Cheat_Sheet; cwe: CWE-323, CWE-326, CWE-327, CWE-330  
  *See:* WEB-CRYPTO-015

- [ ] **MOB-CRYPTO-012** Check that the app verifies signatures and acts on the result  
  *Severity if fail:* High | *Type:* Code Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds signature checks that are skipped, ignored or trust keys that an attacker can replace.  
  *Steps:*
  1. List the data that the app must check with signatures, such as updates, configuration, licenses and tokens.
  2. Search the code for the Signature class, SecKeyVerifySignature and token validation calls.
  3. Check that a failed check stops the operation and that the code does not swallow the result.
  4. Check that the public key comes from a trusted set and not from the same download as the data.
  5. Change signed data in transit with a proxy and make sure the app rejects it.
  *Example:* `jadx -d src app.apk; grep -rn "\.verify(" src/; r2 -qc "aaa; axt sym.imp.SecKeyVerifySignature" Payload/App.app/App; frida -U -f <package> -l hook-signature-verify.js (return false and see the app behavior); mitmproxy -s tamper.py`  
  *Expected:* The app rejects every item with a wrong, missing or foreign signature. It enforces the expected algorithm and trusted keys.  
  *Refs:* mobile_top10: M10:2024; masvs: MASVS-CRYPTO-1; maswe: MASWE-0011; cheatsheet: Cryptographic_Storage_Cheat_Sheet; cwe: CWE-295, CWE-347  
  *See:* WEB-JWT-001, WEB-JWT-002

- [ ] **MOB-CRYPTO-013** Check that keys derived from passwords use a password KDF  
  *Severity if fail:* Medium | *Type:* Code Review | *Level:* MASVS L1  
  *Objective:* Finds keys derived with a plain hash, a low work factor, a missing salt or a low-entropy input.  
  *Steps:*
  1. Search the code for key derivation from passwords, PINs and passphrases.
  2. Flag plain hashes such as SHA-256 of a password, used as a key.
  3. Look for PBKDF2, scrypt or Argon2 and note the iterations, memory and parallelism values.
  4. Check that each derivation uses a unique random salt that is not hardcoded.
  5. Check that a short PIN is combined with a random key from the Keystore or Keychain.
  *Example:* `jadx -d src app.apk; grep -rnE "PBKDF2|SecretKeyFactory.getInstance|scrypt|Argon2" src/; r2 -qc "aaa; afl~CCKeyDerivationPBKDF" Payload/App.app/App; frida-trace -U -f <package> -j "javax.crypto.spec.PBEKeySpec!*"`  
  *Expected:* The app derives keys from passwords only with PBKDF2, scrypt or Argon2. It uses a current work factor and a unique random salt.  
  *Refs:* mobile_top10: M10:2024; masvs: MASVS-CRYPTO-2; maswe: MASWE-0014; cheatsheet: Cryptographic_Storage_Cheat_Sheet, Mobile_Application_Security_Cheat_Sheet; cwe: CWE-326, CWE-327, CWE-759, CWE-760, CWE-916  
  *See:* WEB-CRYPTO-013

- [ ] **MOB-CRYPTO-014** Check that the app can rotate its cryptographic keys  
  *Severity if fail:* Low | *Type:* Config Review, Manual | *Level:* MASVS L2  
  *Objective:* Finds keys with no cryptoperiod, no versioning and no way to replace them.  
  *Steps:*
  1. Read the design documents and find how the app stores and uses long-lived keys.
  2. Search the code for key versions, keysets and key identifiers in the stored data format.
  3. Find the cryptoperiod that the team defined for each key type.
  4. Replace a key in a test build. Old data must stay readable and new data must use the new key.
  5. Make sure the app restricts old keys to decryption and then destroys them.
  *Example:* `jadx -d src app.apk; grep -rnE "keyVersion|KeysetHandle|rotate" src/; adb shell run-as <package> ls files shared_prefs (look for key version markers)`  
  *Expected:* The data format supports key versions. The team defines cryptoperiods, and rotation works without data loss.  
  *Refs:* mobile_top10: M10:2024; masvs: MASVS-CRYPTO-2; maswe: MASWE-0015; cheatsheet: Cryptographic_Storage_Cheat_Sheet, Key_Management_Cheat_Sheet; cwe: CWE-324  
  *See:* WEB-SECRET-002

- [ ] **MOB-CRYPTO-015** Check that key use needs authentication and an unlocked device  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS L2  
  *Objective:* Finds keys that any code in the app, or anyone with the unlocked device, can use without limits.  
  *Steps:*
  1. Android: Search KeyGenParameterSpec.Builder for setUserAuthenticationRequired, setUnlockedDeviceRequired and the validity duration.
  2. iOS: Search SecAccessControlCreateWithFlags and the kSecAttrAccessible values of Keychain items.
  3. Flag keys for sensitive data that need no authentication, or that work while the device is locked.
  4. Flag iOS items with kSecAttrAccessibleAlways or without the ThisDeviceOnly suffix.
  5. Flag keys in StrongBox or the Secure Enclave that have no use restrictions.
  *Example:* `jadx -d src app.apk; grep -rnE "setUserAuthenticationRequired|setUnlockedDeviceRequired|setUserAuthenticationParameters" src/; r2 -qc "aaa; axt sym.imp.SecAccessControlCreateWithFlags" Payload/App.app/App; objection -g <bundle> explore -> ios keychain dump (read the Accessible column)`  
  *Expected:* Keys for sensitive data need user authentication and an unlocked device, are bound to the device and have a short or zero validity.  
  *Refs:* mobile_top10: M10:2024; masvs: MASVS-CRYPTO-2, MASVS-AUTH-2, MASVS-AUTH-3; maswe: MASWE-0016; cheatsheet: Key_Management_Cheat_Sheet; cwe: CWE-284, CWE-306

- [ ] **MOB-CRYPTO-016** Check that the app needs a secure device lock for sensitive features  
  *Severity if fail:* Low | *Type:* Manual, Code Review | *Level:* MASVS L2  
  *Objective:* Finds sensitive features that work on devices with no PIN, pattern, password or biometric lock.  
  *Steps:*
  1. Search the code for KeyguardManager.isDeviceSecure and LAContext canEvaluatePolicy.
  2. Search iOS Keychain items for kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly.
  3. Remove the screen lock on a test device and start the sensitive feature.
  4. Remove the screen lock while the app runs and use the feature again.
  5. See if the app blocks the feature or the key access in both cases.
  *Example:* `jadx -d src app.apk; grep -rn "isDeviceSecure\|isKeyguardSecure" src/; r2 -qc "aaa; axt sym.imp.SecAccessControlCreateWithFlags" Payload/App.app/App; adb shell locksettings clear --old <PIN> (test device)`  
  *Expected:* The app checks the device lock state at each use of sensitive features. It blocks the feature or the key use when no lock is set.  
  *Refs:* mobile_top10: M10:2024; masvs: MASVS-CRYPTO-2; maswe: MASWE-0017; cheatsheet: Key_Management_Cheat_Sheet


## TASK

- [ ] **MOB-TASK-001** Check Android activities for task affinity and task reparenting hijack  
  *Severity if fail:* Medium | *Type:* Config Review, Manual | *Level:* MASVS L2  
  *Objective:* Find activities with a task affinity or reparenting setting that lets another app move its screen into the task of the app.  
  *Steps:*
  1. Decode the manifest. List all activities with the taskAffinity, allowTaskReparenting and launchMode attributes.
  2. Find the attribute allowTaskReparenting set to true on the application or on an activity. Examine the reason.
  3. Make sure the activities that show login or sensitive screens use the default task affinity and no custom value.
  4. Make sure no activity uses a launch mode that places it in a task of another app without need.
  5. Read minSdkVersion. Note if it is lower than 30. Only Android 11 and later fix version 2 of the attack.
  6. On a test device, install the test app that sets the same taskAffinity. Start the target app and look for the screen of the test app on top.
  7. Make sure the user does not see a foreign screen when the app opens or when a sensitive activity ends.
  *Example:* `apktool d app.apk -o out; grep -nE "taskAffinity|allowTaskReparenting|launchMode" out/AndroidManifest.xml; aapt dump badging app.apk | grep sdkVersion; adb shell dumpsys activity activities | grep -A3 "Task id"`  
  *Expected:* No activity sets allowTaskReparenting to true or a custom taskAffinity without a reason. The target app opens its own screens only, and minSdkVersion is 30 or higher.  
  *Refs:* mobile_top10: M8:2024; masvs: MASVS-PLATFORM-3; maswe: MASWE-0039; cwe: CWE-1021, CWE-451; capec: CAPEC-501; other: Android StrandHogg guide: https://developer.android.com/privacy-and-security/risks/strandhogg  
  *See:* MOB-UI-005, MOB-CODE-001, MOB-IPC-001


## XPLAT

- [ ] **MOB-XPLAT-001** Check pinning and TLS in the own network stack of cross-platform apps  
  *Severity if fail:* Medium | *Type:* Manual, Code Review | *Level:* MASVS L2  
  *Objective:* Find cross-platform apps whose own HTTP stack ignores the platform pinning, trust and cleartext settings.  
  *Steps:*
  1. Identify the framework from the app package. Find out if the app uses the platform HTTP stack or its own.
  2. For Flutter, look for pinning in Dart code with SecurityContext or a badCertificateCallback. NSC and ATS pins do not apply to Dart.
  3. Look in the Dart code for a badCertificateCallback that returns true without a check.
  4. For React Native on iOS, check if the pins in ATS or the URLSession code cover the traffic. For Cordova, check the native pinning plugin.
  5. Set a system proxy and start the app. A Flutter app does not use the system proxy, so route its traffic by iptables or DNS.
  6. Look at the traffic to first-party domains with a proxy certificate that the device trusts. Make sure the connection fails.
  7. Look for HTTP URLs and cleartext traffic that the framework allows when the platform settings forbid it.
  *Example:* `reflutter app.apk (test device only); frida -U -f com.example.app -l disable-flutter-tls.js; iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to <proxy>:8080; grep -rn "badCertificateCallback\|SecurityContext" lib/`  
  *Expected:* The app pins first-party domains in the code path that the framework uses. A trusted proxy certificate does not give access to traffic, and cleartext is not allowed.  
  *Refs:* mobile_top10: M5:2024; masvs: MASVS-NETWORK-1, MASVS-NETWORK-2; mastg: MASTG-TEST-0237; maswe: MASWE-0028, MASWE-0026; cheatsheet: Pinning_Cheat_Sheet; cwe: CWE-295  
  *See:* MOB-NETWORK-006, MOB-NETWORK-013, MOB-NETWORK-015

- [ ] **MOB-XPLAT-002** Check the integrity of React Native bundles and over-the-air updates  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* MASVS R  
  *Objective:* Find apps that run a changed or downloaded JavaScript bundle without an integrity check.  
  *Steps:*
  1. Unpack the package. Find assets/index.android.bundle on Android or main.jsbundle on iOS.
  2. Look at the bundle. Note if it is minified JavaScript or Hermes bytecode.
  3. Change a harmless string in the bundle. Repack and re-sign the app. Install it on the test device.
  4. Start the app. Look for an integrity check or tamper detection that stops the app.
  5. Find the code that downloads a new bundle or update. Make sure the app checks a signature or a hash before it runs the update.
  6. Replace the downloaded bundle in a test environment. Make sure the app rejects it.
  7. Make sure the app does not run a bundle after a failed integrity check.
  *Example:* `unzip app.apk -d out; file out/assets/index.android.bundle; hermes-dec out/assets/index.android.bundle; apktool b out; apksigner sign --ks test.jks app.apk`  
  *Expected:* The app detects a changed bundle and refuses to run an unsigned or changed update. A failed integrity check stops the use of the resource.  
  *Refs:* mobile_top10: M7:2024; masvs: MASVS-RESILIENCE-2, MASVS-CODE-4; maswe: MASWE-0057; cwe: CWE-494, CWE-345  
  *See:* MOB-RESIL-008, MOB-STORAGE-009, MOB-CODE-009

- [ ] **MOB-XPLAT-003** Check hybrid app WebViews, plugins and allowed origins  
  *Severity if fail:* High | *Type:* Manual, Code Review | *Level:* MASVS L1  
  *Objective:* Find hybrid apps that load untrusted origins in a WebView with native bridges, or that ship vulnerable web libraries and plugins.  
  *Steps:*
  1. List the origins that the app may load in its WebView. Read the allowed origin and navigation settings of the framework.
  2. Make sure the list holds only the origins that the app needs and has no wildcard.
  3. Make sure JavaScript is on only for content that the app controls.
  4. Look at the native plugins that the page can call. Make sure untrusted content cannot reach sensitive plugins.
  5. Try to load a page from another origin in the WebView, for example by a link or a redirect. Make sure the app blocks it.
  6. List the plugins and the JavaScript libraries in the package. Compare their versions with known vulnerabilities.
  7. Make sure external content opens in Custom Tabs when the app does not need a WebView for it.
  *Example:* `grep -rn "loadUrl\|allow" config.xml capacitor.config.*; npm audit; retire --path www/`  
  *Expected:* The WebView loads only listed origins. Untrusted content cannot call sensitive plugins, and plugins and web libraries have no known vulnerabilities.  
  *Refs:* mobile_top10: M2:2024; masvs: MASVS-PLATFORM-2, MASVS-CODE-3; maswe: MASWE-0035; cwe: CWE-749  
  *See:* MOB-WEBVIEW-003, MOB-WEBVIEW-007, MOB-CODE-004


## IPC

- [ ] **MOB-IPC-001** Check exported Android components for missing permissions  
  *Severity if fail:* Medium | *Type:* Config Review, Code Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds activities, services and receivers that other apps can start or call without permission.  
  *Steps:*
  1. Android: Decode the APK and read the AndroidManifest.xml.
  2. Android: List every activity, service and receiver with android:exported and android:permission.
  3. Android: Find components that are exported without a permission or with a normal protection level.
  4. Android: Read the code of each exported component for sensitive data or actions.
  5. Android: Start each exported component from the shell. Send a crafted intent to each receiver.
  6. Android: Make sure each service checks the caller permission at runtime before it acts.
  *Example:* `apktool d app.apk -o out ; aapt2 d xmltree app.apk --file AndroidManifest.xml | grep -A20 -E "E: (activity|service|receiver)" ; adb shell am start -n <pkg>/<exported.Activity> ; adb shell am startservice -n <pkg>/<exported.Service> ; adb shell am broadcast -a <action> -n <pkg>/<exported.Receiver> --es key value`  
  *Expected:* The app exports only components that must be public. Each exported component that handles sensitive data needs a signature-level permission, and no unauthenticated caller can reach it.  
  *Refs:* mobile_top10: M8:2024; masvs: MASVS-PLATFORM-1; mastg: MASTG-TEST-0364, MASTG-TEST-0365, MASTG-TEST-0366; maswe: MASWE-0018; cwe: CWE-306, CWE-749, CWE-862, CWE-863, CWE-923

- [ ] **MOB-IPC-002** Check exported content providers for missing permissions and data leaks  
  *Severity if fail:* High | *Type:* Config Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds content providers that give other apps read or write access to private app data.  
  *Steps:*
  1. Android: Read the AndroidManifest.xml. List each provider with android:exported, readPermission and writePermission.
  2. Android: Find exported providers that have no android:permission, readPermission or writePermission.
  3. Android: Look at the protection level of each declared permission. Normal and dangerous levels do not limit access.
  4. Android: Use the app until the database holds sensitive test data.
  5. Android: Query each exported provider from the shell without any permission.
  6. Android: Look at the rows that come back for sensitive data.
  *Example:* `adb shell content query --uri content://<authority>/<path> ; adb shell content query --uri content://<authority>/<path> --where "name='Bob'" ; xmlstarlet sel -t -m "//provider" -v "@android:name" -o " exported=" -v "@android:exported" -n AndroidManifest.xml`  
  *Expected:* No exported content provider returns or changes sensitive data for a caller without a signature-level permission. Providers for internal use are not exported.  
  *Refs:* mobile_top10: M8:2024; masvs: MASVS-PLATFORM-1; mastg: MASTG-TEST-0355, MASTG-TEST-0356; maswe: MASWE-0018; cwe: CWE-306, CWE-749, CWE-862, CWE-863, CWE-923

- [ ] **MOB-IPC-003** Check FileProvider paths for access outside the shared directory  
  *Severity if fail:* High | *Type:* Config Review, Code Review | *Level:* MASVS L1  
  *Objective:* Finds FileProvider path settings that let other apps open private files through content URIs.  
  *Steps:*
  1. Android: Decode the APK. Find each exported FileProvider in the AndroidManifest.xml.
  2. Android: Open the file paths XML resource that the provider uses.
  3. Android: Look for root-path entries and for path values of "/", "." or an empty string.
  4. Android: Find calls to FileProvider.getUriForFile in the code.
  5. Android: Make sure no attacker-controlled input, such as a URI query value, reaches the file argument.
  6. Android: Make sure the provider requires a permission with a dangerous or signature protection level.
  *Example:* `jadx -d out app.apk ; grep -rn "getUriForFile\|root-path" out/ ; cat out/resources/res/xml/file_paths.xml`  
  *Expected:* The FileProvider shares only the intended directory. Path settings do not expose root or private storage, and attacker-controlled input never selects the file.  
  *Refs:* mobile_top10: M8:2024; masvs: MASVS-PLATFORM-1; mastg: MASTG-TEST-0357; maswe: MASWE-0018; cwe: CWE-306, CWE-749, CWE-862, CWE-863, CWE-923

- [ ] **MOB-IPC-004** Check PendingIntent objects for mutable flags and implicit base intents  
  *Severity if fail:* Medium | *Type:* Code Review | *Level:* MASVS L1  
  *Objective:* Finds PendingIntent objects that other apps can change or redirect.  
  *Steps:*
  1. Android: Search the decompiled code for PendingIntent.getActivity, getActivities, getService, getForegroundService and getBroadcast.
  2. Android: Read the flags argument of each call for FLAG_IMMUTABLE or FLAG_MUTABLE.
  3. Android: Read the minSdkVersion in the AndroidManifest.xml.
  4. Android: Check if the base intent names its target with setClass, setClassName or setComponent.
  5. Android: Find a valid use case for each mutable PendingIntent, such as an inline reply.
  *Example:* `jadx -d out app.apk ; grep -rn "PendingIntent\.\(getActivity\|getActivities\|getService\|getForegroundService\|getBroadcast\)" out/ ; grep -rn "FLAG_MUTABLE\|FLAG_IMMUTABLE" out/`  
  *Expected:* Each PendingIntent uses FLAG_IMMUTABLE unless mutability is required and documented. Each base intent is explicit and names its target component.  
  *Refs:* mobile_top10: M8:2024; masvs: MASVS-PLATFORM-1; mastg: MASTG-TEST-0381; maswe: MASWE-0032; cwe: CWE-927, CWE-940

- [ ] **MOB-IPC-005** Check implicit intents used for internal communication and sensitive extras  
  *Severity if fail:* Medium | *Type:* Code Review | *Level:* MASVS L1  
  *Objective:* Finds implicit intents that another app can intercept to read data or take over a flow.  
  *Steps:*
  1. Android: Find all places where the app builds an Intent and sends it with startActivity, startService, bindService or sendBroadcast.
  2. Android: Mark the intents that have no setPackage, setClass, setClassName or setComponent call.
  3. Android: Check if the intent is for an internal component and not a user-selected app or chooser.
  4. Android: Look for putExtra calls with tokens, session IDs, one-time codes or personal data.
  5. Android: Make sure another app cannot register an intent-filter that matches the action, data and categories.
  6. Android: Make sure each broadcast with sensitive data requires a receiver permission.
  *Example:* `jadx -d out app.apk ; grep -rn "new Intent(\"\|setAction(\|putExtra(\|sendBroadcast(" out/ ; semgrep --config <rules> out/`  
  *Expected:* Intents for internal communication name an explicit component or package. Intents that carry sensitive extras go only to a known recipient.  
  *Refs:* mobile_top10: M8:2024; masvs: MASVS-PLATFORM-1, MASVS-CODE-4; mastg: MASTG-TEST-0372, MASTG-TEST-0374; maswe: MASWE-0032; cwe: CWE-927, CWE-940

- [ ] **MOB-IPC-006** Check validation of data that other apps return to the app  
  *Severity if fail:* Medium | *Type:* Manual, Code Review | *Level:* MASVS L1  
  *Objective:* Finds flows where data from an external intent result reaches a sensitive operation without checks.  
  *Steps:*
  1. Android: Install the app and attach a Frida hook to startActivityForResult, ActivityResultLauncher and onActivityResult.
  2. Android: Use the app to start each flow that asks another app for a file, a document or an account.
  3. Android: Install a test app that answers with a crafted URI scheme or a file name with path separators.
  4. Android: Record the reads of Intent.getData, ClipData, extras and ContentResolver calls.
  5. Android: Look at the backtraces. Find returned data that reaches file, parse, storage, network or authorization code.
  6. Android: Make sure the app checks the data before each use.
  *Example:* `frida -U -f <pkg> -l hook_intent_results.js ; objection -g <pkg> explore, then android hooking watch class_method android.app.Activity.onActivityResult --dump-args --dump-backtrace`  
  *Expected:* The app treats data returned from other apps as untrusted. It checks scheme, path, name and type before it uses the data.  
  *Refs:* mobile_top10: M4:2024; masvs: MASVS-CODE-4, MASVS-PLATFORM-1; mastg: MASTG-TEST-0375; maswe: MASWE-0050, MASWE-0032; cwe: CWE-20, CWE-22, CWE-73, CWE-89, CWE-116

- [ ] **MOB-IPC-007** Check deep links for App Links or Universal Links verification  
  *Severity if fail:* Medium | *Type:* Config Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds deep links that another app can claim and use to capture tokens or links.  
  *Steps:*
  1. Android: List the intent-filters with http or https data and the VIEW and BROWSABLE entries in the AndroidManifest.xml.
  2. Android: Find filters that miss android:autoVerify="true".
  3. Android: Check on the device that each declared domain has the verified state.
  4. Android: Look for custom URL schemes used for login, reset or payment flows.
  5. iOS: Read the Associated Domains entitlement of the app binary.
  6. iOS: Fetch the apple-app-site-association file of each domain and compare its paths with the app.
  7. Make sure no deep link carries a long-lived token or other secret.
  *Example:* `adb shell pm get-app-links <pkg> ; python3 deeplink_analyser.py -op verify-applinks -apk app.apk ; rabin2 -OC app_binary | grep -A3 associated-domains ; curl https://<domain>/.well-known/apple-app-site-association`  
  *Expected:* Sensitive flows use only verified Android App Links and iOS Universal Links. Custom URL schemes do not start sensitive actions, and links carry no long-lived secrets.  
  *Refs:* mobile_top10: M4:2024; masvs: MASVS-PLATFORM-1; mastg: MASTG-TEST-0393; maswe: MASWE-0029; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-939, CWE-917

- [ ] **MOB-IPC-008** Check input validation in deep link and URL scheme handlers  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds deep link handlers that use attacker-controlled parameters without checks.  
  *Steps:*
  1. Android: Find the code for each intent-filter that has a VIEW action and a custom scheme or http scheme.
  2. iOS: Find the code for each custom URL scheme and each Universal Link handler in the binary.
  3. Read how the handler converts, limits and sanitizes each path and query parameter.
  4. Look for raw strings used for amounts, file paths, SQL queries, WebView URLs or navigation.
  5. Open the deep link on the device with a negative number, a path traversal value and a script value.
  6. Make sure the handler rejects each value and keeps the app stable.
  *Example:* `adb shell am start -W -a android.intent.action.VIEW -d "myapp://open?path=../../data/x" ; adb shell am start -W -a android.intent.action.VIEW -d "myapp://transfer?amount=-1" ; xcrun devicectl device process launch --device <UDID> --payload-url 'mastgtest://open?path=../../x' <bundle_id> ; xcrun simctl openurl booted "https://example.com/open?path=../../x"`  
  *Expected:* Handlers convert each parameter to its expected type, check ranges and allowlists, and sanitize special characters before the value reaches a sink.  
  *Refs:* mobile_top10: M4:2024; masvs: MASVS-PLATFORM-1, MASVS-CODE-4; mastg: MASTG-TEST-0394, MASTG-TEST-0370, MASTG-TEST-0395; maswe: MASWE-0029, MASWE-0050; cwe: CWE-939, CWE-917, CWE-20, CWE-22, CWE-73

- [ ] **MOB-IPC-009** Check source validation in iOS custom URL scheme handlers  
  *Severity if fail:* Low | *Type:* Code Review | *Level:* MASVS L1  
  *Objective:* Finds URL scheme handlers that act on sensitive requests without checking the calling app.  
  *Steps:*
  1. iOS: Find the scene(_:openURLContexts:) method in the app binary.
  2. iOS: Look for reads of UIOpenURLContext.options.sourceApplication.
  3. iOS: Check if the handler compares the source with an allowlist before it acts.
  4. iOS: Find out if the scheme starts a privileged or irreversible action.
  5. Android: Note that Android gives no caller identity for scheme intents. Check that the handler needs a separate user approval or token for sensitive actions.
  *Example:* `r2 -A <app_binary> ; afl~openURLContexts ; izz~sourceApplication`  
  *Expected:* Handlers that start security-sensitive actions read the source application and check it against an allowlist. Sensitive actions also need another check, as the source is often nil.  
  *Refs:* mobile_top10: M4:2024; masvs: MASVS-PLATFORM-1; mastg: MASTG-TEST-0371; maswe: MASWE-0029; cwe: CWE-939, CWE-917

- [ ] **MOB-IPC-010** Check the use of the general pasteboard and the clipboard  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds sensitive data on the system clipboard that other apps or devices can read.  
  *Steps:*
  1. iOS: Search the binary for UIPasteboard.general and the calls addItems, setItems, string and items.
  2. iOS: Run the app. Copy a password or personal data. Monitor the general pasteboard with Frida.
  3. iOS: Make sure setItems uses the localOnly and expirationDate options for sensitive data.
  4. iOS: Check that the app clears the pasteboard with items = [] when it goes to the background or ends.
  5. Android: Search the code for ClipboardManager.setPrimaryClip and ClipDescription.EXTRA_IS_SENSITIVE.
  6. Android: Make sure sensitive fields cannot be copied, or that copied values have the sensitive flag and a short life.
  7. Treat pasted clipboard data as untrusted input.
  *Example:* `r2 -A <app_binary> ; afl~UIPasteboard ; frida -U -n <app> -l monitor_pasteboard.js (poll UIPasteboard.generalPasteboard().changeCount()) ; grep -rn "setPrimaryClip\|EXTRA_IS_SENSITIVE" out/`  
  *Expected:* The app does not put secrets on the clipboard. If it must, the data is local only, expires soon, is marked sensitive and is cleared.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PLATFORM-1; mastg: MASTG-TEST-0276, MASTG-TEST-0277, MASTG-TEST-0278, MASTG-TEST-0279, MASTG-TEST-0280; maswe: MASWE-0030; cwe: CWE-200, CWE-668

- [ ] **MOB-IPC-011** Check that the app restricts custom keyboards for sensitive input  
  *Severity if fail:* Medium | *Type:* Code Review, Config Review | *Level:* MASVS L1  
  *Objective:* Finds apps that let third-party keyboards read passwords and other secrets.  
  *Steps:*
  1. iOS: Look for application:shouldAllowExtensionPointIdentifier: in the app delegate of the binary.
  2. iOS: Check that the method returns false for UIApplicationKeyboardExtensionPointIdentifier.
  3. iOS: Check that password, PIN and OTP fields use isSecureTextEntry, so that they use the system keyboard.
  4. iOS: Open the Info.plist of each bundled keyboard extension. Look at RequestsOpenAccess.
  5. iOS: Find keyboard code that sends typed text off the device or writes it to a shared container.
  6. Android: Note that this control has no MASTG test for Android. Check that sensitive fields use a non-caching text input type.
  *Example:* `unzip app.ipa ; plutil -p Payload/App.app/PlugIns/*.appex/Info.plist | grep -i RequestsOpenAccess ; r2 -A <app_binary> ; afl~shouldAllowExtensionPointIdentifier`  
  *Expected:* The app rejects custom keyboards app-wide when it handles sensitive input. A bundled keyboard asks for Full Access only with a feature that needs it.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PLATFORM-1, MASVS-PRIVACY-1; mastg: MASTG-TEST-0389, MASTG-TEST-0390; maswe: MASWE-0031, MASWE-0066; cwe: CWE-829, CWE-250

- [ ] **MOB-IPC-012** Check the app for unsafe object deserialization of untrusted data  
  *Severity if fail:* High | *Type:* Code Review | *Level:* MASVS L1  
  *Objective:* Finds deserialization of data from other apps or the network that can lead to code execution.  
  *Steps:*
  1. Android: Search for ObjectInputStream, Serializable and Parcelable reads in Intent extras, Bundles, files and network data.
  2. iOS: Search the binary for decodeObject(forKey:), unarchiveObject(with:) and unarchiveTopLevelObjectWithData.
  3. iOS: Check that NSKeyedUnarchiver uses secure coding and a list of allowed classes.
  4. Follow the data back to its source. Find sources that other apps or attackers control.
  5. Make sure the app uses a data-only format such as JSON, or checks a signature, before it deserializes.
  *Example:* `jadx -d out app.apk ; grep -rn "ObjectInputStream\|readSerializable\|getSerializableExtra" out/ ; r2 -A <app_binary> ; afl~unarchive`  
  *Expected:* The app does not deserialize native objects from untrusted sources. If it must, it restricts the classes and checks integrity first.  
  *Refs:* mobile_top10: M4:2024; masvs: MASVS-CODE-4; mastg: MASTG-TEST-0337, MASTG-TEST-0386; maswe: MASWE-0050; cheatsheet: Deserialization_Cheat_Sheet, Input_Validation_Cheat_Sheet; cwe: CWE-20, CWE-22, CWE-73, CWE-89, CWE-116

- [ ] **MOB-IPC-013** Check SQL queries built from content provider URIs for injection  
  *Severity if fail:* High | *Type:* Code Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds content providers that put URI or selection input into SQL text.  
  *Steps:*
  1. Android: Find every ContentProvider class in the decompiled code.
  2. Android: Look at the query, update and delete methods for uses of Uri.getPathSegments and appendWhere.
  3. Android: Find SQL text that joins strings from the URI or the selection argument.
  4. Android: Send a quote character or an OR clause through the URI from the shell.
  5. Android: Make sure the provider uses selection arguments or a query builder with bound parameters.
  *Example:* `adb shell content query --uri content://<authority>/students/1%20OR%201=1 ; adb shell content query --uri content://<authority>/students --where "name='a' OR '1'='1" ; grep -rn "appendWhere\|getPathSegments\|rawQuery" out/`  
  *Expected:* The provider binds all input from URIs and selection arguments as parameters. No input becomes part of the SQL text.  
  *Refs:* mobile_top10: M4:2024; masvs: MASVS-CODE-4, MASVS-PLATFORM-1; mastg: MASTG-TEST-0339; maswe: MASWE-0050; cheatsheet: Input_Validation_Cheat_Sheet; cwe: CWE-20, CWE-22, CWE-73, CWE-89, CWE-116


## NETWORK

- [ ] **MOB-NETWORK-001** Check that app configuration does not allow cleartext traffic  
  *Severity if fail:* Medium | *Type:* Config Review, Automated | *Level:* MASVS L1  
  *Objective:* Finds Android and iOS settings that let the app send HTTP traffic that anyone on the network can read.  
  *Steps:*
  1. Android: Read AndroidManifest.xml and note android:usesCleartextTraffic and android:networkSecurityConfig.
  2. Android: Read the Network Security Configuration and flag cleartextTrafficPermitted="true" in base-config or domain-config.
  3. iOS: Read Info.plist and note the NSAppTransportSecurity dictionary.
  4. iOS: Flag NSAllowsArbitraryLoads, NSAllowsArbitraryLoadsInWebContent, NSAllowsArbitraryLoadsForMedia, NSAllowsLocalNetworking and NSExceptionAllowsInsecureHTTPLoads.
  5. Find out if each exception is needed for core app functions and has a justification.
  *Example:* `apktool d -s -f app.apk -o out; grep -E "usesCleartextTraffic|networkSecurityConfig" out/AndroidManifest.xml; grep -i cleartextTrafficPermitted out/res/xml/network_security_config.xml; unzip app.ipa; plutil -convert json -o Info.json Payload/App.app/Info.plist; jq .NSAppTransportSecurity Info.json`  
  *Expected:* The app permits no cleartext traffic. Exceptions exist only for needed domains with a documented reason.  
  *Refs:* mobile_top10: M5:2024, M8:2024; masvs: MASVS-NETWORK-1; mastg: MASTG-TEST-0235, MASTG-TEST-0322; maswe: MASWE-0026; cheatsheet: Mobile_Application_Security_Cheat_Sheet, Transport_Layer_Security_Cheat_Sheet; cwe: CWE-319  
  *See:* WEB-TLS-005

- [ ] **MOB-NETWORK-002** Check that the app sends no cleartext HTTP traffic  
  *Severity if fail:* Medium | *Type:* Manual, Automated | *Level:* MASVS L1  
  *Objective:* Finds hardcoded http:// URLs and real cleartext connections that carry app data.  
  *Steps:*
  1. Search the unpacked app and its libraries for http:// URLs.
  2. Follow each URL in the code and see if the app uses it to open a connection.
  3. Set up an interception proxy or a network capture for the device.
  4. Use every workflow of the app and look for cleartext HTTP or other cleartext protocols.
  5. Use a capture tool when the app does not work with a proxy.
  6. Keep only traffic that comes from the target app.
  *Example:* `apktool d app.apk; grep -rnoE "http://[^\" ]+" out/ src/; unzip app.ipa; strings -n 8 Payload/App.app/App | grep -E "^http://"; adb shell "tcpdump -i any -w /data/local/tmp/cap.pcap"; wireshark -r cap.pcap -Y "http || (tcp && !tls)"; rvictl -s <UDID> (iOS capture on macOS); mitmproxy --mode regular`  
  *Expected:* The capture shows no cleartext traffic from the app. All connections use TLS.  
  *Refs:* mobile_top10: M5:2024; masvs: MASVS-NETWORK-1; mastg: MASTG-TEST-0233, MASTG-TEST-0321, MASTG-TEST-0236; maswe: MASWE-0026; cheatsheet: Mobile_Application_Security_Cheat_Sheet, Transport_Layer_Security_Cheat_Sheet; cwe: CWE-319  
  *See:* WEB-TLS-005, WEB-TLS-006

- [ ] **MOB-NETWORK-003** Check that low-level iOS networking APIs use TLS  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds Network framework, CFNetwork and BSD socket connections that skip App Transport Security and send cleartext.  
  *Steps:*
  1. Extract the binaries and search for NWConnection, CFSocketStream, CFHTTPStream and the BSD socket functions.
  2. Look at each location and see if the connection uses TLS, for example .tls in NWParameters.
  3. Capture the traffic of the app and look for non-TLS connections.
  *Example:* `unzip app.ipa; r2 -qc "aaa; afl~NWConnection; afl~CFStream; afl~connect" Payload/App.app/App; strings Payload/App.app/App | grep -E "NWParameters|NWProtocolTLS"; frida-trace -U -f <bundle> -i connect -i send`  
  *Expected:* Every low-level connection uses TLS with a safe configuration. No connection sends sensitive data in cleartext.  
  *Refs:* mobile_top10: M5:2024; masvs: MASVS-NETWORK-1; mastg: MASTG-TEST-0323; maswe: MASWE-0026; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-319

- [ ] **MOB-NETWORK-004** Check that code sets no TLS version below 1.2  
  *Severity if fail:* Medium | *Type:* Code Review, Automated | *Level:* MASVS L1  
  *Objective:* Finds code that enables TLS 1.0 or TLS 1.1 on Android and iOS.  
  *Steps:*
  1. Android: Search for SSLContext.getInstance("TLSv1.1") and for SSLSocket.setEnabledProtocols.
  2. Android: Search for OkHttp ConnectionSpec.COMPATIBLE_TLS and ConnectionSpec.Builder.tlsVersions.
  3. iOS: Search for tlsMinimumSupportedProtocolVersion and tlsMinimumSupportedProtocol in URLSessionConfiguration.
  4. iOS: Search for sec_protocol_options_set_min_tls_protocol_version and the max version function in Network framework code.
  5. Flag the values TLSv1.0, TLSv1.1, kTLSProtocol1 and kTLSProtocol11.
  *Example:* `jadx -d src app.apk; grep -rnE "TLSv1(\.[01])?\"|setEnabledProtocols|COMPATIBLE_TLS|tlsVersions" src/; r2 -qc "aaa; afl~tls_protocol_version; afl~sec_protocol_options_set" Payload/App.app/App; frida-trace -U -f <bundle> -i sec_protocol_options_set_min_tls_protocol_version`  
  *Expected:* The app enables only TLS 1.2 and TLS 1.3. No code sets a lower minimum version or a lower maximum version.  
  *Refs:* mobile_top10: M5:2024; masvs: MASVS-NETWORK-1; mastg: MASTG-TEST-0217, MASTG-TEST-0343, MASTG-TEST-0344; maswe: MASWE-0026; cheatsheet: Transport_Layer_Security_Cheat_Sheet; cwe: CWE-319  
  *See:* WEB-TLS-001

- [ ] **MOB-NETWORK-005** Check that ATS exceptions do not weaken TLS policy  
  *Severity if fail:* Medium | *Type:* Config Review, Automated | *Level:* MASVS L1  
  *Objective:* Finds Info.plist exceptions that turn off ATS or allow TLS 1.0, TLS 1.1 or no forward secrecy.  
  *Steps:*
  1. Convert Info.plist to JSON and read NSAppTransportSecurity.
  2. Flag NSAllowsArbitraryLoads set to true.
  3. Flag any NSExceptionMinimumTLSVersion of TLSv1.0 or TLSv1.1.
  4. Flag any NSExceptionRequiresForwardSecrecy set to false.
  5. Look at the scope of each exception, especially with NSIncludesSubdomains.
  *Example:* `unzip app.ipa; plutil -convert json -o Info.json Payload/App.app/Info.plist; jq ".NSAppTransportSecurity.NSExceptionDomains" Info.json`  
  *Expected:* The app sets no weak TLS exceptions. Required exceptions are narrow, justified and apply only to named domains.  
  *Refs:* mobile_top10: M5:2024, M8:2024; masvs: MASVS-NETWORK-1; mastg: MASTG-TEST-0342; maswe: MASWE-0026; cheatsheet: Transport_Layer_Security_Cheat_Sheet; cwe: CWE-319

- [ ] **MOB-NETWORK-006** Check the TLS settings of embedded and third-party network stacks  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds bundled OpenSSL, BoringSSL, mbedTLS, curl or gRPC code that weakens TLS and ignores ATS.  
  *Steps:*
  1. List the bundled libraries and frameworks in the IPA.
  2. Search for TLS library symbols, such as SSL_CTX_set_min_proto_version and SSL_CTX_set_verify.
  3. Look at the code at each location and note the minimum TLS version and cipher list.
  4. Flag disabled certificate verification and custom trust stores with no validation.
  5. Compare the results with the settings of the platform stack.
  *Example:* `unzip -o app.ipa; find Payload -type d \( -name "*.framework" -o -name "*.appex" \); r2 -qc "aaa; afl~SSL_CTX" Payload/App.app/Frameworks/<lib>.framework/<lib>; frida-trace -U -f <bundle> -i SSL_CTX_set_min_proto_version -i SSL_CTX_set_verify; jadx -d src app.apk (Android native libraries: strings lib/*/*.so | grep -i ssl)`  
  *Expected:* Every embedded stack allows only TLS 1.2 and higher, uses strong cipher suites and checks certificates against a valid trust store.  
  *Refs:* mobile_top10: M5:2024; masvs: MASVS-NETWORK-1; mastg: MASTG-TEST-0345; maswe: MASWE-0026; cheatsheet: Transport_Layer_Security_Cheat_Sheet; cwe: CWE-319

- [ ] **MOB-NETWORK-007** Check the TLS version in live app traffic  
  *Severity if fail:* Medium | *Type:* Manual, Automated | *Level:* MASVS L1  
  *Objective:* Finds connections that negotiate TLS 1.0 or TLS 1.1 in practice.  
  *Steps:*
  1. Install the app and capture its network traffic.
  2. Use every workflow of the app with sensitive data.
  3. Open the capture and list the TLS version in each handshake.
  4. Flag any connection that uses a version below TLS 1.2.
  *Example:* `adb shell "tcpdump -i any -w /data/local/tmp/cap.pcap"; rvictl -s <UDID>; tshark -r cap.pcap -Y "tls.handshake.type==2" -T fields -e ip.src -e tls.handshake.version -e tls.handshake.extensions.supported_version; testssl.sh --protocols api.example.com`  
  *Expected:* All connections use TLS 1.2 or TLS 1.3.  
  *Refs:* mobile_top10: M5:2024; masvs: MASVS-NETWORK-1; mastg: MASTG-TEST-0218, MASTG-TEST-0348; maswe: MASWE-0026; cheatsheet: Transport_Layer_Security_Cheat_Sheet; cwe: CWE-319  
  *See:* WEB-TLS-001

- [ ] **MOB-NETWORK-008** Check that Android code checks server host names  
  *Severity if fail:* High | *Type:* Code Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds SSLSocket use without host name checks and HostnameVerifier code that accepts any host.  
  *Steps:*
  1. Search the code for SSLSocket and SSLSocketFactory.
  2. Check that the code calls a HostnameVerifier for each SSLSocket connection.
  3. Search for HostnameVerifier implementations and read their host check methods.
  4. Flag methods that return true for all hosts, use broad wildcard rules or skip some channels.
  5. Present a valid certificate of another host with a MITM proxy and see if the app connects.
  *Example:* `jadx -d src app.apk; grep -rnE "SSLSocket|HostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier" src/; mitmproxy --mode regular --certs *=wrong-host.pem; frida-trace -U -f <package> -j "javax.net.ssl.HostnameVerifier!*"`  
  *Expected:* The app checks the server host name against the certificate on every TLS channel, including SSLSocket. The MITM test fails to connect.  
  *Refs:* mobile_top10: M5:2024; masvs: MASVS-NETWORK-1; mastg: MASTG-TEST-0234, MASTG-TEST-0283; maswe: MASWE-0027; cheatsheet: Mobile_Application_Security_Cheat_Sheet, Transport_Layer_Security_Cheat_Sheet; cwe: CWE-295, CWE-297  
  *See:* WEB-TLS-010

- [ ] **MOB-NETWORK-009** Check that custom trust checks reject untrusted certificates  
  *Severity if fail:* High | *Type:* Code Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds custom TrustManager and URLSession delegate code that accepts every certificate.  
  *Steps:*
  1. Android: Search for X509TrustManager and checkServerTrusted implementations.
  2. Android: Flag empty methods, ignored exceptions, checkValidity-only checks and empty getAcceptedIssuers results.
  3. iOS: Search for urlSession(_:didReceive:completionHandler:) and cross-references to SecTrustEvaluateWithError.
  4. iOS: Flag code that calls completionHandler with useCredential and URLCredential(trust:) before it evaluates the trust.
  5. Send a self-signed certificate with a MITM proxy and see if the app accepts it.
  *Example:* `jadx -d src app.apk; grep -rn "checkServerTrusted\|X509TrustManager\|getAcceptedIssuers" src/; r2 -qc "aaa; axt sym.imp.SecTrustEvaluateWithError" Payload/App.app/App; strings Payload/App.app/App | grep -i "URLAuthenticationChallenge"; mitmproxy --mode regular`  
  *Expected:* The app uses the platform trust checks. Custom code rejects bad certificates and the self-signed MITM test fails.  
  *Refs:* mobile_top10: M5:2024; masvs: MASVS-NETWORK-1; mastg: MASTG-TEST-0282, MASTG-TEST-0396; maswe: MASWE-0027; cheatsheet: Mobile_Application_Security_Cheat_Sheet, Transport_Layer_Security_Cheat_Sheet; cwe: CWE-295, CWE-297  
  *See:* WEB-TLS-010

- [ ] **MOB-NETWORK-010** Check that WebViews do not ignore TLS certificate errors  
  *Severity if fail:* High | *Type:* Code Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds WebView code that proceeds after a certificate error and so allows MITM attacks.  
  *Steps:*
  1. Android: Search for onReceivedSslError overrides in WebViewClient classes.
  2. Android: Flag handler.proceed() calls that do not check the error, and catch blocks that do not call cancel().
  3. iOS: Search for WKNavigationDelegate webView(_:didReceive:completionHandler:) implementations.
  4. iOS: Flag code that accepts the server trust credential without a successful trust evaluation.
  5. Load a page with an invalid certificate in the WebView and see if it loads.
  *Example:* `jadx -d src app.apk; grep -rn "onReceivedSslError\|proceed()" src/; r2 -qc "aaa; axt sym.imp.SecTrustEvaluateWithError; axt sym.imp.SecTrustEvaluateAsyncWithError" Payload/App.app/App; mitmproxy --mode regular`  
  *Expected:* WebViews cancel loads after certificate errors. No code accepts an untrusted server trust.  
  *Refs:* mobile_top10: M5:2024; masvs: MASVS-NETWORK-1; mastg: MASTG-TEST-0284, MASTG-TEST-0397; maswe: MASWE-0027; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-295, CWE-297  
  *See:* WEB-TLS-010

- [ ] **MOB-NETWORK-011** Check that Android does not trust user-installed CAs  
  *Severity if fail:* Medium | *Type:* Config Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds apps that trust CA certificates that the user or an attacker adds to the device.  
  *Steps:*
  1. Read minSdkVersion in the manifest and flag values below 24.
  2. Read the Network Security Configuration and look for <certificates src="user" /> in trust-anchors.
  3. Install a proxy CA as a user certificate on a test device.
  4. Start the app and see if it connects through the proxy.
  *Example:* `apktool d -s -f app.apk -o out; grep minSdkVersion out/AndroidManifest.xml out/apktool.yml; grep -n "certificates src" out/res/xml/network_security_config.xml; adb push burp-ca.der /sdcard/Download/ (install as a user CA in Settings)`  
  *Expected:* The app uses a minSdkVersion of 24 or higher and trusts no user CAs. The proxy cannot read the traffic.  
  *Refs:* mobile_top10: M5:2024; masvs: MASVS-NETWORK-1; mastg: MASTG-TEST-0285, MASTG-TEST-0286; maswe: MASWE-0027; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-295, CWE-297

- [ ] **MOB-NETWORK-012** Check that the Android app updates the GMS security provider  
  *Severity if fail:* Low | *Type:* Code Review | *Level:* MASVS L1  
  *Objective:* Finds apps on Android that skip the security provider update and so keep known TLS flaws.  
  *Steps:*
  1. Search the code for ProviderInstaller.installIfNeeded and installIfNeededAsync.
  2. Check that the call runs before the first network connection.
  3. Check that the code handles errors and does not continue silently.
  *Example:* `jadx -d src app.apk; grep -rn "ProviderInstaller\|installIfNeeded" src/`  
  *Expected:* The app calls ProviderInstaller before any network connection and handles update errors.  
  *Refs:* mobile_top10: M5:2024; masvs: MASVS-NETWORK-1; mastg: MASTG-TEST-0295; maswe: MASWE-0027; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-295, CWE-297

- [ ] **MOB-NETWORK-013** Check that first-party domains use certificate pinning in app configuration  
  *Severity if fail:* Medium | *Type:* Config Review, Manual | *Level:* MASVS L2  
  *Objective:* Finds first-party endpoints that rely only on the default CA trust and so allow MITM by a rogue CA.  
  *Steps:*
  1. List the first-party domains that the app uses for core and security functions.
  2. Android: Read the Network Security Configuration and list domain-config entries with a pin-set.
  3. iOS: Read Info.plist and look for NSPinnedDomains in NSAppTransportSecurity.
  4. Compare the pinned domains with the first-party list.
  5. Check that the app connects to the unpinned domains, and look for other pinning code.
  *Example:* `apktool d -s -f app.apk -o out; xmlstarlet sel -t -c "//domain-config[pin-set]" out/res/xml/network_security_config.xml; unzip app.ipa; plutil -convert json -o Info.json Payload/App.app/Info.plist; jq ".NSAppTransportSecurity.NSPinnedDomains" Info.json; strings -n 8 Payload/App.app/App | grep -E "^https://"`  
  *Expected:* Every relevant first-party domain has a pin in the NSC or in ATS, or another documented pinning method covers it.  
  *Refs:* mobile_top10: M5:2024; masvs: MASVS-NETWORK-2; mastg: MASTG-TEST-0242, MASTG-TEST-0385; maswe: MASWE-0028; cheatsheet: Pinning_Cheat_Sheet, Mobile_Application_Security_Cheat_Sheet; cwe: CWE-295

- [ ] **MOB-NETWORK-014** Check that Android certificate pins have not expired  
  *Severity if fail:* Medium | *Type:* Config Review | *Level:* MASVS L2  
  *Objective:* Finds NSC pins with a past expiration date that Android no longer enforces.  
  *Steps:*
  1. Read the Network Security Configuration and list each pin-set with its expiration attribute.
  2. Compare each date with the current date.
  3. Compare the domains with the list of first-party domains that the app uses.
  4. Check that the app still connects to those domains.
  *Example:* `apktool d -s -f app.apk -o out; grep -n "pin-set\|expiration" out/res/xml/network_security_config.xml; date +%F`  
  *Expected:* No pin-set for a first-party domain has an expiration date in the past.  
  *Refs:* mobile_top10: M5:2024; masvs: MASVS-NETWORK-2; mastg: MASTG-TEST-0243; maswe: MASWE-0028; cheatsheet: Pinning_Cheat_Sheet; cwe: CWE-295

- [ ] **MOB-NETWORK-015** Check that a MITM proxy cannot read first-party HTTPS traffic  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* MASVS L2  
  *Objective:* Finds first-party endpoints with no effective pinning, whatever the implementation is.  
  *Steps:*
  1. Install the app on a test device and set up an interception proxy with its CA trusted by the system.
  2. Use every workflow of the app.
  3. Look at the proxy log for first-party domains whose HTTPS traffic it decrypted.
  4. Watch the device log for pin check failures when pinning is active.
  5. Ignore unrelated third-party domains.
  *Example:* `burp / mitmproxy --mode regular; adb shell settings put global http_proxy <host>:8080; adb logcat | grep -i "Pin verification failed"; iOS: iproxy 2222 22; ssh -R 8080:localhost:8080 mobile@localhost -p 2222; do not disable pinning in this test`  
  *Expected:* The proxy cannot decrypt traffic to first-party domains. The app refuses the connection with an untrusted CA.  
  *Refs:* mobile_top10: M5:2024; masvs: MASVS-NETWORK-2; mastg: MASTG-TEST-0244; maswe: MASWE-0028; cheatsheet: Pinning_Cheat_Sheet; cwe: CWE-295


## PRIV

- [ ] **MOB-PRIV-001** Check Android permissions for minimal, justified and revocable access  
  *Severity if fail:* Medium | *Type:* Config Review, Manual | *Level:* MASVS P  
  *Objective:* Finds permissions that the app does not need or does not explain to the user.  
  *Steps:*
  1. Android: Read the AndroidManifest.xml and list all declared permissions.
  2. Android: Compare the list with the Android list of dangerous permissions.
  3. Android: Match each dangerous permission to a visible app feature.
  4. Android: Look for permissions that have a less intrusive option, such as coarse location or a picker.
  5. Android: Start the app. Check that it asks for each permission at the time of use and shows a rationale.
  6. Android: Check that the app drops permissions it no longer needs.
  *Example:* `aapt2 d permissions app.apk ; aapt d permissions app.apk ; adb shell dumpsys package <pkg> | grep -A30 "requested permissions" ; adb shell pm revoke <pkg> <permission>`  
  *Expected:* The app declares only permissions that its features need. It asks for each one when needed, explains why, and lets the user revoke it.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PRIVACY-1; mastg: MASTG-TEST-0254, MASTG-TEST-0255, MASTG-TEST-0256, MASTG-TEST-0257; maswe: MASWE-0066; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-250

- [ ] **MOB-PRIV-002** Check iOS purpose strings against the protected resources that the app uses  
  *Severity if fail:* Low | *Type:* Config Review, Manual | *Level:* MASVS P  
  *Objective:* Finds access to protected resources without a clear and accurate purpose string.  
  *Steps:*
  1. iOS: Read the Info.plist and list all UsageDescription keys with their strings.
  2. iOS: Search the binary for the APIs that request or use each protected resource.
  3. iOS: Flag an API with no matching key, and a string that is vague or wrong.
  4. iOS: Hook the protected resource APIs at runtime. Use all app flows.
  5. iOS: Check that each system prompt shows a purpose string that matches the visible feature.
  *Example:* `plutil -p Payload/App.app/Info.plist | grep UsageDescription ; r2 -A <app_binary> ; afl~requestAuthorization ; frida -U -f <bundle_id> -l hook_protected_apis.js`  
  *Expected:* Each protected resource has a specific and true purpose string. The app asks only when a visible feature needs the resource.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PRIVACY-1; mastg: MASTG-TEST-0360, MASTG-TEST-0361; maswe: MASWE-0066; cwe: CWE-250

- [ ] **MOB-PRIV-003** Check iOS entitlements for capabilities that the app does not need  
  *Severity if fail:* Low | *Type:* Config Review, Manual | *Level:* MASVS P  
  *Objective:* Finds signed capabilities that widen data access without a user-visible reason.  
  *Steps:*
  1. iOS: Extract the entitlements of the main binary and of each app extension.
  2. iOS: Search the binary for APIs, shared containers and identifiers that relate to each entitlement.
  3. iOS: Hook entitlement-backed APIs at runtime. Use all app flows.
  4. iOS: Match each entitlement to a visible app feature.
  5. iOS: Flag entitlements for health, shared storage, iCloud or associated domains with no use.
  *Example:* `rabin2 -OC App ; codesign -d --entitlements :- App.app ; frida -U -f <bundle_id> -l hook_entitlement_apis.js`  
  *Expected:* Each signed entitlement links to a visible feature. The app signs no entitlement that widens data access without need.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PRIVACY-1; mastg: MASTG-TEST-0362, MASTG-TEST-0363; maswe: MASWE-0066; cwe: CWE-250

- [ ] **MOB-PRIV-004** Check network traffic for personal data that the app does not declare  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* MASVS P  
  *Objective:* Finds personal data that leaves the device but is missing from the privacy declarations.  
  *Steps:*
  1. Write down the sensitive and personal test data that you enter into the app.
  2. Capture and decrypt the HTTPS traffic of the app while you use all workflows.
  3. Search the traffic for the test data, also in background requests.
  4. Compare the found data with the Data Safety section, the Privacy Nutrition Label and the privacy policy.
  5. Find the code that sends each undeclared item.
  *Example:* `mitmproxy -s mitm_sensitive_logger.py ; Burp Suite: filter on the test data ; adb shell settings put global http_proxy <host>:8080`  
  *Expected:* All personal data in the traffic matches the store declarations and the privacy policy. The app sends nothing undeclared, also in the background.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PRIVACY-3, MASVS-PRIVACY-1; mastg: MASTG-TEST-0206; maswe: MASWE-0073; cwe: CWE-359

- [ ] **MOB-PRIV-005** Check third-party SDKs for sensitive data sharing and consent  
  *Severity if fail:* Medium | *Type:* Manual, Code Review | *Level:* MASVS P  
  *Objective:* Finds SDKs that receive personal data, or start to collect before the user consents.  
  *Steps:*
  1. Android: List the SDKs in the app. Find the APIs that send user data, such as analytics events and user properties.
  2. Android: Hook these API calls at runtime. Record the arguments and backtraces.
  3. Start the app for the first time. Capture the traffic before you answer any consent prompt.
  4. Look for SDK requests that carry identifiers or personal data before consent.
  5. Check that each SDK follows the consent signal and the data that the app declares.
  *Example:* `jadx -d out app.apk ; grep -rn "logEvent\|setUserProperty\|setUserId" out/ ; frida -U -f <pkg> -l hook_sdk_calls.js ; Burp Suite: capture first-start traffic`  
  *Expected:* SDKs receive only declared data, and only after consent. No SDK collects data before the user decides.  
  *Refs:* mobile_top10: M6:2024, M2:2024; masvs: MASVS-PRIVACY-1, MASVS-PRIVACY-3; mastg: MASTG-TEST-0318, MASTG-TEST-0319; maswe: MASWE-0073; cwe: CWE-359

- [ ] **MOB-PRIV-006** Check that iOS tracking domains appear in the privacy manifests  
  *Severity if fail:* Low | *Type:* Config Review, Manual | *Level:* MASVS P  
  *Objective:* Finds tracking domains that the app contacts but does not declare.  
  *Steps:*
  1. iOS: Extract every PrivacyInfo.xcprivacy file of the app, also those from SDKs and frameworks.
  2. iOS: Read NSPrivacyTrackingDomains in each file.
  3. iOS: Search the binary for strings of known tracking domains.
  4. iOS: Capture the traffic during use. List all contacted domains.
  5. iOS: Compare the domains found with a list of known trackers and with the declared domains.
  *Example:* `find . -name PrivacyInfo.xcprivacy ; plutil -convert json -o PrivacyInfo.json PrivacyInfo.xcprivacy ; jq .NSPrivacyTrackingDomains PrivacyInfo.json ; strings -a App | grep -i -E "doubleclick|facebook|adjust"`  
  *Expected:* The privacy manifests declare every tracking domain that the code contains or that the app contacts at runtime.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PRIVACY-3; mastg: MASTG-TEST-0281; maswe: MASWE-0074; cwe: CWE-359

- [ ] **MOB-PRIV-007** Check use of identifiers for user tracking  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS P  
  *Objective:* Finds persistent identifiers that let parties follow users across apps and services.  
  *Steps:*
  1. Search the code and SDKs for the Advertising ID, ANDROID_ID, serial numbers, MAC addresses and identifierForVendor.
  2. Look for non-resettable identifiers and for identifiers that join data from different services.
  3. Check that the app asks for tracking consent where the platform needs it, and respects an opt-out.
  4. Reset the identifier in the device settings. Check that the app does not link the new value to the old one.
  5. Check if privacy-preserving APIs, such as Play Integrity or DeviceCheck, can replace an identifier.
  *Example:* `grep -rn "AdvertisingIdClient\|ANDROID_ID\|getSerial\|identifierForVendor\|ASIdentifierManager" out/ ; Burp Suite: look for identifiers in the requests`  
  *Expected:* The app uses resettable or app-scoped identifiers only with consent. It does not link identifiers across services.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PRIVACY-2; maswe: MASWE-0068; cwe: CWE-359

- [ ] **MOB-PRIV-008** Check that the app anonymizes personal data before sharing it  
  *Severity if fail:* Medium | *Type:* Manual, Code Review | *Level:* MASVS P  
  *Objective:* Finds personal data that the app sends in a form that identifies the user.  
  *Steps:*
  1. Capture the data that the app sends to its server, to SDKs and to AI services.
  2. Look for user IDs, names, e-mail addresses, precise location and metadata such as Exif.
  3. Check that hashes of identifiers use a secret key and are not plain stable hashes.
  4. Check that the app does not store the key with the pseudonymized data.
  5. Check that the app redacts sensitive fields before it sends data to AI services.
  *Example:* `Burp Suite: inspect request bodies ; exiftool uploaded_image.jpg ; sha256sum <identifier> and compare with the sent value`  
  *Expected:* The app removes or transforms identifiers before it collects or shares data. Pseudonyms are keyed, and AI services get redacted data.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PRIVACY-2; maswe: MASWE-0067; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-359

- [ ] **MOB-PRIV-009** Check for privacy-preserving platform alternatives  
  *Severity if fail:* Low | *Type:* Code Review, Manual | *Level:* MASVS P  
  *Objective:* Finds features that expose more user data than a platform alternative would.  
  *Steps:*
  1. Look for login flows in embedded WebViews. Check if the app uses ASWebAuthenticationSession or Custom Tabs.
  2. Look for broad photo, camera or file permissions where a system picker would work.
  3. Look for user data that goes to a remote AI service when on-device processing is possible.
  4. Check that the app asks for broad access only when the feature needs it.
  *Example:* `grep -rn "ACTION_OPEN_DOCUMENT\|PickVisualMedia\|PHPickerViewController\|ASWebAuthenticationSession\|CustomTabsIntent" out/`  
  *Expected:* The app uses system pickers, system authentication sessions and on-device processing where they can support the feature.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PRIVACY-2; maswe: MASWE-0069, MASWE-0066; cwe: CWE-359, CWE-250

- [ ] **MOB-PRIV-010** Check that privacy-relevant actions show scope and consequences  
  *Severity if fail:* Low | *Type:* Manual | *Level:* MASVS P  
  *Objective:* Finds actions that share data without a clear view of what, with whom and for how long.  
  *Steps:*
  1. List actions that share or publish user data, such as share, export, post and invite.
  2. Open each action. Look for the affected data, metadata, destination and audience.
  3. Check that the user can review and confirm the action before it completes.
  4. Check that the app shows the resulting privacy state afterward and allows reversal.
  *Example:* `Manual review with screenshots of each sharing flow`  
  *Expected:* Each privacy-relevant action shows the data, the audience and the effect before it completes, and the user can review and undo it.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PRIVACY-2; maswe: MASWE-0070; cwe: CWE-359

- [ ] **MOB-PRIV-011** Check that default settings expose the least data  
  *Severity if fail:* Low | *Type:* Manual | *Level:* MASVS P  
  *Objective:* Finds defaults that share more data or reach a wider audience than needed.  
  *Steps:*
  1. Install the app fresh. Complete the first run without a change to any setting.
  2. List the defaults for audience, visibility, retention, analytics and recipients.
  3. Compare each default with the narrowest option that still gives the feature.
  4. Check that the app asks the user before it widens an audience or shares more data.
  *Example:* `Manual review of the first-run flow and the privacy settings screen`  
  *Expected:* Defaults use the narrowest audience, the least data and the shortest retention that the feature allows.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PRIVACY-2; maswe: MASWE-0071; cheatsheet: Mobile_Application_Security_Cheat_Sheet

- [ ] **MOB-PRIV-012** Check the privacy policy and the privacy labels against app behavior  
  *Severity if fail:* Low | *Type:* Manual | *Level:* MASVS P  
  *Objective:* Finds apps with a missing, unclear or wrong privacy policy.  
  *Steps:*
  1. Find the privacy policy in the app and in the store listing. Check that it is easy to reach.
  2. Check that it covers the data practices of this app and not only the company in general.
  3. Compare it with the Data Safety section and the Privacy Nutrition Label.
  4. Compare all three with the traffic and permissions that you saw in other tests.
  *Example:* `Manual review ; compare the store listing with Burp Suite traffic logs`  
  *Expected:* The privacy policy is easy to reach and clear. It matches the store declarations and the real behavior of the app.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PRIVACY-3; maswe: MASWE-0072, MASWE-0073; cwe: CWE-359

- [ ] **MOB-PRIV-013** Check that the build is reproducible  
  *Severity if fail:* Info | *Type:* Manual, Config Review | *Level:* MASVS P  
  *Objective:* Finds apps whose published binary cannot be matched to the claimed source code.  
  *Steps:*
  1. Find the source, the build scripts and the pinned toolchain versions for the release.
  2. Build the app twice in the same environment. Compare the two outputs.
  3. Look for timestamps, absolute paths and unstable ordering in the artifacts.
  4. Look for published provenance for the release, such as a SLSA statement.
  5. Check if the obfuscation settings give the same result on each build.
  *Example:* `sha256sum build1.apk build2.apk ; diffoscope build1.apk build2.apk`  
  *Expected:* Builds of the same source in the same environment give identical binaries. The release has provenance that others can check.  
  *Refs:* mobile_top10: M2:2024; masvs: MASVS-PRIVACY-3; maswe: MASWE-0075; cheatsheet: Software_Supply_Chain_Security_Cheat_Sheet; cwe: CWE-1357, CWE-494

- [ ] **MOB-PRIV-014** Check that users can delete, export and change their data  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* MASVS P  
  *Objective:* Finds apps that give users no way to manage their personal data.  
  *Steps:*
  1. Open the account and privacy settings. Look for delete, export, change and opt-out options.
  2. Delete the account and the data of a test user. Check the backend for remaining data.
  3. Export the data of the test user. Check that the export is complete.
  4. Check that granular opt-outs for data collection and sharing exist.
  5. Check that the app removes data automatically when the retention period ends.
  *Example:* `Manual test with a test account ; compare backend records before and after the deletion`  
  *Expected:* Users can delete, export and change their data and opt out of collection from inside the app. The deletion reaches the backend.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PRIVACY-4; maswe: MASWE-0076; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-359

- [ ] **MOB-PRIV-015** Check privacy settings for control over data visibility  
  *Severity if fail:* Low | *Type:* Manual | *Level:* MASVS P  
  *Objective:* Finds apps that offer no fine control over who sees user data.  
  *Steps:*
  1. Open the privacy settings. List the controls for location, contacts and profile data.
  2. Check that each data category has its own control.
  3. Change each control. Check with a second test account that the change takes effect.
  4. Check that help text explains each option.
  *Example:* `Manual test with two test accounts`  
  *Expected:* Users control each data category on its own, and a change takes effect for other users and for sharing partners.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PRIVACY-4; maswe: MASWE-0077; cwe: CWE-359

- [ ] **MOB-PRIV-016** Check that consent is explicit, informed and renewed on change  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* MASVS P  
  *Objective:* Finds apps that process personal data without clear prior consent.  
  *Steps:*
  1. Start a fresh install. Look at each consent prompt before any data collection.
  2. Check that consent is not bundled into the terms of service and is not implied.
  3. Check that the text names the data, the purpose and the effect.
  4. Withdraw consent in the settings. Check that collection stops in the traffic.
  5. Install an update that collects more data. Check that the app asks for consent again.
  *Example:* `Burp Suite: capture traffic before and after consent and after withdrawal ; compare two app versions`  
  *Expected:* The app asks for explicit, specific consent before it collects data. Withdrawal stops collection, and new data collection needs new consent.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PRIVACY-4, MASVS-PRIVACY-1; maswe: MASWE-0078; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-200, CWE-285, CWE-358, CWE-359


## RESIL

- [ ] **MOB-RESIL-001** Check root and jailbreak detection  
  *Severity if fail:* Low | *Type:* Code Review, Manual | *Level:* MASVS R  
  *Objective:* Finds apps that run with sensitive functions on a rooted or jailbroken device.  
  *Steps:*
  1. Android: Search the code for root checks, such as su paths, test-keys, root packages and system property reads.
  2. iOS: Search the binary for jailbreak checks, such as Cydia paths, writable system folders and URL scheme tests.
  3. Hook the file, property and system calls at runtime and record the checks that run.
  4. Run the app on a rooted or jailbroken test device. Check how the app reacts.
  5. Try an automated bypass tool. Note which checks it must bypass.
  6. Make sure the app restricts sensitive functions or warns the backend when it detects the change.
  *Example:* `frida -U -f <pkg> -l hook_root_checks.js ; objection -g <pkg> explore, then android root disable ; objection -g <bundle_id> explore, then ios jailbreak disable ; frida-trace -U -f <pkg> -i "access" -i "fopen"`  
  *Expected:* The app detects a rooted or jailbroken device with several checks. It limits sensitive functions or informs the backend when it finds one.  
  *Refs:* mobile_top10: M7:2024; masvs: MASVS-RESILIENCE-1, MASVS-RESILIENCE-4; mastg: MASTG-TEST-0324, MASTG-TEST-0325, MASTG-TEST-0240, MASTG-TEST-0241; maswe: MASWE-0051; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-1326

- [ ] **MOB-RESIL-002** Check emulator and virtual device detection  
  *Severity if fail:* Low | *Type:* Manual | *Level:* MASVS R  
  *Objective:* Finds apps that run sensitive functions in an emulator where attackers have full control.  
  *Steps:*
  1. Android: Search the code for checks of Build properties, QEMU files and emulator sensors.
  2. iOS: Look for hooks on the checks that find a simulator or virtual device.
  3. Run the app in an emulator or virtual device. Hook the checks and trace the system calls.
  4. Record which checks run and how the app reacts.
  5. Make sure the app limits sensitive functions when it detects the virtual device.
  *Example:* `frida -U -f <pkg> -l hook_build_props.js ; frida-trace -U -f <pkg> -i "__system_property_get" ; run the app in an Android Virtual Device or an iOS simulator`  
  *Expected:* The app detects emulators and virtual devices with several checks. It limits sensitive functions when it detects one.  
  *Refs:* mobile_top10: M7:2024; masvs: MASVS-RESILIENCE-1, MASVS-RESILIENCE-4; mastg: MASTG-TEST-0351, MASTG-TEST-0367; maswe: MASWE-0053; cheatsheet: Mobile_Application_Security_Cheat_Sheet

- [ ] **MOB-RESIL-003** Check detection of app cloning and virtual app environments  
  *Severity if fail:* Info | *Type:* Manual | *Level:* MASVS R  
  *Objective:* Finds apps that run inside a virtual container where another app can read and change them.  
  *Steps:*
  1. Android: Run the app inside a known app-virtualization or dual-app tool.
  2. Android: Look at the process path, data folder and package structure that the app reads at runtime.
  3. Check if the app compares these values with the expected ones.
  4. Check if the app restricts sensitive functions, informs the backend or ends when it finds a container.
  *Example:* `adb shell pm list packages | grep <container> ; adb shell ps -A | grep <pkg> ; frida -U -f <pkg> -l hook_process_path.js`  
  *Expected:* The app finds that it runs in a virtual container, and it limits sensitive functions or informs the backend.  
  *Refs:* mobile_top10: M7:2024; masvs: MASVS-RESILIENCE-1; maswe: MASWE-0052; cwe: CWE-693

- [ ] **MOB-RESIL-004** Check device attestation in the backend  
  *Severity if fail:* Medium | *Type:* Manual, Code Review | *Level:* MASVS R  
  *Objective:* Finds backends that cannot tell real devices from rooted, emulated or automated ones.  
  *Steps:*
  1. Find the code that asks the platform for a device attestation, such as Play Integrity or hardware key attestation.
  2. iOS: Find the use of DeviceCheck and App Attest.
  3. Capture the request that carries the attestation. Look for a server-issued nonce.
  4. Replay an old attestation and send a changed one. Check that the backend rejects both.
  5. Check that the backend checks the verdict itself and gates sensitive operations on it.
  *Example:* `Burp Suite: capture and replay the attestation request ; grep -rn "IntegrityManager\|requestIntegrityToken\|DCAppAttestService" out/`  
  *Expected:* The backend checks device attestation evidence with a fresh nonce. It blocks sensitive operations when the evidence is missing or bad.  
  *Refs:* mobile_top10: M7:2024; masvs: MASVS-RESILIENCE-1; maswe: MASWE-0054; cheatsheet: Mobile_Application_Security_Cheat_Sheet

- [ ] **MOB-RESIL-005** Check that the app detects a device without a secure screen lock  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS L2  
  *Objective:* Finds apps that keep sensitive data and keys on devices that have no passcode.  
  *Steps:*
  1. Android: Search the code for KeyguardManager.isDeviceSecure and BiometricManager.canAuthenticate.
  2. iOS: Search the binary for LAContext canEvaluatePolicy with deviceOwnerAuthentication.
  3. iOS: Check the Keychain items for kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly.
  4. Hook these calls at runtime. Remove the device lock and use the app.
  5. Check that the app checks the lock again before it enables sensitive functions.
  *Example:* `frida -U -f <pkg> -l hook_keyguard.js ; objection -g <pkg> explore, then android hooking watch class_method android.app.KeyguardManager.isDeviceSecure --dump-return`  
  *Expected:* The app checks that a secure screen lock exists before it enables sensitive functions. Keys bind to the device lock.  
  *Refs:* masvs: MASVS-CRYPTO-2, MASVS-RESILIENCE-1; mastg: MASTG-TEST-0247, MASTG-TEST-0249, MASTG-TEST-0246, MASTG-TEST-0248; maswe: MASWE-0017  
  *See:* MOB-CRYPTO-016

- [ ] **MOB-RESIL-006** Check the app signature scheme, key size and code signature format  
  *Severity if fail:* Low | *Type:* Config Review, Automated | *Level:* MASVS R  
  *Objective:* Finds weak or old signatures that attackers can abuse to repackage the app.  
  *Steps:*
  1. Android: Read minSdkVersion in the AndroidManifest.xml.
  2. Android: List the signature schemes of the APK. Flag a v1-only signature when minSdkVersion is 24 or higher.
  3. Android: Read the key size of each signer. Flag RSA keys below 2048 bits.
  4. iOS: Extract the binary and read the CodeDirectory version of the code signature.
  5. iOS: Compare it with the latest code signature format that Apple recommends.
  *Example:* `apksigner verify --verbose --print-certs app.apk ; apksigner verify -v app.apk | grep -i "scheme" ; codesign -dv --verbose=4 App.app | grep -E "CodeDirectory|Format"`  
  *Expected:* The APK uses v2 or newer signatures with strong keys. The iOS app uses the current code signature format.  
  *Refs:* mobile_top10: M7:2024; masvs: MASVS-RESILIENCE-2; mastg: MASTG-TEST-0224, MASTG-TEST-0225, MASTG-TEST-0220; maswe: MASWE-0056; cwe: CWE-347

- [ ] **MOB-RESIL-007** Check app attestation in the backend  
  *Severity if fail:* Medium | *Type:* Manual, Code Review | *Level:* MASVS R  
  *Objective:* Finds backends that accept requests from modified or repackaged copies of the app.  
  *Steps:*
  1. Find the code that checks the signing identity, the package identity and the packaged files at runtime.
  2. Find the use of App Attest or the Play Integrity app verdict.
  3. Repackage the app with a test change. Send its requests to a test backend.
  4. Check that the backend rejects requests from the changed app.
  5. Check how the app reacts when its own checks fail.
  *Example:* `apktool d app.apk ; apktool b -o repack.apk ; apksigner sign --ks test.jks repack.apk ; adb install repack.apk`  
  *Expected:* The backend checks an app integrity signal and rejects modified or repackaged clients. The app reacts to failed checks.  
  *Refs:* mobile_top10: M7:2024; masvs: MASVS-RESILIENCE-2; maswe: MASWE-0056; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-347

- [ ] **MOB-RESIL-008** Check integrity checks on data that the app stores locally  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS R  
  *Objective:* Finds apps that trust local data for security decisions without an integrity check.  
  *Steps:*
  1. Find data in SharedPreferences, UserDefaults, files and databases that drives a security decision.
  2. Examples are login state, feature access, limits and server settings.
  3. Search the code for HMAC, Signature and digest APIs around the reads of that data.
  4. Change the stored value on a rooted or jailbroken device. Start the app.
  5. Check that the app finds the change and reacts.
  *Example:* `grep -rn "javax.crypto.Mac\|SharedPreferences" out/ ; r2 -A <app_binary> ; afl~CCHmac ; adb shell run-as <pkg> cat shared_prefs/<file>.xml`  
  *Expected:* The app signs or authenticates data that drives a security decision, checks it on each read and reacts to a change.  
  *Refs:* mobile_top10: M7:2024; masvs: MASVS-RESILIENCE-2, MASVS-CODE-4; mastg: MASTG-TEST-0338, MASTG-TEST-0387; maswe: MASWE-0057; cwe: CWE-471

- [ ] **MOB-RESIL-009** Check detection of hooking tools and code changes at runtime  
  *Severity if fail:* Low | *Type:* Manual | *Level:* MASVS R  
  *Objective:* Finds apps that let attackers hook sensitive APIs and read secrets without any reaction.  
  *Steps:*
  1. Install the app and attach Frida to it.
  2. Hook sensitive APIs, such as AccountManager, KeyStore, SecItemCopyMatching and SecKey functions.
  3. Record whether the hook runs and returns data, or whether the app ends or blocks it.
  4. Look in the code for checks of loaded libraries, named pipes, ports and function prologues.
  5. Check that the app reacts, for example by ending the session or warning the backend.
  *Example:* `frida -U -f <pkg> -l hook_keystore_getkey.js ; frida -U -f <bundle_id> -l hook_secitemcopymatching.js ; objection -g <pkg> explore`  
  *Expected:* The hook fails or the app reacts. The app detects hooking tools and changed code with several checks.  
  *Refs:* mobile_top10: M7:2024; masvs: MASVS-RESILIENCE-2, MASVS-RESILIENCE-4; mastg: MASTG-TEST-0341, MASTG-TEST-0354; maswe: MASWE-0058, MASWE-0065

- [ ] **MOB-RESIL-010** Check detection of malware and risky apps on the device  
  *Severity if fail:* Info | *Type:* Manual | *Level:* MASVS R  
  *Objective:* Finds apps that handle high-risk flows without any check for a hostile environment.  
  *Steps:*
  1. Find uses of platform threat signals, such as Play Protect status or Play Integrity verdicts.
  2. Check if the app considers apps with accessibility or overlay rights in risk decisions.
  3. Install a test app with accessibility rights. Start a sensitive flow.
  4. Check if the app warns the user, asks for more checks or restricts the flow.
  5. Check if the backend restricts the account and not only the local client.
  *Example:* `adb shell settings get secure enabled_accessibility_services ; adb shell dumpsys window | grep -i overlay`  
  *Expected:* For high-risk flows, the app uses threat signals and reacts in proportion. Restrictions apply to the account and not only to the device.  
  *Refs:* mobile_top10: M7:2024; masvs: MASVS-RESILIENCE-2; maswe: MASWE-0055; cwe: CWE-693

- [ ] **MOB-RESIL-011** Check code obfuscation of security-relevant logic  
  *Severity if fail:* Low | *Type:* Code Review, Manual | *Level:* MASVS R  
  *Objective:* Finds readable security logic that helps attackers to find and remove checks.  
  *Steps:*
  1. Android: Decompile the DEX code. Look for readable class and method names in security logic.
  2. Android: Extract the native libraries. Look for readable strings, symbols and constants.
  3. iOS: Extract the main binary and bundled Mach-O files. Read the symbols and strings, and demangle Swift names.
  4. Find root checks, attestation, integrity checks and key handling.
  5. Check that an attacker cannot find and understand these parts with reasonable effort.
  *Example:* `jadx-gui app.apk ; strings -a lib/arm64-v8a/lib.so | head -100 ; r2 -A <app_binary> ; izz ; xcrun swift-demangle <symbol>`  
  *Expected:* Security-relevant code is obfuscated in the Java, Kotlin and native layers. An attacker needs much effort to find and understand it.  
  *Refs:* mobile_top10: M7:2024; masvs: MASVS-RESILIENCE-3; mastg: MASTG-TEST-0368, MASTG-TEST-0369, MASTG-TEST-0391; maswe: MASWE-0059; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-693

- [ ] **MOB-RESIL-012** Check obfuscation of resources and identifiers  
  *Severity if fail:* Info | *Type:* Manual | *Level:* MASVS R  
  *Objective:* Finds readable resources and strings that show how the app works.  
  *Steps:*
  1. Unpack the APK or IPA. List strings, layouts, configuration files and bundled data.
  2. Look for descriptive resource and string names that map to security features.
  3. Look for sensitive strings and settings in clear form.
  4. Check if integrity checks protect the obfuscated resources from replacement.
  *Example:* `apktool d app.apk -o out ; cat out/res/values/strings.xml ; unzip app.ipa ; plutil -p Payload/App.app/Info.plist`  
  *Expected:* Resources that reveal security behavior are obfuscated or encrypted. Their identifiers carry no meaning in release builds.  
  *Refs:* mobile_top10: M7:2024; masvs: MASVS-RESILIENCE-3; maswe: MASWE-0060; cwe: CWE-693

- [ ] **MOB-RESIL-013** Check native binaries for debug symbols  
  *Severity if fail:* Low | *Type:* Automated, Config Review | *Level:* MASVS R  
  *Objective:* Finds binaries with symbols that show names and structure of the code.  
  *Steps:*
  1. Android: Extract the native libraries and read their symbol and line number information.
  2. Android: Flag libraries that are not stripped or that have line numbers.
  3. iOS: Extract the binaries. List the symbols of each executable and library.
  4. iOS: Flag symbols that are marked as debug symbols.
  5. Check that release builds keep dSYM files out of the app package.
  *Example:* `r2 -A lib.so ; i~stripped,linenum,lsyms ; r2 -A <app_binary> ; is~debug ; nm -a lib.so | head`  
  *Expected:* Release binaries are stripped. They hold no debug symbols or line numbers.  
  *Refs:* mobile_top10: M7:2024; masvs: MASVS-RESILIENCE-3; mastg: MASTG-TEST-0288, MASTG-TEST-0219; maswe: MASWE-0061; cwe: CWE-489, CWE-497, CWE-540, CWE-912, CWE-1295

- [ ] **MOB-RESIL-014** Check release builds for debug logging and StrictMode  
  *Severity if fail:* Low | *Type:* Code Review, Manual | *Level:* MASVS R  
  *Objective:* Finds logs that show implementation details to attackers.  
  *Steps:*
  1. Android: Search the code for StrictMode setVmPolicy and setThreadPolicy.
  2. Android: Run the release build and read the logcat output for StrictMode messages.
  3. iOS: Search the binary for NSLog, print, dump, debugPrint and os_log calls and their strings.
  4. Run the release build and trigger errors, such as network failures and invalid input.
  5. Read the device logs for stack traces, endpoints, internal paths and verbose messages.
  *Example:* `adb logcat | grep -i StrictMode ; adb logcat --pid=$(adb shell pidof <pkg>) ; xcrun simctl spawn booted log stream --style compact --level debug --predicate 'process CONTAINS[c] "App"'`  
  *Expected:* Release builds do not use StrictMode. Logs show no implementation details, debug messages or detailed errors.  
  *Refs:* mobile_top10: M8:2024; masvs: MASVS-RESILIENCE-3; mastg: MASTG-TEST-0263, MASTG-TEST-0264, MASTG-TEST-0265, MASTG-TEST-0358, MASTG-TEST-0359; maswe: MASWE-0061; cwe: CWE-489, CWE-497, CWE-540, CWE-912, CWE-1295

- [ ] **MOB-RESIL-015** Check that release builds are not debuggable  
  *Severity if fail:* Medium | *Type:* Config Review, Automated | *Level:* MASVS R  
  *Objective:* Finds builds that let an attacker attach a debugger and read app memory and data.  
  *Steps:*
  1. Android: Read the android:debuggable attribute in the AndroidManifest.xml.
  2. Android: Flag the value true.
  3. iOS: Extract the entitlements of the main binary and look for get-task-allow.
  4. iOS: Flag the value true.
  5. Try to attach a debugger to the release build.
  *Example:* `aapt2 d badging app.apk | grep -i debuggable ; apktool d app.apk ; grep debuggable out/AndroidManifest.xml ; rabin2 -OC App | grep -A1 get-task-allow ; adb jdwp`  
  *Expected:* The release build is not debuggable. The debuggable flag and the get-task-allow entitlement are false or missing.  
  *Refs:* mobile_top10: M8:2024; masvs: MASVS-RESILIENCE-4; mastg: MASTG-TEST-0226, MASTG-TEST-0261; maswe: MASWE-0063; cwe: CWE-489

- [ ] **MOB-RESIL-016** Check that WebView debugging is off in release builds  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS R  
  *Objective:* Finds WebViews that let attackers inspect and change web content with remote tools.  
  *Steps:*
  1. Android: Search the code for WebView.setWebContentsDebuggingEnabled.
  2. Android: Flag calls with true that do not check ApplicationInfo.FLAG_DEBUGGABLE.
  3. Android: Open chrome://inspect with the release build running. Look for WebViews to inspect.
  *Example:* `grep -rn "setWebContentsDebuggingEnabled" out/ ; open chrome://inspect on the host with the device connected by USB`  
  *Expected:* The app calls setWebContentsDebuggingEnabled with true only when FLAG_DEBUGGABLE is set. The release build offers no WebView to inspect.  
  *Refs:* mobile_top10: M8:2024; masvs: MASVS-RESILIENCE-4, MASVS-PLATFORM-2; mastg: MASTG-TEST-0227; maswe: MASWE-0063; cwe: CWE-489

- [ ] **MOB-RESIL-017** Check detection of attached debuggers  
  *Severity if fail:* Low | *Type:* Code Review, Manual | *Level:* MASVS R  
  *Objective:* Finds apps that keep running while a debugger controls them.  
  *Steps:*
  1. Android: Search for Debug.isDebuggerConnected, ptrace, TracerPid reads and JDWP checks.
  2. iOS: Search the binary for ptrace with PT_DENY_ATTACH, sysctl P_TRACED, getppid and exception port checks.
  3. Hook the detection calls at runtime. Record return values and backtraces.
  4. Attach a debugger to the running app.
  5. Check that the app ends, limits functions or informs the backend.
  *Example:* `adb jdwp ; adb forward tcp:7777 jdwp:<pid> ; jdb -attach localhost:7777 ; grep -rn "isDebuggerConnected\|TracerPid" out/ ; frida -U -f <pkg> -l hook_debug_detect.js`  
  *Expected:* The app detects an attached debugger in the Java, Kotlin, native and iOS code. It reacts when it finds one.  
  *Refs:* mobile_top10: M7:2024; masvs: MASVS-RESILIENCE-4; mastg: MASTG-TEST-0352, MASTG-TEST-0353, MASTG-TEST-0401, MASTG-TEST-0402; maswe: MASWE-0064

- [ ] **MOB-RESIL-018** Check application-level encryption of API payloads  
  *Severity if fail:* Info | *Type:* Manual | *Level:* MASVS R  
  *Objective:* Finds apps whose API payloads show in clear text once an attacker defeats TLS pinning.  
  *Steps:*
  1. Defeat certificate pinning on a test device. Capture the app traffic.
  2. Read the request and response bodies of security-relevant calls.
  3. Check if the app encrypts or signs the payloads in a second layer.
  4. Check that the keys come from the platform keystore.
  5. Change a captured request and replay it. Check that the server rejects it.
  *Example:* `objection -g <pkg> explore, then android sslpinning disable ; Burp Suite: capture, edit and replay requests`  
  *Expected:* Security-relevant payloads have a second layer of encryption or signature on top of TLS. The server rejects changed requests.  
  *Refs:* mobile_top10: M7:2024; masvs: MASVS-RESILIENCE-3; maswe: MASWE-0062; cwe: CWE-319


## STORAGE

- [ ] **MOB-STORAGE-001** Check that Android private storage holds no plaintext sensitive data  
  *Severity if fail:* High | *Type:* Manual, Automated | *Level:* MASVS L2  
  *Objective:* Finds sensitive data that the app writes unencrypted to its Android private data directory or to SharedPreferences.  
  *Steps:*
  1. Install the app and make a first copy of its private data directory.
  2. Hook the SharedPreferences write methods and the Cipher classes with Frida.
  3. Use every workflow of the app and enter sensitive data wherever possible.
  4. Make a second copy of the private data directory and find the files that are new or changed.
  5. Search the new files and the hook output for the sensitive values.
  6. Decode base64, hex, URL-encoded and compressed content, because these methods hide data but do not protect it.
  7. Look at the hook trace to see if each write of a sensitive value follows a Cipher operation.
  *Example:* `adb install app.apk; objection -g <package> explore -> env (shows data paths); adb shell run-as <package> tar cf - . > data1.tar (debuggable builds) or adb pull /data/data/<package>; diff -r data1 data2; grep -rniE "token|passw|secret" data2/shared_prefs data2/databases; frida-trace -U -f <package> -j "android.content.SharedPreferences$Editor!putString" -j "javax.crypto.Cipher!*"; trufflehog filesystem data2/`  
  *Expected:* The app stores no sensitive data in plaintext or in trivially encoded form. Sensitive values are encrypted with keys that the Android Keystore protects.  
  *Refs:* mobile_top10: M9:2024; masvs: MASVS-STORAGE-1, MASVS-STORAGE-2; mastg: MASTG-TEST-0207, MASTG-TEST-0287; maswe: MASWE-0001; cheatsheet: Mobile_Application_Security_Cheat_Sheet, Cryptographic_Storage_Cheat_Sheet; cwe: CWE-200, CWE-284, CWE-312, CWE-313, CWE-732, CWE-922  
  *See:* WEB-SESS-029

- [ ] **MOB-STORAGE-002** Check that iOS private storage and Keychain hold no plaintext secrets  
  *Severity if fail:* High | *Type:* Manual, Automated | *Level:* MASVS L2  
  *Objective:* Finds sensitive data that the app writes unencrypted to the iOS sandbox, UserDefaults or the Keychain with weak settings.  
  *Steps:*
  1. Extract the app binaries from the IPA and search them for file, UserDefaults, Core Data, SQLite and Keychain APIs.
  2. List the Keychain calls with their access control and accessibility attributes.
  3. Install the app, list the files in the sandbox and take a first snapshot of the Keychain.
  4. Hook the file and Keychain APIs with Frida and use every workflow of the app with sensitive data.
  5. List the files and the Keychain again and compare both snapshots.
  6. Search new and changed files for sensitive values in plaintext, base64, hex and binary plist forms.
  7. Make sure each secret is in the Keychain or encrypted with a Keychain key before the app writes it.
  *Example:* `unzip app.ipa; r2 -qc "aaa; afl~SecItem" Payload/App.app/App; objection -g <bundle> explore -> env; ios keychain dump; ios plist cat Library/Preferences/<bundle>.plist; frida-trace -U -f <bundle> -m "-[NSUserDefaults setObject:forKey:]" -m "-[NSFileManager createFileAtPath:*]" -i SecItemAdd -i SecItemUpdate; diff -r sandbox1 sandbox2`  
  *Expected:* The app stores no sensitive data in plaintext in the sandbox. Secrets are in the Keychain or encrypted with keys from the Keychain.  
  *Refs:* mobile_top10: M9:2024; masvs: MASVS-STORAGE-1, MASVS-STORAGE-2; mastg: MASTG-TEST-0300, MASTG-TEST-0301, MASTG-TEST-0302; maswe: MASWE-0001; cheatsheet: Mobile_Application_Security_Cheat_Sheet, Cryptographic_Storage_Cheat_Sheet; cwe: CWE-200, CWE-284, CWE-312, CWE-313, CWE-732, CWE-922  
  *See:* WEB-SESS-029

- [ ] **MOB-STORAGE-003** Check the data protection class of iOS files with sensitive data  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* MASVS L2  
  *Objective:* Finds files with sensitive data that have the data protection class NSFileProtectionNone.  
  *Steps:*
  1. Start the test from a clean install and use every workflow of the app with sensitive data.
  2. List the files in the app sandbox with their data protection classes.
  3. List the files in the App Group shared containers that the app and its extensions use, with their classes.
  4. Mark the files that hold sensitive data.
  5. Find the marked files that have the class NSFileProtectionNone.
  *Example:* `objection -g <bundle> explore -> env (shows the data and App Group paths); cd <path>; ls (the NSFileProtection column shows the class of each file); look for NSFileProtectionNone`  
  *Expected:* Files with sensitive data use a protection class that locks them when the device is locked. No such file has the class NSFileProtectionNone.  
  *Refs:* mobile_top10: M9:2024; masvs: MASVS-STORAGE-1; mastg: MASTG-TEST-0299; maswe: MASWE-0001; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-200, CWE-284, CWE-312, CWE-313, CWE-732, CWE-922

- [ ] **MOB-STORAGE-004** Check that iOS App Group containers hold no unprotected secrets  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS L2  
  *Objective:* Finds secrets in shared UserDefaults or shared files that the app and all its extensions can read.  
  *Steps:*
  1. Extract the main binary and every extension binary in PlugIns/*.appex.
  2. Search them for UserDefaults(suiteName:), containerURL(forSecurityApplicationGroupIdentifier:) and shared Core Data stores.
  3. Look at the code at each location and find the values that the app writes to the shared container.
  4. Mark the values that are credentials, tokens or keys.
  5. Make sure the app keeps each secret in a shared Keychain and does not write it to the container.
  6. Look at the entitlements for keychain-access-groups and the protection class of the shared files.
  *Example:* `unzip app.ipa; find Payload -name "*.appex"; r2 -qc "aaa; iz~suiteName" Payload/App.app/PlugIns/X.appex/X; codesign -d --entitlements :- Payload/App.app; grep -a "group\." on the entitlements output`  
  *Expected:* The shared container holds no secrets in plaintext. Secrets are in a shared Keychain or are encrypted and protected with a strong protection class.  
  *Refs:* mobile_top10: M9:2024; masvs: MASVS-STORAGE-1; mastg: MASTG-TEST-0388; maswe: MASWE-0001; cwe: CWE-200, CWE-284, CWE-312, CWE-313, CWE-732, CWE-922

- [ ] **MOB-STORAGE-005** Check that sensitive data is not written to shared storage  
  *Severity if fail:* Medium | *Type:* Manual, Automated | *Level:* MASVS L1  
  *Objective:* Finds sensitive data that the app writes unencrypted to Android external storage or to iOS folders that the user can reach.  
  *Steps:*
  1. Android: List the files in external storage before and after you use the app.
  2. Android: Hook the external storage APIs and FileOutputStream with Frida and use every workflow of the app.
  3. Android: Reverse engineer the app and look for these APIs and for the WRITE_EXTERNAL_STORAGE and MANAGE_EXTERNAL_STORAGE permissions.
  4. iOS: Read Info.plist and look at UIFileSharingEnabled and LSSupportsOpeningDocumentsInPlace.
  5. iOS: Search the binary for writes to the Documents directory and look at the data that the code writes.
  6. Look at each new file or code location to see if it holds sensitive data without encryption.
  *Example:* `adb shell ls -R /sdcard/Android/data/<package> /sdcard/Download > before.txt (repeat after use, then diff); frida-trace -U -f <package> -j "android.os.Environment!getExternalStorageDirectory" -j "android.content.Context!getExternalFilesDir"; apktool d app.apk; grep -R "getExternalStorage\|MediaStore" smali*/; aapt d permissions app.apk; plutil -p Payload/App.app/Info.plist | grep -E "UIFileSharing|LSSupportsOpening"`  
  *Expected:* The app writes no sensitive data unencrypted to shared storage. The iOS app does not expose a Documents folder that holds sensitive data.  
  *Refs:* mobile_top10: M9:2024; masvs: MASVS-STORAGE-1, MASVS-STORAGE-2; mastg: MASTG-TEST-0200, MASTG-TEST-0201, MASTG-TEST-0202, MASTG-TEST-0303; maswe: MASWE-0002; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-200, CWE-284, CWE-312, CWE-313, CWE-732, CWE-921, CWE-922

- [ ] **MOB-STORAGE-006** Check that the app does not write sensitive data to logs  
  *Severity if fail:* Low | *Type:* Manual, Automated | *Level:* MASVS L1  
  *Objective:* Finds sensitive data in Android logcat output or in iOS device logs.  
  *Steps:*
  1. Reverse engineer the app and list the uses of logging APIs.
  2. Android: Look for Log, Logger, System.out.print, System.err.print and printStackTrace.
  3. iOS: Look for NSLog, NSAssert, NSCAssert, print and printf in the binary.
  4. Monitor the device log while you use every workflow of the app with sensitive data.
  5. Close the app and search the log for the sensitive values.
  6. Look at the code of each match to find which log call writes the data.
  *Example:* `adb logcat --pid=$(adb shell pidof -s <package>) > app.log; grep -iE "token|passw|secret|card" app.log; frida-trace -U -f <package> -j "android.util.Log!*"; apktool d app.apk; grep -R "Landroid/util/Log;" smali*/; xcrun simctl spawn booted log stream --style compact --predicate 'process CONTAINS[c] "App"'; frida-trace -U -f <bundle> -i NSLog`  
  *Expected:* Logs contain no passwords, tokens, personal data or other sensitive values. Release builds remove or disable such log calls.  
  *Refs:* mobile_top10: M9:2024; masvs: MASVS-STORAGE-2; mastg: MASTG-TEST-0203, MASTG-TEST-0231, MASTG-TEST-0296, MASTG-TEST-0297; maswe: MASWE-0005; cheatsheet: Mobile_Application_Security_Cheat_Sheet, Logging_Cheat_Sheet; cwe: CWE-209, CWE-359, CWE-497, CWE-532

- [ ] **MOB-STORAGE-007** Check that sensitive files are excluded from backups  
  *Severity if fail:* Medium | *Type:* Config Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds sensitive data that the system copies to a cloud backup, a device transfer or a local backup.  
  *Steps:*
  1. Android: Read AndroidManifest.xml and note the values of allowBackup, fullBackupContent and dataExtractionRules.
  2. Android: Read backup_rules.xml or data_extraction_rules.xml and see if all sensitive files are excluded.
  3. Android: Use the app with sensitive data, then back up and restore its data with the backup daemon.
  4. Android: Reinstall the app, restore the data and list the restored files.
  5. iOS: Search the binary for isExcludedFromBackup and list the files that the code marks.
  6. iOS: Hook the file APIs and list the files that the app creates outside tmp and Library/Caches.
  7. Find the sensitive files in these lists.
  *Example:* `apktool d -s -f app.apk; grep -E "allowBackup|fullBackupContent|dataExtractionRules" AndroidManifest.xml; cat res/xml/data_extraction_rules.xml; adb root; adb shell bmgr backupnow <package>; adb pull /data/data/com.android.localtransport/files/1/_full/<package> app.ab; tar xvf app.ab; r2 -qc "aaa; iz~isExcludedFromBackup" Payload/App.app/App; frida-trace -U -f <bundle> -m "-[NSFileManager createFileAtPath:*]"`  
  *Expected:* Sensitive files are not in the backup or the restored set. iOS files that need exclusion are also encrypted, because isExcludedFromBackup gives no guarantee.  
  *Refs:* mobile_top10: M9:2024; masvs: MASVS-STORAGE-2; mastg: MASTG-TEST-0216, MASTG-TEST-0262, MASTG-TEST-0215, MASTG-TEST-0298; maswe: MASWE-0006; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-212, CWE-313

- [ ] **MOB-STORAGE-008** Check that iOS text fields with sensitive input disable keyboard caching  
  *Severity if fail:* Low | *Type:* Manual, Code Review | *Level:* MASVS L2  
  *Objective:* Finds iOS input fields that let the keyboard cache or suggest sensitive text.  
  *Steps:*
  1. Search the binary for UITextField, UITextView and UISearchBar and the input trait settings.
  2. Look at isSecureTextEntry, autocorrectionType and spellCheckingType at each location, and in storyboards.
  3. Hook the text field classes with Frida and use every input screen with sensitive data.
  4. Note the trait values and the entered value of each field.
  5. Find the fields with sensitive data where isSecureTextEntry is off or autocorrection or spell checking is on or default.
  *Example:* `r2 -qc "aaa; iz~autocorrectionType" Payload/App.app/App; plutil -p Payload/App.app/Base.lproj/*.storyboardc/*.nib; frida-trace -U -f <bundle> -m "-[UITextField setSecureTextEntry:]" -m "-[UITextField setAutocorrectionType:]" -m "-[UITextField setSpellCheckingType:]"`  
  *Expected:* Each field for sensitive input has isSecureTextEntry on, or autocorrection and spell checking off. The keyboard does not cache the entered text.  
  *Refs:* mobile_top10: M9:2024; masvs: MASVS-STORAGE-2; mastg: MASTG-TEST-0313, MASTG-TEST-0314; maswe: MASWE-0036; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-200, CWE-359

- [ ] **MOB-STORAGE-009** Check that the app package holds no hardcoded secrets  
  *Severity if fail:* High | *Type:* Automated, Code Review | *Level:* MASVS L1  
  *Objective:* Finds API keys, passwords, tokens and private keys that ship inside the APK or IPA.  
  *Steps:*
  1. Unpack the APK or IPA and decompile the code.
  2. Search code, resources, plists, JSON files, native libraries and bundled frameworks for secrets.
  3. Run a secret scanner over the unpacked package.
  4. Look at each hit to see if it is a live API key, credential or private key.
  5. Check the scope and the permissions of each secret that you find.
  6. Make sure the app gets static secrets from a backend at run time or uses scoped tokens that expire.
  *Example:* `apktool d app.apk -o out; jadx -d src app.apk; unzip app.ipa -d ipa; strings -n 8 ipa/Payload/App.app/App | grep -iE "api[_-]?key|secret|passw|BEGIN (RSA|EC|PRIVATE)"; grep -riE "api[_-]?key|secret|token" out/res src/; gitleaks detect --no-git -s out; trufflehog filesystem out ipa`  
  *Expected:* The package holds no live secrets, credentials or private keys. Unavoidable static keys have the least permissions and can be rotated.  
  *Refs:* mobile_top10: M1:2024; masvs: MASVS-STORAGE-1; maswe: MASWE-0004; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-312, CWE-321, CWE-540, CWE-798  
  *See:* WEB-CRYPTO-018, WEB-OAUTH-032


## UI

- [ ] **MOB-UI-001** Check that sensitive screens stay out of screenshots and the app switcher  
  *Severity if fail:* Medium | *Type:* Manual, Code Review | *Level:* MASVS L2  
  *Objective:* Finds screens that leak sensitive data through task snapshots, screenshots or screen recordings.  
  *Steps:*
  1. List the screens that show sensitive data, such as login, payment, health and personal data.
  2. Android: Search the code for FLAG_SECURE, setRecentsScreenshotEnabled, setSecure on SurfaceView and SecureOn in Compose dialogs.
  3. Android: Open each sensitive screen. Press Home. Pull the system task snapshot files from the device.
  4. Android: Try a screenshot and a screen recording on each sensitive screen.
  5. iOS: Open each sensitive screen. Press Home. Pull the snapshot files from the SplashBoard folder of the app.
  6. Look at each snapshot image for passwords, tokens, personal data or other secrets.
  *Example:* `adb shell ls /data/system_ce/0/snapshots (root) ; adb pull /data/system_ce/0/snapshots ; adb exec-out screencap -p > shot.png ; grep -rn "FLAG_SECURE\|setRecentsScreenshotEnabled" out/ ; iOS: scp the Library/SplashBoard/Snapshots folder of the app container`  
  *Expected:* No snapshot, screenshot or recording shows sensitive data. The app hides or protects sensitive screens when it moves to the background.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PLATFORM-3; mastg: MASTG-TEST-0289, MASTG-TEST-0291, MASTG-TEST-0290, MASTG-TEST-0292, MASTG-TEST-0293, MASTG-TEST-0294; maswe: MASWE-0038; cwe: CWE-200, CWE-359

- [ ] **MOB-UI-002** Check that Android keyboards do not cache sensitive input  
  *Severity if fail:* Low | *Type:* Code Review | *Level:* MASVS L2  
  *Objective:* Finds input fields that let the keyboard learn and suggest sensitive text.  
  *Steps:*
  1. Android: Extract the layout files from the app package.
  2. Android: List every android:inputType attribute and every setInputType call.
  3. Android: Find fields for passwords, PINs, card data and other secrets.
  4. Android: Check that these fields use a non-caching type such as textPassword or textNoSuggestions.
  *Example:* `apktool d app.apk -o out ; grep -rn "android:inputType" out/res/layout ; grep -rn "setInputType" out/`  
  *Expected:* Every field that takes sensitive data uses an input type that stops keyboard caching and suggestions.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PLATFORM-3; mastg: MASTG-TEST-0258; maswe: MASWE-0036; cwe: CWE-200, CWE-359  
  *See:* MOB-STORAGE-008

- [ ] **MOB-UI-003** Check that password, PIN and code fields hide the typed text  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS L2  
  *Objective:* Finds secret input fields that show characters to bystanders and screen recordings.  
  *Steps:*
  1. Android: Find text fields for passwords, PINs and one-time codes in XML and in Compose code.
  2. Android: Flag a plain TextField, and flag a SecureTextField that uses TextObfuscationMode.Visible.
  3. iOS: Check that each UITextField for a secret sets isSecureTextEntry to true.
  4. iOS: Check that SwiftUI code uses SecureField and not TextField for secrets.
  5. Type test secrets into each field at runtime. Look at the screen for visible characters.
  *Example:* `grep -rn "textPassword\|TextObfuscationMode\|SecureTextField" out/ ; r2 -A <app_binary> ; izz~isSecureTextEntry ; frida -U -f <bundle_id> -l hook_uitextfield.js`  
  *Expected:* Every field for a password, PIN or code masks the typed characters. Full values show only after a user action and for a short time.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PLATFORM-3; mastg: MASTG-TEST-0316, MASTG-TEST-0346, MASTG-TEST-0347; maswe: MASWE-0036, MASWE-0040; cwe: CWE-200, CWE-359  
  *See:* MOB-STORAGE-008

- [ ] **MOB-UI-004** Check that notifications hold no sensitive data  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS L2  
  *Objective:* Finds notifications that show secrets or personal data on the lock screen or to other apps.  
  *Steps:*
  1. Android: Read minSdkVersion and the POST_NOTIFICATIONS permission in the AndroidManifest.xml.
  2. Android: Find notification code that uses setContentTitle, setContentText or setStyle.
  3. Android: Check the visibility setting and setPublicVersion of each notification.
  4. Trigger each notification with test data. Look at the lock screen and at the notification list.
  5. Look for one-time codes, message text, balances or other personal data.
  *Example:* `aapt2 d permissions app.apk | grep POST_NOTIFICATIONS ; grep -rn "setContentText\|setContentTitle\|setVisibility\|setPublicVersion" out/`  
  *Expected:* Notifications only say that an event occurred. They show no sensitive values, and the lock screen shows a redacted version.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PLATFORM-3; mastg: MASTG-TEST-0315; maswe: MASWE-0037; cwe: CWE-200, CWE-359

- [ ] **MOB-UI-005** Check sensitive screens for overlay attack protection  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS L2  
  *Objective:* Finds screens where a malicious app can cover or imitate the UI and steal taps.  
  *Steps:*
  1. Android: List the screens for login, payment approval, permission requests and security settings.
  2. Android: Search for setFilterTouchesWhenObscured, android:filterTouchesWhenObscured and onFilterTouchEventForSecurity.
  3. Android: Search for FLAG_WINDOW_IS_OBSCURED checks in touch handlers.
  4. Android: Read targetSdkVersion. If it is 31 or higher, look for setHideOverlayWindows and the HIDE_OVERLAY_WINDOWS permission.
  5. Android: Draw a test overlay over each sensitive screen. Tap through it.
  *Example:* `grep -rn "setFilterTouchesWhenObscured\|filterTouchesWhenObscured\|onFilterTouchEventForSecurity\|setHideOverlayWindows" out/ ; aapt2 d permissions app.apk | grep HIDE_OVERLAY_WINDOWS`  
  *Expected:* Sensitive screens ignore touches when another window covers them. The app hides external overlays on API level 31 and higher.  
  *Refs:* mobile_top10: M8:2024; masvs: MASVS-PLATFORM-3; mastg: MASTG-TEST-0340; maswe: MASWE-0039, MASWE-0036; cwe: CWE-1021, CWE-200, CWE-359

- [ ] **MOB-UI-006** Check that sensitive views are hidden from accessibility services  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS L2  
  *Objective:* Finds views that any accessibility service can read or control.  
  *Steps:*
  1. Android: Search the layouts and code for accessibilityDataSensitive and setAccessibilityDataSensitive.
  2. Android: Search for filterTouchesWhenObscured, because it also makes a view data sensitive.
  3. Android: Hook the setters at runtime and use the app on every sensitive screen.
  4. Android: Dump the UI hierarchy of each sensitive screen. Look at the isAccessibilityDataSensitive value of each view.
  5. Android: Take a screenshot of each screen. Find the views with secrets or personal data.
  *Example:* `adb shell uiautomator dump /sdcard/ui.xml ; adb pull /sdcard/ui.xml ; adb shell dumpsys activity top ; adb exec-out screencap -p > screen.png ; frida -U -f <pkg> -l hook_a11y_sensitive.js`  
  *Expected:* Each view that shows or takes sensitive data is accessibility data sensitive. Only declared accessibility tools can read it.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PLATFORM-3; mastg: MASTG-TEST-0403, MASTG-TEST-0404; maswe: MASWE-0040; cwe: CWE-200, CWE-359

- [ ] **MOB-UI-007** Check that screens show only the sensitive data that the task needs  
  *Severity if fail:* Low | *Type:* Manual | *Level:* MASVS L2  
  *Objective:* Finds screens that show full secrets or personal data without need.  
  *Steps:*
  1. Open each screen that shows card numbers, identifiers, account data or personal data.
  2. Look for values that the app could show in part, such as the last four digits.
  3. Check that the app shows full values only after an explicit user action.
  4. Check that the full value hides again after a short time or when the screen closes.
  *Example:* `Manual review with screenshots of each screen ; compare displayed values with the stored data`  
  *Expected:* The app shows only the part of a sensitive value that the task needs. Full values need a user action and hide again.  
  *Refs:* mobile_top10: M6:2024; masvs: MASVS-PLATFORM-3; maswe: MASWE-0036; cheatsheet: Mobile_Application_Security_Cheat_Sheet; cwe: CWE-200, CWE-359


## WEBVIEW

- [ ] **MOB-WEBVIEW-001** Check Android WebViews for JavaScript with local file access  
  *Severity if fail:* High | *Type:* Code Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds WebViews where injected script can read local files and send them out.  
  *Steps:*
  1. Android: Search the decompiled code for WebView, WebSettings and setJavaScriptEnabled.
  2. Android: Read the values of setAllowFileAccess, setAllowFileAccessFromFileURLs and setAllowUniversalAccessFromFileURLs.
  3. Android: Read minSdkVersion. Below API 30 setAllowFileAccess defaults to true. Below API 16 the two file URL settings default to true.
  4. Android: Hook the setters at runtime to see the real values and backtraces.
  5. Android: Find the WebViews that load file:// content or handle sensitive data.
  6. Android: Look for a way to inject HTML or script into those WebViews.
  *Example:* `jadx -d out app.apk ; grep -rn "setJavaScriptEnabled\|setAllowFileAccess\|setAllowUniversalAccessFromFileURLs\|setAllowFileAccessFromFileURLs" out/ ; frida -U -f <pkg> -l hook_websettings.js`  
  *Expected:* No WebView enables JavaScript together with file access and file URL access. WebViews that load local content do not render untrusted content.  
  *Refs:* mobile_top10: M4:2024; masvs: MASVS-PLATFORM-2, MASVS-CODE-4; mastg: MASTG-TEST-0252, MASTG-TEST-0253; maswe: MASWE-0034; cwe: CWE-22, CWE-79, CWE-200, CWE-669

- [ ] **MOB-WEBVIEW-002** Check Android WebViews for content provider access  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds WebViews that let script read content providers of the app.  
  *Steps:*
  1. Android: Search the decompiled code for setAllowContentAccess and setJavaScriptEnabled.
  2. Android: Note that setAllowContentAccess defaults to true when the code does not set it.
  3. Android: List all content providers in the AndroidManifest.xml, also those that are not exported.
  4. Android: Hook the WebSettings setters at runtime. Record the values and backtraces.
  5. Android: Find out if the providers hold sensitive data.
  6. Android: Check if setAllowUniversalAccessFromFileURLs is true.
  *Example:* `grep -rn "setAllowContentAccess\|setAllowUniversalAccessFromFileURLs" out/ ; aapt2 d xmltree app.apk --file AndroidManifest.xml | grep -A8 "E: provider" ; frida -U -f <pkg> -l hook_websettings.js`  
  *Expected:* WebViews that run JavaScript disable content access, or no content provider holds sensitive data. Universal access from file URLs stays off.  
  *Refs:* mobile_top10: M4:2024; masvs: MASVS-PLATFORM-2; mastg: MASTG-TEST-0250, MASTG-TEST-0251; maswe: MASWE-0034; cwe: CWE-22, CWE-79, CWE-200, CWE-669

- [ ] **MOB-WEBVIEW-003** Check JavaScript bridges between WebViews and native code  
  *Severity if fail:* High | *Type:* Code Review | *Level:* MASVS L1  
  *Objective:* Finds bridges that give web content access to sensitive native functions or data.  
  *Steps:*
  1. Android: Search the code for addJavascriptInterface and setJavaScriptEnabled(true).
  2. Android: Read each object that the code registers. List its public methods that have @JavascriptInterface.
  3. iOS: Search the binary for WKUserContentController add(_:name:) and WKScriptMessageHandler classes.
  4. iOS: Read each userContentController(_:didReceive:) method. List the actions that a message can start.
  5. Check if a bridge method returns credentials, changes app state or runs a privileged action.
  6. Check if the bridge checks the message input and the origin of the page.
  *Example:* `jadx -d out app.apk ; grep -rn "addJavascriptInterface\|@JavascriptInterface" out/ ; r2 -A <app_binary> ; afl~WKUserContentController ; izz~addScriptMessageHandler`  
  *Expected:* The app exposes no sensitive native function or data through a WebView bridge. Each remaining bridge checks its input and serves only trusted pages.  
  *Refs:* mobile_top10: M4:2024; masvs: MASVS-PLATFORM-2; mastg: MASTG-TEST-0334, MASTG-TEST-0376; maswe: MASWE-0033, MASWE-0034; cwe: CWE-749, CWE-94, CWE-22, CWE-79, CWE-200

- [ ] **MOB-WEBVIEW-004** Check iOS evaluateJavaScript calls for data leaks to web content  
  *Severity if fail:* Medium | *Type:* Code Review | *Level:* MASVS L1  
  *Objective:* Finds uses of evaluateJavaScript that expose sensitive data to script in the page.  
  *Steps:*
  1. iOS: Search the binary for evaluateJavaScript:completionHandler: and list the enclosing functions.
  2. iOS: Find calls inside userContentController(_:didReceive:) that send bridge replies as a JavaScript callback.
  3. iOS: Find calls that assign sensitive data to innerHTML, textContent, innerText or value.
  4. iOS: Find calls that read DOM values, and check if they use the content world variant.
  5. iOS: Make sure the page cannot override the callback function or read the injected DOM data.
  *Example:* `r2 -A <app_binary> ; afl~evaluateJavaScript ; axt sym.imp.evaluateJavaScript ; izz~innerHTML`  
  *Expected:* The app does not pass sensitive data to the page through evaluateJavaScript. DOM reads use an isolated content world.  
  *Refs:* mobile_top10: M4:2024; masvs: MASVS-PLATFORM-2; mastg: MASTG-TEST-0377, MASTG-TEST-0379, MASTG-TEST-0380; maswe: MASWE-0034; cwe: CWE-22, CWE-79, CWE-200, CWE-669

- [ ] **MOB-WEBVIEW-005** Check iOS WebViews for password fields in loaded HTML  
  *Severity if fail:* Medium | *Type:* Code Review | *Level:* MASVS L1  
  *Objective:* Finds password inputs in web pages where script can read the typed value.  
  *Steps:*
  1. iOS: Search the binary strings for type="password" and type='password'.
  2. iOS: Check if the HTML loads into a WKWebView.
  3. iOS: Look for a WKUserScript that sends focus to a native secure text field.
  4. iOS: Check if third-party scripts or user content can run on the same page.
  *Example:* `unzip app.ipa ; strings -a Payload/App.app/App | grep -i "type=.password" ; grep -rn "type=\"password\"" Payload/App.app/*.html`  
  *Expected:* The app does not collect passwords in WebView HTML. If it does, a native input overlay reads the value and the page cannot read it.  
  *Refs:* mobile_top10: M4:2024; masvs: MASVS-PLATFORM-2; mastg: MASTG-TEST-0378; maswe: MASWE-0034; cwe: CWE-22, CWE-79, CWE-200, CWE-669

- [ ] **MOB-WEBVIEW-006** Check iOS WKWebView local file access and file origin settings  
  *Severity if fail:* High | *Type:* Code Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds WKWebViews where script from file URLs can read other local files.  
  *Steps:*
  1. iOS: Search the binary for loadFileURL(_:allowingReadAccessTo:). Read the readAccessURL argument of each call.
  2. iOS: Flag read access to the whole Documents directory or the app container root.
  3. iOS: Search for allowFileAccessFromFileURLs and allowUniversalAccessFromFileURLs set with setValue:forKey:.
  4. iOS: Hook the setting calls at runtime. Record values and backtraces.
  5. iOS: Check if attacker-controlled input selects the loaded file or injects script.
  *Example:* `r2 -A <app_binary> ; afl~loadFileURL ; izz~allowFileAccessFromFileURLs ; frida -U -f <bundle_id> -l hook_wkwebview_setvalue.js`  
  *Expected:* The app limits readAccessURL to the one folder that it needs. Neither file origin setting is true for WebViews that load local files.  
  *Refs:* mobile_top10: M4:2024; masvs: MASVS-PLATFORM-2; mastg: MASTG-TEST-0333, MASTG-TEST-0335, MASTG-TEST-0336; maswe: MASWE-0034; cwe: CWE-22, CWE-79, CWE-200, CWE-669

- [ ] **MOB-WEBVIEW-007** Check that WebViews load only trusted URLs  
  *Severity if fail:* Medium | *Type:* Code Review, Manual | *Level:* MASVS L1  
  *Objective:* Finds WebViews that open attacker-controlled or arbitrary URLs.  
  *Steps:*
  1. Android: Find setWebViewClient calls and classes that extend WebViewClient.
  2. Android: Read shouldOverrideUrlLoading and shouldInterceptRequest. Check that they match the host against an allowlist.
  3. Android: Hook both methods at runtime. Record the URLs and the return values.
  4. iOS: Search for WKWebView load, loadFileURL, loadHTMLString and loadRequest calls. Trace the URL source.
  5. iOS: Check if a deep link, a pasteboard value or a network response can set the URL.
  6. Send the app a URL on an untrusted host and see if the WebView opens it.
  *Example:* `jadx -d out app.apk ; grep -rn "shouldOverrideUrlLoading\|shouldInterceptRequest\|setWebViewClient" out/ ; frida -U -f <pkg> -l hook_webviewclient.js ; r2 -A <app_binary> ; afl~WKWebView`  
  *Expected:* WebViews open only URLs on allowed hosts. The code checks the full host, not a substring, and external links open in the system browser.  
  *Refs:* mobile_top10: M4:2024; masvs: MASVS-PLATFORM-2, MASVS-CODE-4; mastg: MASTG-TEST-0398, MASTG-TEST-0400, MASTG-TEST-0332; maswe: MASWE-0035; cwe: CWE-79, CWE-601, CWE-829

- [ ] **MOB-WEBVIEW-008** Check that Android SafeBrowsing stays on for WebViews  
  *Severity if fail:* Low | *Type:* Config Review, Code Review | *Level:* MASVS L1  
  *Objective:* Finds WebViews that skip the Safe Browsing check for known bad sites.  
  *Steps:*
  1. Android: Read the AndroidManifest.xml for the android.webkit.WebView.EnableSafeBrowsing meta-data.
  2. Android: Flag the value false.
  3. Android: Search the code for WebSettings.setSafeBrowsingEnabled(false).
  4. Android: Remember that the code setting wins over the manifest value.
  *Example:* `aapt2 d xmltree app.apk --file AndroidManifest.xml | grep -B2 -A2 EnableSafeBrowsing ; grep -rn "setSafeBrowsingEnabled" out/`  
  *Expected:* The manifest does not turn off SafeBrowsing and no code calls setSafeBrowsingEnabled with false.  
  *Refs:* mobile_top10: M8:2024; masvs: MASVS-PLATFORM-2; mastg: MASTG-TEST-0399; maswe: MASWE-0035; cwe: CWE-79, CWE-601, CWE-829

- [ ] **MOB-WEBVIEW-009** Check iOS apps for the deprecated UIWebView  
  *Severity if fail:* Low | *Type:* Code Review | *Level:* MASVS L1  
  *Objective:* Finds apps that use UIWebView, which has weaker isolation than WKWebView.  
  *Steps:*
  1. iOS: Extract the binaries from the IPA, including frameworks.
  2. iOS: Search all binaries for references to UIWebView.
  3. iOS: List the third-party libraries that bring in UIWebView.
  *Example:* `unzip app.ipa ; grep -rl UIWebView Payload/App.app ; r2 -A <app_binary> ; ic~UIWebView`  
  *Expected:* No binary in the app uses UIWebView. All web content uses WKWebView.  
  *Refs:* mobile_top10: M8:2024; masvs: MASVS-PLATFORM-2; mastg: MASTG-TEST-0331; maswe: MASWE-0035; cwe: CWE-79, CWE-601, CWE-829

- [ ] **MOB-WEBVIEW-010** Check that the app cleans WebView storage with sensitive data  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* MASVS L1  
  *Objective:* Finds WebView caches, cookies and storage that keep sensitive data after use.  
  *Steps:*
  1. Android: List the WebView storage settings that the app enables, such as cache, DOM storage and database.
  2. Android: Hook the cleanup calls, such as clearCache with includeDiskFiles, and record them.
  3. Android: Use the app with sensitive test data in the WebView. Close the app.
  4. Android: Pull the app_webview directory from the app data folder.
  5. Android: Search the files for the sensitive test data.
  6. Android: Check for the cleanup of cookies and WebStorage when the user logs out.
  *Example:* `adb shell run-as <pkg> ls app_webview ; adb exec-out run-as <pkg> tar c app_webview | tar x ; grep -rl "<test data>" app_webview ; frida -U -f <pkg> -l hook_webview_cleanup.js`  
  *Expected:* The app_webview folder holds no sensitive data after the app closes. The app calls the cleanup APIs for each storage area that it enables.  
  *Refs:* masvs: MASVS-PLATFORM-2; mastg: MASTG-TEST-0320; maswe: MASWE-0001; cwe: CWE-200, CWE-284, CWE-312, CWE-313, CWE-732

- [ ] **MOB-WEBVIEW-011** Check third-party scripts that run in WebViews  
  *Severity if fail:* Medium | *Type:* Manual, Code Review | *Level:* MASVS L1  
  *Objective:* Finds WebView pages that load scripts from outside parties without limits.  
  *Steps:*
  1. List the pages that the app loads in WebViews and the remote scripts on each page.
  2. Check if the script tags use Subresource Integrity with an integrity value.
  3. Check if the vendor host sends CORS headers, as Subresource Integrity needs them.
  4. Check if the page keeps third-party scripts away from sensitive fields and URL parameters.
  5. Check if the page isolates untrusted tags in a sandboxed iframe.
  6. Look at the vendor scripts for changes at regular times.
  *Example:* `Burp Suite: proxy the WebView traffic and list the script hosts ; curl -s https://<page> | grep -i "<script" ; openssl dgst -sha384 -binary script.js | openssl base64 -A`  
  *Expected:* Third-party scripts in WebViews carry integrity values or run in a sandbox. They cannot read sensitive page data.  
  *Refs:* mobile_top10: M2:2024; masvs: MASVS-PLATFORM-2; maswe: MASWE-0035; cheatsheet: Third_Party_Javascript_Management_Cheat_Sheet; cwe: CWE-79, CWE-601, CWE-829
