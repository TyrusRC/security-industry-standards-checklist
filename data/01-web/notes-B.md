# Notes for slice WEB-B (IDM, AUTHN, PWD, MFA, SESS, AUTHZ, IDOR, JWT, OAUTH)

Coverage: all 122 ASVS 5.0 requirements in V6-V10 appear in refs. 32 of 33 WSTG IDs (IDNT, ATHN, ATHZ, SESS) appear in refs.

Not written as a test of this slice:
- WSTG-ATHN-01: merged into WSTG-CRYP-03 in WSTG. The control (credentials only over an encrypted channel) belongs to the transport/crypto slice (see WSTG-CRYP-03 tests in tls.yaml).

Decisions:
- WSTG-IDNT-05 was merged into WSTG-IDNT-04. Both IDs are in WEB-IDM-004, 005 and 006.
- WSTG-SESS-05 (CSRF) is in the WEB-B file list. WEB-SESS-030 covers it with the WSTG text only. The CSRF cheat sheet belongs to another slice. If that slice covers WSTG-SESS-05, delete WEB-SESS-030.
- WSTG-ATHZ-01 (path traversal) is covered by WEB-AUTHZ-015 from the authorization view. The injection slice may go deeper.
- WSTG-ATHN-10 (alternative channel) is merged into WEB-AUTHN-008 with ASVS V6.3.4.
- ASVS documentation requirements (V6.1.x, V7.1.x, V8.1.x) are Config Review tests. They are testable by reading documentation.
- CWE-613 (Insufficient Session Expiration) and CWE-264 are not in catalog/cwe.json. CWE-287 and CWE-384 are used instead.
- Cheat sheets read: Authentication, Session_Management, Authorization, Forgot_Password, Password_Storage, Credential_Stuffing_Prevention, Multifactor_Authentication, Transaction_Authorization (first part), JSON_Web_Token, OAuth2, SAML_Security (headings and rules), Insecure_Direct_Object_Reference_Prevention, Choosing_and_Using_Security_Questions (opened and read the introduction and the question guidance).
- Not read in full, so not cited: Authorization_Testing_Automation, Authorization_Regression_Testing, Authorization_Patterns, Authorization_Decisions_And_Output_Handling, Authorization_Policy_And_Data_Distribution, Authentication_Patterns. Access_Control_Cheat_Sheet is deprecated (points to Authorization).
- A01 items for directory listing, .git exposure and CORS are not covered here (configuration and headers slices).
- Several examples with exploit steps (JWT, SAML, OAuth) are written at checklist level on purpose. Run them only in test environments.
