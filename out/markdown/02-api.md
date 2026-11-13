# API security test cases

114 tests. Tick the box when the test passes.


## AUTHN

- [ ] **API-AUTHN-001** Call every operation without credentials and with bad credentials  
  *Severity if fail:* Critical | *Type:* Manual  
  *Objective:* Finds API operations that work without a valid authentication.  
  *Steps:*
  1. Build a list of all operations from the API description and the proxy history.
  2. Send each operation without any credential.
  3. Send each operation with an empty, expired and random token or API key.
  4. List every operation that does not return 401.
  *Example:* `Newman run with the Authorization header removed; ZAP OpenAPI import plus a script that strips headers; Burp Autorize with an empty session.`  
  *Expected:* Every non-public operation returns 401 without a valid credential. Public operations are listed in the API description.  
  *Refs:* api_top10: API2:2023; wstg: WSTG-APIT-01; cheatsheet: REST_Assessment_Cheat_Sheet, REST_Security_Cheat_Sheet; cwe: CWE-306, CWE-287; attack: T1190  
  *See:* WEB-AUTHZ-005, WEB-AUTHN-009

- [ ] **API-AUTHN-002** Find all authentication flows and test each one  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds login paths, such as mobile, deep link or legacy flows, that skip controls.  
  *Steps:*
  1. Ask the engineers for all ways to authenticate to the API.
  2. Find more flows in the client code, the mobile app and the API description.
  3. Test each flow for the same checks: lock out, rate limit and multi-factor.
  4. Compare the results and list flows with weaker controls.
  *Example:* `Burp site map filter on /login, /token, /auth, /oauth; ZAP spider; review of the gateway routes.`  
  *Expected:* All authentication flows are known. Every flow applies the same lock out, rate limit and factor checks.  
  *Refs:* api_top10: API2:2023; cwe: CWE-287, CWE-306  
  *See:* WEB-AUTHN-009

- [ ] **API-AUTHN-003** Test brute force and credential stuffing limits on API login  
  *Severity if fail:* High | *Type:* Automated  
  *Objective:* Finds login endpoints that allow many password guesses for one account or many accounts.  
  *Steps:*
  1. Send repeated failed logins for one account. Count the requests before a block or delay.
  2. Send one failed login for each of many accounts from one source.
  3. Change the source IP header and the client ID. Check if the limit still holds.
  4. Compare the limit with the limit of normal API calls.
  *Example:* `Burp Turbo Intruder or ffuf against POST /auth/login with a short wordlist on a test account; hydra is not needed.`  
  *Expected:* The login limit is stricter than the general API limit. It holds per account and per source, and header changes do not bypass it.  
  *Refs:* api_top10: API2:2023; cheatsheet: REST_Assessment_Cheat_Sheet; cwe: CWE-307, CWE-799; capec: CAPEC-49, CAPEC-112; attack: T1110, T1110.004  
  *See:* WEB-AUTHN-002, WEB-AUTHN-003

- [ ] **API-AUTHN-004** Treat password reset and recovery endpoints as login endpoints  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds recovery endpoints that allow brute force of reset tokens or one-time codes.  
  *Steps:*
  1. Start a reset for a test account. Send wrong tokens to the confirm endpoint many times.
  2. Count the requests before a block.
  3. Check if the token or code can be used more than once.
  4. Check if the limit also applies on the beta or older API hosts.
  *Example:* `Burp Intruder on POST /password/reset/confirm with a 6-digit range; compare with the limit on the login endpoint.`  
  *Expected:* Reset endpoints have lock out and rate limits like login. A token cannot be guessed in its lifetime.  
  *Refs:* api_top10: API2:2023, API4:2023; cheatsheet: REST_Assessment_Cheat_Sheet; cwe: CWE-307, CWE-799; capec: CAPEC-112; attack: T1110  
  *See:* WEB-PWD-018, WEB-MFA-003

- [ ] **API-AUTHN-005** Check that sensitive account changes need the current password  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds endpoints that change email, phone or password with only a bearer token.  
  *Steps:*
  1. Find the endpoints that change email, phone number, password or factors.
  2. Send each request with a valid token but without the current password.
  3. Send each request with a wrong current password.
  4. Start a password reset after the email change.
  *Example:* `curl -X PUT https://api.example/account -H 'Authorization: Bearer <token>' -d '{"email":"new@x.test"}'`  
  *Expected:* The API asks for the current password or a new login before it changes sensitive data. The request fails without it.  
  *Refs:* api_top10: API2:2023; cwe: CWE-620  
  *See:* WEB-PWD-004

- [ ] **API-AUTHN-006** Check that credentials and tokens are not sent in the URL  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds API keys, tokens and passwords that appear in URLs and logs.  
  *Steps:*
  1. List all endpoints that take an API key, token or password.
  2. Read the securitySchemes of the API description for apiKey values with in: query.
  3. Find the endpoints that accept the secret in the query string.
  4. Look in proxy, gateway and server logs for URLs that hold a secret.
  5. Make sure the secret travels in a header or in the body.
  *Example:* `Burp search for apiKey, token, access_token in URLs; grep -i 'apikey=' access.log; example of an unsafe URL: /v1/data?apiKey=<key>.`  
  *Expected:* No secret is accepted in the URL. Logs do not show secrets.  
  *Refs:* api_top10: API2:2023; cheatsheet: REST_Security_Cheat_Sheet; cwe: CWE-598  
  *See:* WEB-DATA-002

- [ ] **API-AUTHN-007** Check how API keys are used and revoked  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds API keys that act as user logins or that the owner cannot limit.  
  *Steps:*
  1. List the API keys that the API accepts and the clients that use them.
  2. Check if a key identifies a user. Keys must identify only a client.
  3. Send many requests with one key. Look for 429 responses.
  4. Revoke a test key. Check that it is rejected at once.
  *Example:* `curl -H 'X-API-Key: <key>' https://api.example/v1/ping in a loop; review of the key management screen.`  
  *Expected:* API keys identify API clients only. The API rate limits each key and returns 429. A revoked key is rejected.  
  *Refs:* api_top10: API2:2023, API4:2023; cheatsheet: REST_Security_Cheat_Sheet; cwe: CWE-287, CWE-799

- [ ] **API-AUTHN-008** Compare login and reset responses for valid and invalid accounts  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds differences in status, body or time that reveal which accounts exist.  
  *Steps:*
  1. Send a login with a valid user and a wrong password. Record status, body, length and time.
  2. Send a login with an unknown user. Record the same values.
  3. Repeat for the reset and registration endpoints.
  4. Compare the records.
  *Example:* `Burp Comparer and Intruder with response timing; ffuf -mc all -fs <size> against the login endpoint.`  
  *Expected:* Responses for valid and unknown accounts are the same in status, body and time.  
  *Refs:* api_top10: API2:2023; cwe: CWE-204, CWE-203; capec: CAPEC-112  
  *See:* WEB-IDM-004, WEB-PWD-017

- [ ] **API-AUTHN-009** Send malformed and under-scoped tokens to every operation  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds token checks that fail with a server error or that ignore scopes and roles.  
  *Steps:*
  1. Send tokens that are truncated, have extra parts or bad Base64.
  2. Check that the response is 401 and not a server error.
  3. Send a valid token with a scope that does not grant the operation.
  4. Send a valid token of a lower role to owner-only operations.
  *Example:* `jwt_tool <JWT> -M pb -t https://api.example/v1/me -rh 'Authorization: Bearer JWT'; Postman test that expects 401 or 403.`  
  *Expected:* Bad tokens give 401 and never a 500. A token without the needed scope or role gets 403.  
  *Refs:* api_top10: API2:2023; cheatsheet: REST_Assessment_Cheat_Sheet, REST_Security_Cheat_Sheet; cwe: CWE-287, CWE-863  
  *See:* WEB-JWT-001, WEB-JWT-005, WEB-OAUTH-007

- [ ] **API-AUTHN-010** Check how the API stores and shows API keys and client secrets  
  *Severity if fail:* High | *Type:* Manual, Code Review  
  *Objective:* Finds API keys and client secrets that are stored in plain text or shown again.  
  *Steps:*
  1. Create an API key or client secret in a test account. Note how the API shows it.
  2. Read the key list and the key detail endpoints. Look for the full secret in the responses.
  3. Read how the service stores keys: look for plain text and reversible encryption.
  4. Check the length and the random source of the keys.
  *Example:* `curl -H 'Authorization: Bearer <token>' https://api.example/v1/keys; review of the key table in a test database; code search for key generation.`  
  *Expected:* The API shows a key once, at creation. The service stores only a hash or an encrypted value. Keys are long and random.  
  *Refs:* api_top10: API2:2023; cwe: CWE-256, CWE-522  
  *See:* WEB-PWD-012, WEB-JWT-009


## BFLA

- [ ] **API-BFLA-001** Call administrative endpoints as a normal user and as an anonymous client  
  *Severity if fail:* Critical | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds administrative functions that a client without the right role can call.  
  *Steps:*
  1. List administrative functions from the API description, the client code and the proxy history.
  2. Call each function with the token of a normal user.
  3. Call each function without a token.
  4. Compare the result with the result for an administrator.
  *Example:* `curl -X POST https://api.example/api/admin/deleteUser -H 'Authorization: Bearer <userToken>' -d '{"userId":"12345"}'; Burp Autorize; ZAP forced browse.`  
  *Expected:* The API returns 401 or 403 to every client that lacks the role. The function does not run.  
  *Refs:* api_top10: API5:2023; wstg: WSTG-APIT-04; asvs: V8.2.1; cwe: CWE-285, CWE-862, CWE-863; capec: CAPEC-122  
  *See:* WEB-AUTHZ-004, WEB-AUTHZ-005

- [ ] **API-BFLA-002** Change the HTTP method on each endpoint and check the authorization  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds functions that are protected for one HTTP method but open for another.  
  *Steps:*
  1. Take a GET endpoint that a normal user may call.
  2. Send PUT, PATCH, DELETE and POST to the same path with the token of the normal user.
  3. Take a POST endpoint of an administrator and send GET to the same path.
  4. Record every change in the status code or in the response body.
  *Example:* `curl -X DELETE https://api.example/api/users/12345 -H 'Authorization: Bearer <userToken>'; Burp Repeater method change; ZAP active scan with method fuzzing.`  
  *Expected:* Each method has its own authorization check. The API answers 403 or 405 for methods that the caller may not use.  
  *Refs:* api_top10: API5:2023; wstg: WSTG-APIT-04; asvs: V8.2.1; cheatsheet: REST_Security_Cheat_Sheet; cwe: CWE-285, CWE-862  
  *See:* WEB-CONF-008

- [ ] **API-BFLA-003** Find privileged functions that sit under normal routes  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds administrative functions outside the /admin path that have no role check.  
  *Steps:*
  1. Compare the API description with the routes in the code and the client JavaScript.
  2. Look for routes such as /users/export_all and /invites/new next to normal routes.
  3. Guess related names for each normal route and send them as a normal user.
  4. Test old API versions of the same routes.
  *Example:* `ffuf -u https://api.example/api/FUZZ -w api-endpoints.txt -H 'Authorization: Bearer <userToken>'; Kiterunner; route list from the framework (rails routes, springdoc).`  
  *Expected:* Every route that changes or exports data checks the role of the caller. The path name does not decide who has access.  
  *Refs:* api_top10: API5:2023; wstg: WSTG-APIT-04, WSTG-APIT-01; cwe: CWE-285, CWE-862; capec: CAPEC-36; attack: T1595.003  
  *See:* WEB-AUTHZ-004

- [ ] **API-BFLA-004** Test the authorization of each role, group and sub-user  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds role hierarchy errors that give a user the functions of another group.  
  *Steps:*
  1. Write a table of roles, groups and the functions that each may call.
  2. Include users with two roles, sub-users and partner accounts in the table.
  3. Call each function with each account and mark the result in the table.
  4. Look for results that differ from the table.
  *Example:* `Burp AuthMatrix with one session per role; Postman collection with an environment for each role; spreadsheet of expected 200 and 403 results.`  
  *Expected:* The result of each call matches the documented role table. No role can call a function of a higher role.  
  *Refs:* api_top10: API5:2023; wstg: WSTG-APIT-04; asvs: V8.2.1; cwe: CWE-285, CWE-863; capec: CAPEC-122  
  *See:* WEB-AUTHZ-004, WEB-IDM-001

- [ ] **API-BFLA-005** Check deny by default and shared checks for administrative controllers  
  *Severity if fail:* Medium | *Type:* Code Review  
  *Objective:* Finds routes that are open because a developer forgot to add an authorization rule.  
  *Steps:*
  1. Read the authorization module and the code that defines routes.
  2. Make sure the default rule for a new route is to deny access.
  3. Make sure the administrative controllers use one base class or one policy that checks the role.
  4. Add a test route without a rule in a test environment. Call it as a normal user.
  *Example:* `Code review of the middleware chain; grep for routes without an authorization annotation; unit test that lists all routes and their policy.`  
  *Expected:* A new route without an explicit rule is denied. Administrative functions share one central role check.  
  *Refs:* api_top10: API5:2023; wstg: WSTG-APIT-04; cwe: CWE-862, CWE-285  
  *See:* WEB-AUTHZ-017


## BOLA

- [ ] **API-BOLA-001** Replace object IDs in path and query with IDs of another user  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds API endpoints that return objects of other users when the object ID changes.  
  *Steps:*
  1. Create user A and user B. Create objects for each, such as orders.
  2. List every endpoint that takes an object ID in the path or in the query string.
  3. Log in as user A. Send each request with an object ID that belongs to user B.
  4. Compare each response with the response that user B gets for the same request.
  *Example:* `Burp Autorize or AuthMatrix with the token of user A; curl -H 'Authorization: Bearer <tokenA>' https://api.example/v1/orders/<idB>; Postman collection run with two environments.`  
  *Expected:* The API returns 403 or 404 for objects of other users. It checks the owner of the object on every request.  
  *Refs:* api_top10: API1:2023; wstg: WSTG-APIT-02; asvs: V8.2.2; cheatsheet: Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet, REST_Assessment_Cheat_Sheet; cwe: CWE-639, CWE-285, CWE-863; capec: CAPEC-1  
  *See:* WEB-IDOR-001

- [ ] **API-BOLA-002** Change other users' objects with PUT, PATCH and DELETE  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds API write operations that do not check who owns the object.  
  *Steps:*
  1. Create an object as user B and note its ID.
  2. Log in as user A. Send PUT, PATCH and DELETE requests for the object of user B.
  3. Send POST requests that create child objects under the object of user B.
  4. Log in as user B and read the object. Look for changes or deletion.
  *Example:* `curl -X DELETE -H 'Authorization: Bearer <tokenA>' https://api.example/v1/documents/<idB>; Burp Repeater with a Match and Replace rule for the token.`  
  *Expected:* The API rejects every write, delete and create request on objects of other users. The object stays unchanged.  
  *Refs:* api_top10: API1:2023; wstg: WSTG-APIT-02; asvs: V8.2.2; cheatsheet: Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet; cwe: CWE-639, CWE-285; capec: CAPEC-1  
  *See:* WEB-IDOR-002

- [ ] **API-BOLA-003** Test object IDs in request bodies, headers and nested routes  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds object references outside the path that the API trusts without an owner check.  
  *Steps:*
  1. Find IDs in JSON bodies, custom headers and nested routes such as /users/{id}/orders/{id}.
  2. Change one ID at a time to an ID of user B. Keep the other IDs valid for user A.
  3. Send a parent ID of user A with a child ID of user B.
  4. Repeat for every object type that the API exposes.
  *Example:* `Burp Intruder or ZAP fuzzer with a list of IDs of user B; Postman pre-request script that swaps IDs; example request: PUT /v1/users/<idA>/orders/<idB>.`  
  *Expected:* The API checks the owner of each object in the request, also for nested routes. A mismatch between parent and child gives 403 or 404.  
  *Refs:* api_top10: API1:2023; wstg: WSTG-APIT-02; asvs: V8.2.2; cheatsheet: REST_Assessment_Cheat_Sheet, Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet; cwe: CWE-639, CWE-863; capec: CAPEC-1  
  *See:* WEB-IDOR-003

- [ ] **API-BOLA-004** Test list, search and bulk endpoints for objects of other users  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds collection endpoints that return all objects instead of the objects of the caller.  
  *Steps:*
  1. Call each list endpoint, such as GET /users or GET /orders, as a normal user.
  2. Add filter parameters such as owner, user_id, tenant or all to the request.
  3. Change the page size and the sort order. Look for objects that the caller does not own.
  4. Send bulk requests that carry many IDs, some of them from user B.
  *Example:* `curl 'https://api.example/v1/orders?user_id=<idB>&limit=100' -H 'Authorization: Bearer <tokenA>'; Burp Param Miner for hidden filter names.`  
  *Expected:* List and bulk endpoints return only the objects that the caller may access. Filter parameters cannot widen the result.  
  *Refs:* api_top10: API1:2023; wstg: WSTG-APIT-02; cheatsheet: Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet; cwe: CWE-639, CWE-285; capec: CAPEC-1  
  *See:* WEB-IDOR-001

- [ ] **API-BOLA-005** Test whether unpredictable IDs are the only object protection  
  *Severity if fail:* Medium | *Type:* Manual, Code Review  
  *Objective:* Finds objects that any user can read when the user learns the ID from another source.  
  *Steps:*
  1. Collect IDs from list responses, error messages, notification links and shared URLs.
  2. Use an ID of user B that user A can see. Request the object as user A.
  3. Check if IDs are sequential or follow a pattern that a script can guess.
  4. Read the code to make sure an owner check exists for each lookup.
  *Example:* `curl with GUIDs taken from the activity feed of user B; Burp Sequencer on a sample of IDs; code search for findById( without an owner filter.`  
  *Expected:* The API denies access even when the caller knows a valid ID. The owner check does not depend on the secrecy of the ID.  
  *Refs:* api_top10: API1:2023; wstg: WSTG-APIT-02; cheatsheet: Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet, REST_Assessment_Cheat_Sheet; cwe: CWE-639; capec: CAPEC-1  
  *See:* WEB-IDOR-005

- [ ] **API-BOLA-006** Test cross-tenant access with changed tenant identifiers  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds multi-tenant APIs that let one tenant read or change the objects of another tenant.  
  *Steps:*
  1. Create two tenants with one user each. Create objects in both tenants.
  2. Send requests from tenant A with the tenant ID, subdomain or header of tenant B.
  3. Use an object ID of tenant B in a request with the tenant context of tenant A.
  4. Look for data of tenant B in responses, exports and search results.
  *Example:* `curl -H 'X-Tenant-Id: <tenantB>' -H 'Authorization: Bearer <tokenA>' https://api.example/v1/invoices/<idB>; Burp Match and Replace on the tenant header.`  
  *Expected:* The API takes the tenant from the validated token or session. A tenant value from the client never widens access.  
  *Refs:* api_top10: API1:2023; wstg: WSTG-APIT-02; asvs: V8.4.1; cheatsheet: Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet; cwe: CWE-639, CWE-285  
  *See:* WEB-AUTHZ-012

- [ ] **API-BOLA-007** Check that object access uses a policy, not only the token ID  
  *Severity if fail:* Medium | *Type:* Code Review  
  *Objective:* Finds code that compares the user ID in the token to one ID parameter and misses other objects.  
  *Steps:*
  1. Find all handlers that take an object ID from the client.
  2. Read how each handler decides if the caller may use the object.
  3. Find handlers that only compare the token user ID to a request parameter.
  4. Send requests for shared, delegated and group objects to test the policy.
  *Example:* `grep -rn 'userId ==' src/ ; review of the authorization middleware; Postman test for an object shared with a group.`  
  *Expected:* A central policy checks the caller, the action and the object for every handler. A single ID comparison is not the only check.  
  *Refs:* api_top10: API1:2023; wstg: WSTG-APIT-02; cheatsheet: Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet; cwe: CWE-285, CWE-639  
  *See:* WEB-AUTHZ-009

- [ ] **API-BOLA-008** Run automated authorization tests for object access in the build  
  *Severity if fail:* Low | *Type:* Config Review, Code Review  
  *Objective:* Finds builds that lack regression tests for object-level checks.  
  *Steps:*
  1. Find the test suite for the API in the repository and in the build pipeline.
  2. Look for tests that call each endpoint as a second user and expect 403 or 404.
  3. Remove the owner check in a test branch. Run the pipeline.
  4. Make sure the build fails and that the change cannot be deployed.
  *Example:* `Review of CI configuration; Postman or Newman collection with a two-user matrix; Schemathesis with a custom authorization check.`  
  *Expected:* The pipeline has object-level authorization tests for every endpoint. A test that fails blocks the deployment.  
  *Refs:* api_top10: API1:2023; wstg: WSTG-APIT-02; cwe: CWE-285


## BOPLA

- [ ] **API-BOPLA-001** Compare API response fields with the fields that the client shows  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds responses that carry sensitive fields which the user interface hides.  
  *Steps:*
  1. Open a page that shows user or object data. Record the API request with a proxy.
  2. List all fields in the JSON response and all fields that the page shows.
  3. Mark fields such as password_hash, api_key, role, internal IDs and IP addresses.
  4. Repeat for list, search and detail endpoints.
  *Example:* `Burp Logger++ or browser DevTools Network tab; jq 'keys' on each response; ZAP passive scan rules for information disclosure.`  
  *Expected:* Each response holds only the fields that the client needs and the caller may read. The client does not filter data.  
  *Refs:* api_top10: API3:2023; wstg: WSTG-APIT-03; asvs: V8.2.3; cheatsheet: REST_Security_Cheat_Sheet; cwe: CWE-213, CWE-200  
  *See:* WEB-ARCH-005, WEB-DATA-007

- [ ] **API-BOPLA-002** Compare the fields in responses for different roles and for anonymous calls  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds endpoints that return the same rich object to every caller.  
  *Steps:*
  1. Request one object as the owner, as another user, as an administrator and without a token.
  2. Save the four JSON responses.
  3. Compare the field lists with a diff tool.
  4. Look for fields that a lower role should not see.
  *Example:* `curl -s ... | jq -S . > owner.json; diff owner.json other.json; Burp Comparer.`  
  *Expected:* Fields depend on the role of the caller and the relation to the object. An anonymous call gets no private fields.  
  *Refs:* api_top10: API3:2023; wstg: WSTG-APIT-03; asvs: V8.2.3; cwe: CWE-213, CWE-200  
  *See:* WEB-AUTHZ-007

- [ ] **API-BOPLA-003** Inspect nested objects and error responses for extra properties  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds embedded objects and error bodies that expose data of other objects.  
  *Steps:*
  1. Request objects that embed other objects, such as an order with a customer and a payment.
  2. Read every nested object for fields that the caller does not need.
  3. Send invalid requests and read the error bodies.
  4. Look for internal notes, card data, internal IDs and file paths.
  *Example:* `jq '..|objects|keys' response.json; Burp Search for the strings password, token, secret and internal; ZAP alert list.`  
  *Expected:* Nested objects and error bodies carry only the minimum fields. Sensitive properties of other objects are not shown.  
  *Refs:* api_top10: API3:2023; wstg: WSTG-APIT-03; cwe: CWE-213, CWE-209  
  *See:* WEB-DATA-007

- [ ] **API-BOPLA-004** Add extra properties to write requests and read the object back  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds endpoints that write properties which the caller may not change.  
  *Steps:*
  1. Take a valid create or update request. Add fields such as role, isAdmin, balance, price and status.
  2. Send the request. Read the object back with a second request.
  3. Check if the value was stored and if the behavior changed.
  4. Repeat with PATCH, nulls to delete a property and a different Content-Type.
  *Example:* `Burp Param Miner; Arjun (arjun -u https://api.example/v1/users/me -m JSON); example body: {"email":"a@b.test","role":"admin"}.`  
  *Expected:* The API ignores or rejects properties that the caller may not write. The stored object does not change for those fields.  
  *Refs:* api_top10: API3:2023; wstg: WSTG-APIT-03; asvs: V8.2.3; cheatsheet: Mass_Assignment_Cheat_Sheet, REST_Assessment_Cheat_Sheet; cwe: CWE-915  
  *See:* WEB-INJ-022, WEB-ARCH-006, WEB-AUTHZ-007

- [ ] **API-BOPLA-005** Find hidden properties with the API description and accepted fields  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds properties that the API accepts although the schema does not define them.  
  *Steps:*
  1. Read the schema of the request body in the OpenAPI file.
  2. Send each request with one extra property that the schema does not define.
  3. Read the object back and look for the stored value.
  4. Write each accepted extra property in the report.
  *Example:* `Schemathesis (st run openapi.json --checks all); ZAP OpenAPI add-on; Burp Param Miner guess JSON properties.`  
  *Expected:* The API rejects properties that the schema does not define, or ignores them. It never stores them.  
  *Refs:* api_top10: API3:2023; wstg: WSTG-APIT-03; cheatsheet: REST_Assessment_Cheat_Sheet, Mass_Assignment_Cheat_Sheet; cwe: CWE-915  
  *See:* WEB-INJ-022

- [ ] **API-BOPLA-006** Check how the code limits response and request fields  
  *Severity if fail:* Medium | *Type:* Code Review | *Level:* ASVS L2  
  *Objective:* Finds generic serializers and automatic binders that expose or accept internal properties.  
  *Steps:*
  1. Search the code for to_json, to_string and automatic binders of request data to objects.
  2. Check that each endpoint uses a response schema with named fields.
  3. Check that each endpoint uses an input class or an allowlist of fields.
  4. Check that a block list is not the only protection.
  *Example:* `grep -rn 'to_json\|toString()\|@RequestBody\|permit(' src/; review of DTO classes; response schema validation in the gateway.`  
  *Expected:* Responses use fixed schemas. Input binds only to allowed fields. Both are enforced in code or in the gateway.  
  *Refs:* api_top10: API3:2023; asvs: V8.2.3; cheatsheet: Mass_Assignment_Cheat_Sheet; cwe: CWE-915, CWE-213  
  *See:* WEB-ARCH-006


## CONF

- [ ] **API-CONF-001** Check that API traffic uses TLS on every hop  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds API calls to clients, gateways and back ends that use clear text.  
  *Steps:*
  1. Request the API on HTTP and HTTPS. Check if the HTTP request is refused.
  2. Find the links between the gateway, the services and downstream APIs.
  3. Capture traffic on an internal link. Look for clear text.
  4. Check for privileged APIs that need mutual TLS.
  *Example:* `curl -v http://api.example/v1/ping; nmap --script ssl-enum-ciphers -p 443 api.example; tcpdump on a test node.`  
  *Expected:* All API communication uses TLS, also inside the network. The API gives no data over clear text.  
  *Refs:* api_top10: API8:2023; asvs: V12.3.1; cheatsheet: REST_Security_Cheat_Sheet, Web_Service_Security_Cheat_Sheet; cwe: CWE-319  
  *See:* WEB-TLS-005, WEB-TLS-011

- [ ] **API-CONF-002** Check security headers and cache control on API responses  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds API responses that browsers or caches can store or misuse.  
  *Steps:*
  1. Send requests to endpoints with private data. Read the response headers.
  2. Look for Cache-Control: no-store, Content-Type and X-Content-Type-Options.
  3. Look for Strict-Transport-Security and the frame-ancestors value.
  4. Check responses for 304 and for error codes too.
  *Example:* `curl -i https://api.example/dm/user_updates.json?conversation_id=1; ZAP passive scan; securityheaders.com style check of the API host.`  
  *Expected:* Responses with private data have Cache-Control: no-store and the other listed headers. Content-Type matches the body.  
  *Refs:* api_top10: API8:2023; cheatsheet: REST_Security_Cheat_Sheet; cwe: CWE-525  
  *See:* WEB-DATA-011, WEB-HTTP-001

- [ ] **API-CONF-003** Check the CORS policy of the API  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds APIs that allow cross-origin reads from untrusted origins.  
  *Steps:*
  1. Send requests with an Origin header of an untrusted domain.
  2. Look at Access-Control-Allow-Origin and Access-Control-Allow-Credentials.
  3. Send a preflight OPTIONS request for sensitive methods.
  4. Disable CORS headers if no cross-origin client exists.
  *Example:* `curl -i -H 'Origin: https://evil.test' https://api.example/v1/me; Burp CORS scanner extension.`  
  *Expected:* The API allows only listed origins, and never a wildcard with credentials. An API without browser clients sends no CORS headers.  
  *Refs:* api_top10: API8:2023; cheatsheet: REST_Security_Cheat_Sheet; cwe: CWE-942  
  *See:* WEB-CLIENT-002, WEB-CLIENT-015

- [ ] **API-CONF-004** Check that error responses follow a schema and show no internals  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds error responses with stack traces, queries or paths.  
  *Steps:*
  1. Send invalid JSON, wrong types, absent fields and unknown routes.
  2. Send a very long value and an invalid token.
  3. Read the body of each error response.
  4. Compare the errors with the error schema in the API description.
  *Example:* `curl -i -X POST https://api.example/v1/items -d '{bad'; Burp Intruder with malformed values; grep the responses for 'at com.' and 'Traceback'.`  
  *Expected:* Errors are generic and follow the documented schema. They show no stack trace, query or internal path.  
  *Refs:* api_top10: API8:2023; asvs: V16.5.1; cheatsheet: REST_Security_Cheat_Sheet; cwe: CWE-209  
  *See:* WEB-ERR-001

- [ ] **API-CONF-005** Check content types, accepted formats and safe response types  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds endpoints that accept formats which the API does not need or that echo the Accept header.  
  *Steps:*
  1. Send a body with a Content-Type that the endpoint does not list. Expect 415.
  2. Send an XML body to a JSON endpoint and a JSON body to an XML endpoint.
  3. Send an Accept header with an unknown type. Expect 406 or a fixed default.
  4. Check that the response Content-Type matches the body.
  *Example:* `curl -i -H 'Content-Type: application/xml' -d '<a/>' https://api.example/v1/items; Burp Content Type Converter.`  
  *Expected:* The API accepts only documented content types and returns 415 or 406 for others. It does not copy Accept into Content-Type.  
  *Refs:* api_top10: API8:2023; cheatsheet: REST_Security_Cheat_Sheet; cwe: CWE-20  
  *See:* WEB-HTTP-001, WEB-INJ-008

- [ ] **API-CONF-006** Check that management, debug and health endpoints are not public  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds management endpoints that reveal configuration or allow actions from the internet.  
  *Steps:*
  1. Request common paths such as /actuator, /metrics, /health, /debug and /admin on the API host.
  2. Read the content of any answer for versions, hosts and secrets.
  3. Check on which port and network the management endpoints listen.
  4. Check the firewall rules for them.
  *Example:* `ffuf -u https://api.example/FUZZ -w management-paths.txt; nuclei -t exposures; nmap of the management ports.`  
  *Expected:* Management endpoints are not reachable from the internet. If they must be, they need strong authentication and a restricted network.  
  *Refs:* api_top10: API8:2023; cheatsheet: REST_Security_Cheat_Sheet; cwe: CWE-200, CWE-489; capec: CAPEC-121  
  *See:* WEB-CONF-003, WEB-CONF-002

- [ ] **API-CONF-007** Test how each server in the proxy chain reads requests  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds differences in how gateway, proxy and back end read the length of a request.  
  *Steps:*
  1. List the load balancers, proxies and back ends in front of the API.
  2. Send requests with different Content-Length and Transfer-Encoding headers in a test environment.
  3. Send path forms that the proxy and the back end read in different ways.
  4. Look for desync or access to routes that the gateway blocks.
  *Example:* `Burp HTTP Request Smuggler extension; smuggler.py; curl --path-as-is for path forms.`  
  *Expected:* All servers in the chain read each request in the same way. The gateway rules apply to the back end.  
  *Refs:* api_top10: API8:2023; cwe: CWE-444; capec: CAPEC-33  
  *See:* WEB-HTTP-004, WEB-CONF-013

- [ ] **API-CONF-008** Send header values that the API writes to its logs  
  *Severity if fail:* Critical | *Type:* Manual  
  *Objective:* Finds log libraries that expand placeholders in request data and call outside hosts.  
  *Steps:*
  1. Find headers and fields that the API writes to logs, such as X-Api-Version and User-Agent.
  2. Send a unique out-of-band marker string in each of them.
  3. Look for DNS or HTTP calls to your marker server.
  4. Check the version of the log library and the option for lookups.
  *Example:* `Burp Collaborator marker in the X-Api-Version header; interactsh; dependency scan with OWASP Dependency-Check.`  
  *Expected:* The API writes request data to logs as text. The log library does not expand lookups and has no known vulnerability.  
  *Refs:* api_top10: API8:2023; cwe: CWE-117; attack: T1190  
  *See:* WEB-VAL-003, WEB-DEP-003

- [ ] **API-CONF-009** Check the secure baseline and the configuration reviews of the API stack  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds environments that drift from the hardened baseline or have open cloud permissions.  
  *Steps:*
  1. Read the secure baseline for the API gateway, the services and the cloud.
  2. Compare it with the real settings in each environment.
  3. Check the permissions of cloud storage and orchestration files.
  4. Check for an automated and regular configuration scan.
  *Example:* `Review of Terraform or Helm files; Scout Suite or Prowler for cloud checks; kube-bench for clusters.`  
  *Expected:* A repeatable process for a secure baseline exists. Settings are checked by tools in all environments and patches are current.  
  *Refs:* api_top10: API8:2023; cwe: CWE-1188  
  *See:* WEB-CONF-001, WEB-CONF-010


## CONS

- [ ] **API-CONS-001** Send hostile data from a mocked third-party API  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds code that trusts data from other APIs and passes it to databases or downstream systems.  
  *Steps:*
  1. Find the third-party APIs that the service calls and the fields it stores or uses.
  2. Put a mock between the service and the provider. Return injection test strings in each field.
  3. Check the database, logs and downstream calls for the strings.
  4. Return unexpected types, extra fields and very long values.
  *Example:* `mitmproxy reverse mode or WireMock as the provider; strings for SQL, NoSQL and HTML in the mocked JSON.`  
  *Expected:* The service validates data from other APIs like user input. Test strings are rejected or handled as data.  
  *Refs:* api_top10: API10:2023; cheatsheet: Input_Validation_Cheat_Sheet; cwe: CWE-20, CWE-89; attack: T1190

- [ ] **API-CONS-002** Test if the service follows redirects from third-party APIs  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds clients that repeat sensitive requests to a new host after a redirect.  
  *Steps:*
  1. Set a mock provider that answers a POST request with 308 and a Location of another host.
  2. Send a request that holds test data.
  3. Look at the second host for the same request body and headers.
  4. Read the redirect option of the HTTP client.
  *Example:* `WireMock stub returning 308 with Location: https://collector.test/; code search for follow_redirects and FollowRedirects.`  
  *Expected:* The service does not follow redirects, or it follows them only to an allowlist and removes secrets from the new request.  
  *Refs:* api_top10: API10:2023; cheatsheet: Server_Side_Request_Forgery_Prevention_Cheat_Sheet; cwe: CWE-601, CWE-200

- [ ] **API-CONS-003** Check TLS and certificate checks on calls to partner and provider APIs  
  *Severity if fail:* High | *Type:* Code Review, Manual | *Level:* ASVS L2  
  *Objective:* Finds outbound calls to other APIs that use clear text or skip certificate checks.  
  *Steps:*
  1. List all outbound API calls and the SDK defaults of each provider from the code and the configuration.
  2. Look for http:// URLs and options that turn off certificate checks.
  3. Run the service against a mock with an untrusted certificate. Check that the call fails.
  4. Try to register a partner callback URL that uses http://.
  *Example:* `grep -rn 'verify=False\|InsecureSkipVerify\|rejectUnauthorized' src/; mitmproxy with a self-signed certificate.`  
  *Expected:* All calls to other APIs use TLS and check the server certificate. A call with a bad certificate fails. Callback URLs must use https://.  
  *Refs:* api_top10: API10:2023; asvs: V12.3.2; cheatsheet: Web_Service_Security_Cheat_Sheet; cwe: CWE-319, CWE-295  
  *See:* WEB-TLS-010

- [ ] **API-CONS-004** Test timeouts and size limits for third-party responses  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds services that hang or use much memory when a provider is slow or sends large data.  
  *Steps:*
  1. Make a mock provider that answers after a long delay.
  2. Make the mock send a very large response body.
  3. Watch the threads, memory and response time of the service.
  4. Check the circuit breaker and the fallback.
  *Example:* `toxiproxy with a latency toxic; WireMock fixed delay; a 1 GB response stream from the mock.`  
  *Expected:* Every outbound call has a timeout and a size limit. The service stays available and fails in a safe way.  
  *Refs:* api_top10: API10:2023, API4:2023; asvs: V16.5.2; cwe: CWE-400, CWE-770  
  *See:* WEB-ERR-003

- [ ] **API-CONS-005** Check that inbound callbacks and partner messages are authenticated  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds endpoints that trust calls from partners and do not check who sent them.  
  *Steps:*
  1. List the endpoints that third parties call, such as webhooks and callbacks.
  2. Send a call with no signature, a wrong signature and an old timestamp.
  3. Replay a valid call.
  4. Check the payload against the schema.
  *Example:* `curl -X POST https://api.example/hooks/payment with a changed X-Signature header; Postman pre-request script for HMAC.`  
  *Expected:* The service accepts only signed and fresh calls from known partners. It validates the payload like user input.  
  *Refs:* api_top10: API10:2023; cheatsheet: Web_Service_Security_Cheat_Sheet; cwe: CWE-345, CWE-20  
  *See:* WEB-HTTP-003

- [ ] **API-CONS-006** Review the security of providers and the data sent to them  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds integrations added without a check of the provider or of the data shared.  
  *Steps:*
  1. List the providers and the data fields sent to each.
  2. Read the provider assessment: transport, authentication, validation and cost limits.
  3. Make sure the service sends only needed fields.
  4. Check where the provider keys are stored and who can read them.
  *Example:* `Review of vendor questionnaires; secret store audit; data field list per provider.`  
  *Expected:* Each provider has a security assessment. The service sends only the data that the provider needs.  
  *Refs:* api_top10: API10:2023, API9:2023; cwe: CWE-200  
  *See:* WEB-DATA-004


## FLOW

- [ ] **API-FLOW-001** Test sensitive business flows of the API for scripted abuse  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds flows such as purchase, reservation and post creation that a script can abuse at scale.  
  *Steps:*
  1. Write a list of business flows and mark the ones that harm the business when used too often.
  2. Call each marked flow with a script at a high rate from one source.
  3. Call it again from many sources.
  4. Record what blocks the script: rate limit, captcha, device checks or review.
  *Example:* `Burp Turbo Intruder; Postman runner; a Python requests loop on a test product with limited stock.`  
  *Expected:* Each marked flow has controls that slow a script, and the business owner agreed the limits.  
  *Refs:* api_top10: API6:2023; wstg: WSTG-BUSL-05; cwe: CWE-799, CWE-770; capec: CAPEC-212  
  *See:* WEB-BIZ-009, WEB-BIZ-004

- [ ] **API-FLOW-002** Test referral and credit programs for scripted account creation  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds referral and bonus flows that a script can use to collect credit.  
  *Steps:*
  1. Read the rules of the referral program.
  2. Create several test accounts with a script. Use each to credit one main account.
  3. Check if email, phone or device checks block the script.
  4. Check if the credit can turn into cash or products.
  *Example:* `Python script that calls POST /register and POST /referral/claim; Burp macro for the sign-up step.`  
  *Expected:* The sign-up and the credit steps have checks for scripted use. Credit is not given before the new account is confirmed.  
  *Refs:* api_top10: API6:2023; wstg: WSTG-BUSL-05; cwe: CWE-799, CWE-841  
  *See:* WEB-BIZ-009

- [ ] **API-FLOW-003** Test reservation holds for abuse that blocks other users  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds flows where one client can hold all slots or seats and cancel them in bulk.  
  *Steps:*
  1. Reserve many slots or seats with one account without payment.
  2. Check the time limit of an unpaid hold.
  3. Cancel all reservations at once.
  4. Check if fees, limits or delays apply.
  *Example:* `Postman runner with a loop on POST /reservations; check the hold expiry time in the response.`  
  *Expected:* One account can hold only a small number of slots. Unpaid holds expire quickly. Bulk cancel has a limit.  
  *Refs:* api_top10: API6:2023; wstg: WSTG-BUSL-05; cwe: CWE-799, CWE-841  
  *See:* WEB-BIZ-007

- [ ] **API-FLOW-004** Call later workflow steps without the earlier steps  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds APIs that rely on the client to send steps in the right order.  
  *Steps:*
  1. Write down the steps of a flow, for example create, pay, approve and ship.
  2. Capture the request of each step.
  3. Send a later step without the earlier steps. Replay and reorder steps.
  4. Change status or step values and reuse tokens from other steps.
  *Example:* `Burp Repeater and Sequence of requests; Postman collection with a changed order; example: POST /orders/<id>/ship before payment.`  
  *Expected:* The server checks the state of the flow on every request. Out-of-order calls, replays and changed states are rejected.  
  *Refs:* api_top10: API6:2023; wstg: WSTG-BUSL-06; asvs: V2.3.1; cheatsheet: REST_Security_Cheat_Sheet; cwe: CWE-841; capec: CAPEC-212  
  *See:* WEB-BIZ-005, WEB-BIZ-001

- [ ] **API-FLOW-005** Race parallel requests against single-use functions  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds single-use limits, such as coupons or votes, that fail when requests run at once.  
  *Steps:*
  1. Find functions that must run once or a few times, such as coupons, votes and invites.
  2. Send many identical requests at the same time.
  3. Count how many succeeded.
  4. Compare with the limit.
  *Example:* `Burp Repeater send group in parallel; Turbo Intruder race-single-packet-attack template; curl --parallel.`  
  *Expected:* The function succeeds as many times as the limit allows. The server uses locks or atomic updates.  
  *Refs:* api_top10: API6:2023; wstg: WSTG-BUSL-05; asvs: V2.3.4; cwe: CWE-367, CWE-799; capec: CAPEC-26  
  *See:* WEB-BIZ-014, WEB-BIZ-004

- [ ] **API-FLOW-006** Check that B2B and developer APIs have the same anti-automation controls  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds machine-to-machine APIs that skip the protection of the public client.  
  *Steps:*
  1. List the APIs for partners, developers and machines.
  2. Compare the controls of these APIs with the controls of the web client for the same flow.
  3. Run the scripted flow test against the partner API.
  4. Check the keys, quotas and alerts for each partner.
  *Example:* `Postman collection of the partner API; comparison table of controls; review of the quota settings in the API gateway.`  
  *Expected:* Partner APIs have quotas, keys per client and alerts. The controls are not weaker than those of the public client.  
  *Refs:* api_top10: API6:2023; cwe: CWE-799, CWE-770

- [ ] **API-FLOW-007** Check the detection of scripted misuse and the response  
  *Severity if fail:* Medium | *Type:* Manual, Config Review  
  *Objective:* Finds systems that do not detect or log non-human use of sensitive flows.  
  *Steps:*
  1. Run a script on a sensitive flow with a very short time between steps.
  2. Look for changes in responses, blocks, captcha or extra logins.
  3. Check the logs and alerts for the script.
  4. Read the incident process for the alerts.
  *Example:* `Burp Turbo Intruder; log search for the test source IP; review of the WAF or bot rules.`  
  *Expected:* The system detects non-human speed and device patterns on sensitive flows. It logs the events and sends an alert.  
  *Refs:* api_top10: API6:2023; wstg: WSTG-BUSL-07; cwe: CWE-799, CWE-778  
  *See:* WEB-BIZ-011, WEB-BIZ-010


## GQL

- [ ] **API-GQL-001** Bypass login and OTP limits with batched requests  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds GraphQL APIs where many login or OTP tries fit in one HTTP request.  
  *Steps:*
  1. Send a JSON array of several login mutations in one request.
  2. Send one query that holds many aliased login mutations.
  3. Check if the rate limit and the lock out count each operation or each request.
  4. Check if batched requests work for sensitive operations.
  *Example:* `InQL batch attack; graphql-cop (test for batching and alias overloading); Burp request: [{"query":"mutation{login(...)}"},{...}].`  
  *Expected:* Rate limits and lock outs count each operation. Sensitive operations cannot run in batches, and the batch size has a limit.  
  *Refs:* api_top10: API2:2023, API4:2023; wstg: WSTG-APIT-99; cheatsheet: GraphQL_Cheat_Sheet; cwe: CWE-307, CWE-799; capec: CAPEC-112; attack: T1110  
  *See:* WEB-HTTP-007, WEB-AUTHN-002

- [ ] **API-GQL-002** Bypass resource limits with batched expensive mutations  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds GraphQL endpoints where batched requests skip request limits and size checks.  
  *Steps:*
  1. Find a costly mutation, such as an image upload or an export.
  2. Send the mutation many times in one array or with many aliases.
  3. Watch the CPU, memory and time of the server.
  4. Check the limit for the number of operations in a request.
  *Example:* `graphql-cop; Burp request with 100 aliases of uploadPic; load graph of the test host.`  
  *Expected:* The server limits the number of operations per request and the cost of a request. Total work per client is bounded.  
  *Refs:* api_top10: API4:2023; wstg: WSTG-APIT-99; cheatsheet: GraphQL_Cheat_Sheet; cwe: CWE-770, CWE-400; capec: CAPEC-130  
  *See:* WEB-HTTP-007

- [ ] **API-GQL-003** Bypass a query denylist with aliases  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds access rules that block field names by text match and so miss aliased fields.  
  *Steps:*
  1. Send a query for a blocked field and confirm the block.
  2. Send the same field with an alias.
  3. Send it with changed space characters, fragments and variables.
  4. Check where the access rule runs: at the text level or at the resolver.
  *Example:* `InQL; Burp GraphQL Raider; query { a: adminUsers { id } } compared with query { adminUsers { id } }.`  
  *Expected:* Access is enforced in the resolvers by role. Aliases, fragments and space characters do not change the result.  
  *Refs:* api_top10: API5:2023; wstg: WSTG-APIT-99, WSTG-APIT-04; cheatsheet: GraphQL_Cheat_Sheet; cwe: CWE-863, CWE-285

- [ ] **API-GQL-004** Test object access by ID, node fields and edges in GraphQL  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds queries that return objects of other users by ID or through relations.  
  *Steps:*
  1. Run a query for an object ID of user B as user A.
  2. Use the node and nodes fields with IDs of user B.
  3. Reach the same object through a relation from an object of user A.
  4. Repeat with mutations that delete or change an object of user B.
  *Example:* `InQL scan; graphql-path-enum; query { user(id: "<idB>") { name email } }; mutation deleteReports with an ID of user B.`  
  *Expected:* Every resolver, edge and node checks that the caller may access the object. Another user's ID returns an error or null.  
  *Refs:* api_top10: API1:2023; wstg: WSTG-APIT-02, WSTG-APIT-99; asvs: V8.2.2; cheatsheet: GraphQL_Cheat_Sheet; cwe: CWE-639, CWE-285; capec: CAPEC-1  
  *See:* WEB-IDOR-001

- [ ] **API-GQL-005** Call privileged mutations and queries as a lower role  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds GraphQL operations for admins that other roles can call.  
  *Steps:*
  1. Get the schema from a test environment. List all mutations and queries.
  2. Mark the ones that need a role, such as deleteUser and promoteUser.
  3. Call each marked operation with a lower role and without a token.
  4. Check mutations and subscriptions too.
  *Example:* `InQL; mutation { deleteUser(id: "12345") { success } } with a token of a normal user.`  
  *Expected:* Operations for higher roles return an authorization error for lower roles and for anonymous clients.  
  *Refs:* api_top10: API5:2023; wstg: WSTG-APIT-04, WSTG-APIT-99; asvs: V8.2.1; cheatsheet: GraphQL_Cheat_Sheet; cwe: CWE-285, CWE-862  
  *See:* WEB-AUTHZ-004

- [ ] **API-GQL-006** Look for sensitive fields in the schema and in mutation results  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds types and mutation results that expose private fields of other objects.  
  *Steps:*
  1. Read the schema for fields such as passwordHash, apiKey, ssn, role and recentLocation.
  2. Query these fields as a normal user.
  3. Call mutations that return objects, such as reportUser. Read the returned fields.
  4. Compare the fields with the fields that the client needs.
  *Example:* `InQL; query { __type(name: "User") { fields { name } } }; GraphQL Voyager to view types.`  
  *Expected:* Types expose only fields the caller may read. Mutation results hold no private fields of other users.  
  *Refs:* api_top10: API3:2023; wstg: WSTG-APIT-03, WSTG-APIT-99; asvs: V8.2.3; cheatsheet: GraphQL_Cheat_Sheet; cwe: CWE-213, CWE-200  
  *See:* WEB-HTTP-008, WEB-AUTHZ-007

- [ ] **API-GQL-007** Check query timeouts, pagination and amount limits  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds GraphQL APIs without a time limit or a cap on list sizes.  
  *Steps:*
  1. Send a query that asks for a very large list size.
  2. Send a costly query and measure the time before the server stops it.
  3. Check that list fields use pagination with a maximum.
  4. Check the timeout in the resolver and in the HTTP server.
  *Example:* `graphql-cop; Burp request with first: 99999999; timing in Burp Logger.`  
  *Expected:* List sizes have a server-side maximum. Queries stop after a set time at the application and at the HTTP layer.  
  *Refs:* api_top10: API4:2023; wstg: WSTG-APIT-99; cheatsheet: GraphQL_Cheat_Sheet; cwe: CWE-770, CWE-400; capec: CAPEC-130  
  *See:* WEB-HTTP-007

- [ ] **API-GQL-008** Test GraphQL arguments and custom scalars for injection  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds resolvers that pass arguments to SQL, OS or other interpreters without checks.  
  *Steps:*
  1. List arguments of type String and custom scalars such as DateTime.
  2. Send injection test strings for SQL, NoSQL, OS command and XSS in each argument.
  3. Read errors and response data for changes.
  4. Check that the schema uses enums, input types and length limits.
  *Example:* `InQL; sqlmap with a GraphQL request file (-r); query { dogs(namePrefix: "a'") { name } }.`  
  *Expected:* Arguments are checked against strict types and allowlists. Resolvers use safe query methods. Test strings do not change the result.  
  *Refs:* wstg: WSTG-APIT-99; cheatsheet: GraphQL_Cheat_Sheet, Input_Validation_Cheat_Sheet; cwe: CWE-89, CWE-20, CWE-79  
  *See:* WEB-INJ-001, WEB-INJ-003

- [ ] **API-GQL-009** Test if GraphQL arguments reach an older REST API unchecked  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds GraphQL layers that forward arguments to old APIs and use the rights of the GraphQL node.  
  *Steps:*
  1. Find GraphQL fields that call an older REST or internal API.
  2. Send an ID argument with path parts, for example 1/delete.
  3. Check if the call reaches another route or object of the old API.
  4. Check if the old API sees the user rights or the rights of the GraphQL node.
  *Example:* `Burp Repeater with id variable values such as "1/delete" and "1?admin=true" on a test system.`  
  *Expected:* The GraphQL layer validates arguments and passes them in a safe way. The old API gets the rights of the caller.  
  *Refs:* api_top10: API5:2023; wstg: WSTG-APIT-99; cheatsheet: GraphQL_Cheat_Sheet; cwe: CWE-20, CWE-285  
  *See:* WEB-AUTHZ-011

- [ ] **API-GQL-010** Check GraphQL errors, debug mode and schema tools in production  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds GraphQL servers that return stack traces, debug data or schema tools.  
  *Steps:*
  1. Send invalid queries, wrong types and a query that fails in a resolver.
  2. Read the error body for traces, paths and SQL text.
  3. Look for debug flags, GraphiQL and Playground on the host.
  4. Check the error format against the documentation.
  *Example:* `graphql-cop; InQL; curl -d '{"query":"{ x }"}' https://api.example/graphql.`  
  *Expected:* Errors are generic. Stack traces and debug mode are off in production, and schema tools are not reachable.  
  *Refs:* api_top10: API8:2023; wstg: WSTG-APIT-99; cheatsheet: GraphQL_Cheat_Sheet; cwe: CWE-209, CWE-489  
  *See:* WEB-HTTP-008, WEB-ERR-001


## GRPC

- [ ] **API-GRPC-001** Check that gRPC services use TLS and mutual TLS  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L2  
  *Objective:* Finds gRPC ports that accept plain text or clients without a certificate.  
  *Steps:*
  1. Connect to each gRPC port without TLS.
  2. Check the TLS version and cipher suites.
  3. For service-to-service calls, connect without a client certificate.
  4. Check the life time and the rotation of certificates.
  *Example:* `grpcurl -plaintext host:50051 list; testssl.sh host:443; openssl s_client -connect host:443.`  
  *Expected:* Production gRPC accepts only TLS 1.2 or newer. Service-to-service calls need a client certificate with a short life.  
  *Refs:* asvs: V12.3.1; cheatsheet: gRPC_Security_Cheat_Sheet; cwe: CWE-319, CWE-295  
  *See:* WEB-TLS-011

- [ ] **API-GRPC-002** Check that gRPC reflection is off in production  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds gRPC servers that list all services and messages to any client.  
  *Steps:*
  1. Call the reflection service on each production gRPC port.
  2. List the services, methods and message types.
  3. Check for internal or admin methods in the list.
  4. Check the option in the server code.
  *Example:* `grpcurl host:443 list; grpcurl host:443 describe <service>; grpcui for exploration.`  
  *Expected:* Reflection is off in production, or only authorized clients can use it.  
  *Refs:* api_top10: API9:2023; cheatsheet: gRPC_Security_Cheat_Sheet; cwe: CWE-200, CWE-489; capec: CAPEC-36  
  *See:* WEB-HTTP-008

- [ ] **API-GRPC-003** Check authentication on every gRPC method, also for streams  
  *Severity if fail:* High | *Type:* Manual, Code Review  
  *Objective:* Finds methods, mostly stream methods, that no authentication interceptor covers.  
  *Steps:*
  1. List all methods, also stream methods, with the proto files.
  2. Call each method without metadata credentials.
  3. Call each method with an expired token.
  4. Read the server code for the interceptors and check unary and stream registration.
  *Example:* `grpcurl -d '{}' host:443 pkg.Service/Method without the authorization header; review of grpc.UnaryInterceptor and grpc.StreamInterceptor.`  
  *Expected:* Every protected method returns UNAUTHENTICATED without a valid credential. Stream methods have an interceptor too.  
  *Refs:* api_top10: API2:2023; cheatsheet: gRPC_Security_Cheat_Sheet; cwe: CWE-306, CWE-287

- [ ] **API-GRPC-004** Test method-level and object-level authorization in gRPC  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds gRPC methods and message IDs that any authenticated client can use.  
  *Steps:*
  1. Call each method with tokens of different roles.
  2. Check for PERMISSION_DENIED for methods the role may not use.
  3. Change object IDs in messages to IDs of another user.
  4. Check that denials are logged.
  *Example:* `grpcurl -H 'authorization: Bearer <userToken>' -d '{"userId":"<idB>"}' host:443 pkg.Admin/DeleteUser`  
  *Expected:* Each method checks the role of the caller. Object IDs in messages are checked against the owner. Failures return PERMISSION_DENIED and are logged.  
  *Refs:* api_top10: API1:2023, API5:2023; asvs: V8.2.1, V8.2.2; cheatsheet: gRPC_Security_Cheat_Sheet; cwe: CWE-285, CWE-639  
  *See:* WEB-AUTHZ-004, WEB-IDOR-001

- [ ] **API-GRPC-005** Test protobuf field validation and message size limits  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds gRPC servers that trust field types and accept very large messages or streams.  
  *Steps:*
  1. Send values at the edge of range, empty, over length and with injection test strings.
  2. Send a message over the size limit in both directions.
  3. Send a stream with many messages or a very long run time.
  4. Check the maximum messages per stream and the session time.
  *Example:* `grpcurl -d @ < big.json host:443 pkg.Service/Method; ghz load tool in a test environment; fuzz with protobuf-aware tools.`  
  *Expected:* The server validates every field for business rules. It rejects oversize messages and ends streams that pass the message and time limits.  
  *Refs:* api_top10: API4:2023; cheatsheet: gRPC_Security_Cheat_Sheet; cwe: CWE-20, CWE-770; capec: CAPEC-130

- [ ] **API-GRPC-006** Check rate limits and deadlines for gRPC calls  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds gRPC services without limits per client or without call deadlines.  
  *Steps:*
  1. Send many unary calls from one client. Look for RESOURCE_EXHAUSTED.
  2. Open many streams from one client.
  3. Send a call without a deadline and a slow call.
  4. Check the client and the server timeout settings.
  *Example:* `ghz --rps 500 --total 5000 host:443; grpcurl -max-time 1; review of the limiter and stream interceptor.`  
  *Expected:* The service limits calls and streams per client. Server-side deadlines end slow calls.  
  *Refs:* api_top10: API4:2023; cheatsheet: gRPC_Security_Cheat_Sheet; cwe: CWE-770, CWE-400; attack: T1499

- [ ] **API-GRPC-007** Check gRPC errors, status codes and credential placement  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds detailed errors and credentials in message fields.  
  *Steps:*
  1. Send invalid messages and read the status and the error text.
  2. Look for stack traces and internal names.
  3. Check that credentials travel in metadata and not in message fields.
  4. Check the token life time.
  *Example:* `grpcurl -v ... to see the status and trailers; review of proto files for password and token fields.`  
  *Expected:* Errors are generic and use the right status codes. Credentials are in metadata. Tokens are short lived.  
  *Refs:* api_top10: API8:2023; cheatsheet: gRPC_Security_Cheat_Sheet; cwe: CWE-209, CWE-598  
  *See:* WEB-ERR-001


## INV

- [ ] **API-INV-001** Compare the inventory of API hosts with the exposed hosts  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds API hosts that are not in the inventory or whose purpose is unclear.  
  *Steps:*
  1. Get the inventory of API hosts with environment, network exposure and version.
  2. List hosts from DNS, certificate logs, the cloud account and the gateway.
  3. Compare the two lists.
  4. Write down hosts that have no owner, no environment or no version.
  *Example:* `subfinder -d example.com | httpx -title -tech-detect; amass enum -passive; crt.sh query; cloud API listing of gateways.`  
  *Expected:* Every exposed API host is in the inventory with environment, audience and version. No host is unknown.  
  *Refs:* api_top10: API9:2023; wstg: WSTG-APIT-01; cwe: CWE-1059; attack: T1590, T1596  
  *See:* WEB-INFO-004

- [ ] **API-INV-002** Find old, beta and undocumented API versions and test them  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds retired or test versions that run with weaker controls.  
  *Steps:*
  1. Change the version in the path, header or host: v1, v2, beta, internal, test.
  2. Search archives and old documents for retired endpoints.
  3. Send the same request to each version that answers.
  4. Compare the authentication, authorization and limits with the current version.
  *Example:* `waybackurls api.example.com | grep -E '/v[0-9]'; gau; ffuf -u https://api.example/FUZZ/users -w versions.txt.`  
  *Expected:* Retired versions are off. Each version that runs has the same security controls as the current version.  
  *Refs:* api_top10: API9:2023; wstg: WSTG-APIT-01; cwe: CWE-1059; capec: CAPEC-36, CAPEC-121; attack: T1595.003, T1593

- [ ] **API-INV-003** Compare controls on non-production hosts with production  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds beta, staging or test hosts that run the same API without the protection of production.  
  *Steps:*
  1. Find the staging, beta and test hosts of the API.
  2. Repeat a rate limit test and a login brute force test on each host.
  3. Check the gateway, WAF and authentication of each host.
  4. Check which data these hosts hold.
  *Example:* `ffuf against beta.api.example.com/password/reset/confirm; compare response headers of both hosts; review of the DNS records.`  
  *Expected:* Non-production hosts have the same controls as production or are not reachable from the internet. They hold no production data.  
  *Refs:* api_top10: API9:2023, API4:2023; cwe: CWE-1059, CWE-200; capec: CAPEC-121

- [ ] **API-INV-004** Check that API documentation is limited to authorized users  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds public API descriptions and explorers that expose the full attack surface.  
  *Steps:*
  1. Request /openapi.json, /swagger.json, /api-docs, /doc and /swagger on every API host.
  2. Request them without a token and with a low-privilege token.
  3. Compare the document with the routes that really exist.
  4. Look for internal routes and test servers in the document.
  *Example:* `curl -s https://api.example/openapi.json | jq '.paths|keys'; ZAP OpenAPI add-on; nuclei -t exposures/apis.`  
  *Expected:* API descriptions and explorers are available only to authorized users and only for the routes that the user may call.  
  *Refs:* api_top10: API9:2023; wstg: WSTG-APIT-01; cheatsheet: REST_Assessment_Cheat_Sheet; cwe: CWE-1059, CWE-200  
  *See:* WEB-CONF-003

- [ ] **API-INV-005** Compare the API description with the real behavior  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds undocumented endpoints, parameters and security rules in the real API.  
  *Steps:*
  1. Import the OpenAPI file into a proxy or a test tool.
  2. Call endpoints that the file does not list and send fields that it does not define.
  3. Build a table of the effective security rules for each operation, with overrides of the global rule.
  4. Write down each difference between file and behavior.
  *Example:* `ZAP OpenAPI add-on; Burp OpenAPI Parser; Schemathesis; jq on the security and paths keys of the file.`  
  *Expected:* The description lists all endpoints, parameters, authentication, errors and limits that the API has. No difference remains.  
  *Refs:* api_top10: API9:2023; wstg: WSTG-APIT-01; cheatsheet: REST_Assessment_Cheat_Sheet; cwe: CWE-1059; capec: CAPEC-36

- [ ] **API-INV-006** Search public sources and client code for API information  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds leaked API documents, keys and hidden endpoints in public sources.  
  *Steps:*
  1. Search web and code hosts for the API host name, the paths and keys.
  2. Read the JavaScript and mobile client for API routes and secrets.
  3. Read robots.txt and sitemap files for API paths.
  4. Check collections shared on API directories.
  *Example:* `Google dorks site:example.com inurl:/api; GitHub code search for the host; JSMiner; trufflehog github --org example.`  
  *Expected:* No API key, internal route or private document is in public sources. Findings go to the incident process.  
  *Refs:* api_top10: API9:2023; wstg: WSTG-APIT-01; cwe: CWE-200, CWE-538; attack: T1593, T1589  
  *See:* WEB-INFO-001, WEB-INFO-005

- [ ] **API-INV-007** Review the inventory of integrated services and sensitive data flows  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds data shared with third parties without approval, inventory or detail.  
  *Steps:*
  1. Read the list of third-party services that the API calls or that call the API.
  2. For each, find the business reason, the approval and the data types shared.
  3. Compare with real outbound traffic of a test environment.
  4. Look for flows that are not in the list.
  *Example:* `Review of the architecture document; mitmproxy capture of outbound calls; data flow diagram per service.`  
  *Expected:* Each third-party data flow has an owner, an approval and a list of data types. No unknown flow exists.  
  *Refs:* api_top10: API9:2023; cheatsheet: Microservices_based_Security_Arch_Doc_Cheat_Sheet; cwe: CWE-1059, CWE-200  
  *See:* WEB-ARCH-001, WEB-DATA-004

- [ ] **API-INV-008** Check the retirement plan and the security updates for old API versions  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds versions that stay open without a plan or without security patches.  
  *Steps:*
  1. Read the version policy and the retirement dates.
  2. List the versions that run and the clients that still use them.
  3. Find security fixes of the new version and check if the old version has them.
  4. Check that documentation is built in the pipeline and stays current.
  *Example:* `Review of the changelog and the gateway analytics per version; diff of the security rules between versions.`  
  *Expected:* Each version has a retirement date. Security fixes are moved to old versions or the old version is closed.  
  *Refs:* api_top10: API9:2023; cwe: CWE-1059

- [ ] **API-INV-009** Check that non-production APIs do not use production data  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds test environments that hold real user data under weaker controls.  
  *Steps:*
  1. List the databases and storage that the non-production APIs use.
  2. Look for real names, emails and tokens in test data.
  3. If production data is needed, compare the controls with production.
  *Example:* `Review of data copy jobs; sample queries on the test database; scan for personal data patterns.`  
  *Expected:* Non-production APIs use synthetic data. Any real data has the same controls as in production.  
  *Refs:* api_top10: API9:2023; cwe: CWE-200, CWE-359  
  *See:* WEB-DATA-001


## MSVC

- [ ] **API-MSVC-001** Call back-end services directly and skip the API gateway  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds services that trust the gateway and have no checks of their own.  
  *Steps:*
  1. List the internal services and their addresses from the architecture document.
  2. From a test client in the network, call a service directly without a gateway.
  3. Send requests without the headers that the gateway adds.
  4. Check the network rules that restrict direct access.
  *Example:* `curl http://orders.internal:8080/v1/orders/1 from a test pod; kubectl get networkpolicy; nmap of the service ports.`  
  *Expected:* Services accept calls only from the gateway or from authenticated services. Direct calls without checks fail.  
  *Refs:* api_top10: API2:2023; cheatsheet: Microservices_Security_Cheat_Sheet; cwe: CWE-306, CWE-284  
  *See:* WEB-TLS-011, WEB-CONF-015

- [ ] **API-MSVC-002** Test object and tenant rules at each service behind the gateway  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds services that rely on the edge for object and tenant checks.  
  *Steps:*
  1. Send calls to an internal service with the identity of user A and an object of user B.
  2. Change the tenant in the call.
  3. Check each internal hop for its own checks.
  4. Check that denials are logged.
  *Example:* `curl -H 'X-User-Id: <idA>' http://orders.internal/v1/orders/<idB> from a test pod; Postman against the service address.`  
  *Expected:* Each service enforces object, tenant and business rules itself. Edge checks are not the only protection.  
  *Refs:* api_top10: API1:2023, API5:2023; asvs: V8.2.2; cheatsheet: Microservices_Security_Cheat_Sheet; cwe: CWE-639, CWE-285  
  *See:* WEB-AUTHZ-011, WEB-AUTHZ-012

- [ ] **API-MSVC-003** Test identity propagation between services  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds forged or reused user context headers and tokens between services.  
  *Steps:*
  1. Find how the user context moves between services: header, signed token or mTLS identity.
  2. Change the user ID or role in the context.
  3. Send a call with a context for a user without the caller service identity.
  4. Replay a context after the token has expired.
  *Example:* `curl with a changed X-User header; jwt_tool on the internal token; Burp between two test services.`  
  *Expected:* Services check the integrity of the user context. They authenticate the service that makes the call separately from the user.  
  *Refs:* api_top10: API2:2023; cheatsheet: Microservices_Security_Cheat_Sheet; cwe: CWE-290, CWE-345  
  *See:* WEB-AUTHZ-011

- [ ] **API-MSVC-004** Check service-to-service authentication and token validation  
  *Severity if fail:* High | *Type:* Manual | *Level:* ASVS L3  
  *Objective:* Finds internal calls with no authentication, weak tokens or slow revoke.  
  *Steps:*
  1. List the authentication method for each service call: mTLS or tokens.
  2. Call a service without a client certificate or token.
  3. Use a token meant for another service.
  4. Revoke a token. Measure how long it still works. Check that a failed validation rejects the call.
  *Example:* `openssl s_client -cert; curl with a token for another audience; introspection endpoint checks.`  
  *Expected:* Internal calls need mTLS or a validated token. Revoke takes effect in a known time. Failed validation rejects the request.  
  *Refs:* api_top10: API2:2023; asvs: V12.3.5; cheatsheet: Microservices_Security_Cheat_Sheet; cwe: CWE-306, CWE-287  
  *See:* WEB-TLS-011, WEB-ARCH-003

- [ ] **API-MSVC-005** Review the architecture document for services, data flows and API definitions  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds absent records of services, relations, data assets and API definitions.  
  *Steps:*
  1. Read the list of services, stores and queues with their API definitions.
  2. Read the list of service-to-service and service-to-store relations.
  3. Compare with the real traffic and the cluster objects.
  4. Mark services that have no entry or that have broad scopes.
  *Example:* `kubectl get svc -A; service mesh traffic graph; comparison with the architecture document.`  
  *Expected:* The document lists all services, relations, data assets and API definitions. Each service has least privilege scopes.  
  *Refs:* api_top10: API9:2023; cheatsheet: Microservices_based_Security_Arch_Doc_Cheat_Sheet; cwe: CWE-1059  
  *See:* WEB-ARCH-001

- [ ] **API-MSVC-006** Check the logs of a service architecture  
  *Severity if fail:* Low | *Type:* Config Review  
  *Objective:* Finds services that log secrets or cannot be traced across calls.  
  *Steps:*
  1. Make one call that passes through several services.
  2. Find the correlation ID in the log entries of each service.
  3. Look for secrets and tokens in the logs.
  4. Check that the log agent and broker use mutual authentication.
  *Example:* `Search in the central log system for the request ID; review of the agent and broker configuration.`  
  *Expected:* Each service logs a correlation ID and no secrets. Log transport is authenticated and encrypted.  
  *Refs:* cheatsheet: Microservices_Security_Cheat_Sheet; cwe: CWE-532, CWE-778  
  *See:* WEB-LOG-013


## RES

- [ ] **API-RES-001** Find out what each rate limit is based on  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds rate limits that one client can bypass with a new IP, key or session.  
  *Steps:*
  1. Send requests to an expensive endpoint until the API returns 429. Record the count and the time window.
  2. Change the source IP header, the user agent and the client ID. Send again.
  3. Log in as a second user and repeat. Check if the limit is per user or per key.
  4. Check if an authenticated session removes the limit.
  *Example:* `Burp Turbo Intruder; ffuf -rate; curl with X-Forwarded-For set to random values; record the 429 point and the Retry-After header.`  
  *Expected:* Limits apply per account and per API key, not only per IP. A header change or a login does not remove the limit.  
  *Refs:* api_top10: API4:2023; cheatsheet: REST_Assessment_Cheat_Sheet, REST_Security_Cheat_Sheet; cwe: CWE-770, CWE-799; capec: CAPEC-125; attack: T1499  
  *See:* WEB-BIZ-009

- [ ] **API-RES-002** Test the page size and the number of records per response  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds endpoints that return very large result sets in one response.  
  *Steps:*
  1. Find parameters such as limit, page_size, per_page and count.
  2. Send very large, zero and negative values.
  3. Send a request without a page size and check the default.
  4. Compare the response size and time.
  *Example:* `curl 'https://api.example/v1/items?limit=1000000'; Burp Intruder with a number list for the limit parameter.`  
  *Expected:* The API enforces a maximum page size on the server. Invalid values give 400 or the default value.  
  *Refs:* api_top10: API4:2023; cheatsheet: REST_Assessment_Cheat_Sheet, REST_Security_Cheat_Sheet; cwe: CWE-770, CWE-400; capec: CAPEC-130

- [ ] **API-RES-003** Test the limits for body size, string length and array size  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds endpoints that accept very large payloads.  
  *Steps:*
  1. Send a body that is larger than the documented maximum.
  2. Send a string with a length far over the field limit.
  3. Send an array with many thousands of elements.
  4. Send deeply nested JSON.
  *Example:* `curl --data-binary @big.json -H 'Content-Type: application/json' https://api.example/v1/items; python -c to build a nested JSON file; check for HTTP 413.`  
  *Expected:* The API rejects oversize requests with 413 or 400 before it does costly work. Limits exist at the gateway and in the service.  
  *Refs:* api_top10: API4:2023; cheatsheet: REST_Security_Cheat_Sheet, Web_Service_Security_Cheat_Sheet; cwe: CWE-770, CWE-400; capec: CAPEC-130; attack: T1499  
  *See:* WEB-ARCH-010

- [ ] **API-RES-004** Test file upload size limits and the work after the upload  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds upload endpoints where a large or many files use too much memory or CPU.  
  *Steps:*
  1. Find endpoints that take files or Base64 data and process them, for example thumbnails.
  2. Send a file over the size limit.
  3. Send many small uploads in parallel.
  4. Watch the server time and memory in a test environment.
  *Example:* `curl -F file=@big.png https://api.example/v1/avatar; Turbo Intruder with 50 parallel uploads; monitoring graphs of the test host.`  
  *Expected:* The API checks the size before it processes the file. The number of uploads and the work per upload have limits.  
  *Refs:* api_top10: API4:2023; cheatsheet: Denial_of_Service_Cheat_Sheet, REST_Security_Cheat_Sheet; cwe: CWE-770, CWE-400; capec: CAPEC-130  
  *See:* WEB-FILE-003

- [ ] **API-RES-005** Test slow requests and operations that run too long  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds absent timeouts for slow clients and for expensive queries.  
  *Steps:*
  1. Open a connection and send the request headers or the body very slowly.
  2. Send expensive search, sort and filter requests.
  3. Measure the time until the server stops the request.
  4. Compare with the documented timeout.
  *Example:* `slowhttptest -c 1000 -H -u https://test.api.example/ ; curl --limit-rate 10; a search request with a wildcard filter.`  
  *Expected:* The server closes slow connections and stops long requests after a set time. Minimum data rates and absolute timeouts exist.  
  *Refs:* api_top10: API4:2023; cheatsheet: Denial_of_Service_Cheat_Sheet; cwe: CWE-400, CWE-770; capec: CAPEC-125; attack: T1499

- [ ] **API-RES-006** Check that costly third-party calls are limited per target and per account  
  *Severity if fail:* High | *Type:* Manual, Config Review  
  *Objective:* Finds endpoints that trigger paid SMS, email or other provider calls without a limit.  
  *Steps:*
  1. Find endpoints that make the back end call a paid provider, such as SMS or email.
  2. Send many requests for the same phone number and for different numbers.
  3. Count the provider calls in the test sandbox of the provider.
  4. Check the cost limits and cost alerts at the provider.
  *Example:* `Mock provider or sandbox account; Burp Turbo Intruder on POST /initiate_forgot_password; review of provider billing settings.`  
  *Expected:* The API limits requests per target and per account. The provider account has a cost limit or a cost alert.  
  *Refs:* api_top10: API4:2023; cheatsheet: REST_Assessment_Cheat_Sheet; cwe: CWE-770, CWE-799

- [ ] **API-RES-007** Check the limit on single operations such as OTP check and recovery  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds operations that a client can repeat without a limit, for example OTP checks.  
  *Steps:*
  1. List operations that must have a low repeat count: OTP check, recovery and coupon check.
  2. Repeat each operation many times with one account.
  3. Note the count where the API blocks or delays.
  4. Repeat the test with a second token of the same account.
  *Example:* `Burp Turbo Intruder with a 6-digit OTP range on a test account; Postman runner with 100 iterations.`  
  *Expected:* Each sensitive operation has its own low limit per account. A new token does not reset the count.  
  *Refs:* api_top10: API4:2023; cheatsheet: REST_Assessment_Cheat_Sheet; cwe: CWE-799, CWE-307; capec: CAPEC-112; attack: T1110  
  *See:* WEB-MFA-003

- [ ] **API-RES-008** Check that limits bound the work of one request  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds endpoints where one request does a large amount of work.  
  *Steps:*
  1. Find search, export, bulk write and report endpoints.
  2. Send one request that asks for the maximum work, such as a full export.
  3. Send the same request in parallel up to the rate limit.
  4. Compare the server load with a normal request.
  *Example:* `curl 'https://api.example/v1/export?format=csv&all=true'; bulk write with 10000 items; load graph in the test environment.`  
  *Expected:* Costly operations have limits on the work per request, such as items and time, and on concurrent runs per client.  
  *Refs:* api_top10: API4:2023; cheatsheet: REST_Assessment_Cheat_Sheet, Web_Service_Security_Cheat_Sheet; cwe: CWE-770, CWE-400; capec: CAPEC-130  
  *See:* WEB-ARCH-010

- [ ] **API-RES-009** Check CPU, memory and process limits of the API runtime  
  *Severity if fail:* Medium | *Type:* Config Review  
  *Objective:* Finds services that can use all the memory, file descriptors or processes of the host.  
  *Steps:*
  1. Read the container or serverless settings of each API service.
  2. Look for limits on memory, CPU, restarts, file descriptors and processes.
  3. Check the limits for open connections and simultaneous files.
  4. Check the alerts for the limits.
  *Example:* `kubectl describe pod and docker inspect for limits; ulimit -a in the container; review of the deployment files.`  
  *Expected:* Each API service has limits for memory, CPU, file descriptors and processes. Alerts show when a limit is near.  
  *Refs:* api_top10: API4:2023; cheatsheet: Web_Service_Security_Cheat_Sheet, Denial_of_Service_Cheat_Sheet; cwe: CWE-770, CWE-400


## REST

- [ ] **API-REST-001** Build a security test matrix from the OpenAPI description  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds operations whose real security rule differs from the rule in the description.  
  *Steps:*
  1. Import the OpenAPI file. Read the global security rule and each operation override.
  2. Build a table of operation, method, required scheme and required scope or role.
  3. Call each operation with every credential type and role in the table.
  4. Mark each result that differs from the table.
  *Example:* `Schemathesis; ZAP OpenAPI add-on; Burp OpenAPI Parser; Postman collection generated from openapi.json; Newman for the matrix.`  
  *Expected:* The behavior of each operation matches its documented security rule. No operation allows more than the table says.  
  *Refs:* api_top10: API2:2023, API5:2023, API9:2023; wstg: WSTG-APIT-01; cheatsheet: REST_Assessment_Cheat_Sheet; cwe: CWE-862, CWE-287  
  *See:* WEB-AUTHZ-004

- [ ] **API-REST-002** Mutate valid requests one constraint at a time from the schema  
  *Severity if fail:* Medium | *Type:* Automated  
  *Objective:* Finds endpoints that fail or misbehave when a field leaves its declared type or range.  
  *Steps:*
  1. Send a valid request that follows the declared types, required fields and enum values.
  2. Change one constraint at a time: type, length, range, enum value or a required field.
  3. Record every 5xx response, every accepted invalid value and every long delay.
  4. Check that the server rejects the bad value with 400.
  *Example:* `schemathesis run openapi.json --checks all; RESTler fuzz; ZAP OpenAPI active scan; Burp Intruder on single fields.`  
  *Expected:* The API rejects each invalid value with 400 or 422 and a generic message. No 5xx response occurs.  
  *Refs:* api_top10: API8:2023; wstg: WSTG-APIT-01; cheatsheet: REST_Assessment_Cheat_Sheet, REST_Security_Cheat_Sheet; cwe: CWE-20; capec: CAPEC-28  
  *See:* WEB-VAL-012

- [ ] **API-REST-003** Find hidden parameters in headers, URL segments and structured values  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds API inputs that the description and the user interface do not show.  
  *Steps:*
  1. Record full requests with a proxy while you use all functions with accounts of each role.
  2. Look for unusual headers and URL segments that repeat with different values.
  3. Find structured values in JSON, XML or custom formats.
  4. Test suspected segments with an invalid value to see if they are parameters.
  *Example:* `Burp Param Miner; Arjun; ZAP spider with the AJAX spider; ffuf for parameter names.`  
  *Expected:* All inputs are known and documented. Unknown inputs are ignored or rejected.  
  *Refs:* wstg: WSTG-APIT-01; cheatsheet: REST_Assessment_Cheat_Sheet; cwe: CWE-1059; capec: CAPEC-215  
  *See:* WEB-INFO-006

- [ ] **API-REST-004** Check that each endpoint allows only the documented HTTP methods  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds endpoints that accept methods which the API does not need.  
  *Steps:*
  1. Send OPTIONS to each endpoint of the API description and read the Allow header.
  2. Compare the Allow header with the methods that the API description lists.
  3. Send each other method, also HEAD, and check for 405.
  4. Check that the caller may use each allowed method on the object.
  *Example:* `curl -i -X OPTIONS https://api.example/v1/items; Burp Intruder with a list of HTTP methods.`  
  *Expected:* Only documented methods work. Other methods return 405. Authorization checks also apply to each allowed method.  
  *Refs:* api_top10: API8:2023; cheatsheet: REST_Security_Cheat_Sheet; cwe: CWE-650  
  *See:* WEB-CONF-008

- [ ] **API-REST-005** Check that input is validated for type, length, range and unexpected fields  
  *Severity if fail:* Medium | *Type:* Manual | *Level:* ASVS L1  
  *Objective:* Finds endpoints that process unchecked input from JSON, XML or form bodies.  
  *Steps:*
  1. Send wrong types, negative numbers, empty strings and values over the length limit.
  2. Send extra fields and repeated fields.
  3. Send injection test strings in every field.
  4. Send XML with external entities if the endpoint accepts XML.
  *Example:* `Burp Intruder with a type-confusion list; curl -d '{"qty":"abc"}'; ZAP active scan.`  
  *Expected:* The API checks each field on the server against a schema or allowlist. Unexpected content gives 400 and a log entry.  
  *Refs:* api_top10: API8:2023; asvs: V2.2.1; cheatsheet: REST_Security_Cheat_Sheet, Input_Validation_Cheat_Sheet; cwe: CWE-20; capec: CAPEC-137  
  *See:* WEB-VAL-012, WEB-INJ-001, WEB-INJ-008

- [ ] **API-REST-006** Check that status codes do not reveal more than needed  
  *Severity if fail:* Low | *Type:* Manual  
  *Objective:* Finds APIs that use wrong status codes or show if a hidden object exists.  
  *Steps:*
  1. Request objects that exist, that do not exist and that belong to others.
  2. Compare status codes and bodies. Look for 200 with an error text in the body.
  3. Request protected routes without a token (401) and with a weak role (403).
  4. Check for a generic 500 body.
  *Example:* `curl -i for each case; Burp Comparer; Postman tests with expected status codes.`  
  *Expected:* The API uses 401, 403, 404, 405, 413, 415, 429 and 5xx as defined. It does not show whether an object of another user exists.  
  *Refs:* cheatsheet: REST_Security_Cheat_Sheet; cwe: CWE-204, CWE-209

- [ ] **API-REST-007** Check the audit log of API security events  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds absent or unsafe logs for authentication, token and validation failures.  
  *Steps:*
  1. Make failed logins, bad tokens, denied calls and validation errors in a test environment.
  2. Find each event in the log system.
  3. Check the fields: who, when, where, what and a request ID.
  4. Send log injection test strings. Check that secrets are not logged.
  *Example:* `Splunk or Kibana search for the test request ID; curl with a header that holds a newline marker in a test environment.`  
  *Expected:* Security events are logged before and after the action with a request ID. Log data is cleaned and holds no secrets.  
  *Refs:* cheatsheet: REST_Security_Cheat_Sheet; cwe: CWE-778, CWE-117, CWE-532  
  *See:* WEB-LOG-002, WEB-AUTHZ-018


## SOAP

- [ ] **API-SOAP-001** Check that SOAP messages are validated against the XML schema  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds SOAP services that accept messages that do not match the schema.  
  *Steps:*
  1. Read the XSD of the service for maximum lengths, character sets and patterns.
  2. Send messages with wrong types, fields over the length limit and unexpected elements.
  3. Send malformed XML.
  4. Check that each is rejected.
  *Example:* `SoapUI security tests; Burp WSDL Wizard and Scanner; ZAP WSDL import.`  
  *Expected:* The service validates each message against the XSD. The schema sets length, character set and patterns for every field.  
  *Refs:* cheatsheet: Web_Service_Security_Cheat_Sheet; cwe: CWE-20  
  *See:* WEB-INJ-007

- [ ] **API-SOAP-002** Test SOAP endpoints against oversize, recursive and expanded XML  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds services that use too many resources for large, deep or expanded XML.  
  *Steps:*
  1. Send a message over the size limit.
  2. Send deeply nested elements and very long element names.
  3. Send a message with entity expansion in a test environment.
  4. Watch CPU, memory and response time.
  *Example:* `SoapUI with a generated large message; Burp Intruder; a small billion-laughs file on a test system.`  
  *Expected:* The parser rejects oversize, recursive messages and entity expansion. A message size limit and resource limits exist.  
  *Refs:* api_top10: API4:2023; cheatsheet: Web_Service_Security_Cheat_Sheet; cwe: CWE-776, CWE-400, CWE-611; capec: CAPEC-528  
  *See:* WEB-INJ-008

- [ ] **API-SOAP-003** Check authentication and authorization for each SOAP method  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds web service methods that are open or that rely on weak authentication.  
  *Steps:*
  1. Call each method without credentials.
  2. Check whether Basic authentication works over plain HTTP.
  3. Call administrative methods as a normal client.
  4. Check for client certificate use for sensitive services.
  *Example:* `SoapUI with and without WS-Security headers; curl --cacert --cert for mTLS; Burp Autorize.`  
  *Expected:* TLS protects every call. Each method checks the rights of the client. Administrative methods are separate and limited.  
  *Refs:* api_top10: API5:2023; cheatsheet: Web_Service_Security_Cheat_Sheet; cwe: CWE-306, CWE-862, CWE-285  
  *See:* WEB-AUTHZ-004

- [ ] **API-SOAP-004** Check message integrity, confidentiality and attachment scans  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds sensitive SOAP data without signature, message encryption or file scans.  
  *Steps:*
  1. Find messages with sensitive data that are stored or forwarded after receipt.
  2. Check for XML signatures and for encryption of sensitive elements.
  3. Change a signed element. Check that the service rejects it.
  4. Send a test file with the EICAR string as an attachment.
  *Example:* `SoapUI WS-Security configuration; xmlsec1 to check signatures; EICAR test file.`  
  *Expected:* Sensitive messages use signatures and element encryption beyond TLS. Attachments are scanned before they are stored.  
  *Refs:* cheatsheet: Web_Service_Security_Cheat_Sheet; cwe: CWE-345, CWE-311, CWE-434  
  *See:* WEB-HTTP-003, WEB-FILE-003


## SSRF

- [ ] **API-SSRF-001** Find API parameters that make the server fetch a URL  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds API features such as webhooks, import and preview that call client-supplied URLs.  
  *Steps:*
  1. Search the API description and the client code for parameters named url, uri, callback, webhook and image_url.
  2. Look for features that fetch files, send test requests or build link previews.
  3. Send a URL to a server that you control. Look for a request in its log.
  4. Write down the source IP, headers and protocol of each request.
  *Example:* `Burp Collaborator or interactsh-client for an out-of-band URL; Burp Param Miner; example body: {"picture_url":"https://<collaborator>/p.jpg"}.`  
  *Expected:* Every URL parameter is known and documented. Each one is tied to an allowlist or a controlled fetch service.  
  *Refs:* api_top10: API7:2023; cheatsheet: Server_Side_Request_Forgery_Prevention_Cheat_Sheet; cwe: CWE-918; capec: CAPEC-664; attack: T1190  
  *See:* WEB-INJ-021

- [ ] **API-SSRF-002** Test URL parameters for access to internal addresses and ports  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds API endpoints that call loopback, private or internal hosts for the client.  
  *Steps:*
  1. Send a URL that points to the loopback address or an internal host name.
  2. Send private network addresses and a different port for each request.
  3. Compare the response time and the error text for open and closed ports.
  4. Read the response body for data of the internal service.
  *Example:* `Burp Intruder on the url parameter with an internal address list; compare response times in Burp Logger.`  
  *Expected:* The API refuses internal and private targets. Errors and response time do not show which internal ports are open.  
  *Refs:* api_top10: API7:2023; cheatsheet: Server_Side_Request_Forgery_Prevention_Cheat_Sheet; cwe: CWE-918; capec: CAPEC-664; attack: T1190  
  *See:* WEB-INJ-021

- [ ] **API-SSRF-003** Test webhook creation and test requests for response disclosure  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds webhook features that show the response of the target to the user.  
  *Steps:*
  1. Create a webhook that points to a server that you control.
  2. Check the options that send a test request at creation time.
  3. Create a webhook to an internal address. Read the API response and the delivery log.
  4. Check if the full response body of the target returns to the client.
  *Example:* `POST /graphql createNotificationChannel with a callback URL; interactsh for blind calls; read the delivery history endpoint.`  
  *Expected:* The API does not send raw responses of the target back to the client. Internal targets are refused at creation and at delivery.  
  *Refs:* api_top10: API7:2023; cheatsheet: Server_Side_Request_Forgery_Prevention_Cheat_Sheet; cwe: CWE-918, CWE-200; capec: CAPEC-664  
  *See:* WEB-INJ-021

- [ ] **API-SSRF-004** Test if the fetch follows redirects to internal targets  
  *Severity if fail:* High | *Type:* Manual, Code Review  
  *Objective:* Finds fetch code that follows redirects and so passes the allowlist check.  
  *Steps:*
  1. Host a URL on an allowed domain that sends a redirect to an internal address.
  2. Send this URL in the API parameter.
  3. Look at the logs of the redirect target.
  4. Check the option for redirects in the HTTP client.
  *Example:* `python -m http.server with a 302 handler; interactsh as the redirect target; code review of the HTTP client options.`  
  *Expected:* The fetch client does not follow redirects, or it checks each redirect target with the same rules.  
  *Refs:* api_top10: API7:2023; cheatsheet: Server_Side_Request_Forgery_Prevention_Cheat_Sheet; cwe: CWE-918, CWE-601; capec: CAPEC-664

- [ ] **API-SSRF-005** Test URL parser differences and allowlist bypass cases  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds allowlists that fail because of URL parser differences or address forms.  
  *Steps:*
  1. Send URLs with user info, extra dots, mixed case and alternative IP notations.
  2. Send an IPv4-mapped IPv6 address and a name with more than one A record.
  3. Send a name that resolves to a public address and then to a private one.
  4. Check that the check and the request use the same parsed host.
  *Example:* `Burp Intruder with a list of URL forms and address notations; a DNS test domain with short TTL.`  
  *Expected:* The API uses one URL parser. It checks the resolved IP address, binds the request to it and normalizes addresses before it compares them.  
  *Refs:* api_top10: API7:2023; cheatsheet: Server_Side_Request_Forgery_Prevention_Cheat_Sheet; cwe: CWE-918; capec: CAPEC-664  
  *See:* WEB-HTTP-006

- [ ] **API-SSRF-006** Check the allowed schemes, ports and media types of fetch features  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds fetch features that accept protocols or content that the feature does not need.  
  *Steps:*
  1. Read which schemes and ports the fetch feature must use.
  2. Send file, ftp and other non-HTTP schemes.
  3. Send ports that are not on the allowlist.
  4. Send a URL that returns a type that the feature does not expect.
  *Example:* `curl -X POST https://api.example/api/profile/upload_picture -d '{"picture_url":"file:///etc/hostname"}' on a test system.`  
  *Expected:* Only the listed schemes, ports and media types work. Other values give a generic 400 error.  
  *Refs:* api_top10: API7:2023; cheatsheet: Server_Side_Request_Forgery_Prevention_Cheat_Sheet; cwe: CWE-918, CWE-20; capec: CAPEC-664  
  *See:* WEB-ARCH-004

- [ ] **API-SSRF-007** Check outbound network rules and metadata service protection  
  *Severity if fail:* High | *Type:* Config Review  
  *Objective:* Finds hosts that can reach internal services and cloud metadata from the API process.  
  *Steps:*
  1. Read the egress firewall and network policy for the hosts that fetch URLs.
  2. From a test host, call the cloud metadata address of the provider.
  3. Check that the metadata service needs a session token header (IMDSv2) and that the old version is off.
  4. Check that fetch workers run in a separate network segment.
  *Example:* `aws ec2 describe-instances --query HttpTokens; kubectl get networkpolicy; curl to the metadata address from a test pod.`  
  *Expected:* Fetch workers can reach only needed targets. The metadata service is protected and the old version is off.  
  *Refs:* api_top10: API7:2023, API8:2023; cheatsheet: Server_Side_Request_Forgery_Prevention_Cheat_Sheet; cwe: CWE-918, CWE-668; capec: CAPEC-664; attack: T1552.005  
  *See:* WEB-ARCH-004, WEB-CONF-001


## WS

- [ ] **API-WS-001** Test authorization of each WebSocket message and action  
  *Severity if fail:* High | *Type:* Manual  
  *Objective:* Finds sockets where a valid connection gives access to all actions and objects.  
  *Steps:*
  1. Open a connection as a normal user with a valid token.
  2. Send messages for admin actions and for objects of another user.
  3. Subscribe to channels of another user.
  4. Check the authorization again after a role change.
  *Example:* `wscat -c wss://api.example/ws -H 'Authorization: Bearer <token>'; Burp WebSockets history and Repeater; ZAP WebSocket tab.`  
  *Expected:* The server checks the role and the object for each message. A connection is not full access.  
  *Refs:* api_top10: API1:2023, API5:2023; cheatsheet: WebSocket_Security_Cheat_Sheet; cwe: CWE-285, CWE-639  
  *See:* WEB-HTTP-009, WEB-IDOR-001

- [ ] **API-WS-002** Test WebSocket message validation, size and flood limits  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds sockets that accept malformed, oversize or very frequent messages.  
  *Steps:*
  1. Send messages that break the JSON schema.
  2. Send injection test strings in each field.
  3. Send a message larger than the limit.
  4. Send many messages in a short time.
  *Example:* `wscat; Burp WebSocket Turbo Intruder; custom Python websockets script in a test environment.`  
  *Expected:* The server checks each message against a schema, limits size to a small value and limits the message rate per client.  
  *Refs:* api_top10: API4:2023; cheatsheet: WebSocket_Security_Cheat_Sheet, Input_Validation_Cheat_Sheet; cwe: CWE-20, CWE-770; capec: CAPEC-125

- [ ] **API-WS-003** Test connection limits, idle timeouts and backpressure  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds sockets that let one client hold many connections or fill server memory.  
  *Steps:*
  1. Open many connections from one user and one IP.
  2. Leave connections idle. Measure the time until the server closes them.
  3. Send data fast and read slowly.
  4. Check the heartbeat frames.
  *Example:* `Python script with asyncio and websockets; Artillery WebSocket engine; monitor server memory.`  
  *Expected:* The server limits connections per user. Idle and dead connections close. Memory use stays bound under fast producers.  
  *Refs:* api_top10: API4:2023; cheatsheet: WebSocket_Security_Cheat_Sheet; cwe: CWE-770, CWE-400; attack: T1499

- [ ] **API-WS-004** Check WebSocket session end, replay protection and logs  
  *Severity if fail:* Medium | *Type:* Manual  
  *Objective:* Finds sockets that stay open after logout or token expiry and leave no audit trail.  
  *Steps:*
  1. Open a connection. Log out or let the token expire.
  2. Check if the connection closes and if messages still work.
  3. Replay a captured message.
  4. Look in the logs for connect, close, denied and flood events.
  *Example:* `wscat with a recorded message; Burp WebSockets history; log search for the connection ID.`  
  *Expected:* Connections close at logout and token expiry. Messages use nonces or timestamps. Security events are logged without secrets.  
  *Refs:* cheatsheet: WebSocket_Security_Cheat_Sheet; cwe: CWE-294, CWE-778  
  *See:* WEB-HTTP-009
