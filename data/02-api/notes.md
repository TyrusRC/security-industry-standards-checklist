# API sheet notes

## Counts
114 tests in 16 files (bola, bfla, bopla, authn, res, flow, ssrf, conf, inv, cons, gql, grpc, ws, rest, soap, msvc).
Per risk (tests with the api_top10 ref): API1=12, API2=16, API3=7, API4=21, API5=13, API6=7, API7=7, API8=15, API9=13, API10=6.
WSTG-APIT-01, 02, 03, 04 and 99 are all in refs. WSTG-BUSL-05, 06, 07 are in refs (FLOW).
All 13 cheat sheets that were read are cited (GraphQL, REST_Security, REST_Assessment, Mass_Assignment, Web_Service_Security,
Denial_of_Service, IDOR_Prevention, SSRF_Prevention, Microservices_Security, Microservices_based_Security_Arch_Doc, gRPC, WebSocket, Input_Validation).

## Merge decisions
- ASVS V4, V9 and V10: every requirement is already used by a WEB test. The API sheet writes no copy and adds no `refs.asvs` for V4, V9 or V10.
  API tests that touch the same control carry `see: [WEB-...]` (for example API-REST-004 and WEB-CONF-008, API-CONS-005 and WEB-HTTP-003).
  `level` follows the lowest level of the ASVS refs of the test. A test with no ASVS ref has no `level`.
- JWT, OAuth and OIDC: no API test. Only API-AUTHN-009 (malformed and under-scoped tokens on every operation) points to WEB-JWT-001/005 and WEB-OAUTH-007.
- GraphQL introspection, field suggestions, depth and cost limits stay in WEB-HTTP-007/008. The API sheet covers batching and alias bypass,
  node and edge authorization, mutation roles, injection, underlying API exposure and errors (API-GQL-*).
- WebSocket origin, WSS and session tokens stay in WEB-HTTP-009 and WEB-CLIENT-004. API-WS-* covers per-message authorization, validation, limits and session end.
- Mass assignment: WEB has WEB-INJ-022, WEB-ARCH-006 and WEB-AUTHZ-007. API-BOPLA-004/005/006 add the API view (WSTG-APIT-03, hidden properties, OpenAPI diff, binding review).
- IDOR: WEB-IDOR-001..005 stay in WEB. API-BOLA-* are the API variants (WSTG-APIT-02), with `see`.
- API8 tests (CONF) are thin API views of WEB controls (TLS, headers, CORS, errors, smuggling). They keep API-specific steps and `see` pointers.
- Business logic: WEB-BIZ-* own WSTG-BUSL-*. API-FLOW-* add API6 and the out-of-order execution check from REST_Security.

## Not used or not available
- `JSON_Web_Token_for_Java_Cheat_Sheet.md` does not exist in sources. `JSON_Web_Token_Cheat_Sheet` was not opened, so it is not cited (JWT belongs to WEB).
- API Top 10 intro files (0x03, 0x04, 0x11) were not opened and are not cited.
- WSTG-APIT-00 (overview) was only skimmed for headings, so it is not in `sources_read`; it has no test ID.
- CWE-2, CWE-16, CWE-388 and CWE-840 (cited in the API8 text) and CWE-613 are not in catalog/cwe.json. They are left out.
- Attack IDs used: T1190, T1110, T1110.004, T1499, T1552.005, T1590, T1596, T1593, T1589, T1595.003 (all found in catalog/attack.json).

## Uncovered IDs
- WSTG-BUSL-01, 02, 03, 04, 08, 09, 10: owned by the WEB sheet (WEB-BIZ-*, WEB-FILE-*); not API-specific.
- Top10 API intro and "next steps" files give no testable control.
- API tests for SSE, MQTT and other API styles: no source text was read, so no test.
