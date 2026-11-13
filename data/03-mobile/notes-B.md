# Notes for slice MOB-B (PLATFORM, CODE, RESILIENCE, PRIVACY)

Files: ipc.yaml (13), webview.yaml (11), ui.yaml (7), code.yaml (10), resil.yaml (18), priv.yaml (16). Total 75 tests.

Coverage (checked with a script against the refs of these six files):
- All 15 MASVS controls of PLATFORM-1..3, CODE-1..4, RESILIENCE-1..4, PRIVACY-1..4 are in refs.
- All 118 MASTG tests of these four folders (tests-beta, Android and iOS) are in refs. This includes the six placeholder tests (MASTG-TEST-0255, 0256, 0257, 0292, 0293, 0294). Their only content is a note, so the steps in the related tests follow that note text.
- All 49 MASWE weaknesses of these four chapters are in refs. Mobile Top 10 2024 M2, M4, M6, M7 and M8 are in refs.
- The deprecated MASTG v1 tests (folder tests/) are excluded. The beta tests list the replacements.

Decisions:
- The beta MASTG tests have no MASVS ID in their front matter. The group of each test comes from its folder path (for example tests-beta/android/MASVS-PLATFORM).
- Static, dynamic, Android and iOS variants of one control are merged into one test with "Android:" and "iOS:" step prefixes.
- Level: the MASVS control files have no level. The level comes from the profiles field of the MASWE weakness (L1, L2, R, P). A test with several profiles uses the lowest, for example "MASVS L1". The privacy weaknesses have only the profile P, so those tests use "MASVS P". The schema does not list P. Change it if the build tool needs only L1, L2 and R.
- The 2024 Mobile Top 10 text is in sources/repos/www-project-mobile-top-10/2023-risks/ (the index.md of the repository links the 2024 list to these files). MASWE text is in sources/mastg/files/ (flat copies). MASTG-TECH files are in sources/repos/mastg/techniques/.
- Tests outside the folders of this slice that sit in my refs because the MASTG test is in my folder: MASTG-TEST-0355..0357 and 0364..0366 (MASWE-0018, a weakness in the AUTH chapter), MASTG-TEST-0246..0249 (MASWE-0017, CRYPTO chapter), MASTG-TEST-0320 (MASWE-0001, STORAGE chapter).
- MASWE with no MASTG test are written from the MASWE text only: 0030 (Android clipboard steps), 0042, 0046, 0047, 0048, 0049, 0052, 0054, 0055, 0056 (backend part), 0060, 0062, 0065, 0067-0072, 0075-0078. The steps follow the modes of introduction and mitigations in the weakness text.
- MASTG-TEST-0372, 0374, 0375 and 0398..0400 sit in the CODE folder but belong to IPC and WebView topics. They are in ipc.yaml and webview.yaml with MASVS-CODE-4 in refs.
- MOB-RESIL-005 (secure screen lock) maps to MASVS-CRYPTO-2 in MASWE-0017. It has a pointer to MOB-CRYPTO-016 from the MOB-A slice. MOB-UI-002 and MOB-UI-003 point to MOB-STORAGE-008 (iOS keyboard caching). Merge or remove the duplicates when the sheets are joined.
- Possible overlap with the MOB-A slice, not changed: MOB-AUTH-008 (system flows for OAuth) and MOB-PRIV-009 (system authentication sessions as a privacy option); MOB-STORAGE-009 (hardcoded secrets) is not in this slice.
- Cheat sheets read: Mobile_Application_Security_Cheat_Sheet (all), Software_Supply_Chain_Security_Cheat_Sheet (dependency, build and runtime sections), Dependency_Graph_SBOM_Cheat_Sheet, Vulnerable_Dependency_Management_Cheat_Sheet (tools section), Input_Validation_Cheat_Sheet, Third_Party_Javascript_Management_Cheat_Sheet (defense sections), Deserialization_Cheat_Sheet (Java and language-agnostic sections). User_Privacy_Protection_Cheat_Sheet was read but is written for web apps, so it is not cited.
- No nist_800_53 or capec refs were added. No NIST item came from a source text that this slice read.
- Examples are hints. Commands follow the MASTG-TECH files. Frida script names (hook_*.js) are placeholders for scripts that the tester writes.
