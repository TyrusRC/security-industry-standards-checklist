# Test-case schema (YAML, one list per file in data/<NN-sheet>/<category>.yaml)

Required fields: id, sheet, category, title, objective, steps, expected, severity, test_type, refs, sources_read
Optional: preconditions, example, level, notes, see (list of IDs that cover the same control in another sheet)

- id: `<SHEET>-<CAT>-<NNN>`; SHEET in WEB API MOB CLD K8S NET LLM CICD PCI NIST PRIV DESK IOT. Unique and never reused.
- title: one imperative sentence, max 12 words.
- objective: one sentence, what weakness this test finds.
- preconditions: list of strings (accounts, scope, tools).
- steps: list of strings. One action per string. Imperative. Max 20 words each.
- example: ONE string holding all payloads, commands and tool hints for the test (the "example" column).
- expected: pass criteria. Describe the SAFE behavior. Max 25 words per sentence.
- severity: Critical | High | Medium | Low | Info (see severity-rubric.md). Severity if the test FAILS.
- test_type: Manual | Automated | Config Review | Code Review (list allowed).
- level: ASVS L1/L2/L3, MASVS L1/L2/R/P (P = privacy profile from MASWE profiles), CIS L1/L2 (string, optional).
- refs: mapping to every standard item the test covers. Keys:
  owasp_top10, api_top10, mobile_top10, llm_top10, agentic_top10, k8s_top10, cicd_top10, cloud_native_top10, privacy_top10, desktop_top10, iot_top10,
  wstg, asvs, masvs, mastg, maswe, cheatsheet, cwe, capec, attack, atlas, pci_dss, nist_800_53, cis, other.
  Each value is a list of IDs that EXIST in catalog/*.json. `other` is free text.
- sources_read: list of file paths under sources/ that the author opened to write the test. Required. Empty list is an error.
- Merge rule: ONE test per verifiable control. If another source says the same, add its ID to refs. Do not write a second test.
  If the control already lives in another sheet, write no test. Add the ID to `see` in a short pointer row only if needed.

Tracking columns (Status, Evidence, Tester, Date, Notes) are added by tools/build.py. Do not write them in YAML.
