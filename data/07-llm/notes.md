# Notes for the LLM sheet (data/07-llm)

Total tests: 184. Files: agency 16, agent 33, data 13, dos 13, gov 7, mcp 10, misinfo 10, model 7, output 11, pinj 18, poison 7, rag 18, supply 14, sysprompt 7.
Severity counts: {'High': 82, 'Critical': 4, 'Medium': 83, 'Low': 15}.

## Edition mapping used for refs (map by title, not by number)
| Topic | 2025 | 2026 |
|---|---|---|
| Prompt Injection | LLM01 | LLM01 |
| Sensitive Information Disclosure | LLM02 | LLM02 |
| Supply Chain | LLM03 | LLM04 |
| Data and Model Poisoning | LLM04 | LLM05 |
| Improper Output Handling | LLM05 | LLM10 |
| Excessive Agency | LLM06 | LLM03 |
| System Prompt Leakage | LLM07 | LLM08 Hidden Context Exposure (re-scoped) |
| Vector and Embedding Weaknesses | LLM08 | LLM09 |
| Misinformation | LLM09 | LLM07 |
| Unbounded Consumption | LLM10 | LLM06 |

Both editions sit under refs.llm_top10 (the validator merges llm_top10 and llm_top10_2026). Every test that cites a pair uses the title mapping above.

## Merge decisions
- One test per verifiable control. A 2025 item, its 2026 successor, the related ASI item, ATLAS technique or mitigation and cheat sheet section share one test.
- ASI items that restate an LLM control (ASI02 with LLM06/LLM03, ASI05 with LLM05/LLM10, ASI04 with LLM03/LLM04) are merged into the LLM-side test in AGENCY, OUTPUT and SUPPLY. Agent-only controls (delegation, inter-agent trust, cascade, rogue agent, human trust) are in AGENT.
- LLM08:2026 Hidden Context Exposure is merged with LLM07:2025 System Prompt Leakage (SYSPROMPT). Its severity tiers were used: no secret = Low/Medium, credentials or authorization logic = High.
- Prompt injection is split by delivery surface (direct, role-play, multi-turn, encoded, suffix and best-of-N, payload splitting, web, document, invisible Unicode, markdown exfil, multimodal, MCP/trusted channel) and by control (separation, schema, filters, guardrail, adaptive test, unintentional, self-replication).
- MCP tests live in MCP and are linked from AGENCY and SUPPLY by the shared IDs LLM03:2026, LLM04:2026, ASI02, ASI04.
- Generic web controls are not repeated. The `see` field points to WEB-XSS, WEB-INJ, WEB-DEP, WEB-SECRET, WEB-ERR, WEB-CLIENT, WEB-BIZ and WEB-FILE tests (LLM-specific test kept because the model is the injection source).
- Tests are black-box with a canary string and a test-only rule in the system prompt. No real harmful content is used.
- NIST AI RMF and AI 600-1 are not cited as IDs (no local source). They are named in the LLM02:2026 text only.

## AITG test mapping (refs.other)
AITG-APP-01 PINJ-001, PINJ-002, PINJ-003, PINJ-004, PINJ-014; AITG-APP-02 PINJ-007, PINJ-008; AITG-APP-03 DATA-001; AITG-APP-04 DATA-004; AITG-APP-05 MISINFO-010, OUTPUT-001; AITG-APP-06 AGENCY-004, AGENCY-015, AGENT-032, DOS-008; AITG-APP-07 SYSPROMPT-001; AITG-APP-08 RAG-001, RAG-007; AITG-APP-09 DOS-009; AITG-APP-10 MISINFO-009; AITG-APP-11 MISINFO-002; AITG-APP-12 MISINFO-010; AITG-APP-13 MISINFO-007; AITG-APP-14 MISINFO-008; AITG-DAT-01 DATA-002, DATA-012; AITG-DAT-02 DATA-003, DATA-005, DATA-011; AITG-DAT-03 GOV-001; AITG-DAT-04 GOV-002; AITG-DAT-05 DATA-013, GOV-003; AITG-INF-01 SUPPLY-010; AITG-INF-02 DOS-001; AITG-INF-03 AGENCY-016; AITG-INF-04 AGENCY-001, AGENCY-006; AITG-INF-05 POISON-001, POISON-002; AITG-INF-06 SUPPLY-011; AITG-MOD-01 MODEL-001; AITG-MOD-02 AGENT-017, POISON-005; AITG-MOD-03 POISON-001; AITG-MOD-04 MODEL-002; AITG-MOD-05 MODEL-003, RAG-005; AITG-MOD-06 MODEL-004; AITG-MOD-07 MODEL-005, PINJ-002, POISON-003

## Uncovered or only partly covered
- All LLM01-10 (2025), LLM01-10 (2026) and ASI01-ASI10 IDs appear in refs of several tests.
- Not turned into tests because they are design or training choices, not verifiable controls: federated learning, homomorphic encryption, adversarial robustness training of the model, watermark design details, user education content.
- CloudBorne/CloudJacking (LLM03:2025 scenario 7) is covered only through GPU and runtime isolation (SUPPLY) and cloud controls (not part of this sheet).
- Metadata traffic analysis between agents (ASI07 example 6) has no separate test.
- Split-view and frontrunning data poisoning (LLM04:2025) are covered through data lineage and validation tests, not by specific exploit steps.
- Tool hints use the tools named in the sources (garak, promptfoo, PyRIT, Giskard, llm-guard, mcp-scan, ART and the AITG lists) plus generic security tools (Burp Suite, semgrep, curl, Wireshark). Only garak modules named in the AITG tool lists are cited; other tool names are bare; testers must check tool versions.

## Review notes
- Merged after review: markdown-image exfiltration (OUTPUT), stop/limit tests (AGENCY vs DOS), memory poisoning from web content (AGENT), tool-return injection (PINJ MCP test), authorization outside the model (AGENCY mediation test).
- IDs are numbered by position in each file; they were assigned once before any use outside this sheet. Do not renumber after handback.
- Cheat sheets not opened (XSS, SQLi, command injection, deserialization, logging, DoS, SBOM, supply chain, input validation) are not cited. Generic web controls are linked with `see`.
