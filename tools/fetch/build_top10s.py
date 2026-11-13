import re, json, glob
ROOT = "/home/kali/test/sec-checklist"
S = f"{ROOT}/sources/top10s"
RET = "2026-11-12"

def rd(p):
    return open(f"{S}/{p}", encoding="utf-8", errors="ignore").read()

def items_from(pattern, text):
    out = []
    for m in re.finditer(pattern, text, flags=re.M):
        out.append({"id": m.group(1).strip(), "title": m.group(2).strip()})
    return out

lists = {}

# web 2025 (mkdocs nav, English)
mk = rd("web2025_mkdocs.yml")
web = items_from(r"^\s*- (A\d\d) ([^:]+): 'en/", mk)
web = [{"id": f"{x['id']}:2025", "title": x["title"]} for x in web]
lists["web_top10"] = {"version": "2025 (OWASP Top 10:2025)", "url": "https://owasp.org/Top10/2025/", "items": web}

# API 2023 (TOC)
api = items_from(r"^\* \[(API\d+:2023) ([^\]]+)\]", rd("api2023_toc.md"))
lists["api_top10"] = {"version": "2023 (edition in OWASP/API-Security editions/2023; repo VERSION 2.7.0)",
                      "url": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/", "items": api}

# Mobile 2024
mob = items_from(r"^- \[(M\d+): ([^\]]+)\]\(2023-risks/", rd("mobile_index.md"))
mob = [{"id": f"{x['id']}:2024", "title": x["title"]} for x in mob]
lists["mobile_top10"] = {"version": "2024 (final release, OWASP/www-project-mobile-top-10 index)",
                         "url": "https://owasp.org/www-project-mobile-top-10/", "items": mob}

# LLM 2025 (per-risk pages)
def llm_items(prefix, year):
    out = []
    for f in sorted(glob.glob(f"{S}/{prefix}*.md")):
        for ln in open(f, encoding="utf-8", errors="ignore"):
            m = re.match(r"^## (LLM\d\d):(\d{4}) (.+)$", ln.strip())
            if m:
                out.append({"id": f"{m.group(1)}:{m.group(2)}", "title": m.group(3).strip()})
                break
    return out
lists["llm_top10"] = {"version": "2025 (OWASP Top 10 for LLM Applications 2025)",
                      "url": "https://genai.owasp.org/llm-top-10/",
                      "items": llm_items("llm_LLM", 2025)}
lists["llm_top10_2026"] = {"version": "2026 (OWASP GenAI LLM Top 10 2026, canonical repo 2026/final; newer than 2025 list)",
                           "url": "https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026/final",
                           "items": llm_items("llm2026_LLM", 2026)}

# Agentic 2026 (titles verified against official PDF sources/top10s/agentic.pdf)
agentic = [
    ("ASI01", "Agent Goal Hijack"), ("ASI02", "Tool Misuse and Exploitation"),
    ("ASI03", "Identity and Privilege Abuse"), ("ASI04", "Agentic Supply Chain Vulnerabilities"),
    ("ASI05", "Unexpected Code Execution (RCE)"), ("ASI06", "Memory & Context Poisoning"),
    ("ASI07", "Insecure Inter-Agent Communication"), ("ASI08", "Cascading Failures"),
    ("ASI09", "Human-Agent Trust Exploitation"), ("ASI10", "Rogue Agents"),
]
lists["agentic_top10"] = {"version": "2026 (OWASP Top 10 for Agentic Applications for 2026, published 2025-12-09)",
                          "url": "https://genai.owasp.org/download/52117/ (PDF; landing page https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)",
                          "items": [{"id": a, "title": t} for a, t in agentic]}

# K8s 2025
k8s = items_from(r"^- \[(K\d\d): ([^\]]+)\]\(\./2025/", rd("k8s_index.md"))
lists["k8s_top10"] = {"version": "2025 (OWASP Kubernetes Top Ten 2025)",
                      "url": "https://owasp.org/www-project-kubernetes-top-ten/", "items": k8s}

# CI/CD
cicd = []
for m in re.finditer(r"^\[(CICD-SEC-\d+)\]\([^)]*\): (.+)$", rd("cicd_index.md"), flags=re.M):
    cicd.append({"id": m.group(1), "title": m.group(2).strip()})
lists["cicd_top10"] = {"version": "current master of OWASP/www-project-top-10-ci-cd-security-risks",
                       "url": "https://owasp.org/www-project-top-10-ci-cd-security-risks/", "items": cicd}

# Cloud-native
cnas = []
for m in re.finditer(r"^#### \[(CNAS-\d+): ([^\]]+)\]", rd("cnas_index.md"), flags=re.M):
    cnas.append({"id": m.group(1), "title": m.group(2).strip()})
lists["cloud_native_top10"] = {"version": "2022 (OWASP Cloud-Native Application Security Top 10 2022)",
                               "url": "https://owasp.org/www-project-cloud-native-application-security-top-10/", "items": cnas}

# Privacy 2.0 (2021)
priv = []
for m in re.finditer(r"^\s*(P\d+)\s+(?:\d+|New)\s+(.+?)\s*$", rd("privacy_index.md"), flags=re.M):
    priv.append({"id": m.group(1), "title": m.group(2).strip()})
lists["privacy_top10"] = {"version": "2.0 (2021)",
                          "url": "https://owasp.org/www-project-top-10-privacy-risks/", "items": priv}

# Desktop 2021
desk = []
for m in re.finditer(r"^\| (DA\d+) - ([^|]+?) \|", rd("desktop_index.md"), flags=re.M):
    desk.append({"id": m.group(1), "title": m.group(2).strip()})
lists["desktop_top10"] = {"version": "2021", "url": "https://owasp.org/www-project-desktop-app-security-top-10/", "items": desk}

# IoT 2018 (titles as listed in OWASP IoT mapping project; see docs)
iot = [("I1","Weak, Guessable, or Hardcoded Passwords"),("I2","Insecure Network Services"),
       ("I3","Insecure Ecosystem Interfaces"),("I4","Lack of Secure Update Mechanism"),
       ("I5","Use of Insecure or Outdated Components"),("I6","Insufficient Privacy Protection"),
       ("I7","Insecure Data Transfer and Storage"),("I8","Lack of Device Management"),
       ("I9","Insecure Default Settings"),("I10","Lack of Physical Hardening")]
lists["iot_top10"] = {"version": "2018 (titles from secondary mapping project; official PDF link 404)", "url": "https://owasp.org/www-project-internet-of-things/",
                      "items": [{"id": a, "title": t} for a, t in iot]}

for k, v in lists.items():
    ids = [x["id"] for x in v["items"]]
    assert len(ids) == len(set(ids)), k
    print(k, len(ids), ids[0] if ids else None, ids[-1] if ids else None)

out = {"source": "OWASP Top 10 lists (official OWASP GitHub repos / genai.owasp.org)",
       "retrieved": RET, "lists": lists}
json.dump(out, open(f"{ROOT}/catalog/top10s.json", "w"), indent=1, ensure_ascii=False)
