import json, glob, re, os
ROOT = "/home/kali/test/sec-checklist"
RET = "2026-11-12"
d = json.load(open(f"{ROOT}/sources/wstg/checklist.json"))
items = []
seen = set()
for cat, v in d["categories"].items():
    for t in v["tests"]:
        items.append({"id": t["id"], "title": t["name"], "chapter": cat})
        seen.add(t["id"])
# latest-only IDs from dev doc (not in checklist.json)
for f in glob.glob(f"{ROOT}/sources/wstg/doc4/*"):
    txt = open(f, errors="ignore").read()
    ids = set(re.findall(r"WSTG-[A-Z]{4}-\d{2}", txt))
    for i in ids - seen:
        # only the page's own ID: the one most frequently mentioned
        pass
latest = {
    "WSTG-CONF-08": ("RIA Cross Domain Policy", "Configuration and Deployment Management (latest)"),
    "WSTG-CLNT-08": ("Cross Site Flashing", "Client-side (latest)"),
}
for i, (title, chap) in latest.items():
    assert i not in seen
    items.append({"id": i, "title": title, "chapter": chap})
items.sort(key=lambda x: x["id"])
out = {
    "source": "OWASP Web Security Testing Guide (WSTG) checklist; latest-only IDs from document/4-Web_Application_Security_Testing (master)",
    "version": "v4.2 checklist (master branch checklist.json; WSTG v4.2 IDs)",
    "url": "https://raw.githubusercontent.com/OWASP/wstg/master/checklists/checklist.json",
    "retrieved": RET,
    "items": items,
}
json.dump(out, open(f"{ROOT}/catalog/wstg.json", "w"), indent=1, ensure_ascii=False)
print(len(items))
