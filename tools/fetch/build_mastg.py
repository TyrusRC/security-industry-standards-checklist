import json, re, glob, os
ROOT = "/home/kali/test/sec-checklist"
RET = "2026-11-12"

def front(path):
    lines = open(path, encoding="utf-8", errors="ignore").read().split("\n")
    if not lines or lines[0].strip() != "---":
        return {}
    fm = {}
    for ln in lines[1:]:
        if ln.strip() == "---":
            break
        m = re.match(r"^([A-Za-z_0-9]+):\s*(.*)$", ln)
        if m:
            v = m.group(2).strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            fm[m.group(1)] = v
    return fm

tree = json.load(open(f"{ROOT}/sources/mastg/tree.json"))
paths = [t["path"] for t in tree["tree"] if t["type"] == "blob"]
tests = []
for p in paths:
    m = re.match(r"^(tests|tests-beta)/(android|ios|network)/.*?(MASTG-TEST-\d+)\.md$", p)
    if not m:
        continue
    kind, plat, tid = m.groups()
    name = tid + ".md"
    fm = front(os.path.join(f"{ROOT}/sources/mastg/files", p.replace("/", "_")))
    if not fm.get("title"):
        print("no title", p)
        continue
    plat = fm.get("platform", plat)  # front matter wins (2 MASVS-NETWORK tests declare platform: network)
    chapter = plat + (" beta" if kind == "tests-beta" else "")
    if fm.get("status"):
        chapter += f" ({fm['status']})"
    tests.append({"id": tid, "title": fm["title"], "chapter": chapter})
tests.sort(key=lambda x: x["id"])
c = json.load(open(f"{ROOT}/sources/mastg/commit.json"))
ver = "master@" + c["sha"][:12] + " (commit " + c["commit"]["committer"]["date"][:10] + ")"
ids = [t["id"] for t in tests]
assert len(ids) == len(set(ids)), "dup MASTG ids"
json.dump({"source": "OWASP MASTG (tests/ and tests-beta/ front matter)", "version": ver,
           "url": "https://github.com/OWASP/mastg/tree/master/tests-beta",
           "retrieved": RET, "items": tests},
          open(f"{ROOT}/catalog/mastg.json", "w"), indent=1, ensure_ascii=False)
print("mastg", len(tests))

c = json.load(open(f"{ROOT}/sources/mastg/maswe_commit.json"))
ver = "main@" + c["sha"][:12] + " (commit " + c["commit"]["committer"]["date"][:10] + ")"
wk = []
for f in sorted(glob.glob(f"{ROOT}/sources/mastg/files/MASWE__*.md")):
    base = os.path.basename(f)
    m = re.search(r"(MASWE-\d{4})\.md$", base)
    fm = front(f)
    if not m or not fm.get("title"):
        print("skip", base)
        continue
    cat = re.search(r"weaknesses_([^_]+)_", base)
    chapter = cat.group(1) if cat else "weaknesses"
    wk.append({"id": m.group(1), "title": fm["title"], "chapter": chapter})
wk.sort(key=lambda x: x["id"])
json.dump({"source": "OWASP MASWE (weaknesses/ front matter)", "version": ver,
           "url": "https://github.com/OWASP/maswe/tree/main/weaknesses",
           "retrieved": RET, "items": wk},
          open(f"{ROOT}/catalog/maswe.json", "w"), indent=1, ensure_ascii=False)
print("maswe", len(wk))
