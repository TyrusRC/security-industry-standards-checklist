import json
ROOT = "/home/kali/test/sec-checklist"
d = json.load(open(f"{ROOT}/sources/cheatsheets/listing.json"))
c = json.load(open(f"{ROOT}/sources/cheatsheets/commit.json"))
items = []
for x in sorted(d, key=lambda x: x["name"].lower()):
    if not x["name"].endswith(".md"):
        continue
    stem = x["name"][:-3]
    items.append({"id": stem, "title": stem.replace("_", " "), "chapter": "cheatsheets"})
out = {
    "source": "OWASP Cheat Sheet Series (cheatsheets/ directory, file stems)",
    "version": "master@" + c["sha"][:12] + " (commit " + c["commit"]["committer"]["date"][:10] + ")",
    "url": "https://github.com/OWASP/CheatSheetSeries/tree/master/cheatsheets",
    "retrieved": "2026-11-12",
    "items": items,
}
json.dump(out, open(f"{ROOT}/catalog/cheatsheets.json", "w"), indent=1, ensure_ascii=False)
print(len(items))
