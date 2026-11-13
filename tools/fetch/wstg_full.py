import re, json, pathlib
base=pathlib.Path("sources/repos/wstg/document/4-Web_Application_Security_Testing")
items=[]
for f in sorted(base.glob("*/*.md")):
    t=f.read_text(encoding="utf8")
    m=re.search(r"\|\s*(WSTG-[A-Z]+-\d+)\s*\|",t)
    if not m: continue
    h=re.search(r"^#\s+(.+)$",t,re.M)
    items.append({"id":m.group(1),"title":(h.group(1) if h else f.stem).strip(),"chapter":f.parent.name,"file":str(f)})
json.dump({"source":"OWASP WSTG (document tree, master)","version":"master checkout 2026-11-12","url":"https://github.com/OWASP/wstg","retrieved":"2026-11-12","items":items},open("catalog/wstg.json","w"),indent=1)
print(len(items), len({i['id'] for i in items}))
