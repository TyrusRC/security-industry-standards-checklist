import json,glob,yaml,sys
ids={t['id'] for f in glob.glob('data/*/*.yaml') for t in yaml.safe_load(open(f)) or []}
cats={"pci_dss":"pci_dss","nist_800_53":"nist80053","cheatsheet":"cheatsheets","tool_check":"checks"}; err=0
for mf in glob.glob("data/mappings/*.json"):
    for k,m in json.load(open(mf)).items():
        cat={i["id"] for i in json.load(open(f"catalog/{cats[k]}.json"))["items"]}
        for item,tests in m.items():
            if item not in cat: print(mf,"unknown item",item); err+=1
            for t in tests:
                if t not in ids: print(mf,item,"unknown test",t); err+=1
        print(mf,k,len(m),"items mapped")
print(err,"errors"); sys.exit(1 if err else 0)
