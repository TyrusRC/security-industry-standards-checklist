import openpyxl, re, json, warnings
warnings.filterwarnings("ignore")
ws=openpyxl.load_workbook("sources/pci_dss/Prioritized-Approach-Tool-For-PCI-DSS-v4_0_1.xlsx",read_only=True)["Prioritized Approach Milestones"]
items={}
for r in ws.iter_rows(values_only=True):
    for c in r:
        if isinstance(c,str):
            m=re.match(r"^(\d{1,2}(?:\.\d+){1,3})\s+(.+)",c.strip(),re.S)
            if m and m.group(1) not in items:
                t=" ".join(m.group(2).split()); w=t.split()
                items[m.group(1)]=" ".join(w[:14])+(" ..." if len(w)>14 else "")
            break
SW=("2.","3.","4.","6.","7.","8.","10.")
def soft(i): return i.startswith(SW) or i.startswith(("11.3.","11.4.","11.6.")) or i=="12.3.1"
L=[{"id":i,"title":t,"chapter":"Req "+i.split(".")[0],"software":soft(i)} for i,t in items.items()]
json.dump({"source":"PCI DSS v4.0.1 (numbers+truncated text from official Prioritized Approach Tool)","version":"4.0.1","url":"user-supplied sources/pci_dss","retrieved":"2026-11-12","note":"titles truncated to 14 words; full text in sources/pci_dss/PCI-DSS-v4_0_1.md","items":L},open("catalog/pci_dss.json","w"),indent=1)
print(len(L),sum(i["software"] for i in L))
