import sys,glob,yaml,re
BAD=r"\b(perform|ensure|utili[sz]e|leverage|verify|attempt|obtain|via|e\.g\.|i\.e\.|(?<!/)etc\.?|don't|doesn't|can't|won't|shouldn't)\b"
bad=0;n=0
def chk(i,f,s,mx):
    global bad
    for sent in re.split(r'(?<=[.!?])\s+',s.strip()):
        w=len(sent.split())
        if w>mx: print(f"{i} {f}: {w} words: {sent[:70]}"); bad+=1
        m=re.search(BAD,sent,re.I)
        if m: print(f"{i} {f}: banned word '{m.group(0)}'"); bad+=1
for p in sorted(glob.glob(sys.argv[1]+'/**/*.yaml',recursive=True)):
    for t in yaml.safe_load(open(p)) or []:
        n+=1;i=t['id']
        for s in t.get('steps',[]): chk(i,'step',s,20)
        for k in('objective','expected'): chk(i,k,t.get(k,''),25)
        chk(i,'title',t.get('title',''),12)
print(f"{n} tests, {bad} STE issues");sys.exit(1 if bad else 0)
