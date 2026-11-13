import sys,json,glob,yaml
# usage: coverage.py <data dir> <refkey> <catalog> [list_key] [id-prefix-filter]
d,key,cat=sys.argv[1:4]; lk=sys.argv[4] if len(sys.argv)>4 and sys.argv[4]!='-' else None; pre=sys.argv[5] if len(sys.argv)>5 else ''
c=json.load(open(f'catalog/{cat}.json')); items=c['lists'][lk]['items'] if lk else c['items']
ids=[i['id'] for i in items if i['id'].startswith(pre)]
used=set(x for f in glob.glob(d+'/**/*.yaml',recursive=True) for t in yaml.safe_load(open(f)) or [] for x in (t.get('refs') or {}).get(key,[]))
miss=[i for i in ids if i not in used]
print(f"{key}: {len(ids)-len(miss)}/{len(ids)} covered; missing: {' '.join(miss)}")
