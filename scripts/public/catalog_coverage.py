"""공개 규칙 목록(Sigma·Elastic·Splunk)이 탐지하는 CloudTrail API와 LogFinder 범위 대조.

  python scripts/public/catalog_coverage.py <sigma> <detection-rules> <security_content>

각 목록에서 eventName을 뽑고, 2곳 이상에 나오는 API마다 이벤트 하나(파라미터 거의 없음)를 LogFinder에 넣어
규칙이 걸리는지 본다. 파라미터가 있어야 걸리는 규칙(예: 0.0.0.0/0 개방)은 여기서 안 걸린 것으로 나오므로
'안 걸림'은 '빈 영역 후보'일 뿐이다. 코드에서 그 API를 다루는지 따로 확인한다.
"""
import collections, glob, json, re, sys
from pathlib import Path
import yaml
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
SIG, ELA, SPL = sys.argv[1:4]
from logsight.normalize import parse_cloudtrail
from logsight.detect import run_detections
def lst(v): return v if isinstance(v,list) else [v]
sig=collections.defaultdict(set)  # (src,name)->rules
for f in glob.glob(SIG + '/rules/cloud/aws/**/*.yml',recursive=True):
    d=yaml.safe_load(open(f))
    if (d.get('logsource') or {}).get('service')!='cloudtrail': continue
    det=d.get('detection',{});names=set();srcs=set()
    def walk(x):
        if isinstance(x,dict):
            for k,v in x.items():
                kk=k.split('|')[0]
                if kk=='eventName': names.update(str(i) for i in lst(v))
                elif kk=='eventSource': srcs.update(str(i) for i in lst(v))
                else: walk(v)
        elif isinstance(x,list):
            for i in x: walk(i)
    walk(det)
    for n in names:
        for s in (srcs or {''}): sig[(s.split('.')[0],n)].add(d.get('title'))
ela=collections.defaultdict(set)
for f in glob.glob(ELA + '/rules/integrations/aws/*.toml'):
    t=open(f).read()
    if 'aws.cloudtrail' not in t: continue
    q=re.search(r'query\s*=\s*\'\'\'(.*?)\'\'\'',t,re.S) or re.search(r'query\s*=\s*"""(.*?)"""',t,re.S)
    if not q: continue
    q=q.group(1)
    acts=set(re.findall(r'event\.action\s*(?::|==)\s*\(?\s*([^)\n]+)',q))
    names=set()
    for a in acts: names.update(re.findall(r'"([A-Za-z0-9]+)"',a))
    provs=set(re.findall(r'event\.provider\s*(?::|==)\s*"?([a-z0-9-]+)\.amazonaws\.com',q))
    name=re.search(r'\nname\s*=\s*"([^"]+)"',t)
    for n in names:
        for p in (provs or {''}): ela[(p,n)].add(name.group(1) if name else f)
def fires(src,name):
    if not src: return None
    r={'eventTime':'2026-01-01T00:00:00Z','eventSource':f'{src}.amazonaws.com','eventName':name,'sourceIPAddress':'198.51.100.7',
       'userIdentity':{'type':'IAMUser','userName':'u','arn':'arn:aws:iam::111122223333:user/u'},'requestParameters':{'x':'y'},'recipientAccountId':'111122223333'}
    ev=parse_cloudtrail(json.dumps({'Records':[r]}),'c.json')
    return sorted({f.rule for f in run_detections(ev,{})})
_src = collections.defaultdict(collections.Counter)
for (s, n) in list(sig) + list(ela):
    if s:
        _src[n][s] += 1
# 같은 API에 출처가 여럿이면 가장 많이 쓰인 것(동률이면 이름순)으로 정해 실행마다 같은 결과를 낸다
src_of = {n: sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] for n, c in _src.items()}
names_s={n for (_,n) in sig}; names_e={n for (_,n) in ela}
both=names_s&names_e
rows=[]
for n in sorted(names_s|names_e):
    s=src_of.get(n,'')
    fr=fires(s,n)
    rows.append((n,s,n in names_s,n in names_e,fr))
print('sigma names',len(names_s),'elastic names',len(names_e),'both',len(both))
nb=[r for r in rows if r[2] and r[3]]
print('both: bare call fires',sum(bool(r[4]) for r in nb),'/',len(nb))
for r in nb:
    if not r[4]: print('  MISS',r[1],r[0])

spl=set()
for f in glob.glob(SPL + '/detections/cloud/*.yml'):
    t=open(f).read()
    if 'cloudtrail' not in t.lower(): continue
    for blk in re.findall(r'eventName\s*(?:=|IN)\s*\(?([^|\n]+)',t):
        spl.update(re.findall(r'"?([A-Z][A-Za-z0-9]+)"?',blk))
spl-= {'IN','OR','AND','NOT'}
cnt=collections.Counter()
for n in names_s|names_e|spl:
    cnt[n]=(n in names_s)+(n in names_e)+(n in spl)
two=[n for n,c in cnt.items() if c>=2]
print('splunk names',len(spl),'in >=2 catalogs',len(two))
miss=[]
for n in sorted(two):
    s=src_of.get(n,'')
    fr=fires(s,n) if s else None
    if not fr: miss.append((cnt[n],s,n))
print('>=2 catalogs, bare call not flagged:',len(miss))
for m in miss: print(' ',m)

