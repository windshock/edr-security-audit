#!/usr/bin/env python3
# query_event_types.py <search_term>
# SIEM-X에서 마커 검색 후 이벤트 타입(meta.event.name)별 분포 + 파일경로 집계.
import os
import sys, json, ssl, base64, urllib.request

def q(term):
    url = "https://<siemx_HOST>:5601/api/console/proxy?path=logs-edr.edr/_search&method=POST"
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    dsl = {"size":200,"query":{"query_string":{"query":f"*{term}*"}}}
    req = urllib.request.Request(url, data=json.dumps(dsl).encode())
    req.add_header("Authorization","Basic "+base64.b64encode(os.environ.get("siemx_BASICAUTH","admin:admin").encode()).decode())
    req.add_header("osd-xsrf","true"); req.add_header("Content-Type","application/json")
    return json.load(urllib.request.urlopen(req, context=ctx, timeout=30))

term = sys.argv[1]
r = q(term)
hits = r.get("hits",{}).get("hits",[])
total = r.get("hits",{}).get("total",{}).get("value",0)
print(f"=== '{term}': total={total}, fetched={len(hits)} ===")
from collections import Counter
ev = Counter()
fileevents = []
for h in hits:
    s = h.get("_source",{})
    name = s.get("meta",{}).get("event",{}).get("name","?")
    ev[name]+=1
    # 파일 이벤트면 대상 경로 추출
    if "FILE" in name.upper():
        tgt = (s.get("tgt",{}).get("file",{}).get("path") or
               s.get("file",{}).get("path") or
               s.get("target",{}).get("file",{}).get("path") or "?")
        fileevents.append((name, tgt))
print("이벤트 타입 분포:")
for k,v in ev.most_common():
    print(f"  {v:3d}  {k}")
if fileevents:
    print("파일 이벤트 상세:")
    for name,tgt in fileevents[:20]:
        print(f"  {name}: {tgt}")
else:
    print("  (FILE* 이벤트 없음)")
