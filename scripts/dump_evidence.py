#!/usr/bin/env python3
# dump_evidence.py <marker> <outfile> — SIEM-X에서 마커 매칭 이벤트 _source 전체를 JSON으로 저장 (증거 보존)
import os
import sys, json, ssl, base64, urllib.request
marker, out = sys.argv[1], sys.argv[2]
url="https://<siemx_HOST>:5601/api/console/proxy?path=logs-edr.edr/_search&method=POST"
ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE  # 내부망 self-signed
dsl={"size":300,"query":{"query_string":{"query":f"*{marker}*"}}}
req=urllib.request.Request(url,data=json.dumps(dsl).encode())
req.add_header("Authorization","Basic "+base64.b64encode(os.environ.get("siemx_BASICAUTH","admin:admin").encode()).decode())
req.add_header("osd-xsrf","true"); req.add_header("Content-Type","application/json")
r=json.load(urllib.request.urlopen(req,context=ctx,timeout=30))
hits=[h["_source"] for h in r.get("hits",{}).get("hits",[])]
with open(out,"w") as f:
    json.dump({"marker":marker,"total":r.get("hits",{}).get("total",{}).get("value"),"events":hits}, f, ensure_ascii=False, indent=2)
from collections import Counter
ev=Counter(s.get("meta",{}).get("event",{}).get("name","?") for s in hits)
print(f"{marker}: {len(hits)}건 → {out}")
for k,v in ev.most_common(): print(f"  {v:3d} {k}")
