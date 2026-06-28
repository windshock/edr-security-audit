#!/usr/bin/env python3
# analyze_privesc.py <term> — PRIVESC 이벤트 정밀 분석: 프로세스 분포 + BEHAVIOR_INDICATOR 상세 + threats 인덱스
import os
import sys, json, ssl, base64, urllib.request
from collections import Counter

def query(index, term, size=300):
    url = f"https://<siemx_HOST>:5601/api/console/proxy?path={index}/_search&method=POST"
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    dsl = {"size":size,"query":{"query_string":{"query":f"*{term}*"}}}
    req = urllib.request.Request(url, data=json.dumps(dsl).encode())
    req.add_header("Authorization","Basic "+base64.b64encode(os.environ.get("siemx_BASICAUTH","admin:admin").encode()).decode())
    req.add_header("osd-xsrf","true"); req.add_header("Content-Type","application/json")
    try:
        return json.load(urllib.request.urlopen(req, context=ctx, timeout=30))
    except Exception as e:
        return {"error":str(e)}

term = sys.argv[1]

# 1) raw .edr — 프로세스 x 이벤트
r = query("logs-edr.edr", term)
hits = r.get("hits",{}).get("hits",[])
print(f"=== raw .edr: {len(hits)}건 ===")
proc_ev = Counter()
bi = []
for h in hits:
    s = h.get("_source",{})
    ev = s.get("meta",{}).get("event",{}).get("name","?")
    proc = s.get("src",{}).get("process",{}).get("name","?")
    proc_ev[(proc,ev)] += 1
    if ev == "BEHAVIOR_INDICATOR":
        bi.append(s)
print("프로세스 × 이벤트 분포:")
for (p,e),c in proc_ev.most_common():
    print(f"  {c:3d}  {p:18s} {e}")

# 2) 핵심 공격 단계 프로세스가 잡혔나
print("\n핵심 공격 단계 탐지 여부:")
allcmd = " ".join(json.dumps(h.get("_source",{})) for h in hits)
for label, kw in [("sudo python3 (공격실행)","sudo"),("cp(bash복사)","/bin/bash"),
                  ("chmod 4755(SUID설정)","4755"),("chown root","chown"),
                  ("rootbash 실행(euid=0)","rootbash -p"),("chmod(any)","chmod")]:
    print(f"  {'✅' if kw in allcmd else '❌'} {label}  (키:'{kw}')")

# 3) BEHAVIOR_INDICATOR 상세
print(f"\nBEHAVIOR_INDICATOR {len(bi)}건 상세:")
for s in bi:
    inds = s.get("indicators") or s.get("meta",{}).get("indicators") or []
    proc = s.get("src",{}).get("process",{}).get("name","?")
    cmd = (s.get("src",{}).get("process",{}).get("cmdline","") or "")[:90]
    print(f"  process={proc} cmd={cmd!r}")
    print(f"    indicators={json.dumps(inds)[:300]}")
    # 전체 소스에서 indicator/category 흔적
    sj = json.dumps(s)
    for kw in ["category","indicator","tactic","technique","Privilege","privilege","escal","SUID","suid"]:
        if kw in sj:
            i = sj.find(kw); print(f"    ...{sj[i:i+120]}")

# 4) threats 인덱스 (위협 승격?)
print("\n=== logs-edr.threats (위협 승격 여부) ===")
t = query("logs-edr.threats", term, 50)
if "error" in t:
    print("  query error:", t["error"])
else:
    th = t.get("hits",{}).get("hits",[])
    print(f"  매칭 위협: {len(th)}건")
    for h in th[:10]:
        s=h.get("_source",{})
        print("   ", json.dumps(s.get("threat", s))[:200])
