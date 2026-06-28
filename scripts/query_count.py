#!/usr/bin/env python3
"""
query_count.py - Return ONLY the total matching-document count for a search
term against the SIEM-X EDR index. Used by run_all.sh for fast, parseable
ingestion checks (prints a single integer to stdout, or -1 on error).

Usage: query_count.py <search_term>
"""
import os
import sys
import json
import ssl
import base64
import urllib.request


def count(term, index="logs-edr*"):
    # NOTE: default index is the WILDCARD logs-edr* so we cover BOTH the
    # raw telemetry index (.edr) AND the threats index (.threats). Querying
    # only .edr produced a FALSE "visibility gap" for anti-tamper threats, which
    # actually land in logs-edr.threats. (corrected 2026-06-19)
    url = ("https://<siemx_HOST>:5601/api/console/proxy"
           f"?path={index}/_count&method=POST")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    auth = b"Basic " + base64.b64encode(os.environ.get("siemx_BASICAUTH","admin:admin").encode())
    body = json.dumps({"query": {"query_string": {"query": f"*{term}*"}}}).encode()
    req = urllib.request.Request(url, data=body)
    req.add_header("Authorization", auth.decode())
    req.add_header("osd-xsrf", "true")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as r:
            return json.loads(r.read()).get("count", -1)
    except Exception as e:
        sys.stderr.write(f"query_count error: {e}\n")
        return -1


if __name__ == "__main__":
    term = sys.argv[1] if len(sys.argv) > 1 else ""
    index = sys.argv[2] if len(sys.argv) > 2 else "logs-edr*"
    print(count(term, index))
