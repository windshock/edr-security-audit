#!/usr/bin/env python3
"""Search SIEM-X OpenSearch via the Dashboards console proxy.

Usage:
  query_siemx_search.py <term> [index] [size]

Examples:
  query_siemx_search.py EDR_POC_CRUX_RULES_123 'logs-*' 20
  query_siemx_search.py ReadPasswdFile '*'
"""

import os
import base64
import json
import ssl
import sys
import urllib.parse
import urllib.request


BASE_URL = "https://<siemx_HOST>:5601/api/console/proxy"
AUTH = "Basic " + base64.b64encode(os.environ.get("siemx_BASICAUTH","admin:admin").encode()).decode()


def get_path(index: str) -> str:
    return urllib.parse.quote(f"{index}/_search", safe="")


def search(term: str, index: str, size: int) -> dict:
    url = f"{BASE_URL}?path={get_path(index)}&method=POST"
    query = {
        "size": size,
        "query": {"query_string": {"query": f"*{term}*"}},
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
    }
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, data=json.dumps(query).encode())
    req.add_header("Authorization", AUTH)
    req.add_header("osd-xsrf", "true")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, context=ctx, timeout=30) as response:
        return json.loads(response.read())


def pick(source: dict, dotted: str, default: str = ""):
    value = source
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    term = sys.argv[1]
    index = sys.argv[2] if len(sys.argv) > 2 else "logs-*"
    size = int(sys.argv[3]) if len(sys.argv) > 3 else 10

    result = search(term, index, size)
    total = result.get("hits", {}).get("total", {})
    total_value = total.get("value", total) if isinstance(total, dict) else total
    print(f"total={total_value} term={term!r} index={index!r}")

    for i, hit in enumerate(result.get("hits", {}).get("hits", []), 1):
        source = hit.get("_source", {})
        timestamp = source.get("@timestamp") or source.get("timestamp") or source.get("createdAt", "")
        event = pick(source, "meta.event.name") or source.get("event", {}).get("action", "")
        endpoint = pick(source, "endpoint.name") or pick(source, "agent.name") or source.get("host", {}).get("name", "")
        proc = pick(source, "src.process.name") or source.get("process", {}).get("name", "")
        cmd = pick(source, "src.process.cmdline") or source.get("process", {}).get("command_line", "")
        rule = (
            pick(source, "rule.name")
            or pick(source, "kibana.alert.rule.name")
            or pick(source, "signal.rule.name")
            or source.get("name", "")
        )
        severity = (
            pick(source, "rule.severity")
            or pick(source, "kibana.alert.severity")
            or pick(source, "signal.rule.severity")
            or source.get("severity", "")
        )
        print(f"[{i}] index={hit.get('_index')} time={timestamp} endpoint={endpoint}")
        if rule or severity:
            print(f"    rule={rule} severity={severity}")
        if event or proc:
            print(f"    event={event} process={proc}")
        if cmd:
            print(f"    cmdline={cmd[:500]}")
        if not any([rule, event, proc, cmd]):
            print(f"    source={json.dumps(source, ensure_ascii=False)[:500]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
