import os
from mcp.server.fastmcp import FastMCP
import urllib.request
import ssl
import json
import base64
import sys

mcp = FastMCP("OpenSearch-Proxy")

@mcp.tool()
def search_edr_raw_events(search_term: str = "", size: int = 5) -> str:
    """
    Search EDR-X EDR raw events from SIEM-X OpenSearch index via Dashboard Console Proxy.
    If search_term is provided, it performs a query string search on logs-edr.edr.
    Otherwise, it returns the latest events.
    """
    url = "https://<siemx_HOST>:5601/api/console/proxy?path=logs-edr.edr/_search&method=POST"
    
    # Bypass SSL Verification
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    # Basic Authentication: admin / admin
    auth_str = os.environ.get("siemx_BASICAUTH","admin:admin").encode()
    auth_header = b"Basic " + base64.b64encode(auth_str)
    
    if search_term:
        query_dsl = {
            "size": size,
            "query": {
                "query_string": {
                    "query": f"*{search_term}*"
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
    else:
        query_dsl = {
            "size": size,
            "query": {"match_all": {}},
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        
    req = urllib.request.Request(url, data=json.dumps(query_dsl).encode('utf-8'))
    req.add_header("Authorization", auth_header.decode('utf-8'))
    req.add_header("osd-xsrf", "true")
    req.add_header("Content-Type", "application/json")
    
    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            res_data = response.read()
            result = json.loads(res_data.decode('utf-8'))
            
            hits = result.get("hits", {}).get("hits", [])
            total_val = result.get("hits", {}).get("total", {}).get("value", 0)
            
            output = [f"Total matching EDR documents: {total_val}\n"]
            for idx, hit in enumerate(hits):
                source = hit.get("_source", {})
                timestamp = source.get("timestamp", source.get("@timestamp", "unknown"))
                meta_event = source.get("meta", {}).get("event", {}).get("name", "Unknown Event")
                endpoint_name = source.get("endpoint", {}).get("name", "Unknown Endpoint")
                process_name = source.get("src", {}).get("process", {}).get("name", "Unknown Process")
                cmdline = source.get("src", {}).get("process", {}).get("cmdline", "")
                
                evt_str = f"[{idx+1}] Timestamp: {timestamp} | Endpoint: {endpoint_name} | Event: {meta_event} | Process: {process_name}"
                if cmdline:
                    evt_str += f" | Cmdline: {cmdline}"
                output.append(evt_str)
                
            return "\n".join(output)
            
    except Exception as e:
        return f"Error querying OpenSearch: {str(e)}"

if __name__ == "__main__":
    mcp.run()
