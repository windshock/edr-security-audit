import os
import sys
import json
import urllib.request
import urllib.parse
import ssl

def query_opensearch(query_dsl):
    url = "https://<siemx_HOST>:5601/api/console/proxy?path=logs-edr.edr/_search&method=POST"
    
    # Bypass SSL Verification for internal network testing
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    # Basic Authentication: admin / admin
    import base64
    auth_str = os.environ.get("siemx_BASICAUTH","admin:admin").encode()
    auth_header = b"Basic " + base64.b64encode(auth_str)
    
    req = urllib.request.Request(url, data=json.dumps(query_dsl).encode('utf-8'))
    req.add_header("Authorization", auth_header.decode('utf-8'))
    req.add_header("osd-xsrf", "true")
    req.add_header("Content-Type", "application/json")
    
    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            res_data = response.read()
            return json.loads(res_data.decode('utf-8'))
    except Exception as e:
        print(f"Error connecting to siemx OpenSearch: {e}")
        return None

def main():
    print("SIEM-X (OpenSearch) EDR Raw Event Query Tool")
    print("-" * 50)
    
    search_term = ""
    if len(sys.argv) > 1:
        search_term = sys.argv[1]
        print(f"Searching for EDR events containing: '{search_term}'")
        
        # OpenSearch Query DSL for finding the search term anywhere in the document
        query_dsl = {
            "size": 5,
            "query": {
                "query_string": {
                    "query": f"*{search_term}*"
                }
            },
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc"
                    }
                }
            ]
        }
    else:
        print("No search term provided. Fetching latest 5 EDR raw events...")
        query_dsl = {
            "size": 5,
            "query": {
                "match_all": {}
            },
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc"
                    }
                }
            ]
        }
        
    result = query_opensearch(query_dsl)
    if not result:
        return
        
    hits = result.get("hits", {}).get("hits", [])
    total_val = result.get("hits", {}).get("total", {}).get("value", 0)
    
    print(f"Total matching documents found: {total_val}")
    print("-" * 50)
    
    if not hits:
        print("No events found.")
        return
        
    for idx, hit in enumerate(hits):
        source = hit.get("_source", {})
        timestamp = source.get("timestamp", source.get("@timestamp", "unknown"))
        meta_event = source.get("meta", {}).get("event", {}).get("name", "Unknown Event")
        endpoint_name = source.get("endpoint", {}).get("name", "Unknown Endpoint")
        process_name = source.get("src", {}).get("process", {}).get("name", "Unknown Process")
        cmdline = source.get("src", {}).get("process", {}).get("cmdline", "")
        
        print(f"[{idx+1}] Timestamp: {timestamp}")
        print(f"    Endpoint:  {endpoint_name}")
        print(f"    Event:     {meta_event}")
        print(f"    Process:   {process_name}")
        if cmdline:
            print(f"    Cmdline:   {cmdline}")
        
        # Check if the query matches details
        print(f"    Source JSON slice: {json.dumps(source)[:200]}...")
        print("-" * 50)

if __name__ == "__main__":
    main()
