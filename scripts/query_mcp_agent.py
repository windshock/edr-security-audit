import subprocess
import json
import sys
import os

def main():
    # 1. Prepare env
    env = os.environ.copy()
    env["EDR_MCP_CONSOLE_TOKEN"] = os.environ.get("EDR_ONPREM_TOKEN","")
    # 도메인 기반 호스트네임 매핑 사용
    env["EDR_MCP_CONSOLE_BASE_URL"] = "https://edr-console.local"
    # 파이썬 HTTP 클라이언트가 사설 SSL 인증서를 신뢰하도록 경로 주입
    env["REQUESTS_CA_BUNDLE"] = "<REPO_ROOT>/bin/extracted/edr_onprem_ca.crt"
    env["SSL_CERT_FILE"] = "<REPO_ROOT>/bin/extracted/edr_onprem_ca.crt"
    
    cmd = [
        "uvx",
        "--from", "git+https://github.com/edr-vendor/edr-mcp.git",
        "edr-mcp",
        "--mode", "stdio"
    ]
    
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        bufsize=1
    )
    
    def read_stdout_line():
        return proc.stdout.readline()

    def write_request(req):
        payload = json.dumps(req) + "\n"
        proc.stdin.write(payload)
        proc.stdin.flush()

    try:
        # 2. Handshake
        write_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "query-client", "version": "1.0.0"}
            }
        })
        read_stdout_line() # Skip init response
        
        write_request({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })
        
        # 3. Call tool 'search_inventory_items'
        filters_json = json.dumps({"name__contains": ["colima"]})
        call_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "search_inventory_items",
                "arguments": {
                    "filters": filters_json
                }
            }
        }
        print("Sending 'tools/call' for search_inventory_items...")
        write_request(call_req)
        
        # Read response
        resp_raw = read_stdout_line()
        print("Response received:")
        if resp_raw:
            resp = json.loads(resp_raw)
            print(json.dumps(resp, indent=2, ensure_ascii=False))
        else:
            print("No response from tool.")
            errs = proc.stderr.read()
            print(f"Stderr: {errs}")
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        proc.terminate()
        proc.wait()

if __name__ == "__main__":
    main()
