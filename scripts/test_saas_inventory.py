import subprocess
import json
import os

def main():
    print("--- Testing edr-mcp SaaS Console ---")
    
    env = os.environ.copy()
    env["EDR_MCP_CONSOLE_TOKEN"] = os.environ.get("EDR_SAAS_TOKEN","")
    env["EDR_MCP_CONSOLE_BASE_URL"] = "https://<EDR_SAAS_CONSOLE>"
    
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
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()

    try:
        # Initialize
        write_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"}
            }
        })
        init_resp = read_stdout_line()
        if not init_resp:
            print("Failed to init.")
            return
            
        write_request({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })
        
        # Call search_inventory_items
        filters = json.dumps({"name__contains": ["lima"]})
        write_request({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "search_inventory_items",
                "arguments": {
                    "filters": filters
                }
            }
        })
        
        resp_raw = read_stdout_line()
        if resp_raw:
            print("Response received:")
            print(json.dumps(json.loads(resp_raw), indent=2))
        else:
            print("No response on stdout.")
            print(f"Stderr:\n{proc.stderr.read()}")
            
    except Exception as e:
        print(f"Exception: {e}")
    finally:
        proc.terminate()
        proc.wait()

if __name__ == "__main__":
    main()
