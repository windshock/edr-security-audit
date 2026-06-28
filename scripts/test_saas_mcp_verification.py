import subprocess
import json
import os

def run_test():
    print("--- Testing Patched local edr-mcp against SaaS Console ---")
    
    env = os.environ.copy()
    env["EDR_MCP_CONSOLE_TOKEN"] = os.environ.get("EDR_SAAS_TOKEN","")
    env["EDR_MCP_CONSOLE_BASE_URL"] = "https://<EDR_SAAS_CONSOLE>"
    env["EDR_MCP_AUTH_PREFIX"] = "Bearer"
    env["PYTHONPATH"] = "<REPO_ROOT>/edr-mcp/src"
    
    cmd = [
        "<REPO_ROOT>/edr-mcp/.venv/bin/python3",
        "-m", "edr_mcp.cli",
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
        
        # Call list_inventory_items
        write_request({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "list_inventory_items",
                "arguments": {
                    "limit": 5
                }
            }
        })
        
        resp_raw = read_stdout_line()
        if resp_raw:
            print("Response received:")
            print(json.dumps(json.loads(resp_raw), indent=2))
        else:
            print("No response on stdout.")
            
        proc.terminate()
        proc.wait()
        errs = proc.stderr.read()
        if errs:
            print(f"Stderr:\n{errs}")
            
    except Exception as e:
        print(f"Exception: {e}")
    finally:
        proc.terminate()
        proc.wait()

if __name__ == "__main__":
    run_test()
