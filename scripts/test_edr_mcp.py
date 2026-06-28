import subprocess
import json
import sys
import os

def main():
    print("Testing edr-mcp local execution and protocol integration...")
    
    # 1. Prepare env
    env = os.environ.copy()
    env["EDR_MCP_CONSOLE_TOKEN"] = os.environ.get("EDR_SAAS_TOKEN","")
    env["EDR_MCP_CONSOLE_BASE_URL"] = "https://<EDR_SAAS_CONSOLE>"
    
    # 2. Spawn edr-mcp via uvx
    cmd = [
        "uvx",
        "--from", "git+https://github.com/edr-vendor/edr-mcp.git",
        "edr-mcp",
        "--mode", "stdio"
    ]
    
    print(f"Launching process: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        bufsize=1
    )
    
    # helper to read line with timeout to avoid hanging
    def read_stdout_line():
        # Using select or simple readline since it is stdio
        # To avoid blocking indefinitely, we'll try reading lines.
        # But subprocess in Python can block if there's no newline.
        # FastMCP writes json-rpc messages separated by newlines.
        return proc.stdout.readline()

    # helper to write json-rpc request
    def write_request(req):
        payload = json.dumps(req) + "\n"
        proc.stdin.write(payload)
        proc.stdin.flush()

    try:
        # Let's perform the MCP initialize handshake
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }
        print("Sending 'initialize' request...")
        write_request(init_req)
        
        # Read response
        init_resp_raw = read_stdout_line()
        print(f"Received raw initialize response: {init_resp_raw}")
        
        if not init_resp_raw:
            # Maybe it errored out? Check stderr
            errs = proc.stderr.read()
            print(f"No response. Stderr:\n{errs}")
            return
            
        init_resp = json.loads(init_resp_raw)
        print("Initialize Response Parsed successfully!")
        
        # Send initialized notification
        init_notif = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }
        print("Sending 'notifications/initialized'...")
        write_request(init_notif)
        
        # Send tools/list request
        list_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }
        print("Sending 'tools/list' request...")
        write_request(list_req)
        
        # Read tools response
        tools_resp_raw = read_stdout_line()
        print(f"Received raw tools/list response: {tools_resp_raw}")
        
        tools_resp = json.loads(tools_resp_raw)
        tools = tools_resp.get("result", {}).get("tools", [])
        print(f"\nSuccessfully retrieved {len(tools)} tools:")
        for t in tools:
            print(f" - {t.get('name')}: {t.get('description', '')[:60]}...")
            
    except Exception as e:
        print(f"Error during test: {e}")
    finally:
        proc.terminate()
        proc.wait()

if __name__ == "__main__":
    main()
