import subprocess
import json
import os

def test_mcp_server(name, cmd, env=None):
    print(f"\n--- Testing MCP Server: {name} ---")
    print(f"Command: {' '.join(cmd)}")
    
    proc_env = os.environ.copy()
    if env:
        proc_env.update(env)
        
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=proc_env,
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
        # 1. Initialize handshake
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
        write_request(init_req)
        init_resp_raw = read_stdout_line()
        if not init_resp_raw:
            errs = proc.stderr.read()
            print(f"Failed to initialize. Stderr:\n{errs}")
            return
            
        print("Initialize handshake successful.")
        
        # 2. Send initialized
        write_request({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })
        
        # 3. List tools
        write_request({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        })
        tools_resp_raw = read_stdout_line()
        if tools_resp_raw:
            tools_resp = json.loads(tools_resp_raw)
            tools = tools_resp.get("result", {}).get("tools", [])
            print(f"Successfully retrieved {len(tools)} tools:")
            for t in tools:
                print(f" - {t.get('name')}: {t.get('description', '')[:60]}...")
        else:
            print("Failed to list tools.")
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        proc.terminate()
        proc.wait()

def main():
    # Test 1: opensearch-mcp
    cmd1 = ["uvx", "opensearch-mcp-server-py"]
    env1 = {
        "OPENSEARCH_URL": "https://<siemx_HOST>:9200",
        "OPENSEARCH_USERNAME": "admin",
        "OPENSEARCH_PASSWORD": "admin",
        "OPENSEARCH_SSL_VERIFY": "false"
    }
    test_mcp_server("opensearch-mcp", cmd1, env1)
    
    # Test 2: opensearch-proxy-mcp
    cmd2 = ["python3", "<REPO_ROOT>/scripts/opensearch_proxy_mcp.py"]
    test_mcp_server("opensearch-proxy-mcp", cmd2)

if __name__ == "__main__":
    main()
