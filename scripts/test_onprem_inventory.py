import subprocess
import json
import os

def run_test(base_url, use_ssl_bundle=True, bypass_ssl=False):
    print(f"\n--- Testing edr-mcp with URL: {base_url} (use_ssl_bundle={use_ssl_bundle}, bypass_ssl={bypass_ssl}) ---")
    
    env = os.environ.copy()
    env["EDR_MCP_CONSOLE_TOKEN"] = os.environ.get("EDR_ONPREM_TOKEN","")
    env["EDR_MCP_CONSOLE_BASE_URL"] = base_url
    
    env["EDR_MCP_AUTH_PREFIX"] = "ApiToken"
    env["PYTHONPATH"] = "<REPO_ROOT>/edr-mcp/src"
    if use_ssl_bundle:
        env["REQUESTS_CA_BUNDLE"] = "<REPO_ROOT>/bin/extracted/edr_onprem_ca.crt"
        env["SSL_CERT_FILE"] = "<REPO_ROOT>/bin/extracted/edr_onprem_ca.crt"
    if bypass_ssl:
        env["PYTHONHTTPSVERIFY"] = "0"
        
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
            print(f"Failed to init. Stderr:\n{proc.stderr.read()}")
            return
            
        write_request({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })
        
        # Call list_alerts
        write_request({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "list_alerts",
                "arguments": {}
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

def main():
    # Scenario A: Domain edr-console.local with edr_onprem_ca.crt
    run_test("https://edr-console.local", use_ssl_bundle=True)
    
    # Scenario B: IP <EDR_ONPREM_CONSOLE> with bypass SSL
    # run_test("https://<EDR_ONPREM_CONSOLE>", use_ssl_bundle=False, bypass_ssl=True)

if __name__ == "__main__":
    main()
