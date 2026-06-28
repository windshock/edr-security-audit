import os
import urllib.request
import ssl
import json

def test_direct_api():
    url = "https://edr-console.local/web/api/v2.1/agents"
    token = os.environ.get("EDR_ONPREM_TOKEN","")
    
    # SSL verification using the CA bundle
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cafile="<REPO_ROOT>/bin/extracted/edr_onprem_ca.crt")
    
    for prefix in ["ApiToken", "Bearer"]:
        headers = {
            "Authorization": f"{prefix} {token}",
            "Content-Type": "application/json"
        }
        req = urllib.request.Request(url, headers=headers, method="GET")
        print(f"\n--- Testing with header: Authorization: {prefix} <token> ---")
        try:
            with urllib.request.urlopen(req, context=ctx) as resp:
                print(f"Status Code: {resp.status}")
                data = json.loads(resp.read().decode('utf-8'))
                print("Response successfully received!")
                print(f"Total Agents: {len(data.get('data', []))}")
        except urllib.error.HTTPError as e:
            print(f"HTTP Error: {e.code} - {e.reason}")
            try:
                print(f"Response: {e.read().decode('utf-8')}")
            except Exception:
                pass
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    test_direct_api()
