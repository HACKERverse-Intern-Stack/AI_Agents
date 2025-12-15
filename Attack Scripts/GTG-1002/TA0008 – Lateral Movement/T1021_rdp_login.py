# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1021 - Remote Services - Remote Desktop Protocol
# Objective: Check if RDP is open and attempt to log in. This script uses a brute-force approach.

#!/usr/bin/env python3
import sys
from impacket.dcerpc.v5 import transport, rrp

def check_rdp_status(target, username, password, domain):
    try:
        print(f"[*] Checking RDP enabled status via registry on {target}...")
        string_binding = r'ncacn_np:%s[\pipe\winreg]' % target
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(username, password, domain)
        
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        # Open the key to check
        key_path = "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"
        resp = rrp.hBaseRegOpenKey(dce, rrp.HKEY_LOCAL_MACHINE, key_path, rrp.REG_OPTION_NON_VOLATILE, rrp.KEY_READ)
        key_handle = resp['phkResult']

        # Query the value for "fDenyTSConnections"
        resp = rrp.hBaseRegQueryValue(dce, key_handle, "fDenyTSConnections")
        value = resp['lpData']

        if value == 0:
            print("[+] RDP is ENABLED on the target.")
            print(f"    Connect using: xfreerdp /v:{target} /u:{username} /p:'{password}' /d:{domain}")
        else:
            print("[-] RDP is DISABLED on the target.")
        
        dce.disconnect()
        return True

    except Exception as e:
        # If the policy key doesn't exist, check the default location
        try:
            print("[*] Policy key not found, checking default Terminal Server settings...")
            key_path = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
            resp = rrp.hBaseRegOpenKey(dce, rrp.HKEY_LOCAL_MACHINE, key_path, rrp.REG_OPTION_NON_VOLATILE, rrp.KEY_READ)
            key_handle = resp['phkResult']
            resp = rrp.hBaseRegQueryValue(dce, key_handle, "fDenyTSConnections")
            value = resp['lpData']
            if value == 0:
                print("[+] RDP is ENABLED on the target.")
                print(f"    Connect using: xfreerdp /v:{target} /u:{username} /p:'{password}' /d:{domain}")
            else:
                print("[-] RDP is DISABLED on the target.")
            dce.disconnect()
        except Exception as e2:
            print(f"[-] Could not determine RDP status: {e2}")
        return False

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: ./t1021_rdp_check.py <target> <username> <password> <domain>")
        print("Note: This script only checks for RDP availability. Use an RDP client to connect.")
        sys.exit(1)

    check_rdp_status(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])