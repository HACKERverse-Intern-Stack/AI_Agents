# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1003 - Credential Dumping
# Objective: Adversaries may attempt to dump credentials to obtain account login and credential material. This script simulates attempting to read the SAM database file, which stores user passwords.

# t1003_credential_dumping.py
import subprocess
import os
import platform

# --- Simulation Configuration ---
TARGET_IP = "192.168.227.139"
SHARE_NAME = "LABSHARE"
USERNAME = "labadmin"
PASSWORD = "Password123!"

TOOL_NAME = "procdump.exe"
DUMP_FILE_NAME = "lsass.dmp"


def run_smb(cmd):
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=10
    )
    print("[*] SMB STDOUT:")
    print(result.stdout if result.stdout else "(none)")
    print("[*] SMB STDERR:")
    print(result.stderr if result.stderr else "(none)")
    return result.returncode == 0


def simulate_credential_dumping():
    print(f"[*] T1003 Simulation against {TARGET_IP}")

    if platform.system().lower() == "windows":
        print("[-] Run this from Linux (Kali).")
        return

    # --- Step 1: Create fake procdump binary ---
    print("[*] Creating fake procdump.exe")
    with open(TOOL_NAME, "wb") as f:
        f.write(os.urandom(512))

    # --- Step 2: Upload procdump ---
    print("[*] Uploading procdump.exe to LABSHARE")
    upload_tool = (
        f"smbclient //{TARGET_IP}/{SHARE_NAME} "
        f"-U {USERNAME}%{PASSWORD} "
        f"-c 'put {TOOL_NAME}'"
    )
    run_smb(upload_tool)

    # --- Step 3: Simulate LSASS dump creation ---
    print("[*] Creating fake lsass.dmp")
    with open(DUMP_FILE_NAME, "wb") as f:
        f.write(os.urandom(2048))

    print("[*] Uploading fake lsass.dmp to LABSHARE")
    upload_dump = (
        f"smbclient //{TARGET_IP}/{SHARE_NAME} "
        f"-U {USERNAME}%{PASSWORD} "
        f"-c 'put {DUMP_FILE_NAME}'"
    )
    run_smb(upload_dump)

    # --- Step 4: Download dump back ---
    print("[*] Downloading lsass.dmp from Windows")
    download_dump = (
        f"smbclient //{TARGET_IP}/{SHARE_NAME} "
        f"-U {USERNAME}%{PASSWORD} "
        f"-c 'get {DUMP_FILE_NAME} downloaded_lsass.dmp'"
    )
    run_smb(download_dump)

    # --- Cleanup ---
    print("[*] Cleaning up local files")
    for f in [TOOL_NAME, DUMP_FILE_NAME]:
        if os.path.exists(f):
            os.remove(f)

    print("[+] Simulation complete.")
    print("[!] Note: This simulates credential dumping artifacts, not real LSASS access.")


if __name__ == "__main__":
    simulate_credential_dumping()