# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1078 - Valid Accounts
# Objective: Adversaries may obtain and abuse credentials of existing accounts. This script simulates the use of a compromised account by making a network request that requires authentication, like accessing a network share.

# t1078_valid_accounts.py
import os
import subprocess

# --- Simulation Configuration ---
# This simulates an attacker trying to access a share with a 'found' credential.
# In a real lab, you would set up a share and use valid/invalid credentials to test detection.
SHARE_PATH = r"\\127.0.0.1\C$"  # Attempting to access the admin share
USERNAME = "testuser"  # Placeholder for a compromised username
PASSWORD = "Password123!" # Placeholder for a compromised password

def simulate_valid_account_use():
    """
    Simulates T1078 by attempting to access a network resource using credentials.
    On Windows, this would use 'net use'. On Linux, 'smbclient'.
    This script will likely fail unless you configure it in a lab, but the
    *attempt* is the artifact you want to detect.
    """
    print(f"[*] T1078 Simulation: Attempting to access network share '{SHARE_PATH}' with valid account '{USERNAME}'")
    
    if os.name == 'nt': # Windows
        try:
            # The command to authenticate and map a network drive
            command = f"net use \\\\127.0.0.1\\ipc$ \"{PASSWORD}\" /user:\"{USERNAME}\""
            print(f"[*] Executing command: {command.replace(PASSWORD, '[REDACTED]')}")
            
            # Use subprocess to run the command
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            
            print(f"[+] Command executed with exit code: {result.returncode}")
            if result.stdout:
                print(f"[!] STDOUT: {result.stdout.strip()}")
            if result.stderr:
                print(f"[!] STDERR: {result.stderr.strip()}")
            
            # Clean up the connection
            print("[*] Cleaning up connection with 'net use * /delete'")
            subprocess.run("net use * /delete /y", shell=True, capture_output=True)

        except Exception as e:
            print(f"[!] An error occurred: {e}")
    else: # Linux/macOS
        print("[-] This simulation is for Windows. On Linux, you would use 'smbclient'.")
        print(f"[*] Example command: smbclient //{SHARE_PATH.replace('\\\\', '')} -U {USERNAME}%{PASSWORD}")


if __name__ == "__main__":
    simulate_valid_account_use()