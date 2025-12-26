# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1087 - Account Discovery
# Objective: Enumerate domain users. This script uses SAMR RPC to list user accounts.

#!/usr/bin/env python3
import sys
import subprocess
import re

def enumerate_users_with_nxc(target, username, password, domain):
    """
    Enumerates users on a target using netexec.

    Args:
        target (str): The IP address or hostname of the target.
        username (str): The username for authentication.
        password (str): The password for authentication.
        domain (str): The domain for authentication.
    """
    try:
        # Construct the netexec command
        # -u: username, -p: password, --domain: domain
        # The command uses the 'sam' module to list users via RPC
        command = [
            "nxc",
            "smb",
            target,
            "-u", username,
            "-p", password,
            "--domain", domain,
            "--users"
        ]

        print(f"[*] Running command: {' '.join(command)}")

        # Execute the command and capture output
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False # Don't raise exception on non-zero exit code
        )

        # Check if netexec found valid credentials
        if result.returncode == 0:
            # netexec output contains user information in a specific format
            # We parse it to extract the usernames cleanly
            users = []
            # Example line: SAMR  192.168.44.129  445  CORP  [+] CORP\user1 (Status: enabled | Last logon: <never>)
            for line in result.stdout.splitlines():
                if "SAMR" in line and "[+]" in line:
                    # Use regex to find the username after the domain\
                    match = re.search(rf"{re.escape(domain)}\$$\w+)", line)
                    if match:
                        users.append(match.group(1))

            if result.stdout:
                print("\n[+] Users enumerated. Showcasing results:")
                print("[*] netexec output:")
                print(result.stdout)
            else:
                print("\n[-] No users were enumerated. The credentials might be valid, but lack permissions OR Port 445 (SMB service) potentially closed.")

        else:
            # If the command fails, print the error from stderr
            print(f"[-] netexec failed with exit code {result.returncode}")
            print(f"[-] Error: {result.stderr.strip()}")
            print("[*] This is often due to incorrect credentials, a network issue, or the target being unreachable.")

    except FileNotFoundError:
        print("[-] Error: 'nxc' command not found.")
        print("[*] Please ensure netexec is installed and in your system's PATH.")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: ./T1087_nxc_account_discovery.py <target> <username> <password> <domain>")
        sys.exit(1)

    enumerate_users_with_nxc(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])