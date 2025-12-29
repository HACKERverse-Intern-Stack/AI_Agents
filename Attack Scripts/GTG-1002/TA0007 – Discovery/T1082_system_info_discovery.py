# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1082 - System Information Discovery
# Objective: Enumerate system information from a target. This script uses netexec
# to execute the 'systeminfo' command remotely and parses the output.

#!/usr/bin/env python3
import sys
import subprocess
import re

def get_system_info_with_nxc(target, username, password, domain):
    """
    Gets system information from a target using netexec to execute 'systeminfo'.

    Args:
        target (str): The IP address or hostname of the target.
        username (str): The username for authentication.
        password (str): The password for authentication.
        domain (str): The domain for authentication.
    """
    try:
        # Construct the netexec command to execute 'systeminfo'
        # -x: Execute a command on the target
        command = [
            "netexec", "smb", target,
            "-u", username,
            "-p", password,
            "--domain", domain,
            "-x", "systeminfo"
        ]

        print(f"[*] Running command: {' '.join(command)}")

        # Execute the command and capture output
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False  # Don't raise exception on non-zero exit code
        )

        # Check if netexec executed the command successfully
        if result.returncode == 0:
            if result.stdout:
                print("\n[+] System information retrieved successfully. Showcasing results:")
                print("[*] netexec output:")
                print(result.stdout)
            else:
                print("\n[-] The command executed but returned no output.")
                print("[*] This could mean the 'systeminfo' command failed on the target, the user lacks execution permissions, or port 445 (SMB service) is closed.")

        else:
            # If the command fails, print the error from stderr
            print(f"\n[-] netexec failed with exit code {result.returncode}")
            print(f"[-] Error: {result.stderr.strip()}")
            print("[*] This is often due to incorrect credentials, a network issue, or the target being unreachable.")

    except FileNotFoundError:
        print("[-] Error: 'netexec' command not found.")
        print("[*] Please ensure netexec is installed and in your system's PATH.")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: ./T1082_nxc_system_info_discovery.py <target> <username> <password> <domain>")
        sys.exit(1)
    
    # Note: For local accounts, you can pass '.' as the domain.
    get_system_info_with_nxc(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])