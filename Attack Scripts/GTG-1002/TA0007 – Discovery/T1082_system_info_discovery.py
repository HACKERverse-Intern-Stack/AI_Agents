# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1082 - System Information Discovery
# Objective: Gather detailed system configuration. This script uses WMI over SMB to execute systeminfo remotely.

# !/usr/bin/env python3
import sys
from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException

def run_system_info(target_ip, username, password):
    rpc_transport = None
    dce = None
    server_handle = None
    domain_handle = None
    try:
        print(f"[*] Attempting to get system info from {target_ip}...")
        # 1. Define the target string for the SMB transport
        string_binding = r'ncacn_np:%s[\pipe\samr]' % target_ip

        # 2. Create the main transport object
        rpc_transport = transport.DCERPCTransportFactory(string_binding)

        # 3. Set credentials.
        rpc_transport.set_credentials(username, password)

        # 4. Connect and bind
        rpc_transport.connect()
        print("[*] Main transport connected.")
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        print("[*] SAMR connection established.")

        # 5. Connect to the SAMR service to get a server handle
        server_handle = samr.hSamrConnect(dce, f"\\\\{target_ip}")['ServerHandle']
        print("[*] Connected to SAMR server.")

        # 6. NEW STEP: Use the server handle to get a handle to the domain
        print("[*] Enumerating domains to get a handle...")
        # First, we need to find the domain's SID
        domains = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domain_info = domains['Buffer'][0]
        domain_sid = domain_info['Sid']
        
        # Now, open the domain using its SID to get the domain_handle
        domain_handle = samr.hSamrOpenDomain(dce, server_handle, samr.DOMAIN_READ, domain_sid)['DomainHandle']
        print("[*] Successfully opened a handle to the domain.")

        # 7. Now, use the DOMAIN_HANDLE to query for display information
        print("[*] Querying domain for information...")
        # This will now work because we are passing a DomainHandle
        server_info = samr.hSamrQueryDisplayInformation(
            dce,
            domain_handle,  # Use the domain_handle here!
            3,  # The integer value for DOMAIN_DISPLAY_INFORMATION
            0,  # Index
            1   # EntryCount
        )

        # Extract and print the details
        print("\n[+] System Information Retrieved Successfully!")
        info_data = server_info['Buffer'][0]
        print(f" Domain Name: {info_data['DomainName']}")
        # Note: The 'AccountName' field in this context will be the name of the domain controller
        print(f" Domain Controller / Server Name: {info_data['AccountName']}")

    except DCERPCException as e:
        print(f"[-] A DCE/RPC error occurred: {e}")
        print("[*] This could be due to permissions or an issue with the SAMR pipe.")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
    finally:
        # 8. Clean up connections safely (now closing both handles)
        print("[*] Cleaning up connections...")
        if domain_handle:
            try:
                samr.hSamrCloseHandle(dce, domain_handle)
                print("[*] SAMR domain handle closed.")
            except Exception as e:
                print(f"[-] Error closing domain handle: {e}")
        if server_handle:
            try:
                samr.hSamrCloseHandle(dce, server_handle)
                print("[*] SAMR server handle closed.")
            except Exception as e:
                print(f"[-] Error closing server handle: {e}")
        if dce:
            try:
                dce.disconnect()
                print("[*] SAMR connection disconnected.")
            except Exception as e:
                print(f"[-] Error disconnecting DCE: {e}")
        if rpc_transport:
            try:
                rpc_transport.disconnect()
                print("[*] Main transport disconnected.")
            except Exception as e:
                print(f"[-] Error disconnecting transport: {e}")

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: ./T1082_system_info_discovery.py <target IP> <username> <password>")
        sys.exit(1)

    run_system_info(sys.argv[1], sys.argv[2], sys.argv[3])