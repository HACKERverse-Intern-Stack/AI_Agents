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

        # 6. Try to enumerate domains. If it fails, fall back to the Builtin domain.
        try:
            print("[*] Enumerating domains to get a handle...")
            domains = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            # Check if the buffer is empty
            if not domains['Buffer']:
                raise Exception("No domains found, likely a workgroup machine.")
            domain_info = domains['Buffer'][0]
            domain_sid = domain_info['Sid']
            print(f"[*] Found domain: {domain_info['Name']}")
        except Exception as e:
            print(f"[-] Could not enumerate primary domain ({e}). Falling back to BUILTIN domain.")
            # Fallback for workgroup computers
            # The SID for the BUILTIN domain is always S-1-5-32
            from impacket.dcerpc.v5.dtypes import RPC_SID
            domain_sid = RPC_SID()
            domain_sid.fromCanonical('S-1-5-32')

        # 7. Open the domain (either the primary one or BUILTIN)
        print("[*] Opening a handle to the domain...")
        domain_handle = samr.hSamrOpenDomain(dce, server_handle, samr.DOMAIN_READ, domain_sid)['DomainHandle']
        print("[*] Successfully opened a handle to the domain.")

        # 8. Query for display information using the domain handle
        print("[*] Querying domain for information...")
        server_info = samr.hSamrQueryDisplayInformation(
            dce,
            domain_handle,
            3,  # The integer value for DOMAIN_DISPLAY_INFORMATION
            0,  # Index
            1000 # Get more entries to see local users
        )

        # Extract and print the details
        print("\n[+] System Information Retrieved Successfully!")
        print("--- Domain/Local Group Information ---")
        for info_data in server_info['Buffer']:
            print(f"  Name: {info_data['AccountName']}, Comment: {info_data['AccountDisplayName']}")

    except DCERPCException as e:
        print(f"[-] A DCE/RPC error occurred: {e}")
        print("[*] This could be due to permissions or an issue with the SAMR pipe.")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
    finally:
        # 9. Clean up connections safely
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