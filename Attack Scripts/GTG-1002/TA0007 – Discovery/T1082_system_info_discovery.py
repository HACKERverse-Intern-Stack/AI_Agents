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
    try:
        print(f"[*] Attempting to get system info from {target_ip}...")
        # 1. Define the target string for the SMB transport
        string_binding = r'ncacn_np:%s[\pipe\samr]' % target_ip

        # 2. Create the main transport object
        rpc_transport = transport.DCERPCTransportFactory(string_binding)

        # 3. Set credentials. The domain is omitted for local account authentication.
        rpc_transport.set_credentials(username, password)

        # 4. Connect and bind
        rpc_transport.connect()
        print("[*] Main transport connected.")
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        print("[*] SAMR connection established.")

        # 5. Use SAMR calls to get server info
        # First, connect to the SAMR service on the remote server
        server_handle = samr.hSamrConnect(dce, f"\\\\{target_ip}")['ServerHandle']
        print("[*] Connected to SAMR server.")

        # Now, query the server for its information using the correct modern function
        print("[*] Querying server for information...")
        # The correct function is hSamrQueryDisplayInformation
        # We ask for the domain display information (index 2) to get the server details
        server_info = samr.hSamrQueryDisplayInformation(
            dce,
            server_handle,
            3, # This is the correct information class
            0, # Index
            1  # EntryCount (we only need the one entry for the server itself)
        )

        # Extract and print the details from the new response structure
        print("\n[+] System Information Retrieved Successfully!")
        # The data is now in a list under the 'Buffer' key
        info_data = server_info['Buffer'][0]
        # The fields are also named differently
        print(f" Server Name: {info_data['AccountName']}") # This is the server/computer name
        print(f" Domain Name: {info_data['DomainName']}")

    except DCERPCException as e:
        print(f"[-] A DCE/RPC error occurred: {e}")
        print("[*] This could be due to permissions or an issue with the SAMR pipe.")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
    finally:
        # 6. Clean up connections safely
        print("[*] Cleaning up connections...")
        if server_handle:
            try:
                samr.hSamrCloseHandle(dce, server_handle)
                print("[*] SAMR server handle closed.")
            except Exception as e:
                print(f"[-] Error closing SAMR handle: {e}")
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