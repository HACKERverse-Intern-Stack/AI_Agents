# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1082 - System Information Discovery
# Objective: Gather detailed system configuration. This script uses WMI over SMB to execute systeminfo remotely.

# !/usr/bin/env python3
import sys
from impacket.dcerpc.v5 import transport, samr
from impacket.examples.secretsdump import RemoteOperations

def run_system_info(target_ip, username, password):
    rpc_transport = None
    dce = None
    remote_ops = None # Initialize remote_ops to None

    try:
        print(f"[*] Attempting to get system info from {target_ip}...")

        # 1. Define the target string for the SMB transport
        string_binding = r'ncacn_np:%s[\pipe\samr]' % target_ip

        # 2. Create the main transport object
        rpc_transport = transport.DCERPCTransportFactory(string_binding)

        # 3. Set credentials on the transport
        if username and password:
            rpc_transport.set_credentials(username, password)

        # 4. Connect the main transport
        rpc_transport.connect()
        print("[*] Main transport connected.")

        # 5. Initiate the SAMR connection.
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        print("[*] SAMR connection established.")

        # 6. Pass BOTH the main transport and the SAMR connection object to RemoteOperations
        remote_ops = RemoteOperations(rpc_transport, dce)

        # 7. Use the remote_ops object to get machine info
        remote_ops.getMachineInfo()
        print("[+] System information retrieved successfully.")

        # Print the info stored in the class
        if hasattr(remote_ops, 'MachineInfo'):
            for key, value in remote_ops.MachineInfo.items():
                print(f" {key}: {value}")

    except Exception as e:
        print(f"[-] An error occurred: {e}")

    finally:
        # 8. Clean up connections safely
        # The order of disconnection matters. Disconnect the higher-level objects first.
        print("[*] Cleaning up connections...")
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
    if len(sys.argv) != 5:
        print("Usage: ./T1082_system_info_discovery.py <target IP> <username> <password>")
        sys.exit(1)

    run_system_info(sys.argv[1], sys.argv[2], sys.argv[3])