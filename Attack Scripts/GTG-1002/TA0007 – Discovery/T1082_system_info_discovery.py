# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1082 - System Information Discovery
# Objective: Gather detailed system configuration. This script uses WMI over SMB to execute systeminfo remotely.

# !/usr/bin/env python3
import sys 
from impacket.dcerpc.v5 import transport, samr 
from impacket.examples.secretsdump import RemoteOperations

def run_system_info(target_ip, username, password, domain):
    rpc_transport = None
    dce = None  # This will be our SAMR connection object
    try:
        print(f"[*] Attempting to get system info from {target_ip}...")

        # 1. Define the target string for the SMB transport
        string_binding = r'ncacn_np:%s[\pipe\samr]' % target_ip

        # 2. Create the main transport object, which lets us establish the connection
        rpc_transport = transport.DCERPCTransportFactory(string_binding)

        # 3. Set credentials on the transport
        if username and password:
            rpc_transport.set_credentials(username, password, domain)

        # 4. Connect the main transport
        rpc_transport.connect()

        # 5. Initiate the SAMR connection. We get the DCE/RPC endpoint from the transport and then connect it using the SAMR interface.
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        print("[*] SAMR connection established.")

        # 6. Pass BOTH the main transport and the SAMR connection object to RemoteOperations
        # The second argument is where you provide the pre-connected SAMR object.
        remote_ops = RemoteOperations(rpc_transport, dce)

        # 7. Use the remote_ops object to get machine info
        remote_ops.getMachineInfo()
        print("[+] System information retrieved successfully.")

        # Print the info stored in the class
        if hasattr(remote_ops, 'MachineInfo'):
            for key, value in remote_ops.MachineInfo.items():
                print(f" {key}: {value}")

    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        # 8. Clean up both connections
        if dce:
            dce.disconnect()
            print("[*] SAMR connection disconnected.")
        if rpc_transport:
            rpc_transport.disconnect()
            print("[*] Main transport disconnected.")

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: ./T1082_system_info_discovery.py <target IP> <username> <password> <domain>")
        sys.exit(1)
    run_system_info(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])