# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1087 - Account Discovery
# Objective: Enumerate domain users. This script uses SAMR RPC to list user accounts.

#!/usr/bin/env python3
import sys
from impacket.dcerpc.v5 import transport, samr

def enumerate_users(target, username, password, domain):
    try:
        print(f"[*] Attempting to enumerate domain users on {target}...")
        string_binding = r'ncacn_np:%s[\pipe\samr]' % target
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(username, password, domain)
        
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        
        resp = samr.hSamrConnect(dce)
        server_handle = resp['ServerHandle']
        
        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domains = resp['Buffer']['Buffer']
        domain = domains[0]['Name']
        
        resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain)
        domain_sid = resp['DomainId']
        
        resp = samr.hSamrOpenDomain(dce, server_handle, samr.DOMAIN_LOOKUP, domain_sid)
        domain_handle = resp['DomainHandle']
        
        resp = samr.hSamrEnumerateUsersInDomain(dce, domain_handle)
        users = resp['Buffer']['Buffer']
        
        print(f"[+] Found {len(users)} users in domain '{domain}':")
        for user in users:
            print(f"    - {user['Name']}")

        dce.disconnect()
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: ./t1087_account_discovery.py <target> <username> <password> <domain>")
        sys.exit(1)

    enumerate_users(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])