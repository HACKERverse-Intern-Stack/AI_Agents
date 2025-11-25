import nmap

def active_scan(target):
    """
    Perform an active scan (T1595) on the specified target.
    
    Args:
        target (str): IP address or range to scan (e.g., '192.168.1.1' or '192.168.1.1/24').
    
    Returns:
        dict: Scan results with open ports and services.
    """
    nm = nmap.PortScanner()
    
    try:
        print(f"[*] Scanning {target}...")
        nm.scan(target, arguments='-sS -O')  # SYN scan with OS detection
        
        results = {}
        for host in nm.all_hosts():
            results[host] = {
                'state': nm[host].state(),
                'protocols': nm[host].all_protocols(),
                'ports': {}
            }
            
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    port_info = nm[host][proto][port]
                    results[host]['ports'][port] = {
                        'state': port_info['state'],
                        'service': port_info.get('name', 'unknown'),
                        'product': port_info.get('product', 'unknown'),
                        'version': port_info.get('version', 'unknown')
                    }
        
        return results
    
    except Exception as e:
        print(f"[!] Error during scan: {e}")
        return None

if __name__ == "__main__":
    target = input("Enter target IP or range (e.g., '192.168.1.1/24'): ")
    scan_results = active_scan(target)
    
    if scan_results:
        print("\n[+] Scan Results:")
        for host, data in scan_results.items():
            print(f"\nHost: {host} ({data['state']})")
            for port, info in data['ports'].items():
                print(f"  Port {port}/{info['state']}: {info['service']} ({info['product']} {info['version']})")
    else:
        print("[!] No results or scan failed.")