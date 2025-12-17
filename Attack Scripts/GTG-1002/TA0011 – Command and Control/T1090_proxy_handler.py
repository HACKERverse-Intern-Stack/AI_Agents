# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1090: Proxy
# Description: Using a proxy to redirect traffic (e.g., SOCKS, HTTP proxy).

#!/usr/bin/env python3
import socket
import threading
import argparse

def proxy_handler(client_socket, target_host, target_port):
    target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        target.connect((target_host, target_port))
        print(f"[+] Proxying to {target_host}:{target_port}")
        threading.Thread(target=relay, args=(client_socket, target)).start()
        threading.Thread(target=relay, args=(target, client_socket)).start()
    except Exception as e:
        print(f"[-] Proxy error: {e}")
        client_socket.close()

def relay(source, destination):
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            destination.sendall(data)
    except Exception as e:
        print(f"[-] Relay error: {e}")
    finally:
        source.close()
        destination.close()

def start_proxy(listen_port, target_host, target_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', listen_port))
    server.listen(5)
    print(f"[+] Proxy listening on 0.0.0.0:{listen_port} -> {target_host}:{target_port}")
    while True:
        client, addr = server.accept()
        threading.Thread(target=proxy_handler, args=(client, target_host, target_port)).start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="T1090: Simple TCP Proxy")
    parser.add_argument("--listen-port", type=int, required=True, help="Local port to listen on")
    parser.add_argument("--target-host", required=True, help="Target host (e.g., 192.168.1.100)")
    parser.add_argument("--target-port", type=int, required=True, help="Target port (e.g., 445)")
    args = parser.parse_args()
    start_proxy(args.listen_port, args.target_host, args.target_port)