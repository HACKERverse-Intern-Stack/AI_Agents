# dns_receiver.py
import socketserver
import dns.message
import dns.resolver

class DNSLogger(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        socket = self.request[1]
        
        # Create a DNS message from the received data
        msg = dns.message.from_wire(data)
        
        # Log the question (the domain being queried)
        question = msg.question[0]
        qname = question.name.to_text()
        qtype = dns.rdatatype.to_text(question.rdtype)
        
        print(f"[!] Received DNS Query: {qname} (Type: {qtype})")
        
        # Create a simple "NXDOMAIN" (Non-Existent Domain) response
        # This is the standard response for a domain that doesn't exist
        response = dns.message.make_response(msg)
        response.set_rcode(dns.rcode.NXDOMAIN)
        
        socket.sendto(response.to_wire(), self.client_address)

def run_dns_server():
    print("[*] Starting DNS Logger on port 53...")
    print("[*] Make sure you run this with sudo/administrator privileges.")
    server = socketserver.UDPServer(('0.0.0.0', 53), DNSLogger)
    server.serve_forever()

if __name__ == '__main__':
    run_dns_server()