# upload_receiver.py
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import shutil

class SimpleUploadHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/upload.php':
            try:
                # Find the boundary in the Content-Type header
                content_type = self.headers['Content-Type']
                boundary = content_type.split("boundary=")[1].encode()
                
                # Read the raw POST data
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                
                # Find the start and end of the file data
                # This is a very basic parser and might fail with complex filenames
                header_end = post_data.find(b'\r\n\r\n')
                file_data_start = header_end + 4
                file_data_end = post_data.find(b'\r\n--' + boundary + b'--\r\n')
                
                # Extract the file data
                file_data = post_data[file_data_start:file_data_end]
                
                # Get the filename from the headers
                filename_header = post_data[:header_end].decode()
                filename_start = filename_header.find('filename="') + len('filename="')
                filename_end = filename_header.find('"', filename_start)
                filename = filename_header[filename_start:filename_end]
                
                # Save the file
                with open(filename, 'wb') as f:
                    f.write(file_data)
                
                print(f"[+] Successfully received and saved file: {filename}")
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"File uploaded successfully.")
            
            except Exception as e:
                print(f"[-] Error processing upload: {e}")
                self.send_response(500)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

def run(server_class=HTTPServer, handler_class=SimpleUploadHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"[*] Starting upload receiver on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
