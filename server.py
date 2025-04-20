import http.server
import os
import socketserver

# Paths
base_dir = "/home/ubuntu/Downloads/pentest-project"
output_dir = os.path.join(base_dir, "scan-results")
index_path = os.path.join(base_dir, "index.html")
PORT = 8080

def start_server():
    os.chdir(base_dir)
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"Serving at http://localhost:{PORT}/scan-results/index.html")
        httpd.serve_forever()
start_server()