import http.server
import socketserver
import os
import webbrowser

PORT = 8080
base_dir = os.getcwd()

def start_server():
    os.chdir(base_dir)
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        url = f"http://localhost:{PORT}/"
        print(f"Serving at {url}")
        webbrowser.open(url)  # Auto-open in default browser
        httpd.serve_forever()

if __name__ == "__main__":
    start_server()
