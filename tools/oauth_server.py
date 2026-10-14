from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading

class OAuthCallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        
        # Save the authorization code
        if 'code' in params:
            code = params['code'][0]
            print(f"=== OAUTH CALLBACK RECEIVED ===")
            print(f"Authorization Code: {code[:50]}...")
            with open('/tmp/oauth_code.txt', 'w') as f:
                f.write(code)
        
        # Send a success response
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Authorization successful! You can close this tab.</h1></body></html>")
    
    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    server = HTTPServer(('localhost', 8390), OAuthCallbackHandler)
    print("OAuth callback server started on port 8390")
    server.serve_forever()
