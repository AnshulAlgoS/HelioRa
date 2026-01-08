import json
import sys
from http.server import SimpleHTTPRequestHandler, HTTPServer

class Handler(SimpleHTTPRequestHandler):
    def _set_headers(self, code=200, content_type='application/json'):
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length > 0 else b''
        try:
            data = json.loads(body.decode('utf-8'))
        except Exception:
            data = {'raw': body.decode('utf-8', 'ignore')}

        if self.path == '/api/login':
            self._set_headers(200)
            resp = {'status': 'ok', 'message': 'Login received', 'received': data}
            self.wfile.write(json.dumps(resp).encode('utf-8'))
        elif self.path.startswith('/api/'):
            self._set_headers(200)
            resp = {'status': 'ok', 'path': self.path, 'received': data}
            self.wfile.write(json.dumps(resp).encode('utf-8'))
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({'error': 'Not Found'}).encode('utf-8'))

def run(port):
    httpd = HTTPServer(('', port), Handler)
    print(f"Serving HTTP on :: port {port} (http://[::]:{port}/) ...")
    httpd.serve_forever()

if __name__ == '__main__':
    port = 8000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except Exception:
            pass
    run(port)
