from http.server import BaseHTTPRequestHandler, HTTPServer
import orjson
import orjson.orjson as native

if not native.__file__.endswith('.so'):
    raise RuntimeError('orjson native extension was not loaded')


class Health(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/health':
            self.send_error(404)
            return
        body = orjson.dumps({'status': 'ok', 'runtime': 'python', 'native': True, 'answer': 42})
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


HTTPServer(('0.0.0.0', 8080), Health).serve_forever()
