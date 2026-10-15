"""Test support: a local smart-HTTP git server (git http-backend over CGI) with a throttle injector.

Hermetic: binds 127.0.0.1 on a free port, serves bare repositories under one root, and never inherits
GIT_TRACE2_* (server-side processes must not land in the client's trace). `throttle(n)` makes the next n
requests answer HTTP 429 Too Many Requests, the way a rate-limited forge does.
"""
import http.server
import os
import socketserver
import subprocess
import threading


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class GitHTTPServer:
    def __init__(self, root):
        self.root = str(root)
        self.requests = []
        self.throttled = 0
        self._throttle_left = 0
        self._lock = threading.Lock()
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):  # keep test output clean
                pass

            def do_GET(self):
                server._serve(self, "GET")

            def do_POST(self):
                server._serve(self, "POST")

        self._httpd = _Server(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def url(self, name):
        return "http://127.0.0.1:%d/%s" % (self.port, name)

    def throttle(self, n=1):
        with self._lock:
            self._throttle_left = n

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._httpd.shutdown()
        self._httpd.server_close()

    def _serve(self, h, method):
        path, _, query = h.path.partition("?")
        with self._lock:
            self.requests.append((method, path))
            throttle = self._throttle_left > 0
            if throttle:
                self._throttle_left -= 1
                self.throttled += 1
        if throttle:
            body = b"Too Many Requests\n"
            h.send_response(429, "Too Many Requests")
            h.send_header("Content-Type", "text/plain")
            h.send_header("Retry-After", "0")
            h.send_header("Content-Length", str(len(body)))
            h.end_headers()
            h.wfile.write(body)
            return
        length = int(h.headers.get("Content-Length") or 0)
        data = h.rfile.read(length) if length else b""
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_TRACE")}
        env.update({
            "GIT_PROJECT_ROOT": self.root, "GIT_HTTP_EXPORT_ALL": "1", "REQUEST_METHOD": method,
            "PATH_INFO": path, "QUERY_STRING": query, "REMOTE_ADDR": "127.0.0.1",
            "CONTENT_TYPE": h.headers.get("Content-Type", ""), "CONTENT_LENGTH": str(len(data)),
            "GATEWAY_INTERFACE": "CGI/1.1", "SERVER_PROTOCOL": "HTTP/1.0",
        })
        for header, var in (("Git-Protocol", "HTTP_GIT_PROTOCOL"), ("Content-Encoding", "HTTP_CONTENT_ENCODING")):
            if h.headers.get(header):
                env[var] = h.headers[header]
        out = subprocess.run(["git", "http-backend"], input=data, env=env, capture_output=True).stdout
        head, _, body = out.partition(b"\r\n\r\n")
        if not _:
            head, _, body = out.partition(b"\n\n")
        status, headers = 200, []
        for line in head.decode("latin-1").splitlines():
            key, _, value = line.partition(":")
            if key.lower() == "status":
                status = int(value.strip().split()[0])
            elif key:
                headers.append((key, value.strip()))
        h.send_response(status)
        for key, value in headers:
            h.send_header(key, value)
        h.send_header("Content-Length", str(len(body)))
        h.end_headers()
        h.wfile.write(body)
