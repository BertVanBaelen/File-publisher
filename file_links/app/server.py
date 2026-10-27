#!/usr/bin/env python3
"""File Links: serve chosen files under clean public paths.

Two servers run in one process:
  * public (port 8080): serves only the files you mapped, e.g. /resume
  * admin  (port 8099): the management page, reachable only through
    Home Assistant ingress (so it is protected by your HA login)

Standard library only, so the image builds on every architecture.
"""
import json
import mimetypes
import os
import re
import shutil
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

FILES_DIR = Path(os.environ.get("FILES_DIR", "/share/file_links"))
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
LINKS_FILE = DATA_DIR / "links.json"
OPTIONS_FILE = DATA_DIR / "options.json"
STATIC_DIR = Path(__file__).parent / "static"

PUBLIC_PORT = int(os.environ.get("PUBLIC_PORT", "8080"))
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "8099"))
INGRESS_IP = "172.30.32.2"  # Home Assistant's ingress proxy
ALLOW_ANY_ADMIN = os.environ.get("ALLOW_ANY_ADMIN") == "1"  # local testing only

MAX_UPLOAD = 500 * 1024 * 1024
CHUNK = 64 * 1024
PATH_RE = re.compile(r"^/[A-Za-z0-9._~\-/]*$")

lock = threading.Lock()


# ---------------------------------------------------------------- storage

def load_options():
    try:
        return json.loads(OPTIONS_FILE.read_text())
    except Exception:
        return {}


def load_links():
    try:
        data = json.loads(LINKS_FILE.read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_links(links):
    tmp = LINKS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(links, indent=2, sort_keys=True))
    tmp.replace(LINKS_FILE)


def normalize_path(raw):
    """'/resume/' -> '/resume', '' -> '/', 'cv' -> '/cv'"""
    return "/" + raw.strip().strip("/")


def clean_filename(raw):
    name = os.path.basename(raw.replace("\\", "/")).strip()
    name = "".join(ch for ch in name if ch.isprintable())
    if not name or name.startswith(".") or name in ("..",):
        return None
    return name


def safe_file(name):
    """Resolve a file name inside FILES_DIR, or None if it is unsafe or missing."""
    name = clean_filename(name or "")
    if not name:
        return None
    path = (FILES_DIR / name).resolve()
    if path.parent != FILES_DIR.resolve() or not path.is_file():
        return None
    return path


def list_files(links):
    used = {}
    for p, link in links.items():
        used.setdefault(link.get("file"), []).append(p)
    files = []
    for entry in sorted(FILES_DIR.iterdir(), key=lambda e: e.name.lower()):
        if entry.is_file() and not entry.name.startswith("."):
            st = entry.stat()
            files.append({
                "name": entry.name,
                "size": st.st_size,
                "modified": int(st.st_mtime),
                "used_by": sorted(used.get(entry.name, [])),
            })
    return files


# ---------------------------------------------------------------- helpers

class Base(BaseHTTPRequestHandler):
    server_version = "FileLinks/1.0"
    sys_version = ""
    tag = ""

    def log_message(self, fmt, *args):
        print(f"[{self.tag}] {self.address_string()} {fmt % args}", flush=True)

    def send_text(self, code, text, head=False):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def body_chunks(self, limit):
        """Yield the request body, supporting Content-Length and chunked encoding."""
        total = 0
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline().strip():
                        pass
                    return
                remaining = size
                while remaining:
                    chunk = self.rfile.read(min(CHUNK, remaining))
                    if not chunk:
                        raise ValueError("connection closed during upload")
                    remaining -= len(chunk)
                    total += len(chunk)
                    if total > limit:
                        raise ValueError("file is too large")
                    yield chunk
                self.rfile.readline()
        else:
            remaining = int(self.headers.get("Content-Length") or 0)
            if remaining > limit:
                raise ValueError("file is too large")
            while remaining:
                chunk = self.rfile.read(min(CHUNK, remaining))
                if not chunk:
                    raise ValueError("connection closed during upload")
                remaining -= len(chunk)
                yield chunk

    def read_json(self):
        raw = b"".join(self.body_chunks(1024 * 1024))
        return json.loads(raw or b"{}")

    def query(self):
        return urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)

    def route(self):
        return urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)


# ---------------------------------------------------------------- public server

class PublicHandler(Base):
    tag = "public"

    def do_GET(self):
        self.serve(head=False)

    def do_HEAD(self):
        self.serve(head=True)

    def serve(self, head):
        key = normalize_path(self.route())
        with lock:
            link = load_links().get(key)
        path = safe_file(link.get("file")) if link else None
        if not path:
            return self.send_text(404, "Not found", head)

        ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        disposition = "attachment" if link.get("download") else "inline"
        ascii_name = path.name.encode("ascii", "ignore").decode().replace('"', "") or "file"
        utf8_name = urllib.parse.quote(path.name)

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(path.stat().st_size))
        self.send_header(
            "Content-Disposition",
            f"{disposition}; filename=\"{ascii_name}\"; filename*=UTF-8''{utf8_name}",
        )
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if head:
            return
        try:
            with path.open("rb") as fh:
                shutil.copyfileobj(fh, self.wfile, CHUNK)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        self.send_text(405, "Method not allowed")

    do_PUT = do_DELETE = do_PATCH = do_POST


# ---------------------------------------------------------------- admin server

class AdminHandler(Base):
    tag = "admin"

    def allowed(self):
        if ALLOW_ANY_ADMIN or self.client_address[0] == INGRESS_IP:
            return True
        self.send_text(403, "Open this page from the Home Assistant sidebar.")
        return False

    def state(self):
        with lock:
            links = load_links()
            files = list_files(links)
        public_url = str(load_options().get("public_url") or "").strip().rstrip("/")
        return {
            "public_url": public_url,
            "links": [
                {"path": p, "file": l.get("file"), "download": bool(l.get("download")),
                 "missing": safe_file(l.get("file")) is None}
                for p, l in sorted(links.items())
            ],
            "files": files,
        }

    def do_GET(self):
        if not self.allowed():
            return
        route = self.route()
        if route in ("/", "/index.html"):
            body = (STATIC_DIR / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif route == "/api/state":
            self.send_json(200, self.state())
        else:
            self.send_text(404, "Not found")

    def do_POST(self):
        if not self.allowed():
            return
        if self.route() != "/api/links":
            return self.send_text(404, "Not found")
        try:
            data = self.read_json()
        except Exception:
            return self.send_json(400, {"error": "The request was not valid JSON."})

        path = normalize_path(str(data.get("path", "")))
        old_path = data.get("old_path")
        file_name = clean_filename(str(data.get("file", "")))

        if not PATH_RE.match(path) or "//" in path or "/../" in path + "/":
            return self.send_json(400, {"error": "Paths can use letters, numbers, - _ . ~ and /."})
        if not file_name or not safe_file(file_name):
            return self.send_json(400, {"error": "Choose a file that exists in the file list."})

        with lock:
            links = load_links()
            if old_path and normalize_path(str(old_path)) != path:
                links.pop(normalize_path(str(old_path)), None)
            links[path] = {"file": file_name, "download": bool(data.get("download"))}
            save_links(links)
        self.send_json(200, self.state())

    def do_PUT(self):
        if not self.allowed():
            return
        if self.route() != "/api/files":
            return self.send_text(404, "Not found")
        name = clean_filename((self.query().get("name") or [""])[0])
        if not name:
            return self.send_json(400, {"error": "The file needs a name that doesn't start with a dot."})

        tmp = FILES_DIR / f".upload-{threading.get_ident()}"
        try:
            with tmp.open("wb") as fh:
                for chunk in self.body_chunks(MAX_UPLOAD):
                    fh.write(chunk)
            tmp.replace(FILES_DIR / name)
        except ValueError as err:
            tmp.unlink(missing_ok=True)
            return self.send_json(400, {"error": f"Upload failed: {err}."})
        except Exception as err:
            tmp.unlink(missing_ok=True)
            return self.send_json(500, {"error": f"Upload failed: {err}."})
        self.send_json(200, self.state())

    def do_DELETE(self):
        if not self.allowed():
            return
        route, q = self.route(), self.query()
        if route == "/api/links":
            path = normalize_path((q.get("path") or [""])[0])
            with lock:
                links = load_links()
                links.pop(path, None)
                save_links(links)
            return self.send_json(200, self.state())
        if route == "/api/files":
            name = (q.get("name") or [""])[0]
            path = safe_file(name)
            if not path:
                return self.send_json(404, {"error": "That file no longer exists."})
            with lock:
                links = load_links()
                using = [p for p, l in links.items() if l.get("file") == path.name]
                if using:
                    return self.send_json(409, {
                        "error": f"Remove the link {', '.join(sorted(using))} before deleting this file."})
                path.unlink()
            return self.send_json(200, self.state())
        self.send_text(404, "Not found")


# ---------------------------------------------------------------- main

def main():
    FILES_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not LINKS_FILE.exists():
        save_links({})

    public = ThreadingHTTPServer(("0.0.0.0", PUBLIC_PORT), PublicHandler)
    admin = ThreadingHTTPServer(("0.0.0.0", ADMIN_PORT), AdminHandler)
    public.daemon_threads = admin.daemon_threads = True

    print(f"File Links: serving files from {FILES_DIR}", flush=True)
    print(f"File Links: public server on port {PUBLIC_PORT}, admin on {ADMIN_PORT}", flush=True)
    threading.Thread(target=admin.serve_forever, daemon=True).start()
    public.serve_forever()


if __name__ == "__main__":
    main()
