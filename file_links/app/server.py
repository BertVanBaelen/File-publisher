#!/usr/bin/env python3
"""File Links: serve chosen files under clean public paths.

Two servers run in one process:
  * public (port 8080): serves only the files you mapped, e.g. /resume.
    Links with a password show a lock page first; the file is only sent
    after the right password, to a browser holding a signed cookie.
  * admin  (port 8099): the management page, reachable only through
    Home Assistant ingress (so it is protected by your HA login)

Standard library only, so the image builds on every architecture.
"""
import base64
import hashlib
import hmac
import html
import json
import mimetypes
import os
import re
import secrets
import shutil
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

FILES_DIR = Path(os.environ.get("FILES_DIR", "/share/file_links"))
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
LINKS_FILE = DATA_DIR / "links.json"
OPTIONS_FILE = DATA_DIR / "options.json"
SECRET_FILE = DATA_DIR / "session_secret"
STATIC_DIR = Path(__file__).parent / "static"

PUBLIC_PORT = int(os.environ.get("PUBLIC_PORT", "8080"))
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "8099"))
INGRESS_IP = "172.30.32.2"  # Home Assistant's ingress proxy
ALLOW_ANY_ADMIN = os.environ.get("ALLOW_ANY_ADMIN") == "1"  # local testing only

MAX_UPLOAD = 500 * 1024 * 1024
CHUNK = 64 * 1024
PATH_RE = re.compile(r"^/[A-Za-z0-9._~\-/]*$")

PBKDF2_ROUNDS = 260_000
MIN_PASSWORD = 6
SESSION_SECONDS = 12 * 3600
COOKIE = "fl_unlock"
MAX_TRIES = 8         # wrong passwords per visitor...
TRY_WINDOW = 15 * 60  # ...within this many seconds

# What the lock screen shows behind the password box. Based on the file
# extension only; the file itself is never read for it.
KINDS = {
    "document": "pdf doc docx odt rtf txt md pages epub",
    "image": "png jpg jpeg gif webp avif heic svg bmp tif tiff",
    "video": "mp4 mov m4v webm mkv avi",
    "audio": "mp3 m4a wav flac ogg opus aac",
    "spreadsheet": "xls xlsx ods csv tsv numbers",
    "presentation": "ppt pptx odp key",
    "archive": "zip 7z rar tar gz tgz bz2 xz",
}
KIND_OF = {ext: kind for kind, exts in KINDS.items() for ext in exts.split()}

FAVICON_PATHS = ("/favicon.ico", "/favicon.png")

# Text on the public pages, picked with the add-on's "language" option.
STRINGS = {
    "en": {
        "title": "Password needed",
        "heading": "This file is password protected",
        "intro": "Enter the password to open it.",
        "password": "Password",
        "open": "Open",
        "wrong": "That password isn't right.",
        "too_many": "Too many wrong tries. Wait a few minutes, then try again.",
        "error": "Something went wrong. Try again.",
        "not_found": "Not found",
    },
    "nl": {
        "title": "Wachtwoord nodig",
        "heading": "Dit bestand is beveiligd met een wachtwoord",
        "intro": "Vul het wachtwoord in om het te openen.",
        "password": "Wachtwoord",
        "open": "Openen",
        "wrong": "Dat wachtwoord klopt niet.",
        "too_many": "Te veel foute pogingen. Wacht een paar minuten en probeer het dan opnieuw.",
        "error": "Er ging iets mis. Probeer het opnieuw.",
        "not_found": "Niet gevonden",
    },
    "fr": {
        "title": "Mot de passe requis",
        "heading": "Ce fichier est protégé par un mot de passe",
        "intro": "Saisissez le mot de passe pour l’ouvrir.",
        "password": "Mot de passe",
        "open": "Ouvrir",
        "wrong": "Ce mot de passe n’est pas correct.",
        "too_many": "Trop de tentatives incorrectes. Patientez quelques minutes, puis réessayez.",
        "error": "Une erreur s’est produite. Réessayez.",
        "not_found": "Introuvable",
    },
    "de": {
        "title": "Passwort erforderlich",
        "heading": "Diese Datei ist passwortgeschützt",
        "intro": "Gib das Passwort ein, um sie zu öffnen.",
        "password": "Passwort",
        "open": "Öffnen",
        "wrong": "Das Passwort ist nicht richtig.",
        "too_many": "Zu viele falsche Versuche. Warte ein paar Minuten und versuche es dann erneut.",
        "error": "Etwas ist schiefgelaufen. Versuche es erneut.",
        "not_found": "Nicht gefunden",
    },
}

lock = threading.Lock()
tries_lock = threading.Lock()
failed_tries = {}  # visitor ip -> [timestamps of wrong passwords]
_secret = None


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


# ---------------------------------------------------------------- passwords

def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${b64(salt)}${b64(digest)}"


def check_password(password, stored):
    try:
        algo, rounds, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        attempt = hashlib.pbkdf2_hmac("sha256", password.encode(), unb64(salt), int(rounds))
        return hmac.compare_digest(attempt, unb64(digest))
    except Exception:
        return False


def session_secret():
    """Random key that signs unlock cookies. Kept in /data so restarts don't log people out."""
    global _secret
    if _secret is None:
        try:
            _secret = SECRET_FILE.read_bytes()
        except FileNotFoundError:
            _secret = b""
        if len(_secret) < 32:
            _secret = secrets.token_bytes(32)
            SECRET_FILE.write_bytes(_secret)
            SECRET_FILE.chmod(0o600)
    return _secret


def session_sig(path, expires, stored):
    # Binding the password hash means changing a link's password signs everyone out.
    msg = f"{path}\n{expires}\n{stored}".encode()
    return b64(hmac.new(session_secret(), msg, hashlib.sha256).digest())


def make_session(path, stored):
    expires = int(time.time()) + SESSION_SECONDS
    return f"{expires}.{session_sig(path, expires, stored)}"


def valid_session(token, path, stored):
    try:
        expires, sig = token.split(".", 1)
        if int(expires) < time.time():
            return False
        return hmac.compare_digest(sig, session_sig(path, int(expires), stored))
    except Exception:
        return False


def too_many_tries(ip):
    now = time.time()
    with tries_lock:
        recent = [t for t in failed_tries.get(ip, []) if now - t < TRY_WINDOW]
        if recent:
            failed_tries[ip] = recent
        else:
            failed_tries.pop(ip, None)
        return len(recent) >= MAX_TRIES


def note_failed_try(ip):
    with tries_lock:
        failed_tries.setdefault(ip, []).append(time.time())


def file_kind(name):
    return KIND_OF.get(Path(name or "").suffix.lower().lstrip("."), "file")


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

    def lookup(self):
        key = normalize_path(self.route())
        with lock:
            link = load_links().get(key)
        path = safe_file(link.get("file")) if link else None
        return key, link, path

    def visitor_ip(self):
        # Behind a Cloudflare tunnel every request comes from cloudflared, so use the real visitor.
        return self.headers.get("CF-Connecting-IP") or self.client_address[0]

    def unlocked(self, key, stored):
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE and valid_session(value, key, stored):
                return True
        return False

    def language(self):
        """The add-on's language option; "auto" follows the visitor's browser."""
        lang = str(load_options().get("language") or "en").lower()
        if lang != "auto":
            return lang if lang in STRINGS else "en"
        for part in self.headers.get("Accept-Language", "").split(","):
            code = part.split(";")[0].strip().lower()[:2]
            if code in STRINGS:
                return code
        return "en"

    def send_not_found(self, head=False):
        self.send_text(404, STRINGS[self.language()]["not_found"], head)

    def send_favicon(self, head):
        body = (STATIC_DIR / "favicon.png").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=86400")
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def send_locked(self, code, link, message=None, head=False):
        """The password page. It never contains the file, its name or its size."""
        lang = self.language()
        text = STRINGS[lang]
        kind = file_kind(link.get("file"))
        art = (STATIC_DIR / "art" / f"{kind}.svg").read_text()
        page = (STATIC_DIR / "locked.html").read_text()
        page = page.replace("{{art}}", art).replace("{{kind}}", kind).replace("{{lang}}", lang)
        page = page.replace("{{message}}", html.escape(text[message]) if message else "")
        page = page.replace("{{invalid}}", "true" if message else "false")
        for key, value in text.items():
            page = page.replace("{{" + key + "}}", html.escape(value))
        body = page.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Language", lang)
        self.send_header("Vary", "Accept-Language")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; "
                         "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Robots-Tag", "noindex")
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def serve(self, head):
        key, link, path = self.lookup()
        if not path and key in FAVICON_PATHS:
            return self.send_favicon(head)
        if not path:
            return self.send_not_found(head)
        stored = link.get("password")
        if stored and not self.unlocked(key, stored):
            return self.send_locked(401, link, head=head)

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
        # Protected files must never land in a shared cache, like Cloudflare's.
        self.send_header("Cache-Control", "private, no-store" if stored else "no-cache")
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
        """The password form posts here, to the link's own path."""
        key, link, path = self.lookup()
        if not path:
            return self.send_not_found()
        stored = link.get("password")
        if not stored:
            return self.send_text(405, "Method not allowed")

        ip = self.visitor_ip()
        if too_many_tries(ip):
            return self.send_locked(429, link, "too_many")
        try:
            form = urllib.parse.parse_qs(b"".join(self.body_chunks(4096)).decode())
        except Exception:
            return self.send_locked(400, link, "error")
        if not check_password((form.get("password") or [""])[0], stored):
            note_failed_try(ip)
            return self.send_locked(401, link, "wrong")

        cookie = f"{COOKIE}={make_session(key, stored)}; Path={key}; Max-Age={SESSION_SECONDS}; HttpOnly; SameSite=Lax"
        if self.headers.get("X-Forwarded-Proto", "").lower() == "https":
            cookie += "; Secure"
        self.send_response(303)
        self.send_header("Location", key)
        self.send_header("Set-Cookie", cookie)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PUT(self):
        self.send_text(405, "Method not allowed")

    do_DELETE = do_PATCH = do_PUT


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
                 "protected": bool(l.get("password")),
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

        protect = bool(data.get("protect"))
        password = str(data.get("password") or "")
        if protect and password and len(password) < MIN_PASSWORD:
            return self.send_json(400, {"error": f"Use a password of at least {MIN_PASSWORD} characters."})
        new_hash = hash_password(password) if protect and password else None

        with lock:
            links = load_links()
            old_key = normalize_path(str(old_path)) if old_path else None
            # An empty password box while editing keeps the link's current password.
            stored = new_hash or (protect and (links.get(old_key) or {}).get("password")) or None
            if protect and not stored:
                return self.send_json(400, {"error": "Type a password, or untick the password option."})
            if old_key and old_key != path:
                links.pop(old_key, None)
            links[path] = {"file": file_name, "download": bool(data.get("download"))}
            if stored:
                links[path]["password"] = stored
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
    session_secret()

    public = ThreadingHTTPServer(("0.0.0.0", PUBLIC_PORT), PublicHandler)
    admin = ThreadingHTTPServer(("0.0.0.0", ADMIN_PORT), AdminHandler)
    public.daemon_threads = admin.daemon_threads = True

    print(f"File Links: serving files from {FILES_DIR}", flush=True)
    print(f"File Links: public server on port {PUBLIC_PORT}, admin on {ADMIN_PORT}", flush=True)
    threading.Thread(target=admin.serve_forever, daemon=True).start()
    public.serve_forever()


if __name__ == "__main__":
    main()
