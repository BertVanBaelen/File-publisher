# File Links

Serve chosen files under clean public paths, like `/resume`.

## How it works

The add-on runs two things:

- **A public file server** on port 8090 (changeable on the Configuration tab under Network).
  It only answers paths you've created. Everything else gets a 404. Links can ask for a
  password first.
- **A management page** in the Home Assistant sidebar ("File Links"). It's only reachable
  through Home Assistant, so it's protected by your HA login.

Files live in `/share/file_links`, so you can also copy them in through the Samba share.

## Setup

1. On the **Configuration** tab, set **Public URL** to the address of your tunnel, for
   example `https://files.vanbaelen.dev`. This is only used to show copyable links.
2. Start the add-on and open **File Links** in the sidebar.
3. Upload a file, type a path (like `resume`), choose the file and select **Save link**.
4. Point your tunnel at the add-on:
   - Cloudflare dashboard: Public hostname `files.vanbaelen.dev`, type `HTTP`,
     URL `<your-HA-IP>:8090`.
   - Cloudflared add-on YAML:
     ```yaml
     additional_hosts:
       - hostname: files.vanbaelen.dev
         service: http://<your-HA-IP>:8090
     ```

## Language of the public pages

On the **Configuration** tab, **Public page language** sets the language visitors see on
the password page and the "not found" message: English (`en`), Dutch (`nl`), French (`fr`)
or German (`de`). Choose `auto` to follow each visitor's browser language; browsers set to
another language get English.

The public pages show a green BVB icon in the browser tab. To use a different one, create a
link with the path `favicon.ico` pointing at your own icon file.

## Password-protected links

Tick **Ask for a password before showing the file** when you save a link, and type a
password (at least 6 characters). To change it later, edit the link and type a new one;
leave the box empty to keep the current password.

Visitors first see a lock page with a blurred illustration of the kind of file behind it
(a document, photos, a video, a spreadsheet and so on). That page is built from the file's
extension only: it never contains the file, its name or its size. The file is sent only
after the right password.

- A correct password unlocks that link in that browser for 12 hours.
- Changing a link's password, or moving it to another path, locks everyone out again.
- After 8 wrong passwords in 15 minutes, a visitor has to wait before trying again.
- Passwords are stored as salted PBKDF2 hashes, never as plain text.
- Protected files are sent with `Cache-Control: private, no-store`, so Cloudflare doesn't
  cache them. Keep your tunnel on HTTPS: the password travels in the request.

## Tips

- Want `files.vanbaelen.dev` itself to show something? Create a link with an empty path (`/`).
- Uploading a file with the same name replaces it, and its links keep working. Handy for
  updating your resume.
- Tick **Download the file instead of showing it in the browser** for files that should
  download, like zips.
- Paths are case-sensitive, and a trailing slash is ignored (`/resume/` works too).
