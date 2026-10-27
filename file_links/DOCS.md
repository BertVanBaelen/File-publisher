# File Links

Serve chosen files under clean public paths, like `/resume`.

## How it works

The add-on runs two things:

- **A public file server** on port 8090 (changeable on the Configuration tab under Network).
  It only answers paths you've created. Everything else gets a 404.
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

## Tips

- Want `files.vanbaelen.dev` itself to show something? Create a link with an empty path (`/`).
- Uploading a file with the same name replaces it, and its links keep working. Handy for
  updating your resume.
- Tick **Download the file instead of showing it in the browser** for files that should
  download, like zips.
- Paths are case-sensitive, and a trailing slash is ignored (`/resume/` works too).
