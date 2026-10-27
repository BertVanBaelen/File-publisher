# Changelog

## 1.3.0

- The management page counts, per link, how often the file was opened and how many
  password tries were right, wrong or blocked, with the time of the last one. Counts can
  be reset per link. No IP addresses are stored.

## 1.2.0

- A wrong password no longer reloads the password page; the field shakes and clears.
- The right password opens the lock, sharpens the background and moves straight on to the
  file. Download links start the download and offer a "Download again" button.
- Big files open faster: the file server now supports byte ranges, so PDF viewers fetch
  only the pages on screen and videos can stream and seek.

## 1.1.1

- Favicon on the public pages is now green, to match the pages.

## 1.1.0

- Links can ask for a password. Visitors see a lock page with a blurred picture of the kind
  of file (document, photo, video and so on); the file itself is only sent after the right
  password.
- Add-on icon and logo.
- New **Public page language** option: English, Dutch, French, German, or follow the
  visitor's browser.
- Green BVB favicon on the public pages.

## 1.0.0

- First release: upload files, map them to public paths, serve them inline or as downloads.
