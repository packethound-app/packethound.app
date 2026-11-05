# PacketHound website

A small PHP site: home page with features, screenshots and FAQ; a download page with version,
size, SHA-256 checksum and release notes; a privacy page; and a download counter.
No database, no external services, nothing loaded from other websites.

## Requirements

- Apache 2.4 with PHP 7.4 or later
- `AllowOverride All` for the site's folder, so the `.htaccess` files apply (they block access to
  `inc/` and `data/`, add security headers and force installers to download)
- Optional but recommended: `mod_headers`, `mod_expires`, `mod_deflate`

## Deploying

1. Upload everything in this folder to the web root (or a subfolder).
2. Make `data/` writable by the web server, e.g. `chown www-data data` or `chmod 775 data`.
   It holds the download counts and cached checksums. Without it the site still works, but
   downloads aren't counted and the checksum is recalculated on every visit.
3. If the site is in a subfolder, change `ErrorDocument 404 /404.php` in `.htaccess` to match,
   e.g. `/packethound/404.php`.
4. Use HTTPS (e.g. Let's Encrypt). People are downloading a program that runs as administrator.

## Releasing a new version

1. Bump `<Version>` in `src/PacketHound/PacketHound.csproj`.
2. Run `.\build.ps1 -Installer`. It copies `PacketHound-Setup-<version>.exe` into `downloads/`.
3. Add release notes for that version to `releases` in `config.php`.
4. Upload `downloads/PacketHound-Setup-<version>.exe` and `config.php`.

The newest version in `downloads/` becomes the main download automatically. Older ones stay
listed under "Earlier versions"; delete them from `downloads/` to remove them.

## Update checks

The app fetches `https://packethound.app/version.php` once a week. It reports the newest installer in
`downloads/`, so publishing a release (above) is all it takes for every copy to be told about it.

Behind Cloudflare: the check is a normal HTTPS request, but **Bot Fight Mode** and **"I'm Under Attack"
mode** can answer programs with a challenge page instead. The app then reports "couldn't check" and tries
again later, so nothing breaks, but no one hears about updates. If you use either, add a WAF custom rule
for `URI Path equals /version.php` with the action **Skip** (all remaining custom rules, and the
Browser Integrity Check / Security Level). On the free plan, Bot Fight Mode can't be skipped by rules,
so leave it off if you want update checks to work.

## Screenshots

Put PNG, JPG or WebP files in `screenshots/`. They're shown in file-name order, so number them.
Titles and captions come from `screenshots/captions.json`; a file without an entry is titled from
its name. The Screenshots section and menu link only appear once there's at least one image.

`captions.json` already has entries for these, so taking them with these names is the easy route:

| File | What to capture |
|---|---|
| `01-prompt.png` | An Allow/Block prompt for an app (Win+Shift+S, Window mode) |
| `02-rules.png` | The main window, Rules tab |
| `03-activity.png` | The main window, Activity tab |
| `04-settings.png` | The main window, Settings tab |
| `05-tray.png` | The tray icon's right-click menu |

Width around 1200–2000 px is ideal. Check them for anything private (app names, IP addresses)
before uploading.

## Editing

- Wording, contact email, source-code link, requirements, release notes: `config.php`
- Home page sections and FAQ: `index.php`
- Colours and layout: `assets/css/site.css` (light and dark mode)
- Logo, favicon and app icons are generated from the app's logo by `tools/make-icons.py`

## Files

```
index.php        home page
download.php     download page
get.php          counts a download, then redirects to the file
version.php      latest version as JSON, for the app's update check
privacy.php      privacy page
404.php          "page not found"
config.php       site settings (blocked from the web)
inc/             shared PHP (blocked from the web)
data/            download counts, checksum cache (blocked from the web, must be writable)
downloads/       installers
screenshots/     screenshots + captions.json
assets/          CSS, JS, images
```
