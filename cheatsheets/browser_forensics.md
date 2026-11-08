# Browser forensics (Chromium)

| Artifact | Path (Windows) | What it tells you |
| :--- | :--- | :--- |
| Extensions | `%LOCALAPPDATA%\Google\Chrome\User Data\<Profile>\Extensions\<id>\<version>\` | Installed extension code |
| Extension settings | `...\<Profile>\Preferences`, `Secure Preferences` | Install source, time, path, permissions |
| Extension storage | `...\<Profile>\Local Extension Settings\<id>\` | LevelDB data the extension keeps |
| History | `...\<Profile>\History` | URLs, downloads (SQLite) |
| Cookies | `...\<Profile>\Network\Cookies` | Session tokens (SQLite, DPAPI encrypted values) |
| Login Data | `...\<Profile>\Login Data` | Saved credentials (SQLite) |

Useful `Preferences` fields under `extensions.settings.<id>`: `location` (1 webstore, 4 unpacked, 5 component), `from_webstore`, `install_time` (WebKit epoch), `path`.
