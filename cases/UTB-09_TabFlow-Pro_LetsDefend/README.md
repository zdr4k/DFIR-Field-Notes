# UTB-09 | TabFlow Pro (LetsDefend)

| Field | Value |
| :--- | :--- |
| Platform | LetsDefend |
| Challenge | https://app.letsdefend.io/challenge/tabflow-pro |
| Category | Endpoint / Browser extension |
| Date | 2026-11 |
| Blog post | 🚧 |

## 1. Scenario

After hours, an unknown person accessed workstation `WKSTN-ORION-014` (operations engineer `jharris`) at Orion Logistics, plugged in a removable drive, used the keyboard for a few minutes and left the machine unlocked. The next morning, endpoint telemetry flagged a Chrome extension in the user's profile that did not come from the managed deployment channel.

Evidence provided: a triaged disk image, the recovered extension source and two staging scripts from an adjacent investigation.

## 2. Evidence and tooling

| Evidence | Tool used |
| :--- | :--- |
| Triage disk image | |
| Extension source | |
| Staging scripts (x2) | |

## 3. Investigation

Planned lines of inquiry. Fill in as the lab progresses.

### 3.1 Removable media: what was plugged in and when
**Artifacts to check:** `SYSTEM\CurrentControlSet\Enum\USBSTOR`, `SYSTEM\MountedDevices`, `C:\Windows\INF\setupapi.dev.log`, `Microsoft-Windows-Partition/Diagnostic` (EID 1006), user `MountPoints2`.
**Finding:**

### 3.2 Activity at the keyboard
**Artifacts to check:** LNK files, Jump Lists, ShellBags, RecentDocs, PowerShell history (`ConsoleHost_history.txt`), Prefetch, Amcache.
**Finding:**

### 3.3 How the extension was installed
**Artifacts to check:** `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions\<id>\<version>`, `Preferences` and `Secure Preferences` (`extensions.settings`: `location`, `from_webstore`, `install_time`, `path`), Chrome shortcuts or command lines with `--load-extension`.
**Finding:**

### 3.4 Extension analysis
**Look at:** `manifest.json` (permissions, host permissions, content scripts, background service worker), obfuscation, exfil endpoints, storage use.
**Finding:**

### 3.5 Staging scripts
**Look at:** what they drop, where, persistence, link to the extension.
**Finding:**

## 4. Timeline (UTC)

| Time | Source | Event |
| :--- | :--- | :--- |
| | | |

## 5. MITRE ATT&CK mapping

Candidates to confirm or drop during the investigation.

| Tactic | Technique | Evidence |
| :--- | :--- | :--- |
| Initial Access | T1200 Hardware Additions | |
| Execution | T1059.001 PowerShell | |
| Persistence | T1176.001 Browser Extensions | |
| Collection | T1185 Browser Session Hijacking | |
| Exfiltration | T1041 Exfiltration Over C2 Channel | |

## 6. IOCs

See [`iocs.csv`](./iocs.csv).

## 7. Detections

| Rule | Format | Maturity | Covers |
| :--- | :--- | :--- | :--- |
| [Chrome extension loaded from command line](./detections/sigma/T1176_chrome_load_extension_cmdline.yml) | Sigma | experimental | Sideloaded unpacked extension |
| [Extension dropped by non browser process](./detections/kql/T1176_extension_written_by_non_browser.kql) | KQL | experimental | Extension files written outside Chrome |

## 8. Detection gaps and lessons

🚧
