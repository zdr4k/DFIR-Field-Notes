# USB / removable media forensics (Windows)

| Artifact | Location | What it tells you |
| :--- | :--- | :--- |
| USBSTOR | `SYSTEM\CurrentControlSet\Enum\USBSTOR` | Vendor, product, serial |
| USB | `SYSTEM\CurrentControlSet\Enum\USB` | VID / PID |
| MountedDevices | `SYSTEM\MountedDevices` | Drive letter mapping |
| MountPoints2 | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` | Which user saw the volume |
| setupapi.dev.log | `C:\Windows\INF\setupapi.dev.log` | First install time |
| Partition/Diagnostic | EVTX, Event ID 1006 | Connect / disconnect with volume details |
| LNK / Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\` | Files opened from the drive |
