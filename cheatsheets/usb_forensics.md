# USB / removable media forensics (Windows)

## Where to look

| Artifact | Location | What it tells you | Time |
| :--- | :--- | :--- | :--- |
| USBSTOR | `SYSTEM\ControlSet00X\Enum\USBSTOR` | Vendor/product strings, revision, serial (subkey name + `&0`) | UTC |
| USB | `SYSTEM\ControlSet00X\Enum\USB` | Hex `VID_xxxx&PID_xxxx`, serial, `Service`, `CompatibleIDs`, `ContainerID` | UTC |
| Device properties | `...\USBSTOR\<dev>\<serial>\Properties\{83da6326-97a6-4088-9453-a1923f573b29}` | `0064` Install Date, `0065` First Install Date, `0066` Last Arrival, `0067` Last Removal | UTC (FILETIME) |
| MountedDevices | `SYSTEM\MountedDevices` | Drive letter mapping | |
| MountPoints2 | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` | Which user saw the volume | UTC (key last write) |
| setupapi.dev.log | `C:\Windows\INF\setupapi.dev.log` | Driver install start/end per device | **Local time** |
| Partition/Diagnostic | EVTX, Event ID 1006 | Connect / disconnect with volume details | UTC |
| LNK / Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\` | Files opened from the drive | UTC |

## Gotchas

* **`CurrentControlSet` does not exist offline.** Read `SYSTEM\Select\Current` to find the active `ControlSet00X`.
* **USBSTOR has no hex IDs.** Correlate with `Enum\USB` by serial (USBSTOR subkey minus `&0`) and confirm with `ContainerID`.
* **Analysis VM noise.** `VID_0E0F` = VMware. Filter it out.
* **Mass storage signature:** `CompatibleIDs` `USB\Class_08&SubClass_06&Prot_50` (Mass Storage, SCSI transparent, Bulk Only) and `Service = USBSTOR`.
* **Registry install date vs log.** `0064` and setupapi `Section start` mark when install began. `Section end` marks completion.
* **setupapi.dev.log is local time.** Check the timezone first (see below). Rotated copies may exist as `setupapi.dev.<date>_<time>.log`.

## Timezone check

`SYSTEM\ControlSet00X\Control\TimeZoneInformation`

* `TimeZoneKeyName`: zone name
* `Bias`: minutes, UTC = local + Bias (e.g. -120 = UTC+2)
* `ActiveTimeBias`: bias in effect at last update, includes DST
* `DaylightStart` all zeros: no DST rule
* Raw DWORD is little endian and signed: `88-FF-FF-FF` = `0xFFFFFF88` = -120 (shown as `4294967176` unsigned)
