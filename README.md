# airbnb-check

Run one command on a rental's Wi-Fi and get a clear answer: **camera found, suspicious device, or no camera on this network**. Read-only, nothing installed, Python standard library only.

```sh
curl -fsSL https://raw.githubusercontent.com/junowoz/airbnb-check/main/run.sh | sh
```

That downloads the source into a temporary folder, runs it, and deletes everything when it ends (including the vendor-name cache). It needs `python3` 3.9+ and `curl` or `wget`; on macOS that means the Xcode Command Line Tools (`xcode-select --install`, once). It takes about a minute.

Prefer to read the script before running it?

```sh
curl -fsSL https://raw.githubusercontent.com/junowoz/airbnb-check/main/run.sh -o run.sh && less run.sh && sh run.sh
```

From a clone: `git clone https://github.com/junowoz/airbnb-check && cd airbnb-check && ./run.sh`. Extra options go after `--` when piped, for example `... | sh -s -- --report`.

## What you see

```
  airbnb-check 0.2.0
  hidden-camera check for the Wi-Fi you are on  (read-only, nothing is installed or changed)
  en0  192.168.0.4  network 192.168.0.0/24  gateway 192.168.0.1

  ✓  Finding devices  5 devices (2 passes, some cameras sleep)
  ✓  Probing services  4 open ports
  ✓  Identifying devices  3 names found, vendor list: up to date
  ✓  Deep check of unidentified devices  everything was identified, nothing to dig into
  ✓  Nearby Wi-Fi  44 Wi-Fi networks seen, 0 with camera-like names.

STATUS  IP           WHAT IT IS               PORTS               NAME / VENDOR
ok      192.168.0.1  router                   80,443,49152,49153
ok      192.168.0.4  this computer
ok      192.168.0.6  TV / media               7678,8001,8002+     [TV] Samsung 4 Series (Samsung)
ok      192.168.0.7  phone / tablet / laptop  49152,62078         iPhone sync port

╭──────────────────────────────────────────────────────────────────────────────╮
│ ✓  NO CAMERA ON THIS NETWORK                                                 │
│                                                                              │
│ Checked 4 devices, all identified: 1 router, 1 this computer, 1 phone /      │
│   tablet / laptop, 1 TV / media.                                             │
╰──────────────────────────────────────────────────────────────────────────────╯

A network check cannot see cameras that use 4G or only record to an SD card. Do the 2-minute physical check below.
```

## What it checks

- **Devices**: two discovery passes (ping/TCP sweep, ARP, SSDP/UPnP, ONVIF WS-Discovery, mDNS) because some cameras sleep.
- **Names**: reverse DNS, mDNS host names, NetBIOS names, UPnP device descriptions, and the MAC vendor (IEEE list).
- **Services**: usual camera, TV and printer ports, HTTP titles and `Server` headers, RTSP `DESCRIBE`.
- **Deep pass** on every device that is still unknown or suspicious: all 65535 TCP ports (usual ports first, bounded time), banners, RTSP, and the title of every web port.
- **Nearby Wi-Fi** names that look like camera hotspots (IPC-, CAM-, V380, Yoosee, ESP_, ...).

Every device ends up as: router, this computer, phone/tablet/laptop, TV/media, printer, smart-home/IoT, **camera**, or other. Evidence shown for each is technical and short (for example "answered an ONVIF WS-Discovery probe").

## What the verdicts mean

| Verdict | Meaning | What to do |
|---|---|---|
| **CAMERA FOUND** (red) | A device proved itself a camera: ONVIF reply, RTSP server, camera-maker MAC, camera ports/banner. | Photograph it, do not touch it, leave if unsafe, report in the Airbnb app (indoor cameras are banned). In a bedroom or bathroom, call the police. |
| **SUSPICIOUS DEVICE** (yellow) | Camera-like signals but no proof, such as an Espressif/Tuya chip with web or RTSP-like ports, or a camera-like Wi-Fi name with a strong signal. | The box tells you what to look for in the room. |
| **NOT SURE: SOME CHECKS FAILED** (yellow) | No camera found, but a check did not work (no other device answered, MAC addresses unreadable, a discovery method failed, a device could not be analyzed). | Fix what the box lists (for example Local Network permission) and run again. Never read it as clear. |
| **NO CAMERA ON THIS NETWORK** (green) | Every device was identified, or cleared by the deep pass as having no camera services. | Still do the 2-minute physical check printed below the verdict. |

## What it cannot see

Cameras on 4G, cameras that only record to an SD card, devices that are off or asleep, and anything on another VLAN or a separate guest network. A green result means the network is clean, not that the room is. Always do the physical check (`airbnb-check checklist` prints the full list).

## Safety and ethics

- **Read-only.** Ping, TCP connect, `HTTP GET /`, RTSP `DESCRIBE`, SSDP/ONVIF/mDNS/NetBIOS discovery. No logins, no default passwords, no exploits, no writes to any device. No `sudo`, no `nmap`.
- **Only your own subnet.** Private RFC1918 ranges only, never more than your local /24 (a larger netmask is clamped and the tool says so).
- **Untrusted input.** Everything a device sends (names, banners, SSIDs) is stripped of terminal escape codes and control characters before display; UPnP descriptions are fetched only from the responding device inside your subnet, size-capped, and parsed without an XML parser.
- **Internet access**: only the IEEE vendor list over HTTPS (size-capped, atomic write), plus the download of the script itself when piped.
- Use it **only as a guest on a network you were given access to**. Provided as is, without warranty (MIT).

## Options

```
airbnb-check [scan | wifi | checklist | update-oui] [--report [FILE.md]] [--json] [--offline] [--timeout SEC] [--full]
```

`--report` writes a Markdown report, `--json` prints one JSON object, `--offline` skips the vendor list, `--full` runs the fast pass over all ports for every device (slow). `NO_COLOR` is honored, and output falls back to plain text and ASCII when not on a TTY or when the locale is not UTF-8. To run it without `run.sh`: `PYTHONPATH=src python3 -m airbnb_check`.

## macOS notes

- **Python**: `run.sh` uses Apple's `/usr/bin/python3` (Xcode Command Line Tools), because Homebrew/uv Pythons cannot read MAC addresses (Local Network privacy). If you run another Python, the tool re-runs itself under Apple's automatically.
- **Wi-Fi names** show as `<redacted>` unless your terminal has Location permission (System Settings > Privacy & Security > Location Services). The tool says so in one line and the network verdict does not depend on it.
- If MAC addresses are still empty, allow your terminal under Privacy & Security > Local Network.

## FAQ

**Is a green result proof there is no camera?** No. It means no camera is reachable on this Wi-Fi. Do the physical check.

**Can I run it on hotel or office Wi-Fi?** Only networks you are allowed to use. Captive-portal or client-isolated networks hide other devices, so you will see few of them.

**Why does it take about a minute?** Two discovery passes 5 seconds apart, then a deep port pass on any device that is not obviously a phone, TV, printer or router.

**A device is "other (not a camera)". Is that a guess?** It means the full port pass found no camera service (no RTSP, ONVIF, camera ports or camera banners). Filtered devices may be only partly scanned in the time limit; the table says how many ports were checked.

**Airbnb policy**: since 2024 indoor security cameras are banned in all listings; outdoor cameras must be disclosed and cannot watch private areas.

## Development

```sh
python3 -m unittest discover -s tests
```

Stdlib only, Python 3.9+. Security issues: see [SECURITY.md](SECURITY.md).
