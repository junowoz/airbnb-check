# airbnb-check

A small, read-only command line tool that helps a **guest** check the Wi-Fi of a short-term rental (Airbnb, Vrbo, hotel...) for hidden cameras. Pure Python standard library, no root, no dependencies.

It looks at the network you are already connected to and flags devices that behave like IP cameras: ONVIF/RTSP responders, camera-maker MAC vendors, typical camera ports and web banners, and Wi-Fi hotspots with camera-like names. It then points you to a physical inspection checklist, because software alone can never prove a room is clean.

## Safe by design

- Scans **only the subnet of your own active interface**, and refuses anything that is not a private RFC1918 range (10/8, 172.16/12, 192.168/16) of /24 or smaller.
- Read-only probes: ping, TCP connect, `HTTP GET /`, RTSP `OPTIONS`, SSDP/ONVIF/mDNS discovery. It never tries logins, default passwords or exploits, and never writes to a device.
- Short timeouts and bounded concurrency (at most 300 threads).
- No `sudo`, no `nmap`, no network access except your LAN. The only internet access is the optional `update-oui` command (IEEE vendor list over HTTPS).

## Install

```bash
# macOS: use Apple's Python so the scan can read MAC addresses
uv tool install --python /usr/bin/python3 git+https://github.com/junowoz/airbnb-check
# Linux:
uv tool install git+https://github.com/junowoz/airbnb-check
# or
pipx install git+https://github.com/junowoz/airbnb-check
# or, from a clone, no install at all:
PYTHONPATH=src python3 -m airbnb_check
```

Requires Python 3.9+ on macOS or Linux, no third-party packages. On macOS, Homebrew's Python is blocked from the neighbor (ARP) table by Local Network privacy; Apple's `/usr/bin/python3` is not.

## Usage

```bash
airbnb-check                      # same as `airbnb-check scan`
airbnb-check update-oui           # once, with internet: enables MAC vendor names
airbnb-check scan --report out.md # also write a Markdown report with timestamp
airbnb-check scan --json          # machine-readable output
airbnb-check scan --full          # probe all 65535 ports per host (slow)
airbnb-check wifi                 # nearby Wi-Fi networks, flags camera-like SSIDs
airbnb-check checklist --lang pt  # physical checklist (en, pt, es)
airbnb-check --timeout 2 scan     # slower networks
```

Each device gets **HIGH / MEDIUM / LOW / INFO** with the reasons listed. The gateway is labelled `ROUTER` and your machine `THIS DEVICE`. Output is plain text when not on a TTY and `NO_COLOR` is honored.

Tips: connect to the rental's main Wi-Fi (not a separate "guest" one if there are several), run the scan, then run it again after a few minutes, since some cameras sleep. On `wifi`, macOS hides SSIDs (`<redacted>`) unless your terminal has Location permission. If MACs come back empty on macOS, your Python (e.g. Homebrew's) is blocked by Local Network privacy: use Apple's `/usr/bin/python3`, which works out of the box (see Install).

## What it cannot detect

- Cameras on **another VLAN or a separate guest network** than the one you joined.
- **4G/cellular** cameras and anything that is not on the Wi-Fi.
- **SD-card-only recorders** and any device that is **powered off** or asleep during the scan.
- Cameras that use random MAC addresses, custom ports and no discovery protocol will only show as unknown devices.

A clean scan is a good sign, not proof. Always do the physical check (`airbnb-check checklist`).

## Airbnb policy

Since 2024 Airbnb bans indoor security cameras and recording devices in all listings, and outdoor cameras must be disclosed and cannot watch indoor spaces or private areas like a bathroom. If you find one, do not touch it, photograph it, leave if you feel unsafe, and report it in the Airbnb app. For a camera in a bedroom or bathroom, contact the police.

## Legal and ethics

Use this tool **only on networks you are authorized to use as a guest**. It is meant to protect your own privacy, not to inspect other people's networks. You are responsible for how you use it. Provided as is, without warranty (MIT).

## Development

```bash
python3 -m unittest discover -s tests
```

## Em português

`airbnb-check` é uma ferramenta de linha de comando, somente leitura, para o hóspede verificar o Wi-Fi de um Airbnb em busca de câmeras escondidas. Só usa a biblioteca padrão do Python 3.9+, não precisa de root.

- **Seguro por padrão:** escaneia apenas a sub-rede da sua própria interface, só aceita redes privadas (RFC1918) de /24 ou menores, nunca tenta senha, login ou exploit, e não altera nenhum aparelho.
- **Instalar:** `uv tool install git+https://github.com/junowoz/airbnb-check` ou `pipx install ...`; num clone: `PYTHONPATH=src python3 -m airbnb_check`.
- **Usar:** `airbnb-check` (escaneia), `airbnb-check update-oui` (nomes de fabricantes, uma vez), `airbnb-check wifi` (redes próximas suspeitas), `airbnb-check checklist --lang pt` (checklist físico).
- **Não detecta:** câmeras em outra VLAN/rede de hóspedes, câmeras 4G, gravadores só com cartão SD, aparelhos desligados. Um resultado limpo não é prova: faça sempre a inspeção física.
- **Airbnb:** desde 2024 proíbe câmeras internas; denuncie pelo app. Câmera em quarto ou banheiro é caso de polícia.
- **Ética:** use somente em redes que você está autorizado a usar como hóspede.
