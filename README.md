# airbnb-check

A small, read-only command line tool that helps a **guest** check the Wi-Fi of a short-term rental (Airbnb, Vrbo, hotel...) for hidden cameras. Pure Python standard library, no root, no dependencies.

It looks at the network you are already connected to and flags devices that behave like IP cameras: ONVIF/RTSP responders, camera-maker MAC vendors, typical camera ports and web banners, and Wi-Fi hotspots with camera-like names. It then points you to a physical inspection checklist, because software alone can never prove a room is clean.

## Quick start

```bash
uv tool install git+https://github.com/junowoz/airbnb-check && airbnb-check   # install once, then just `airbnb-check`
git clone https://github.com/junowoz/airbnb-check && cd airbnb-check && ./run.sh   # or from a clone, no install
```

The repo is private for now: you need GitHub access (`gh auth login` or an SSH key) for the first two. Requires Python 3.9+ on macOS or Linux, no third-party packages. `pipx install git+https://github.com/junowoz/airbnb-check` works too.

## Usage

Bare `airbnb-check` runs everything in order: refresh the MAC vendor list (if missing or older than 90 days), scan the network (two discovery passes ~5 s apart, because some cameras sleep), check nearby Wi-Fi for camera-like names, then print a verdict box (overall level, flagged items and why, what the check cannot see) and the full physical checklist. Progress goes to stderr, results to stdout. Language follows `LANG`/`LC_ALL` (en, pt, es); override with `--lang`.

```bash
airbnb-check                      # everything (same as `airbnb-check all`)
airbnb-check --report             # also write airbnb-check-YYYYMMDD-HHMM.md (or --report out.md)
airbnb-check --json               # one combined JSON object: scan + wifi + verdict
airbnb-check --offline            # never download the vendor list
airbnb-check --lang pt            # pt, es, en
airbnb-check scan                 # network scan only (also: wifi, checklist, update-oui)
airbnb-check --full scan          # probe all 65535 ports per host (slow)
airbnb-check --timeout 2          # slower networks
```

Each device gets **HIGH / MEDIUM / LOW / INFO** with the reasons listed. The gateway is labelled `ROUTER` and your machine `THIS DEVICE`. Output is plain text when not on a TTY and `NO_COLOR` is honored. Tip: join the rental's main Wi-Fi, and run it again after a few minutes.

## Notes

- **macOS and MAC addresses:** Homebrew/uv Pythons get an empty ARP table because of Local Network privacy; Apple's `/usr/bin/python3` does not. `airbnb-check` detects this early and transparently re-runs itself under `/usr/bin/python3` (env `AIRBNB_CHECK_REEXEC` prevents loops). Exception: a process started by `uvx` cannot read MACs even under Apple's Python, so prefer `uv tool install` or `./run.sh` if the MAC column is empty. Otherwise allow your terminal in System Settings > Privacy & Security > Local Network.
- **Wi-Fi names on macOS** show as `<redacted>` unless your terminal has Location permission; the tool says so when it happens.

## Safe by design

- Scans **only the subnet of your own active interface**, and refuses anything that is not a private RFC1918 range (10/8, 172.16/12, 192.168/16) of /24 or smaller.
- Read-only probes: ping, TCP connect, `HTTP GET /`, RTSP `OPTIONS`, SSDP/ONVIF/mDNS discovery. It never tries logins, default passwords or exploits, and never writes to a device.
- Short timeouts and bounded concurrency (at most 300 threads).
- No `sudo`, no `nmap`. The only internet access is the IEEE vendor list download (HTTPS, cached in `~/.cache/airbnb-check`, skipped with `--offline`).

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
- **Começar:** `uv tool install git+https://github.com/junowoz/airbnb-check` e depois só `airbnb-check`, ou num clone: `./run.sh`. O repositório é privado por enquanto (precisa de acesso ao GitHub).
- **Usar:** `airbnb-check` faz tudo em sequência (lista de fabricantes, varredura da rede em 2 passadas, Wi-Fi por perto, veredito e checklist completo no idioma do sistema; `--lang pt` força). `--report` grava um relatório `.md`, `--json` imprime tudo em JSON, `--offline` não baixa nada. Subcomandos: `scan`, `wifi`, `checklist`, `update-oui`.
- **macOS:** o Python do Homebrew não lê endereços MAC (privacidade de Rede Local); o programa se reexecuta sozinho com `/usr/bin/python3`. Se rodar via `uvx` e a coluna MAC vier vazia, use `uv tool install` ou `./run.sh`.
- **Não detecta:** câmeras em outra VLAN/rede de hóspedes, câmeras 4G, gravadores só com cartão SD, aparelhos desligados. Um resultado limpo não é prova: faça sempre a inspeção física.
- **Airbnb:** desde 2024 proíbe câmeras internas; denuncie pelo app. Câmera em quarto ou banheiro é caso de polícia.
- **Ética:** use somente em redes que você está autorizado a usar como hóspede.
