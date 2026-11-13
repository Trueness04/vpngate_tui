# VPN Gate TUI — Free VPN Gate Server Scanner for Iran

**Language:** **English (default)** | [فارسی — راهنمای فارسی](README.fa.md)

**Find free VPN Gate servers, test OpenVPN ping and stability, probe SSTP/L2TP-IPsec, download .ovpn configurations, and connect from a terminal.**

VPN Gate TUI is an open-source Python terminal app built with [Textual](https://textual.textualize.io/). It discovers public volunteer **VPN Gate servers** through daily mirrors, tests network responsiveness, and ranks candidates by performance. It is designed with **internet connectivity in Iran** in mind, but can be used in other countries.

**[Download for Windows, Linux and macOS](https://github.com/Trueness04/vpngate_tui/releases)** · [Install from source](#install-from-source) · [Shortcuts](#keyboard-shortcuts) · **[Persian guide / راهنمای فارسی](README.fa.md)**

> **Disclaimer:** This is not a hosted VPN service. The servers are run by independent volunteers. Reachability, speed, privacy, security and working access from Iran are not guaranteed.

## Features

- **Automatic VPN Gate mirror discovery:** Searches several daily mirror sources, fetches lists concurrently, and merges duplicate servers.
- **OpenVPN TCP and UDP testing:** Sends an initial protocol probe to measure response times and check for OpenVPN responses.
- **SSTP and L2TP/IPsec checks:** TLS/SSTP probe over TCP/443 and preliminary IKEv1 probe over UDP/500.
- **VPN server ping and stability tests:** Compares latency, jitter, lost responses, and repeated multi-round measurements.
- **Ranking tailored to networks in Iran:** Estimates server suitability based on latency, jitter, loss, advertised speed, load, protocol and port.
- **Optional real OpenVPN connection test:** Uses a separately installed OpenVPN executable and may perform a small throughput check.
- **Free OpenVPN configuration downloads:** Saves original or timeout-tuned \`.ovpn\` files and up to ten top-ranked working profiles.
- **Terminal OpenVPN connection:** Connect to a selected server or have the app try the best candidates.
- **Search and filters:** Find servers by country, IP or hostname; filter TCP/UDP, TCP/443, SSTP, L2TP, OpenVPN, favorites and blacklist.
- **History and export:** Saves test history to SQLite and exports CSV/JSON.
- **Restricted-network support:** HTTP/SOCKS proxy for mirror/list downloads, manually supplied mirrors, CSV import, and SSTP hostname fallback.

**Testing accuracy:** An IKE response is not proof of successful L2TP/IPsec authentication. A TLS handshake is not proof of SSTP service availability. Quick OpenVPN probing is not the same as an authenticated VPN connection. Results depend on your ISP and may change over time.

## Download — Windows, Linux and macOS

Download the correct archive from the [GitHub Releases page](https://github.com/Trueness04/vpngate_tui/releases):

| Operating system | Download asset |
| --- | --- |
| Windows 10/11 x64 | \`vpngate-tui-windows-x64.zip\` |
| Linux / Ubuntu x64 | \`vpngate-tui-linux-x64.tar.gz\` |
| Linux ARM64 | \`vpngate-tui-linux-arm64.tar.gz\` |
| macOS Intel | \`vpngate-tui-macos-intel.tar.gz\` |
| macOS Apple Silicon | \`vpngate-tui-macos-arm64.tar.gz\` |

Extract the archive and run **from your terminal**: \`vpngate-tui.exe\` on Windows or \`./vpngate-tui\` on Linux/macOS. On Unix, run \`chmod +x vpngate-tui\` if needed.

These are standalone **terminal executables**, not graphical desktop installers. Python is not needed for binary releases. Publishing assets depends on successful GitHub Actions builds. Binaries are not commercially code-signed, so operating-system warnings may appear.

> **Connect / Auto-best / Deep test:** Requires an **OpenVPN command-line client installed separately**, and sufficient OS privileges to create a VPN tunnel. Scanning and downloading \`.ovpn\` profiles do not require OpenVPN.

## Install from source

Requires **Python 3.10+** and a suitable terminal.

\`\`\`bash
git clone https://github.com/Trueness04/vpngate_tui.git
cd vpngate_tui
python -m pip install -r requirements.txt
python vpngate_tui.py
\`\`\`

On Linux, use \`python3\` if \`python\` is unavailable; on Windows, \`py\` may be available.

### Proxy, custom mirror and offline CSV import

\`\`\`bash
# SOCKS5 proxy for fetching mirror/server lists
python vpngate_tui.py --proxy socks5://127.0.0.1:1080

# Add a VPN Gate mirror
python vpngate_tui.py --mirror http://1.2.3.4:5555/

# Import a VPN Gate API-format CSV
python vpngate_tui.py --import servers.csv

# Set download / export directory
python vpngate_tui.py --out ./downloads

# See all options
python vpngate_tui.py --help
\`\`\`

**Proxy scope:** \`--proxy\` applies to HTTP mirror and server-list downloads only. Direct server probes and OpenVPN tunnels do **not** use that HTTP/SOCKS proxy.

## Keyboard shortcuts

| Key | Action |
| --- | --- |
| \`r\` | Refresh daily server list |
| \`t\` | Quick test servers |
| \`u\` | Run multi-round stability test |
| \`g\` / \`d\` | Deep test top candidates / selected server |
| \`a\` | Find and connect to a best-ranked OpenVPN server |
| \`s\` / \`Ctrl+S\` | Save selected \`.ovpn\` / top ten tested configs |
| \`/\` | Search country, IP or hostname |
| \`p\` | Cycle filters |
| \`1\`–\`5\` | Sort by score, ping, jitter, speed, country |
| \`f\` / \`x\` | Toggle favorite / blacklist |
| \`l\` / \`k\` | Show L2TP/IPsec / SSTP connection details |
| \`e\` | Export CSV and JSON |
| \`F2\` | Cycle terminal themes |
| \`z\` / \`q\` | Stop current test / quit |
| \`Enter\` on a row | Open server actions menu |

## Troubleshooting and FAQ

**How do I find free OpenVPN servers that work from Iran?** Refresh the VPN Gate server list, press \`t\` to test, sort by ping or score, and press \`s\` to save a selected \`.ovpn\` file. Results depend on the local network.

**No servers listed?** Mirror sources may be filtered, outdated or offline. Try \`--proxy\`, a trusted \`--mirror\` or \`--import\` with a previously saved VPN Gate CSV.

**A server was found but won't connect?** Being listed is not proof of a functional VPN. Test with \`t\`, then \`d\` for an authenticated OpenVPN connection attempt, provided the CLI is installed.

**OpenVPN is missing?** Install the OpenVPN CLI separately and ensure it is on PATH. Connecting may also require administrative permissions.

**Where are app files stored?** Cache, preferences, mirror overrides and SQLite history default to \`~/.config/vpngate-tui/\`. Set \`VPNGATE_TUI_HOME\` to override. Downloaded configs and exports go to \`~/Downloads\` or \`~/vpngate\`, unless set via \`--out\`.

**Does this app provide its own VPN servers?** No. It searches and tests third-party VPN Gate volunteer servers and can use the installed OpenVPN CLI to connect.

## Development and release process

Native standalone binaries are built with **GitHub Actions and PyInstaller**. See [the multi-platform release workflow](.github/workflows/release.yml). Bug reports and contributions are welcome via [GitHub Issues](https://github.com/Trueness04/vpngate_tui/issues).

## Persian documentation / راهنمای فارسی

For Iranian users, see the full **[راهنمای فارسی VPN Gate TUI](README.fa.md)** with instructions for downloading free OpenVPN configs, VPN Gate mirror troubleshooting and server testing.

---

**Security:** Volunteer VPN Gate servers are third-party systems. Do not assume unknown operators are trustworthy with sensitive traffic.
