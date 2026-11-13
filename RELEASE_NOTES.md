# VPN Gate TUI — Initial release v1.0.0

Documentation: [English](https://github.com/Trueness04/vpngate_tui/blob/master/README.md) | [فارسی](https://github.com/Trueness04/vpngate_tui/blob/master/README.fa.md)

VPN Gate TUI is a free and open-source terminal scanner for VPN Gate volunteer servers, with connectivity checks geared toward Iranian networks.

## Features
- Discover daily VPN Gate mirrors and aggregate available volunteer servers.
- Test OpenVPN TCP/UDP, preliminary SSTP and IKE/L2TP responsiveness.
- Measure latency, jitter and lost responses; compare stability and server scores.
- Optional authenticated OpenVPN connection tests and throughput measurements.
- Save .ovpn files, export CSV/JSON, search and filter servers, and maintain local history.

## Supported systems
- Windows 10/11 x64
- Linux x64 and ARM64
- macOS Intel and Apple Silicon

Extract the matching archive and run the executable in a terminal. An OpenVPN command-line client must be installed separately for actual OpenVPN connections and deep tests. No Python installation is required for packaged binaries.

**Security:** VPN Gate servers are operated by independent volunteers. Neither privacy nor accessibility is guaranteed. Binaries are unsigned.

Checksums are published in SHA256SUMS.txt.
