# Network Mapping Tool

A network scanner for discovering live hosts on a subnet **without relying on ICMP**.  
It combines raw-socket ARP sweeps with TCP connect / RST detection and presents a concise target list.

---

## Features

- **Multi-protocol discovery**
  - **ARP sweep** (`github.com/j-keck/arping`) for instant Layer-2 detection  
  - **TCP probe** counts a host _alive_ on full handshake **or** `RST` (helps when firewalls drop ICMP)
- **Smart filtering**
  - Skips network & broadcast addresses automatically
  - Deduplicates ARP + TCP results
- **Configurable via flags**
  - Target CIDR, port list, concurrency limit, timeout
- **Goroutine-safe throttling**
  - Prevents exhausting file descriptors on /16 or larger scans
- **Extensible**  
  Plug-in friendly layout—add UDP probes, SNMP, mDNS, etc. without touching core logic

---

## Requirements

- **Go 1.22+** -> `sudo apt install golang`
- **github.com/j-keck/arping v1.0.3** -> pulled automatically by `go mod tidy`
- **Root / `CAP_NET_RAW`** -> `sudo setcap cap_net_raw+ep ./network-mapper`

No third-party ports or Python libs required; everything else is pure standard library.

---

## Usage

```bash
# clone & tidy dependencies
git clone https://github.com/s0up33/network-mapper.git
cd network-mapper
go mod tidy

# build (optional)
go build -o network-mapper .

# enumerate a /24 as root (ARP + TCP)
sudo ./network-mapper \
  -cidr 192.168.1.0/24 \
  -ports 22,80,443,445,3389 \
  -concurrency 256 \
  -timeout 45s
