# 🛰️ Rust-LAN-Navigator (RLN)

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](./Dockerfile)

**RLN** is a privacy-first, zero-trust network orchestrator designed for the modern LAN. It provides instant visibility, cryptographic identity, and secure data movement without ever leaving your local subnet. No cloud, no telemetry, just pure local control.

---

## ✨ Key Features

- **🔍 Progressive Discovery**: Automatically scales Layer 2 ARP scan intensity. Fast, lightweight sweeps for instant UI feedback combined with deep, staggered background polling to reliably detect sleeping mobile and IoT devices without network congestion.
- **🏷️ Device Naming**: Resolves custom DHCP hostnames via Reverse DNS, with an automatic fallback to device vendor lookup via the bundled OUI database. Identifies the host running RLN natively.
- **🕸️ Switch Topology**: Live LLDP frame capture to intelligently map out managed network switches and port connections.
- **📈 Stateful Monitoring**: Track network "drift" by comparing current scans against historical SQLite snapshots. Features a smart 5-minute UI grace-period to prevent sleeping Android/iOS devices from triggering false-positive alerts.
- **🛡️ Zero-Trust Identity**: Permanent, cryptographic Peer IDs (Ed25519) powered by `iroh`'s built-in key primitives.
- **🧠 Intelligent Fingerprinting**: Local ML models (via `tract`) identify device types based on network behavior.
- **🚀 High-Speed Streaming**: Encrypted, resilient file movement using QUIC-based P2P streaming (via `iroh` v0.98), now supporting mDNS short-code shorthand for Peer IDs!
- **📊 Modern TUI**: A rich, interactive terminal dashboard built with `ratatui` featuring rounded borders, colored semantic panels, and scrollable system logs.

---

## 🛠️ Technical Stack

- **Runtime**: [Tokio](https://tokio.rs/) (Async I/O)
- **Networking**: [pnet](https://github.com/libpnet/libpnet), [async-arp](https://github.com/skullim/async-arp), [surge-ping](https://github.com/pariahprologue/surge-ping)
- **Name Resolution**: [dns-lookup](https://crates.io/crates/dns-lookup) (PTR records), [mac_oui](https://crates.io/crates/mac_oui) (bundled Wireshark OUI database)
- **P2P/Transfer**: [Iroh v0.98](https://iroh.computer/) / QUIC — latest stable release
- **Identity**: Built-in to `iroh` (`iroh::SecretKey` / `iroh::PublicKey`)
- **Intelligence**: [Tract](https://github.com/sonos/tract) (ONNX Inference)
- **Storage**: SQLite via [rusqlite](https://github.com/rusqlite/rusqlite)
- **UI**: [Ratatui](https://ratatui.rs/) & [Clap v4](https://clap.rs/)

---

## 🚀 Getting Started

### Prerequisites

- **Rust**: Latest stable version.
- **Privileges**: RLN requires low-level network access.
  - **Linux**: `CAP_NET_RAW` capabilities or `sudo`.
  - **Windows**: Administrator privileges (Npcap required).

### Local Installation (macOS, Windows, & Linux)

Because RLN relies on raw OSI Layer 2 network sockets to sniff low-level ARP and LLDP frames, it must be run natively on macOS and Windows to avoid virtualization limitations.

#### Windows

1. **Install the Runtime:** Download and install [Npcap](https://npcap.com/). 
   > ⚠️ **Crucial Step:** During the installation wizard, you **must** check the box that says **"Install Npcap in WinPcap API-compatible Mode"**.

2. **Get the Development SDK (For compiling):** To build RLN from source, the Rust compiler needs the Npcap SDK.
   - Download the **Npcap SDK** (.zip) from the [Npcap downloads page](https://npcap.com/#download).
   - Extract the `.zip` archive to a folder on your computer.

3. **Link the SDK to Rust:** We need to drop two library files into your Rust toolchain so Cargo can find them. Open a PowerShell window and run this quick script (just change `C:\path\to\npcap-sdk` to match where you extracted the zip):
   ```powershell
   $npcap_lib = "C:\path\to\npcap-sdk\Lib\x64"
   $rust_lib = "$(rustc --print sysroot)\lib\rustlib\x86_64-pc-windows-msvc\lib"
   Copy-Item "$npcap_lib\Packet.lib" -Destination $rust_lib
   Copy-Item "$npcap_lib\wpcap.lib" -Destination $rust_lib
   ```

4. **Run the App:** Open an Administrative terminal (PowerShell or Command Prompt as Admin), because RLN needs low-level network access to scan the LAN:
   ```powershell
   git clone https://github.com/XO9A8/rln.git
   cd rln
   cargo run --release -- --dashboard
   ```

#### macOS

macOS uses the built-in BSD Packet Filter (`BPF`) for network taps. You just need root permissions to bind raw sockets to interface hardware (like `en0`).

1. Open your terminal natively.
2. Clone and run with `sudo` privileges:
   ```bash
   git clone https://github.com/XO9A8/rln.git
   cd rln
   sudo cargo run --release -- --dashboard
   ```

#### Linux

Linux users can run RLN natively or via Docker (see below).

1. Clone the repository:
   ```bash
   git clone https://github.com/XO9A8/rln.git
   cd rln
   ```
2. Run with `sudo` (or grant `CAP_NET_RAW` capabilities to the binary):
   ```bash
   sudo cargo run --release -- --dashboard
   ```

### Running with Docker (Linux Recommended)

RLN is fully containerized with host networking support for seamless LAN scanning. Because RLN is an interactive TUI (Terminal User Interface), it must be run with the `run` command rather than the standard `up` background daemon.

```bash
# 1. Build the container
sudo docker-compose build

# 2. Run interactively (attaches your terminal to the UI)
sudo docker-compose run --rm rln
```

> ⚠️ **macOS & Windows Docker limitations:** Docker Desktop on macOS and Windows runs containers inside a hidden Linux VM. This VM acts as a NAT firewall that completely blocks the raw Layer 2 network packets (ARP, NDP, LLDP) that RLN needs to see the physical LAN. Because of this, **Docker is only recommended for native Linux hosts.** On Mac and Windows, you should run RLN natively!

---

## 📂 Project Structure

```text
src/
├── discovery/      # ARP/NDP and mDNS scanning engines + OUI vendor lookup
├── intelligence/   # ICMP probes, ML fingerprinting, and topology mapping
├── identity/       # Iroh-native Ed25519 key management and Peer ID
├── transfer/       # Iroh QUIC-based P2P streaming and SHA-256 verification
├── storage/        # SQLite snapshot engine and drift detection logic
└── tui/            # Ratatui event loop and dashboard views
```

---

## 🔑 Identity & Peer IDs

RLN uses `iroh`'s native Ed25519 key primitives (`iroh::SecretKey` / `iroh::PublicKey`) to generate a unique node identity on first boot. The identity is saved to `data/identity.key` (chmod 600).

In the TUI, your node's `EndpointId` is displayed in the System Logs at startup. Other nodes use this ID (or its generated 8-character device shortcode via mDNS if operating on the local network) to dial you directly for file transfers:

```text
09:24:12 [ID] Peer ID: b09ceb10b3ca3e0aca54dace1998ba495911c5780dcd69b7307fb6bbd945504d
09:24:12 [P2P] Node online. ID: b09ceb10b3ca3e0aca54dace1998ba495911c5780dcd69b7307fb6bbd945504d
```

To send a file, press `s` to open the modal overlay, then type either your target's friendly name (`My-Laptop`), shortcode (`b09ceb10`), or full peer ID, and the file path:

```text
> b09ceb10 /home/user/doc.pdf
```

---

## 🛡️ Security & Privacy

- **Zero-Cloud Guarantee**: All data stays on your machine. AI analysis and database storage happen 100% locally.
- **Privilege Separation**: Scanning components are isolated to minimize the surface area requiring elevated permissions.
- **Immutable Identity**: Your Peer ID is your source of truth. If you lose your identity file, you lose your trusted status with other nodes.
- **SHA-256 Integrity**: Every P2P file transfer includes a streaming SHA-256 digest verified by the receiver before the file is accepted.

---

## ⚖️ License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
