# 🛰️ Rust-LAN-Navigator (RLN) v2.0

> **Vision:** A privacy-first, zero-trust network orchestrator for the modern LAN. RLN provides instant visibility, cryptographic identity, and secure data movement without ever leaving the local subnet.

---

## 🎯 1. Project Objectives

- **Hybrid Discovery:** Simultaneous Layer 2 (ARP/NDP) and Layer 3 (mDNS) scanning for full IPv4 and IPv6 coverage.
- **Stateful Monitoring:** Track network "drift" by comparing current scans against historical snapshots.
- **Zero-Trust Identity:** Replace unstable IP-based targeting with permanent, cryptographic Peer IDs.
- **Intelligent Fingerprinting:** Use local ML models to identify device types based on network behavior, not just MAC addresses.
- **High-Speed Secure Transfer:** Utilize QUIC-based streaming for encrypted, resilient file movement.

---

## 🧩 2. Core Functional Modules

### 🔍 A. The Discovery Engine (The "Detect")
- **Dual-Stack Scanner:** Implements **ARP** (IPv4) via `async-arp` and **NDP** (IPv6 Neighbor Discovery) via `pnet` to ensure full coverage.
- **Snapshot Engine:** Uses `rusqlite` to maintain a local database of "Known Good" network states.
    - *Drift Alert:* Automated diffing between current scans and SQLite snapshots.
- **Identity Mapping:** Correlates MAC vendors (via `oui` crate) and mDNS services (via `simple-mdns`) to provide human-readable names.

### 🧠 B. The Diagnostic & Intelligence Suite (The "Analyze")
- **Async Multi-Probe:** High-speed ICMP checks via `surge-ping` and TCP-SYN checks for port status.
- **AI Fingerprinting:** Local-only inference using `ort` (performance) or `tract` (portability) to categorize devices based on network traffic patterns.
- **Topology Inference:** Captures LLDP frames using `pnet` and parses them with `packet-dissector-lldp` to map switch hierarchies.

### 🛡️ C. The Zero-Trust Interaction Layer (The "Identify")
- **Peer ID System:** Every RLN instance generates a unique **Ed25519** key pair via `ed25519-dalek`.
- **Identity-Based Comm:** Addresses nodes by their Public Key, ensuring connections remain stable even when local IPs change.
- **Secure Handshake:** Leverages the TLS layer built into the QUIC stack (via `rustls`) for confidentiality and authenticity.

### 🚀 D. The Transfer Protocol (The "Stream")
- **Iroh-Powered Blobs:** High-level P2P streaming with built-in NAT punching and hole-punching for multi-subnet support.
- **Atomic Verification:** Real-time SHA-256 hashing during the stream to guarantee bit-perfect delivery.

---

## 🛠️ 3. Recommended Technical Stack

| Category | Subsystem | Recommended Crate(s) | Rationale |
| :--- | :--- | :--- | :--- |
| **Core** | Runtime | `tokio` | The standard for high-performance async I/O in Rust. |
| **Discovery** | L2 ARP/NDP | `pnet`, `async-arp` | `pnet` for raw packets; `async-arp` for async ARP client. |
| **Discovery** | mDNS | `simple-mdns` | Pure Rust, Tokio-friendly (supports `_http._tcp.local` queries). |
| **Storage** | Database | `rusqlite` | Simple, synchronous SQLite bindings; ideal for CLI tools. |
| **Networking** | ICMP / Ping | `surge-ping` | Well-documented async ICMP echo for IPv4/IPv6. |
| **Intelligence** | ONNX AI | `ort` or `tract` | `ort` for speed (ONNX Runtime); `tract` for zero-C-dependency. |
| **Topology** | LLDP | `packet-dissector-lldp` | Safe TLV parser for Link Layer Discovery Protocol. |
| **Identity** | Crypto | `ed25519-dalek` | Fast and secure Ed25519 signing/verification. |
| **Transfer** | P2P/QUIC | `iroh` or `quinn` | `iroh` for P2P ease; `quinn` for a leaner QUIC transport. |
| **UI** | TUI / CLI | `ratatui`, `clap` (v4) | Rich dashboard capabilities and standard argument parsing. |

---

## 📂 4. Project Structure

```text
rln/
├── Cargo.toml                  # Workspace/Project metadata and crate dependencies
├── build.rs                    # Optional: Build script for ONNX model prep or linking
├── assets/                     
│   └── models/                 # Local ONNX/tract models for ML fingerprinting
├── data/                       # Default dir for SQLite snapshots and config (gitignored)
├── src/
│   ├── main.rs                 # CLI entry point, clap setup, and panic handlers
│   ├── app.rs                  # Core application state and main event loop
│   │
│   ├── discovery/              # 🔍 Module A: The Discovery Engine
│   │   ├── mod.rs
│   │   ├── l2_scanner.rs       # pnet and async-arp implementation
│   │   └── mdns_scanner.rs     # simple-mdns integration
│   │
│   ├── intelligence/           # 🧠 Module B: Diagnostic & Intelligence Suite
│   │   ├── mod.rs
│   │   ├── probe.rs            # ICMP (surge-ping) and TCP-SYN logic
│   │   ├── fingerprint.rs      # ort/tract local ML inference logic
│   │   └── topology.rs         # packet-dissector-lldp parsing for switch mapping
│   │
│   ├── identity/               # 🛡️ Module C: Zero-Trust Interaction Layer
│   │   ├── mod.rs
│   │   ├── keys.rs             # ed25519-dalek key generation and secure local storage
│   │   └── peer.rs             # Peer ID management and validation
│   │
│   ├── transfer/               # 🚀 Module D: The Transfer Protocol
│   │   ├── mod.rs
│   │   ├── stream.rs           # iroh/quinn P2P streaming setup
│   │   └── hash.rs             # In-flight SHA-256 verification
│   │
│   ├── storage/                # State and History
│   │   ├── mod.rs
│   │   ├── db.rs               # rusqlite connection pooling and schema creation
│   │   └── drift.rs            # Logic for diffing current state vs snapshots
│   │
│   └── tui/                    # 📊 User Interface
│       ├── mod.rs
│       ├── event.rs            # Crossbeam/Tokio channels for async UI updates
│       ├── layout.rs           # ratatui grid management
│       └── views/              # Specific TUI panes (Dashboard, Map, Logs)
│
└── tests/                      # Integration Tests
    ├── db_snapshot_tests.rs
    ├── l2_mock_tests.rs
    └── crypto_handshake.rs
```

---

## 🗺️ 5. Expanded Development Roadmap

This roadmap builds upon the integration plan, layering in architectural milestones, testing requirements, and permission handling (a critical factor given `CAP_NET_RAW`).

### Phase 1: Foundation & Telemetry
*Focus: Data acquisition and local persistence.*

- **Milestone 1.1: Environment & Storage Prep**
    - [x] Initialize the project and `rusqlite` database schema.
    - [x] Implement CRUD operations for network snapshots (storing MAC, IP, Service Names).
- **Milestone 1.2: Layer 2 & Layer 3 Scanning**
    - [ ] Integrate `pnet` and `async-arp`. Implement custom privilege escalation checks (prompting the user gracefully if sudo or `CAP_NET_RAW` is missing).
    - [ ] Integrate `simple-mdns` for concurrent service discovery.
- **Milestone 1.3: The Drift Engine**
    - [ ] Write the diffing logic. Compare the active network state to the latest SQLite snapshot.
    - [ ] **Testing:** Mock L2 packets to test drift logic without needing a live, changing network.

### Phase 2: Identity & Secure Comms 
*Focus: Establishing the zero-trust paradigm before adding heavy transfers.*

- **Milestone 2.1: Cryptographic Bootstrapping**
    - [ ] Implement `ed25519-dalek` to generate a node's Identity Keypair on first boot.
    - [ ] Save keys to a restricted local config file (e.g., `chmod 600`).
- **Milestone 2.2: P2P Initialization**
    - [ ] Integrate `iroh` or `quinn`. Establish a basic listening state using the generated Peer ID.
    - [ ] Implement the custom TLS handshake to ensure only recognized Peer IDs can connect.

### Phase 3: Visualization & TUI    
*Focus: Bringing the data to life without blocking the async backend.*

- **Milestone 3.1: Async Event Loop**
    - [ ] Set up `tokio` channels to funnel discovery events, drift alerts, and connection attempts from background workers to the UI thread.
- **Milestone 3.2: Ratatui Dashboard**
    - [ ] Build the main views: Node List (color-coded by drift status), Active Transfers, and Event Log.
    - [ ] Integrate `packet-dissector-lldp` data to visually group devices by their connected switch/router.

### Phase 4: Intelligence & Data Movement   
*Focus: Advanced inference and high-speed streaming.*

- **Milestone 4.1: ML Fingerprinting**
    - [ ] Embed a lightweight ONNX model via `ort` or `tract`.
    - [ ] Feed basic packet metadata (TTL, TCP Window Size, open ports via `surge-ping`) into the model to classify devices (e.g., "IoT Camera", "macOS Laptop").
- **Milestone 4.2: Verified File Streaming**
    - [ ] Implement file chunking and piping over the established `iroh` connection.
    - [ ] Add atomic SHA-256 hashing to the stream.
    - [ ] Wire transfer progress events back to the TUI.

### Phase 5: Hardening & Release
- **Milestone 5.1: Privilege Separation**
    - [ ] Refine execution so that only the scanning threads require elevated privileges, dropping them where possible.
- **Milestone 5.2: Cross-Platform Compilation**
    - [ ] Ensure graceful fallbacks. If running on Windows without Npcap/WinPcap, gracefully disable raw L2 features and rely on mDNS/ICMP.

---

## 🛡️ 6. Security & Operating Constraints

- **Zero-Cloud Guarantee:** No telemetry or data leaves the local subnet; all processing is local.
- **Privileged Access:** Low-level packet crafting requires `CAP_NET_RAW` on Linux or Administrator on Windows.
- **Identity Persistence:** Peer IDs are stored in a local secure config; losing this file breaks the "trust" chain with other nodes.
- **License Compliance:** All recommended crates use MIT or Apache-2.0, ensuring no GPL viral issues.
