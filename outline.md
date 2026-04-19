# 🛰️ Rust-LAN-Navigator (RLN) v2.0

> **Vision:** A privacy-first, zero-trust network orchestrator for the modern LAN. RLN provides instant visibility, cryptographic identity, and secure data movement without ever leaving the local subnet.

---

## 🎯 1. Project Objectives

- **Hybrid Discovery:** Simultaneous Layer 2 (ARP/NDP) and Layer 3 (mDNS) scanning for full IPv4 and IPv6 coverage.
- **Vendor Identification:** Automatic device name resolution via the bundled `mac_oui` Wireshark OUI database.
- **Stateful Monitoring:** Track network "drift" by comparing current scans against historical snapshots.
- **Zero-Trust Identity:** Replace unstable IP-based targeting with permanent, cryptographic Peer IDs — powered natively by `iroh`'s key primitives.
- **Intelligent Fingerprinting:** Use local ML models to identify device types based on network behavior.
- **High-Speed Secure Transfer:** Utilize QUIC-based streaming (iroh v0.98) for encrypted, resilient file movement with SHA-256 integrity verification.

---

## 🧩 2. Core Functional Modules

### 🔍 A. The Discovery Engine (The "Detect")
- **Dual-Stack Scanner:** Implements **ARP** (IPv4) via `async-arp` and **NDP** (IPv6 Neighbor Discovery) via `pnet`.
- **Hostname & Vendor Resolution:** On each ARP IPv4 response, the scanner performs a concurrent Reverse DNS (PTR) query to fetch the device's customized DHCP name. If unavailable, it falls back to querying the bundled `mac_oui` Wireshark database to resolve the hardware manufacturer.
- **Snapshot Engine:** Uses `rusqlite` to maintain a local database of "Known Good" network states.
    - *Drift Alert:* Automated diffing between current scans and SQLite snapshots.
- **Identity Mapping:** Correlates OUI vendors and mDNS services (via `simple-mdns`) to provide human-readable names.

### 🧠 B. The Diagnostic & Intelligence Suite (The "Analyze")
- **Async Multi-Probe:** High-speed ICMP checks via `surge-ping` and TCP-SYN checks for port status.
- **AI Fingerprinting:** Local-only inference using `tract` (ONNX) to categorize devices based on network traffic patterns.
- **Topology Inference:** Captures and maps switch hierarchies from LLDP frames, grouping devices visually by their connected switch/router.

### 🛡️ C. The Zero-Trust Interaction Layer (The "Identify")
- **Iroh-Native Keys:** Every RLN instance generates a unique **Ed25519** keypair using `iroh::SecretKey` / `iroh::PublicKey` — no external `ed25519-dalek` dependency needed.
- **Identity-Based Comm:** Addresses nodes by their **`EndpointId`** (Iroh 0.98's new name for NodeId), ensuring connections remain stable even when local IPs change.
- **Secure Handshake:** Leverages the TLS layer built into the QUIC stack for confidentiality and authenticity.

### 🚀 D. The Transfer Protocol (The "Stream")
- **Iroh 0.98 QUIC Streams:** Direct bidirectional QUIC streams established via `Endpoint::builder(presets::N0)`, with the N0 preset enabling the n0.computer relay and PKARR DNS for robust NAT traversal.
- **Manual SHA-256 Verification:** Real-time SHA-256 hashing during the stream (via `sha2`) to guarantee bit-perfect delivery. Note: `iroh-blobs` is not yet compatible with `iroh 0.98` due to a pre-release `ed25519-dalek` conflict; it will be integrated in a future milestone once that is resolved.

---

## 🛠️ 3. Recommended Technical Stack

| Category | Subsystem | Crate(s) | Rationale |
| :--- | :--- | :--- | :--- |
| **Core** | Runtime | `tokio` | The standard for high-performance async I/O in Rust. |
| **Discovery** | L2 ARP/NDP | `pnet`, `async-arp` | `pnet` for raw packets; `async-arp` for async ARP. |
| **Discovery** | mDNS | `simple-mdns` | Pure Rust, Tokio-friendly. |
| **Discovery** | OUI Lookup | `mac_oui` (with-db) | Bundled Wireshark manufacturer DB for offline vendor names. |
| **Storage** | Database | `rusqlite` | Simple, synchronous SQLite bindings. |
| **Networking** | ICMP / Ping | `surge-ping` | Async ICMP echo for IPv4/IPv6. |
| **Intelligence** | ONNX AI | `tract` | Pure-Rust ONNX inference, zero C dependencies. |
| **Identity** | Crypto | `iroh::SecretKey` | Ed25519 built into iroh — no separate dalek needed. |
| **Transfer** | P2P/QUIC | `iroh` v0.98 | Latest iroh release with improved NAT traversal via `presets::N0`. |
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
│   │   ├── l2_scanner.rs       # pnet, async-arp, and mac_oui vendor resolution
│   │   └── mdns_scanner.rs     # simple-mdns integration
│   │
│   ├── intelligence/           # 🧠 Module B: Diagnostic & Intelligence Suite
│   │   ├── mod.rs
│   │   ├── probe.rs            # ICMP (surge-ping) and TCP-SYN logic
│   │   ├── fingerprint.rs      # tract local ML inference logic
│   │   └── topology.rs         # LLDP parsing for switch mapping
│   │
│   ├── identity/               # 🛡️ Module C: Zero-Trust Interaction Layer
│   │   ├── mod.rs
│   │   └── keys.rs             # iroh::SecretKey generation and secure local storage
│   │
│   ├── transfer/               # 🚀 Module D: The Transfer Protocol
│   │   ├── mod.rs
│   │   ├── stream.rs           # iroh 0.98 P2P streaming (presets::N0, EndpointId)
│   │   └── hash.rs             # In-flight SHA-256 verification
│   │
│   ├── storage/                # State and History
│   │   ├── mod.rs
│   │   ├── db.rs               # rusqlite connection pooling and schema creation
│   │   └── drift.rs            # Logic for diffing current state vs snapshots
│   │
│   └── tui/                    # 📊 User Interface
│       ├── mod.rs
│       ├── event.rs            # Tokio channels for async UI updates
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

### Phase 1: Foundation & Telemetry
*Focus: Data acquisition and local persistence.*

- **Milestone 1.1: Environment & Storage Prep**
    - [x] Initialize the project and `rusqlite` database schema.
    - [x] Implement CRUD operations for network snapshots (storing MAC, IP, Service Names).
- **Milestone 1.2: Layer 2 & Layer 3 Scanning**
    - [x] Integrate `pnet` and `async-arp`. Implement privilege escalation checks.
    - [x] Integrate `simple-mdns` for concurrent service discovery.
    - [x] Integrate `dns-lookup` for Reverse DNS resolution of DHCP hostnames.
    - [x] Integrate `mac_oui` (with bundled Wireshark OUI DB) for automatic vendor name resolution on ARP responses.
- **Milestone 1.3: The Drift Engine**
    - [x] Write the diffing logic. Compare the active network state to the latest SQLite snapshot.
    - [x] **Testing:** Mock L2 packets to test drift logic without a live, changing network.

### Phase 2: Identity & Secure Comms
*Focus: Establishing the zero-trust paradigm before adding heavy transfers.*

- **Milestone 2.1: Cryptographic Bootstrapping**
    - [x] Implement Ed25519 key generation using `iroh::SecretKey` / `iroh::PublicKey` (removed `ed25519-dalek` dependency — iroh 0.98 provides this natively).
    - [x] Save keys to a restricted local config file (`chmod 600`).
- **Milestone 2.2: P2P Initialization**
    - [x] Integrate `iroh` v0.98. Establish a listening endpoint using `Endpoint::builder(presets::N0)`.
    - [x] Authenticate peers using `connection.remote_id()` (the new `EndpointId` replaces the old `NodeId`).

### Phase 3: Visualization & TUI
*Focus: Bringing the data to life without blocking the async backend.*

- **Milestone 3.1: Async Event Loop**
    - [x] Set up `tokio` channels to funnel discovery events, drift alerts, and connection attempts to the UI thread.
    - [x] `AppEvent::NetworkUpdate` now carries both `DriftEvent`s and raw `ScannedDevice`s for live topology building.
- **Milestone 3.2: Ratatui Dashboard**
    - [x] Build the main views: Network Topology (LLDP + live scan), Active Transfers, and Event Log.
    - [x] Topology panel now dynamically populated from live ARP, mDNS, and continuous background LLDP scan results (removed mock topologies).
    - [x] Implement semantic color coding, rounded borders, and scrollable logs for enhanced UX.

### Phase 4: Intelligence & Data Movement
*Focus: Advanced inference and high-speed streaming.*

- **Milestone 4.1: ML Fingerprinting**
    - [ ] Embed a lightweight ONNX model via `tract`.
    - [ ] Feed packet metadata (TTL, TCP Window Size, open ports) into the model to classify devices.
- **Milestone 4.2: Verified File Streaming**
    - [x] Implement file chunking and piping over `iroh` 0.98 QUIC streams.
    - [x] Add atomic SHA-256 hashing to the stream via `hash.rs`.
    - [x] Wire transfer progress events back to the TUI.
    - [ ] Integrate `iroh-blobs` when a version compatible with `iroh 0.98` is released.

### Phase 5: Hardening & Release
- **Milestone 5.1: Privilege Separation**
    - [ ] Refine execution so only the scanning threads require elevated privileges.
- **Milestone 5.2: Cross-Platform Compilation**
    - [ ] Graceful fallbacks on Windows without Npcap/WinPcap.

---

## 🛡️ 6. Security & Operating Constraints

- **Zero-Cloud Guarantee:** No telemetry or data leaves the local subnet; all processing is local.
- **Privileged Access:** Low-level packet crafting requires `CAP_NET_RAW` on Linux or Administrator on Windows.
- **Identity Persistence:** Peer IDs are stored in `data/identity.key` (chmod 600); losing this file breaks the "trust" chain with other nodes.
- **License Compliance:** All crates use MIT or Apache-2.0 licenses.
