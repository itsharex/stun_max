# CHANGELOG

## 2026-04-10 - Room Lock, Relay Control Fix, Forward Relay Toggle

### Server: Room Lock
- **Lock room** — dashboard toggle to block new joins (existing peers unaffected)
- **API** — `POST /api/rooms/lock` with `{"room":"name","locked":true/false}`

### Relay Control Fix
- **Signaling passthrough** — relay disable now only blocks bulk data (`tunnel_data`, `speed_test_data`, `file_data`), signaling messages always pass through
- **Encrypted message handling** — `encrypted` envelopes use size heuristic (<8KB = signaling, >8KB = data) instead of blanket block

### Forward Relay Toggle
- **ForceRelay in data path** — `sendPacket()` now checks `isPeerForwardForceRelay()` before attempting P2P UDP
- **UI always shows toggle** — relay switch button visible regardless of current mode (`→ Relay` / `→ Auto`)
- **Per-forward control** — each forward can independently force relay or use auto mode

### WebSocket Keepalive
- **Ping interval** — reduced from 30s to 15s for better NAT mapping persistence on Symmetric NATs

## 2026-04-08 - Server Upgrade + VPN Stability + Relay Control

### Server: SQLite Persistence + Dashboard Upgrade
- **SQLite storage** — rooms, blacklists, relay bytes persisted to `stun_max.db`, survive server restart
- **Dashboard redesign** — search bar, NAT type badges, IP geolocation (ip2region offline DB), peer duration, STUN Server tab, Kick/Ban buttons
- **Room ownership** — client-created rooms auto-delete when owner leaves; dashboard-created rooms persist
- **IP geolocation** — offline ip2region database (10MB), shows city/ISP for each peer endpoint
- **Health endpoint** — `/health` returns status/uptime/connections without auth
- **Graceful shutdown** — SIGINT/SIGTERM syncs bytes to SQLite before exit
- **Relay control** — per-room and global relay on/off toggle via dashboard; only blocks data transfer, signaling always passes through
- **Same-name kick** — server auto-kicks stale connections when same-named client reconnects (fixes Android dual-NIC ghost peers)

### VPN Stability Fixes
- **VPN setup dedup** — ignore duplicate `tun_setup` from same peer when session is alive, re-send ack instead
- **Multi-VPN support** — B can accept VPN from both A and C simultaneously with unique 10.7.{N}.x subnets
- **VPN index allocation** — `nextVPNIndex()` finds unused index instead of `len(tunDevices)` to avoid subnet conflicts
- **VPN auto-restore** — when VPN peer disconnects and reconnects, initiator auto-restarts VPN after 5s
- **Android VPN crash fix** — JNI `NewGlobalRef` protects context from GC during `vpnEstablish`; re-acquire env/context after `startVpnService`
- **stopPlatformVPN guard** — only stops Android VpnService when last VPN session closes, not on each individual stop

### P2P Reconnection Fixes
- **Address-change re-punch** — when peer reconnects with new STUN endpoint, reset mode to "connecting" and re-punch even if previously "direct"
- **NAT detection no re-broadcast** — `detectNATType` no longer sends redundant `sendStunInfo("")`, reducing peer_list flapping
- **Crypto reset cleanup** — cancel active speed tests and close stale forward netstacks when peer address changes
- **Reconnect proxy bypass** — reconnect WebSocket dialer uses `bypassDialer` for TUN proxy environments
- **Reconnect backoff** — 1s → 2s → 3s → 5s (cap), instead of fixed 3s

### Android Fixes
- **Stable machine ID** — `isAndroid()` detects via `/system/bin/app_process` (not `/system/build.prop` which requires root); uses `hostname+name` instead of MAC for ID generation
- **WiFi priority** — `getPrimaryMAC()` and `detectPhysicalIP()` prefer WiFi (wlan0) over cellular (rmnet*), skip CGNAT 198.18.x
- **Port forward binding** — bind to `127.0.0.1` instead of `0.0.0.0` for Android SELinux compatibility

### Speed Test + File Transfer
- **Speed test cancel** — Cancel button in UI, `st_cancel` protocol message, cancel channel in send loop
- **File transfer rate limiting** — P2P UDP send paced at 2ms/chunk to prevent buffer overflow
- **Consecutive failure detection** — P2P send failures >10 auto-switch to relay permanently
- **NACK buffer enlarged** — 64 → 256 to prevent retransmit request overflow

### NAT Detection (Corrected)
- **Simplified classification** — Cone NAT = NAT1 (no false NAT3), Symmetric = NAT4; only 2 categories that matter for punch strategy
- **RFC 5780 natcheck tool** — full rewrite in Chinese, offline proxy bypass, 6 tests, comprehensive report
- **Birthday attack upgrade** — 256 sockets for NAT4 scenarios, ±1000 port prediction range, Phase 4 random port spray (1024 probes)

## 2026-04-07 - NAT Type Detection + Proxy Bypass + Adaptive Hole Punch

### NAT Type Detection
- **Auto-detect on connect** — queries multiple STUN servers after discovery, classifies NAT1 (Open/Full Cone), NAT2 (Restricted Cone), NAT3 (Port Restricted), NAT4 (Symmetric)
- **NAT type in stun_info** — peers exchange NAT types via signaling, stored in PeerConn and broadcast in peer_list
- **Server-side storage** — server stores and broadcasts each peer's NAT type
- **GUI display** — NAT type badge on each peer card (green NAT1/2, yellow NAT3, red NAT4)
- **CLI display** — `peers` command shows NAT column with color-coded types

### Adaptive Hole Punching (NAT3/NAT4)
- **NAT-aware burst sizing** — Phase 1 burst: 20 packets (easy NAT), 30 (NAT3), 40 (NAT4)
- **Scaled birthday attack** — 0 sockets (NAT1/2), 8 (NAT3+NAT3), 12 (NAT3+NAT4), 16 (NAT4+NAT4)
- **Conditional port prediction** — Phase 3 only triggers when Symmetric NAT detected; ±10 for NAT4, ±20 for NAT4+NAT4
- **Strategy selection** — each phase runs only when NAT types warrant it, reducing unnecessary traffic

### Proxy Bypass (TUN Proxy Auto-Detection)
- **Physical interface detection** — auto-detects real NIC (en0/eth0/wlan0), skips TUN/utun/wintun/docker/wireguard interfaces
- **Socket binding** — all WebSocket, STUN, and P2P UDP sockets bound to physical interface IP
- **CGNAT filter** — skips 198.18.0.0/15 addresses (commonly used by Clash/V2Ray TUN mode)
- **Bypass logging** — shows detected physical IP on connect for diagnostics
- **Cross-platform** — works on macOS, Linux, Windows; Android uses VpnService.protect

### Standalone Punch Test Tool
- `tools/punchtest/` — standalone CLI for testing NAT3/NAT4 hole punching between peers
- Connects to signal server, discovers peers, runs 3-phase punch with detailed results
- Reports success/failure per peer, timing, phase attribution, and analysis

## 2026-04-07 - Crypto Upgrade + NAT Diagnostic Enhancement

### Crypto: AES-256-GCM → XChaCha20-Poly1305
- **Thread-safe encryption** — replaced `cipher.AEAD` (AES-GCM) with `chacha20poly1305.NewX()`, explicitly safe for concurrent Seal/Open
- **Removed dead code** — `nonceMu sync.Mutex` declared but unused (nextNonce used atomic), removed unused `EncryptTo` method
- **Race condition fix** — `Encrypted` public field replaced with `IsEncrypted()` method protected by `sync.RWMutex`
- **24-byte nonce** — eliminates counter collision risk (was 12-byte), random start counter per session
- **ARM performance** — XChaCha20 is faster than AES-GCM on devices without AES-NI (Android, older ARM)
- **Dependency** — added `golang.org/x/crypto/chacha20poly1305`

### NAT Diagnostic Tool (natcheck) — Full Rewrite
- **6 comprehensive tests**: STUN reachability, port allocation pattern, filtering behavior, hairpin NAT, binding lifetime, port prediction accuracy
- **Scoring system** — 0-100 score with visual progress bar
- **Difficulty rating** — ★☆☆☆☆ to ★★★★★ with Easy/Medium/Hard/Very Hard/Impossible labels
- **STUN Max strategy display** — shows which hole punch phases will be used (rapid burst, birthday attack, port prediction, relay fallback)
- **Peer compatibility matrix** — detailed table showing P2P feasibility with each NAT type + notes
- **Latency analysis** — min/avg/max/jitter with color-coded output
- **NAT type explanation** — lists all 7 NAT types with current type highlighted, descriptions, and P2P implications
- **More STUN servers** — 7 servers (Cloudflare, Miwifi, Bilibili, Google ×3, Syncthing)
- **5-sample port analysis** — increased from 3 samples for more accurate pattern detection
- **`--fast` flag** — skip binding lifetime test for quicker results
- **Beautiful console output** — box-drawing borders, color-coded sections, spinner animations

## 2026-04-06 - Android Support + Auto-Hop Relay

### Android APK Support
- **Android platform files** — `tun_config_android.go` (TUN via VpnService fd), `files_picker_android.go` (stub)
- **VpnService Java layer** — `StunMaxVpnService.java` + `GoBridge.java` for TUN fd and socket protection
- **Build automation** — `android/build-apk.sh` script, `gogio` integration in `build.sh`
- **GitHub Actions** — `build-android.yml` (standalone) + `build-release.yml` (full multi-platform with Android)
- **Build tag fix** — `tun_config_linux.go` now uses `//go:build linux && !android` to avoid redeclaration
- **File picker split** — `files.go` refactored: `openFilePicker()` in `files_picker_desktop.go` (dialog) / `files_picker_android.go` (stub)

## 2026-04-06 - Auto-Hop Relay: Automatic P2P Route Discovery

### Auto-Hop Feature
- **Automatic hop discovery** — when direct P2P hole punch fails, automatically find an intermediate peer who has P2P connections to both endpoints
- **P2P connectivity map broadcast** — each peer periodically shares its direct P2P connection list with the room (every 15s and on hole punch success)
- **Smart candidate selection** — prefers encrypted channels and peers with fewer punch failures
- **Transparent forwarding** — `StartForward` automatically uses `StartHopForward` when a hop candidate is available; no user action needed
- **Priority chain**: Direct P2P → Auto-Hop → Server Relay (WebSocket)

### Security
- **Allow Hop Relay** toggle in Settings — controls whether this peer allows others to route through its P2P connections (default: on)
- Auto-initiated hops use separate permission (`allowHopRelay`) from manual hops (`allowForward`)

### UI/CLI
- **HOP badge** — cyan-colored badge in peers list and forwards panel when connection uses auto-hop
- CLI shows "HOP" mode in `peers` command output
- New events: `EventAutoHopEstablished`, `EventAutoHopFailed`

### Internal
- New file: `client/core/autohop.go` — broadcastP2PMap, handleP2PMap, findAutoHopCandidate, tryAutoHop, cleanupPeerP2PMap
- New wire message: `p2p_map` (relay_data type)
- `HopForwardRequest.Auto` field distinguishes auto vs manual hops
- P2P maps cleaned up on peer disconnect
- No server-side changes required

## 2026-04-05 - Security Settings + Performance Tuning + Stability Fixes

### Security Settings
- **Allow Incoming VPN** toggle — prevent peers from force-opening VPN on your device
- **Allow File Receive** toggle — prevent peers from sending unsolicited files
- Both settings persist in config.json, applied on connect
- `handleTunSetup` and `handleFileOffer` gated with security checks, rejected with log warning

### Performance Tuning
- gVisor MTU: 1400 → 1472 (max UDP without fragmentation)
- gVisor channel buffer: 1024 → 2048
- TCP send/receive buffer: 256KB → 1MB default, 4MB → 16MB max
- Forward netstack: skip deflate compression (forwarded data mostly TLS/encrypted)
- TUN netstack: use tunCompress smart bypass (skip QUIC/RTP/HTTPS)
- Removed per-packet debug logging from forward netstack

### Stability Fixes
- TUN read loop: immediate exit on "file already closed" / "bad file descriptor" (no more 10-error cascade after VPN restart)
- Reverted multi-hole UDP punching (caused packet reordering instability) — back to single stable hole

## 2026-04-04 - Multi-VPN + Route Append + UI Improvements

### Multi-VPN Support
- **Multiple simultaneous VPN connections** — connect to different peers at the same time, each with independent TUN device, virtual IP (10.7.{N}.X), and routes
- **Per-peer data structure** — `tunDevices map[peerID]*TunDevice` replaces single pointer, per-peer ack channels and transport mode tracking
- **Route append** — adding a new subnet to an existing peer VPN appends the route instead of rejecting, B side notified automatically
- **Per-peer stop** — `StopTunPeer(peerID)` stops specific VPN, `StopTun()` stops all

### GUI VPN Panel
- **VPN list** — each active VPN shown as card with role badge, peer name, stats, and stop button
- **Role badge** — blue `OUT` (initiator/主动) or gray `IN` (responder/被动) per VPN entry
- **Stop button alignment** — pushed to right edge with flexed spacer
- **Stop All button** — appears when any VPN is active
- **Start always visible** — can add new VPN connections without stopping existing ones
- **5-column stats** — Local IP, Peer IP, Routes, Traffic (total), Speed (real-time ↑/s ↓/s)

### CLI VPN Commands
- `vpn <peer> <subnet1> [subnet2...]` — start VPN with multiple subnets
- `vpn <peer> <new-subnet>` — append route to existing VPN
- `vpn stop <peer>` — stop specific peer's VPN
- `vpn stop` — stop all VPNs
- `vpn status` — show all active VPNs with numbered list

### Internal
- Virtual IP allocation: `10.7.{N}.X` where N = VPN index, X = MAC-derived
- UDP packet routing by peer address for multi-device support
- `TunStatusAll() []TunInfo` API for GUI/CLI

## 2026-04-03 - gVisor Netstack + SpeedTest P2P + TUN VPN Improvements

### Architecture: gVisor Userspace TCP/IP Stack
- **TUN VPN Proxy**: Replaced hand-rolled TCP state machine with gVisor netstack (`tun_netstack.go`). TCP connections through VPN now have proper congestion control, SACK, retransmission, and window scaling — same stack used by Tailscale and tun2socks.
- **Port Forwarding**: Replaced RUTP-based tunnel transport with gVisor netstack (`forward_netstack.go`). Each peer pair gets a shared gVisor stack. A side uses `DialTCP`, B side uses TCP forwarder + `io.Copy` bridge. Eliminates RUTP bugs, dedup hash collisions, and memory leaks.
- **Legacy ICMP proxy** retained for raw ICMP socket (gVisor doesn't handle raw ICMP well).

### SpeedTest
- **P2P Transport Fix**: Reduced chunk size from 32KB to 1KB for P2P UDP mode (fits single UDP packet after base64 encoding). Previously 32KB chunks exceeded UDP MTU causing silent packet drops.
- **Transport Mode**: Added P2P-only speed test button. Progress bar and results show transport used.
- **Download Phase Fix**: Fixed `handleSTBegin` overwriting existing test during download phase, causing infinite ping-pong loop and UI stuck at "running + upload 100%".

### TUN VPN Improvements
- **TCP MSS Clamping**: SYN/SYN-ACK packets clamped to MSS 1360 to prevent fragmentation through tunnel.
- **Smart Compression**: Skip deflate for QUIC (UDP 443), RTP, WebRTC, and HTTPS bulk data — saves CPU on already-compressed traffic.
- **Error Recovery**: TUN read loop retries with backoff instead of exiting on first error.
- **ICMP NAT Key Fix**: Include target IP in ICMP NAT key to prevent collision between different destinations with same ICMP ID.
- **TCP Proxy Hardening**: Random initial sequence numbers, MSS option in SYN-ACK, sequence validation on incoming data, write-before-ACK, IP identification field and DF flag.
- **UDP Proxy Timeout**: Increased from 30s to 120s for streaming compatibility.

### Forward Module (Port Forwarding)
- **gVisor Transport**: Forward connections now use gVisor netstack instead of RUTP. Virtual IP scheme 10.99.0.1 ↔ 10.99.0.2 per peer pair.
- **Signaling**: `open_tunnel` with `ns:` prefix triggers netstack path. A waits for B's `tunnel_opened` confirmation before dialing.
- **Traffic Counting**: `BytesUp`/`BytesDown` properly tracked via `io.CopyBuffer` return values.
- **FN: UDP Prefix**: Forward netstack packets use `FN:` prefix on P2P UDP, `fwd_data` on relay.

## 2026-04-03 - Security, Stability & Feature Enhancements

### Security
- **E2E Relay Encryption**: All relay traffic now encrypted with X25519+AES-256-GCM (same keys as P2P). Server can no longer read relay data.
- **TLS Support**: Server supports `--tls-cert` and `--tls-key` flags for HTTPS/WSS
- Key exchange messages remain unencrypted (they're already secure — X25519 public keys)

### Stability
- **WebSocket Keepalive**: Client sends ping every 30s, handles pong with 120s timeout. Server pongWait increased to 120s.
- **Peer Leave Debounce**: 5-second delay before confirming peer departure, prevents false "peer left" during brief network hiccups
- **VPN Session Recovery**: Stale VPN sessions auto-cleaned when peer reconnects; peer ID updated on reconnect

### VPN Improvements
- **MAC-Based Virtual IP**: TUN IP derived from MAC address hash (deterministic, stable across restarts)
- **IP Persistence**: Virtual IP saved to config.json, restored on next launch
- **Userspace Subnet Proxy**: ICMP/UDP/TCP proxied through Go network stack (no kernel NAT dependency)
- **Exit IP Configuration**: Configurable exit gateway IP for subnet routing
- **tun_ack Protocol**: B side confirms VPN with its IP, A waits for ack before creating TUN

### Server Dashboard
- **Feature Tracking**: Clients report active features (VPN, forwards) to server
- **Dashboard Features Column**: Shows per-client feature badges (VPN, forwards, routes)

### UI
- **Peer Dropdown Selector**: All peer input fields replaced with dropdown selectors showing name + connection mode

## 2026-03-31 - natcheck: NAT Diagnostic Tool

### New Tool
- `tools/natcheck/` - 独立二进制，检测网络 NAT 类型和打洞可行性
  - Test 1: 多 STUN 服务器探测，同 socket 端口映射一致性
  - Test 2: 不同 socket 端口分配模式（sequential / port-preserving / random）
  - Test 3: Hairpin NAT 回环测试
  - Test 4: NAT Binding 存活时间
  - NAT 分类: Open / Full Cone / Restricted Cone / Port Restricted / Symmetric / Blocked
  - 打洞成功率评估: High / Medium / Low / None
  - 与各类 NAT 的兼容性矩阵
  - 运行: `go run ./tools/natcheck/` 或 `go build -o natcheck ./tools/natcheck/`


### New Features
- **STUN UDP Hole Punching**: built-in STUN client (no external deps), discovers public endpoint via stun.l.google.com
- **P2P Direct Mode**: after STUN discovery, peers exchange endpoints and attempt UDP hole punch (5 packets over 2s)
- **Auto Fallback**: if hole punch fails within timeout, auto fallback to WS relay; tunnel data seamlessly switches path
- **Periodic Retry**: relay peers re-attempt hole punch every 30s in background
- **UDP Tunnel Transport**: direct peers send raw tunnel data over UDP (no base64 overhead), much faster than relay
- **Dashboard P2P/Relay Display**: each peer shows ⚡ P2P (green) or 🔄 RELAY (orange) with STUN endpoint address
- **CLI `stun` command**: show STUN status and per-peer connection details
- **CLI flags**: `--stun` (custom STUN server), `--no-stun` (relay-only mode)
- **Peer name matching**: resolve peers by name prefix in addition to ID prefix

### Server Changes
- `stun_info` message type: broadcast to room or forward to specific peer
- PeerInfo includes `endpoint` field for STUN-discovered address
- Dashboard API exposes endpoint data

## 2026-03-31 - v2: CLI Client + TCP Tunnel + Web Dashboard

### Breaking Changes
- Web UI is now a server admin dashboard (not a P2P client)
- Client functionality moved to Go CLI tool

### New Features
- **CLI Client** (`client/main.go`): join room, list peers, port forward tunnel
  - `forward <peer_id> <host:port> [local_port]` - tunnel remote port to local
  - `unforward <local_port>` - stop forwarding
  - `peers` - list room peers with status
  - Peer ID prefix matching (type first few chars)
  - ANSI colored output, real-time peer join/leave notifications
- **TCP Tunnel Protocol**: open_tunnel/tunnel_data/close_tunnel over relay_data envelope
  - Bidirectional TCP forwarding through WebSocket relay
  - Multiple concurrent tunnels per peer
  - Base64 encoded binary data transport
- **Web Dashboard**: password-protected admin panel showing all rooms/peers/status
  - `--web-password` flag enables dashboard with HTTP basic auth
  - `/api/rooms` JSON API for room/peer data
  - Auto-refresh every 3s
- **Peer Names**: CLI clients advertise friendly names (--name flag, defaults to hostname)

### Architecture
- `server/` - Signal server + relay + web dashboard (Go)
- `client/` - CLI client with tunnel capability (Go)
- `web/` - Admin dashboard (HTML/JS/CSS)

## 2026-03-31 - v1: Initial Release

### Features
- WebRTC P2P hole punching via STUN
- Auto fallback to server relay (5s timeout)
- Room + password grouping (SHA-256)
- WebSocket signaling server (Go + gorilla/websocket)
