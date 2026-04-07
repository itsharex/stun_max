package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// ════════════════════════════════════════════════════════════════
// ANSI Colors
// ════════════════════════════════════════════════════════════════

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	cyan   = "\033[36m"
	white  = "\033[97m"
	gray   = "\033[90m"
)

// ════════════════════════════════════════════════════════════════
// Protocol types
// ════════════════════════════════════════════════════════════════

type Message struct {
	Type    string          `json:"type"`
	From    string          `json:"from,omitempty"`
	To      string          `json:"to,omitempty"`
	Room    string          `json:"room,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type PeerInfo struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Name     string `json:"name,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
}

// STUN constants
const (
	stunMagicCookie    uint32 = 0x2112A442
	stunBindingRequest uint16 = 0x0001
	stunAttrXorMapped  uint16 = 0x0020
	stunHeaderSize            = 20
	stunTimeout               = 3 * time.Second
)

// ════════════════════════════════════════════════════════════════
// Punch Test State
// ════════════════════════════════════════════════════════════════

type PunchTest struct {
	serverURL    string
	room         string
	passwordHash string
	name         string
	myID         string

	conn   *websocket.Conn
	connMu sync.Mutex

	udpConn    *net.UDPConn
	publicAddr string
	localAddr  string

	peers   []PeerInfo
	peersMu sync.RWMutex

	// Punch state per peer
	punchResults   map[string]*PunchResult
	punchResultsMu sync.RWMutex

	// Dedup stun_info messages
	seenStunInfo   map[string]bool
	seenStunInfoMu sync.Mutex

	// Options
	punchCount   int  // packets per phase
	birthdaySock int  // parallel sockets for birthday attack
	portRange    int  // ± range for port prediction
	verbose      bool
	timeout      time.Duration

	done chan struct{}
}

type PunchResult struct {
	PeerID       string
	PeerName     string
	PeerEndpoint string
	Phase1Sent   int32
	Phase2Sent   int32
	Phase3Sent   int32
	Received     int32
	Success      bool
	SuccessTime  time.Duration
	SuccessPhase string
	SuccessAddr  string
	StartTime    time.Time
}

func main() {
	server := flag.String("server", "ws://localhost:8080/ws", "WebSocket server URL")
	room := flag.String("room", "room1", "Room name")
	password := flag.String("password", "", "Room password")
	name := flag.String("name", "punchtest", "Client display name")
	punchCount := flag.Int("packets", 20, "Packets per burst phase")
	birthdaySock := flag.Int("birthday", 8, "Parallel sockets for birthday attack")
	portRange := flag.Int("port-range", 10, "Port prediction range (±N)")
	verbose := flag.Bool("v", false, "Verbose output")
	timeout := flag.Duration("timeout", 30*time.Second, "Total test timeout")
	flag.Parse()

	hash := ""
	if *password != "" {
		h := sha256.Sum256([]byte(*password))
		hash = hex.EncodeToString(h[:])
	}

	pt := &PunchTest{
		serverURL:    *server,
		room:         *room,
		passwordHash: hash,
		name:         *name,
		punchResults:  make(map[string]*PunchResult),
		seenStunInfo: make(map[string]bool),
		punchCount:   *punchCount,
		birthdaySock: *birthdaySock,
		portRange:    *portRange,
		verbose:      *verbose,
		timeout:      *timeout,
		done:         make(chan struct{}),
	}

	printBanner()

	// Ctrl+C handler
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Printf("\n\n  %sInterrupted — printing results%s\n", yellow, reset)
		close(pt.done)
	}()

	if err := pt.run(); err != nil {
		fmt.Printf("\n  %s✗ Error: %v%s\n\n", red, err, reset)
		os.Exit(1)
	}
}

func printBanner() {
	fmt.Println()
	fmt.Printf("  %s%s╔══════════════════════════════════════════════════╗%s\n", bold, cyan, reset)
	fmt.Printf("  %s%s║%s  %s%s⚡ STUN Max — NAT3/NAT4 Hole Punch Test%s        %s%s║%s\n", bold, cyan, reset, bold, white, reset, bold, cyan, reset)
	fmt.Printf("  %s%s║%s     Port-Restricted & Symmetric NAT traversal   %s%s║%s\n", bold, cyan, reset, bold, cyan, reset)
	fmt.Printf("  %s%s╚══════════════════════════════════════════════════╝%s\n", bold, cyan, reset)
	fmt.Println()
}

func (pt *PunchTest) run() error {
	// Step 1: STUN discovery
	printStep(1, "STUN Discovery")
	publicAddr, localPort, udpConn, err := stunDiscover("stun.cloudflare.com:3478")
	if err != nil {
		// Fallback
		publicAddr, localPort, udpConn, err = stunDiscover("stun.miwifi.com:3478")
		if err != nil {
			return fmt.Errorf("STUN discovery failed: %w", err)
		}
	}
	pt.udpConn = udpConn
	pt.publicAddr = publicAddr
	defer udpConn.Close()

	localIP := getLocalIP()
	pt.localAddr = fmt.Sprintf("%s:%d", localIP, localPort)

	fmt.Printf("    Local:  %s%s%s\n", bold, pt.localAddr, reset)
	fmt.Printf("    Public: %s%s%s\n", bold, publicAddr, reset)

	// Check NAT type quickly
	natType := quickNATCheck(publicAddr, localIP)
	fmt.Printf("    NAT:    %s%s%s\n", natColor(natType), natType, reset)
	fmt.Println()

	// Step 2: Connect to signaling server
	printStep(2, "Connect to Signal Server")
	if err := pt.connect(); err != nil {
		return err
	}
	defer pt.conn.Close()
	fmt.Printf("    ID:     %s%s%s\n", bold, pt.myID, reset)
	fmt.Printf("    Room:   %s%s%s\n", bold, pt.room, reset)
	fmt.Println()

	// Step 3: Join room and discover peers
	printStep(3, "Join Room & Discover Peers")
	if err := pt.joinRoom(); err != nil {
		return err
	}

	// Start WS read loop
	go pt.readLoop()

	// Wait for peer list
	deadline := time.After(10 * time.Second)
	for {
		pt.peersMu.RLock()
		count := len(pt.peers)
		pt.peersMu.RUnlock()
		if count > 0 {
			break
		}
		select {
		case <-deadline:
			return fmt.Errorf("no peers found in room '%s' within 10s", pt.room)
		case <-pt.done:
			return fmt.Errorf("interrupted")
		case <-time.After(200 * time.Millisecond):
		}
	}

	pt.peersMu.RLock()
	otherPeers := 0
	for _, p := range pt.peers {
		if p.ID != pt.myID {
			otherPeers++
			peerName := p.Name
			if peerName == "" {
				peerName = shortID(p.ID)
			}
			fmt.Printf("    %s●%s %-16s %s%s%s\n", green, reset, peerName, gray, shortID(p.ID), reset)
		}
	}
	pt.peersMu.RUnlock()

	if otherPeers == 0 {
		fmt.Printf("\n    %s⚠ No other peers in room. Need at least 2 clients.%s\n", yellow, reset)
		fmt.Printf("    %sStart another client:  go run ./client/ --server %s --room %s --password <pass> --name test2%s\n", gray, pt.serverURL, pt.room, reset)
		return fmt.Errorf("no peers to test with")
	}
	fmt.Printf("    %sFound %d peer(s)%s\n", dim, otherPeers, reset)
	fmt.Println()

	// Step 4: Broadcast STUN info
	printStep(4, "Exchange STUN Endpoints")
	pt.broadcastStunInfo()
	fmt.Printf("    %sSent stun_info to room (public=%s)%s\n", dim, publicAddr, reset)

	// Wait a moment for peer stun_info responses
	time.Sleep(2 * time.Second)
	fmt.Println()

	// Step 5: Start UDP listener + hole punch
	printStep(5, "Hole Punch Test (3 Phases)")
	fmt.Println()

	// Punch all peers
	pt.peersMu.RLock()
	var targets []PeerInfo
	for _, p := range pt.peers {
		if p.ID != pt.myID && p.Endpoint != "" {
			targets = append(targets, p)
		}
	}
	pt.peersMu.RUnlock()

	if len(targets) == 0 {
		fmt.Printf("    %s⚠ No peers have STUN endpoints yet. Waiting...%s\n", yellow, reset)
		// Wait more
		time.Sleep(5 * time.Second)
		pt.peersMu.RLock()
		for _, p := range pt.peers {
			if p.ID != pt.myID && p.Endpoint != "" {
				targets = append(targets, p)
			}
		}
		pt.peersMu.RUnlock()
	}

	if len(targets) == 0 {
		fmt.Printf("    %s✗ No peers responded with STUN info. Ensure peers run with --stun enabled.%s\n", red, reset)
		pt.printReport()
		return nil
	}

	// Initialize results (before UDP read loop starts receiving)
	punchStart := time.Now()
	pt.punchResultsMu.Lock()
	for _, p := range targets {
		peerName := p.Name
		if peerName == "" {
			peerName = shortID(p.ID)
		}
		pt.punchResults[p.ID] = &PunchResult{
			PeerID:       p.ID,
			PeerName:     peerName,
			PeerEndpoint: p.Endpoint,
			StartTime:    punchStart,
		}
	}
	pt.punchResultsMu.Unlock()

	// Start UDP read loop AFTER results initialized
	go pt.udpReadLoop()

	// Run hole punch for each peer
	var wg sync.WaitGroup
	for _, p := range targets {
		wg.Add(1)
		go func(peer PeerInfo) {
			defer wg.Done()
			pt.punchPeer(peer)
		}(p)
	}

	// Wait for completion or timeout
	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
	case <-time.After(pt.timeout):
		fmt.Printf("\n    %s⏱ Timeout reached (%s)%s\n", yellow, pt.timeout, reset)
	case <-pt.done:
	}

	// Step 6: Report
	pt.printReport()
	return nil
}

// ════════════════════════════════════════════════════════════════
// WebSocket Connection
// ════════════════════════════════════════════════════════════════

func (pt *PunchTest) connect() error {
	machineID := generateTestID(pt.name)
	u := pt.serverURL
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	u += sep + "client_id=" + machineID

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := dialer.Dial(u, nil)
	if err != nil {
		return fmt.Errorf("WebSocket dial: %w", err)
	}

	_, data, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return fmt.Errorf("read welcome: %w", err)
	}

	var welcome Message
	if err := json.Unmarshal(data, &welcome); err != nil || welcome.Type != "welcome" {
		conn.Close()
		return fmt.Errorf("unexpected welcome: %s", string(data))
	}

	var payload struct {
		ID string `json:"id"`
	}
	json.Unmarshal(welcome.Payload, &payload)
	pt.myID = payload.ID
	pt.conn = conn
	return nil
}

func (pt *PunchTest) joinRoom() error {
	payload, _ := json.Marshal(map[string]string{
		"room":          pt.room,
		"password_hash": pt.passwordHash,
		"name":          pt.name,
	})
	return pt.sendMsg(Message{
		Type:    "join",
		Room:    pt.room,
		Payload: json.RawMessage(payload),
	})
}

func (pt *PunchTest) sendMsg(msg Message) error {
	pt.connMu.Lock()
	defer pt.connMu.Unlock()
	if pt.conn == nil {
		return fmt.Errorf("not connected")
	}
	return pt.conn.WriteJSON(msg)
}

func (pt *PunchTest) broadcastStunInfo() {
	payload, _ := json.Marshal(map[string]string{
		"addr":  pt.publicAddr,
		"local": pt.localAddr,
	})
	pt.sendMsg(Message{
		Type:    "stun_info",
		Room:    pt.room,
		Payload: json.RawMessage(payload),
	})
}

func (pt *PunchTest) readLoop() {
	for {
		select {
		case <-pt.done:
			return
		default:
		}

		_, data, err := pt.conn.ReadMessage()
		if err != nil {
			return
		}

		// Handle multi-line messages
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var msg Message
			if err := json.Unmarshal([]byte(line), &msg); err != nil {
				continue
			}
			pt.handleMessage(msg)
		}
	}
}

func (pt *PunchTest) handleMessage(msg Message) {
	switch msg.Type {
	case "peer_list":
		var peers []PeerInfo
		if err := json.Unmarshal(msg.Payload, &peers); err == nil {
			pt.peersMu.Lock()
			pt.peers = peers
			pt.peersMu.Unlock()
		}

	case "stun_info":
		if msg.From == "" || msg.From == pt.myID {
			return
		}
		var info struct {
			Addr  string `json:"addr"`
			Local string `json:"local"`
		}
		if err := json.Unmarshal(msg.Payload, &info); err != nil || info.Addr == "" {
			return
		}

		// Check if LAN peer
		targetAddr := info.Addr
		if info.Local != "" && pt.publicAddr != "" {
			myPubIP, _, _ := net.SplitHostPort(pt.publicAddr)
			peerPubIP, _, _ := net.SplitHostPort(info.Addr)
			if myPubIP != "" && myPubIP == peerPubIP {
				targetAddr = info.Local
			}
		}

		// Update peer endpoint
		pt.peersMu.Lock()
		for i, p := range pt.peers {
			if p.ID == msg.From {
				pt.peers[i].Endpoint = targetAddr
				break
			}
		}
		pt.peersMu.Unlock()

		// Dedup: only log first stun_info per peer
		pt.seenStunInfoMu.Lock()
		key := msg.From + ":" + targetAddr
		seen := pt.seenStunInfo[key]
		pt.seenStunInfo[key] = true
		pt.seenStunInfoMu.Unlock()

		if !seen {
			peerName := shortID(msg.From)
			pt.peersMu.RLock()
			for _, p := range pt.peers {
				if p.ID == msg.From && p.Name != "" {
					peerName = p.Name
					break
				}
			}
			pt.peersMu.RUnlock()
			fmt.Printf("    %s← stun_info from %s: %s%s\n", dim, peerName, targetAddr, reset)
		}

		// Send our stun_info back (only once per peer)
		if !seen {
			payload, _ := json.Marshal(map[string]string{
				"addr":  pt.publicAddr,
				"local": pt.localAddr,
			})
			pt.sendMsg(Message{
				Type:    "stun_info",
				To:      msg.From,
				Room:    pt.room,
				Payload: json.RawMessage(payload),
			})
		}
	}
}

// ════════════════════════════════════════════════════════════════
// UDP Hole Punch
// ════════════════════════════════════════════════════════════════

func (pt *PunchTest) punchPeer(peer PeerInfo) {
	addr, err := net.ResolveUDPAddr("udp4", peer.Endpoint)
	if err != nil {
		fmt.Printf("    %s✗ Cannot resolve %s: %v%s\n", red, peer.Endpoint, err, reset)
		return
	}

	peerName := peer.Name
	if peerName == "" {
		peerName = shortID(peer.ID)
	}

	pt.punchResultsMu.RLock()
	pr := pt.punchResults[peer.ID]
	pt.punchResultsMu.RUnlock()
	if pr == nil {
		return
	}

	fmt.Printf("  %s┌─ Punching %s%s%s @ %s%s%s%s\n", gray, reset+bold, peerName, reset, cyan, peer.Endpoint, reset, gray+"─┐"+reset)

	punch := []byte("PUNCH:" + pt.myID)

	// ─── Phase 1: Rapid Burst ───────────────────────────
	fmt.Printf("  %s│%s  Phase 1: Rapid Burst (%d packets, 25ms interval)\n", gray, reset, pt.punchCount)
	startP1 := time.Now()
	for i := 0; i < pt.punchCount; i++ {
		select {
		case <-pt.done:
			return
		default:
		}
		pt.udpConn.WriteToUDP(punch, addr)
		atomic.AddInt32(&pr.Phase1Sent, 1)
		time.Sleep(25 * time.Millisecond)
	}

	// Check early success
	if pr.Success {
		fmt.Printf("  %s│%s  %s✓ Phase 1 success! (%s)%s\n", gray, reset, green, time.Since(startP1).Round(time.Millisecond), reset)
		return
	}
	fmt.Printf("  %s│%s  %s…no response yet (%s)%s\n", gray, reset, gray, time.Since(startP1).Round(time.Millisecond), reset)

	// ─── Phase 2: Birthday Attack ───────────────────────
	fmt.Printf("  %s│%s  Phase 2: Birthday Attack (%d sockets × 5 packets)\n", gray, reset, pt.birthdaySock)
	startP2 := time.Now()

	var extraConns []*net.UDPConn
	for i := 0; i < pt.birthdaySock; i++ {
		c, err := net.ListenUDP("udp4", nil)
		if err != nil {
			continue
		}
		extraConns = append(extraConns, c)
	}

	if len(extraConns) > 0 {
		var wg sync.WaitGroup
		for _, ec := range extraConns {
			wg.Add(1)
			go func(c *net.UDPConn) {
				defer wg.Done()
				for j := 0; j < 5; j++ {
					c.WriteToUDP(punch, addr)
					atomic.AddInt32(&pr.Phase2Sent, 1)
					time.Sleep(50 * time.Millisecond)
				}
			}(ec)
		}
		wg.Wait()
		for _, c := range extraConns {
			c.Close()
		}
	}

	if pr.Success {
		fmt.Printf("  %s│%s  %s✓ Phase 2 success! (%s)%s\n", gray, reset, green, time.Since(startP2).Round(time.Millisecond), reset)
		return
	}
	fmt.Printf("  %s│%s  %s…no response yet (%s)%s\n", gray, reset, gray, time.Since(startP2).Round(time.Millisecond), reset)

	// ─── Phase 3: Port Prediction ───────────────────────
	predictCount := pt.portRange * 2
	fmt.Printf("  %s│%s  Phase 3: Port Prediction (±%d ports = %d targets)\n", gray, reset, pt.portRange, predictCount)
	startP3 := time.Now()

	basePort := addr.Port
	for delta := -pt.portRange; delta <= pt.portRange; delta++ {
		if delta == 0 {
			continue
		}
		select {
		case <-pt.done:
			return
		default:
		}
		p := basePort + delta
		if p <= 0 || p > 65535 {
			continue
		}
		predictedAddr := &net.UDPAddr{IP: addr.IP, Port: p}
		pt.udpConn.WriteToUDP(punch, predictedAddr)
		atomic.AddInt32(&pr.Phase3Sent, 1)
	}

	if pr.Success {
		fmt.Printf("  %s│%s  %s✓ Phase 3 success! (%s)%s\n", gray, reset, green, time.Since(startP3).Round(time.Millisecond), reset)
		return
	}
	fmt.Printf("  %s│%s  %s…no response yet (%s)%s\n", gray, reset, gray, time.Since(startP3).Round(time.Millisecond), reset)

	// ─── Wait for late responses ────────────────────────
	fmt.Printf("  %s│%s  Waiting for late responses (5s)...\n", gray, reset)
	waitEnd := time.After(5 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-waitEnd:
			if pr.Success {
				fmt.Printf("  %s│%s  %s✓ Late response received!%s\n", gray, reset, green, reset)
			} else {
				fmt.Printf("  %s│%s  %s✗ No response — hole punch failed%s\n", gray, reset, red, reset)
			}
			fmt.Printf("  %s└──────────────────────────────────────────┘%s\n", gray, reset)
			return
		case <-ticker.C:
			if pr.Success {
				fmt.Printf("  %s│%s  %s✓ Response received!%s\n", gray, reset, green, reset)
				fmt.Printf("  %s└──────────────────────────────────────────┘%s\n", gray, reset)
				return
			}
		case <-pt.done:
			return
		}
	}
}

func (pt *PunchTest) udpReadLoop() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-pt.done:
			return
		default:
		}

		pt.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := pt.udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		data := buf[:n]

		if bytes.HasPrefix(data, []byte("PUNCH:")) {
			peerID := string(data[6:])

			// Send ACK back
			ack := []byte("PUNCH_ACK:" + pt.myID)
			pt.udpConn.WriteToUDP(ack, remoteAddr)

			pt.recordSuccess(peerID, remoteAddr, "PUNCH")
		} else if bytes.HasPrefix(data, []byte("PUNCH_ACK:")) {
			peerID := string(data[10:])
			pt.recordSuccess(peerID, remoteAddr, "ACK")
		}
	}
}

func (pt *PunchTest) recordSuccess(peerID string, addr *net.UDPAddr, via string) {
	pt.punchResultsMu.Lock()
	defer pt.punchResultsMu.Unlock()

	pr, ok := pt.punchResults[peerID]
	if !ok {
		// Unknown peer — might be a peer we haven't seen in peer_list
		peerName := shortID(peerID)
		pt.peersMu.RLock()
		for _, p := range pt.peers {
			if p.ID == peerID && p.Name != "" {
				peerName = p.Name
				break
			}
		}
		pt.peersMu.RUnlock()

		pr = &PunchResult{
			PeerID:   peerID,
			PeerName: peerName,
			StartTime: time.Now().Add(-1 * time.Second), // approximate
		}
		pt.punchResults[peerID] = pr
	}

	if pr.Success {
		return // already recorded
	}

	atomic.AddInt32(&pr.Received, 1)
	pr.Success = true
	pr.SuccessTime = time.Since(pr.StartTime)
	pr.SuccessAddr = addr.String()

	// Determine which phase succeeded
	p1 := atomic.LoadInt32(&pr.Phase1Sent)
	p2 := atomic.LoadInt32(&pr.Phase2Sent)
	p3 := atomic.LoadInt32(&pr.Phase3Sent)

	if p1 == 0 && p2 == 0 && p3 == 0 {
		pr.SuccessPhase = fmt.Sprintf("Peer-initiated (%s)", via)
	} else if p3 > 0 {
		pr.SuccessPhase = "Phase 3 (Port Prediction)"
	} else if p2 > 0 {
		pr.SuccessPhase = "Phase 2 (Birthday Attack)"
	} else {
		pr.SuccessPhase = "Phase 1 (Rapid Burst)"
	}
}

// ════════════════════════════════════════════════════════════════
// Report
// ════════════════════════════════════════════════════════════════

func (pt *PunchTest) printReport() {
	fmt.Printf("\n\n  %s%s╔══════════════════════════════════════════════════╗%s\n", bold, cyan, reset)
	fmt.Printf("  %s%s║%s  %s%sHole Punch Test Report%s                           %s%s║%s\n", bold, cyan, reset, bold, white, reset, bold, cyan, reset)
	fmt.Printf("  %s%s╚══════════════════════════════════════════════════╝%s\n\n", bold, cyan, reset)

	// Summary
	fmt.Printf("  %s%s  Test Configuration%s\n", bold, white, reset)
	fmt.Printf("  %s──────────────────────────────────────────────────%s\n", gray, reset)
	fmt.Printf("    Server:          %s\n", pt.serverURL)
	fmt.Printf("    Room:            %s\n", pt.room)
	fmt.Printf("    My ID:           %s\n", shortID(pt.myID))
	fmt.Printf("    Public Endpoint: %s\n", pt.publicAddr)
	fmt.Printf("    Phase 1 packets: %d (rapid burst)\n", pt.punchCount)
	fmt.Printf("    Phase 2 sockets: %d (birthday attack)\n", pt.birthdaySock)
	fmt.Printf("    Phase 3 range:   ±%d (port prediction)\n", pt.portRange)
	fmt.Println()

	// Per-peer results
	pt.punchResultsMu.RLock()
	defer pt.punchResultsMu.RUnlock()

	if len(pt.punchResults) == 0 {
		fmt.Printf("    %sNo punch attempts were made (no peers with endpoints)%s\n\n", gray, reset)
		return
	}

	fmt.Printf("  %s%s  Results%s\n", bold, white, reset)
	fmt.Printf("  %s──────────────────────────────────────────────────%s\n", gray, reset)

	totalSuccess := 0
	totalFail := 0

	for _, pr := range pt.punchResults {
		p1 := atomic.LoadInt32(&pr.Phase1Sent)
		p2 := atomic.LoadInt32(&pr.Phase2Sent)
		p3 := atomic.LoadInt32(&pr.Phase3Sent)
		recv := atomic.LoadInt32(&pr.Received)
		totalSent := p1 + p2 + p3

		if pr.Success {
			totalSuccess++
			fmt.Printf("    %s✓ %s%s%s → %sSUCCESS%s\n", green, bold, pr.PeerName, reset, green+bold, reset)
			fmt.Printf("      Endpoint:    %s\n", pr.PeerEndpoint)
			fmt.Printf("      Replied from: %s%s%s\n", cyan, pr.SuccessAddr, reset)
			fmt.Printf("      Via:         %s%s%s\n", green, pr.SuccessPhase, reset)
			fmt.Printf("      Time:        %s%s%s\n", bold, pr.SuccessTime.Round(time.Millisecond), reset)
			fmt.Printf("      Packets:     sent=%d (P1:%d P2:%d P3:%d) recv=%d\n",
				totalSent, p1, p2, p3, recv)
		} else {
			totalFail++
			fmt.Printf("    %s✗ %s%s%s → %sFAILED%s\n", red, bold, pr.PeerName, reset, red+bold, reset)
			fmt.Printf("      Endpoint:    %s\n", pr.PeerEndpoint)
			fmt.Printf("      Packets:     sent=%d (P1:%d P2:%d P3:%d) recv=%d\n",
				totalSent, p1, p2, p3, recv)
		}
		fmt.Println()
	}

	// Overall
	fmt.Printf("  %s%s  Summary%s\n", bold, white, reset)
	fmt.Printf("  %s──────────────────────────────────────────────────%s\n", gray, reset)
	total := totalSuccess + totalFail
	rate := 0
	if total > 0 {
		rate = totalSuccess * 100 / total
	}

	rateColor := red
	if rate >= 80 {
		rateColor = green
	} else if rate >= 50 {
		rateColor = yellow
	}

	fmt.Printf("    Total peers tested:  %d\n", total)
	fmt.Printf("    Successful:          %s%d%s\n", green, totalSuccess, reset)
	fmt.Printf("    Failed:              %s%d%s\n", red, totalFail, reset)
	fmt.Printf("    Success rate:        %s%s%d%%%s\n", bold, rateColor, rate, reset)
	fmt.Println()

	// Analysis
	fmt.Printf("  %s%s  Analysis%s\n", bold, white, reset)
	fmt.Printf("  %s──────────────────────────────────────────────────%s\n", gray, reset)

	if totalSuccess > 0 && totalFail == 0 {
		fmt.Printf("    %s✓ All hole punches succeeded — your NAT is P2P-friendly%s\n", green, reset)
		fmt.Printf("    %s  NAT type is likely Full Cone or Restricted Cone (NAT1/NAT2)%s\n", gray, reset)
	} else if totalSuccess > 0 {
		fmt.Printf("    %s~ Partial success — some peers are behind harder NATs%s\n", yellow, reset)
		fmt.Printf("    %s  Failed peers may be behind Symmetric NAT (NAT4)%s\n", gray, reset)
		fmt.Printf("    %s  or Port-Restricted Cone NAT (NAT3) with strict filtering%s\n", gray, reset)
	} else {
		fmt.Printf("    %s✗ All hole punches failed%s\n", red, reset)
		fmt.Printf("    %s  Possible causes:%s\n", gray, reset)
		fmt.Printf("    %s  • Both sides behind Symmetric NAT (NAT4+NAT4)%s\n", gray, reset)
		fmt.Printf("    %s  • Port-Restricted + Symmetric (NAT3+NAT4)%s\n", gray, reset)
		fmt.Printf("    %s  • Firewall blocking unsolicited inbound UDP%s\n", gray, reset)
		fmt.Printf("    %s  • STUN endpoints expired before punch reached peer%s\n", gray, reset)
		fmt.Printf("    %s  → Server relay will be used automatically in STUN Max%s\n", dim, reset)
	}
	fmt.Println()
}

// ════════════════════════════════════════════════════════════════
// STUN Implementation
// ════════════════════════════════════════════════════════════════

func stunDiscover(server string) (string, int, *net.UDPConn, error) {
	serverAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return "", 0, nil, err
	}

	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return "", 0, nil, err
	}

	localPort := conn.LocalAddr().(*net.UDPAddr).Port

	req := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(req[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(req[2:4], 0)
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	txID := make([]byte, 12)
	rand.Read(txID)
	copy(req[8:20], txID)

	conn.SetWriteDeadline(time.Now().Add(stunTimeout))
	if _, err := conn.WriteToUDP(req, serverAddr); err != nil {
		conn.Close()
		return "", 0, nil, err
	}

	conn.SetReadDeadline(time.Now().Add(stunTimeout))
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		conn.Close()
		return "", 0, nil, err
	}
	conn.SetReadDeadline(time.Time{})
	conn.SetWriteDeadline(time.Time{})

	if n < stunHeaderSize {
		conn.Close()
		return "", 0, nil, fmt.Errorf("response too short")
	}

	resp := buf[:n]
	if binary.BigEndian.Uint16(resp[0:2]) != 0x0101 {
		conn.Close()
		return "", 0, nil, fmt.Errorf("not a binding response")
	}
	if !bytes.Equal(resp[8:20], txID) {
		conn.Close()
		return "", 0, nil, fmt.Errorf("txID mismatch")
	}

	msgLen := binary.BigEndian.Uint16(resp[2:4])
	attrs := resp[stunHeaderSize : stunHeaderSize+int(msgLen)]

	ip, port, err := parseXorMapped(attrs)
	if err != nil {
		conn.Close()
		return "", 0, nil, err
	}

	addr := fmt.Sprintf("%s:%d", ip, port)
	return addr, localPort, conn, nil
}

func parseXorMapped(attrs []byte) (string, int, error) {
	offset := 0
	for offset+4 <= len(attrs) {
		attrType := binary.BigEndian.Uint16(attrs[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(attrs[offset+2 : offset+4]))
		offset += 4
		if offset+attrLen > len(attrs) {
			break
		}
		if attrType == stunAttrXorMapped && attrLen >= 8 {
			family := attrs[offset+1]
			if family != 0x01 {
				offset += attrLen
				continue
			}
			rawPort := binary.BigEndian.Uint16(attrs[offset+2 : offset+4])
			rawIP := binary.BigEndian.Uint32(attrs[offset+4 : offset+8])
			port := rawPort ^ uint16(stunMagicCookie>>16)
			ip := rawIP ^ stunMagicCookie
			ipStr := fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
			return ipStr, int(port), nil
		}
		offset += attrLen
		if attrLen%4 != 0 {
			offset += 4 - (attrLen % 4)
		}
	}
	return "", 0, fmt.Errorf("XOR-MAPPED-ADDRESS not found")
}

// quickNATCheck queries a second STUN server from same socket to detect Symmetric NAT
func quickNATCheck(firstAddr, localIP string) string {
	firstIP, _, _ := net.SplitHostPort(firstAddr)
	if firstIP == localIP {
		return "Open Internet (NAT1)"
	}

	// Query second server from fresh socket
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return "Unknown"
	}
	defer conn.Close()

	servers := []string{"stun.miwifi.com:3478", "stun.l.google.com:19302"}
	var addrs []string

	for _, srv := range servers {
		srvAddr, err := net.ResolveUDPAddr("udp4", srv)
		if err != nil {
			continue
		}
		req := make([]byte, stunHeaderSize)
		binary.BigEndian.PutUint16(req[0:2], stunBindingRequest)
		binary.BigEndian.PutUint16(req[2:4], 0)
		binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
		txID := make([]byte, 12)
		rand.Read(txID)
		copy(req[8:20], txID)

		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		conn.WriteToUDP(req, srvAddr)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil || n < stunHeaderSize {
			continue
		}
		resp := buf[:n]
		if binary.BigEndian.Uint16(resp[0:2]) != 0x0101 || !bytes.Equal(resp[8:20], txID) {
			continue
		}
		msgLen := binary.BigEndian.Uint16(resp[2:4])
		attrs := resp[stunHeaderSize : stunHeaderSize+int(msgLen)]
		ip, port, err := parseXorMapped(attrs)
		if err == nil {
			addrs = append(addrs, fmt.Sprintf("%s:%d", ip, port))
		}
	}

	if len(addrs) < 2 {
		return "Cone NAT (NAT1-3)"
	}

	if addrs[0] == addrs[1] {
		return "Cone NAT (NAT1-3)"
	}
	return "Symmetric NAT (NAT4)"
}

// ════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════

func generateTestID(name string) string {
	// Random ID for test tool — different each run
	b := make([]byte, 8)
	rand.Read(b)
	h := sha256.Sum256(append(b, []byte(name)...))
	return hex.EncodeToString(h[:8])
}

func getLocalIP() string {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12] + "..."
	}
	return id
}

func natColor(natType string) string {
	if strings.Contains(natType, "Symmetric") || strings.Contains(natType, "NAT4") {
		return red + bold
	}
	if strings.Contains(natType, "Open") || strings.Contains(natType, "NAT1") {
		return green + bold
	}
	return yellow + bold
}

func printStep(num int, title string) {
	fmt.Printf("  %s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", dim, cyan, reset)
	fmt.Printf("  %s%s  STEP %d: %s%s\n", bold, cyan, num, title, reset)
	fmt.Printf("  %s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", dim, cyan, reset)
}

// Ensure URL is valid
func init() {
	// Validate URL helper
	_ = url.Parse
}
