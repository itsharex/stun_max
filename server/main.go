package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  256 * 1024,
	WriteBufferSize: 256 * 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
	EnableCompression: true,
}

const defaultPassword = "" // set via --web-password flag

var (
	hub            *Hub
	store          *Store
	relayManager   *RelayManager
	authToken      string
	globalRelayOff int32 // atomic: 1 = relay globally disabled
	sessions     sync.Map
	activeConns  int64 // atomic: current WebSocket connections
	maxConns     int64 = 5000

	loginLimiter = newRateLimiter(5, time.Minute)
	wsLimiter    = newRateLimiter(20, time.Minute)
	joinLimiter  = newRateLimiter(10, time.Minute)
)

// --- Rate limiter ---

type rateLimiter struct {
	counts map[string][]time.Time
	max    int
	window time.Duration
	mu     sync.Mutex
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	return &rateLimiter{counts: make(map[string][]time.Time), max: max, window: window}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-rl.window)
	var valid []time.Time
	for _, t := range rl.counts[key] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if len(valid) >= rl.max {
		rl.counts[key] = valid
		return false
	}
	rl.counts[key] = append(valid, now)
	return true
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// clientIP extracts the real client IP. Does NOT trust X-Forwarded-For
// to prevent rate limiter bypass via header spoofing.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// --- Session auth with expiry ---

const sessionMaxAge = 24 * time.Hour

func createSession() string {
	token := generateToken(32)
	sessions.Store(token, time.Now())
	return token
}

func validSession(token string) bool {
	if token == "" {
		return false
	}
	v, ok := sessions.Load(token)
	if !ok {
		return false
	}
	if time.Since(v.(time.Time)) > sessionMaxAge {
		sessions.Delete(token)
		return false
	}
	return true
}

func getSessionToken(r *http.Request) string {
	if c, err := r.Cookie("stun_max_token"); err == nil {
		return c.Value
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validSession(getSessionToken(r)) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// --- Handlers ---

func serveWs(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !wsLimiter.allow(ip) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	if atomic.LoadInt64(&activeConns) >= maxConns {
		http.Error(w, "server full", http.StatusServiceUnavailable)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	atomic.AddInt64(&activeConns, 1)

	// Use client-provided ID if available (deterministic, MAC-based)
	// Otherwise generate a random one
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		clientID = generateID()
	}

	// If this client ID already exists, close the old connection (reconnect)
	hub.disconnectExisting(clientID)

	client := &Client{
		hub: hub, conn: conn, send: make(chan []byte, 4096),
		id: clientID, status: "connecting",
	}

	hub.register <- client

	welcomePayload, _ := json.Marshal(map[string]string{"id": clientID})
	welcome := Message{Type: "welcome", Payload: json.RawMessage(welcomePayload)}
	data, _ := json.Marshal(welcome)
	client.send <- data

	go client.writePump()
	go func() {
		client.readPump()
		atomic.AddInt64(&activeConns, -1)
	}()
}

func apiLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	if !loginLimiter.allow(ip) {
		http.Error(w, `{"error":"too many attempts"}`, http.StatusTooManyRequests)
		return
	}

	var req struct{ Password string `json:"password"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	if req.Password != authToken {
		log.Printf("Login failed from %s", ip)
		http.Error(w, `{"error":"invalid password"}`, http.StatusUnauthorized)
		return
	}

	token := createSession()
	http.SetCookie(w, &http.Cookie{
		Name: "stun_max_token", Value: token, Path: "/",
		HttpOnly: true, MaxAge: 86400, SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func apiRooms(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hub.getRoomsInfo())
	case http.MethodPost:
		var req struct {
			Name     string `json:"name"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" || len(req.Name) > 128 {
			http.Error(w, `{"error":"invalid room name"}`, http.StatusBadRequest)
			return
		}
		passHash := ""
		if req.Password != "" {
			h := sha256.Sum256([]byte(req.Password))
			passHash = hex.EncodeToString(h[:])
		}
		hub.getOrCreateRoom(req.Name, passHash, "", "") // dashboard-created = persistent
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"name": req.Name, "protected": req.Password != ""})
	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, `{"error":"room name required"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"deleted": hub.deleteRoom(name)})
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func apiAuthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func apiBan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Room     string `json:"room"`
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Room == "" || req.ClientID == "" {
		http.Error(w, `{"error":"room and client_id required"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": hub.banClient(req.Room, req.ClientID)})
}

func apiKick(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Room     string `json:"room"`
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Room == "" || req.ClientID == "" {
		http.Error(w, `{"error":"room and client_id required"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": hub.kickClient(req.Room, req.ClientID)})
}

func apiUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Room     string `json:"room"`
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Room == "" || req.ClientID == "" {
		http.Error(w, `{"error":"room and client_id required"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": hub.unbanClient(req.Room, req.ClientID)})
}

func apiStats(w http.ResponseWriter, r *http.Request) {
	stats := hub.getStats()
	stats.ActiveConns = atomic.LoadInt64(&activeConns)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func serveStatic(webDir string) http.HandlerFunc {
	fs := http.FileServer(http.Dir(webDir))
	return func(w http.ResponseWriter, r *http.Request) { fs.ServeHTTP(w, r) }
}

var stunStatsURL string

func apiStunProxy(w http.ResponseWriter, r *http.Request) {
	if stunStatsURL == "" {
		http.Error(w, `{"error":"stun stats not configured"}`, http.StatusServiceUnavailable)
		return
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(stunStatsURL + "/stats")
	if err != nil {
		http.Error(w, `{"error":"stun server unreachable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	buf := make([]byte, 64*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
}

func apiRelayToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// GET: return current state
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"global_relay_disabled": atomic.LoadInt32(&globalRelayOff) == 1,
		})
		return
	}
	var req struct {
		Room     string `json:"room"`     // empty = global toggle
		Disabled bool   `json:"disabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	if req.Room == "" {
		// Global toggle
		if req.Disabled {
			atomic.StoreInt32(&globalRelayOff, 1)
			log.Printf("Relay globally DISABLED")
		} else {
			atomic.StoreInt32(&globalRelayOff, 0)
			log.Printf("Relay globally ENABLED")
		}
	} else {
		// Per-room toggle
		hub.mu.RLock()
		for _, room := range hub.rooms {
			if room.Name == req.Room {
				room.mu.Lock()
				room.RelayDisabled = req.Disabled
				room.mu.Unlock()
				if req.Disabled {
					log.Printf("Relay DISABLED for room %s", req.Room)
				} else {
					log.Printf("Relay ENABLED for room %s", req.Room)
				}
				// Notify clients in the room
				notifyPayload, _ := json.Marshal(map[string]interface{}{
					"relay_disabled": req.Disabled,
				})
				notifyMsg := Message{Type: "room_config", Payload: json.RawMessage(notifyPayload)}
				data, _ := json.Marshal(notifyMsg)
				room.broadcast(data, "")
				break
			}
		}
		hub.mu.RUnlock()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func apiLockToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Room   string `json:"room"`
		Locked bool   `json:"locked"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Room == "" {
		http.Error(w, `{"error":"room required"}`, http.StatusBadRequest)
		return
	}
	hub.mu.RLock()
	for _, room := range hub.rooms {
		if room.Name == req.Room {
			room.mu.Lock()
			room.Locked = req.Locked
			room.mu.Unlock()
			if req.Locked {
				log.Printf("Room %s LOCKED", req.Room)
			} else {
				log.Printf("Room %s UNLOCKED", req.Room)
			}
			break
		}
	}
	hub.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func apiHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"uptime":  time.Since(serverStartTime).Round(time.Second).String(),
		"conns":   atomic.LoadInt64(&activeConns),
	})
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	webPass := flag.String("web-password", "", "dashboard password (empty=default)")
	webDir := flag.String("web-dir", "../web", "web static files")
	dbPath := flag.String("db", "stun_max.db", "SQLite database path")
	maxC := flag.Int64("max-connections", 5000, "max WebSocket connections")
	ipdbPath := flag.String("ipdb", "ip2region.xdb", "ip2region database file path")
	stunHTTP := flag.String("stun-http", "http://127.0.0.1:3479", "STUN server stats URL (stunserver --http addr)")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (enables HTTPS/WSS)")
	tlsKey := flag.String("tls-key", "", "TLS private key file")
	flag.Parse()

	stunStatsURL = *stunHTTP

	maxConns = *maxC

	// Initialize SQLite store
	var err error
	store, err = newStore(*dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer store.Close()

	hub = newHub(store)
	go hub.run()
	relayManager = newRelayManager()

	// Initialize offline IP geolocation database
	initIPDB(*ipdbPath)

	// Password: CLI flag > default
	if *webPass != "" {
		authToken = *webPass
	} else if defaultPassword != "" {
		authToken = defaultPassword
	} else {
		authToken = generateToken(16)
	}

	proto := "HTTP"
	if *tlsCert != "" && *tlsKey != "" {
		proto = "HTTPS"
	}

	fmt.Println("═══════════════════════════════════════")
	fmt.Println("  STUN Max Server")
	fmt.Println("═══════════════════════════════════════")
	fmt.Printf("  Listen:     %s (%s)\n", *addr, proto)
	fmt.Printf("  Database:   %s\n", *dbPath)
	fmt.Printf("  Max Conns:  %d\n", maxConns)
	fmt.Println("═══════════════════════════════════════")

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", serveWs)
	mux.HandleFunc("/health", apiHealth)
	mux.HandleFunc("/api/login", apiLogin)
	mux.HandleFunc("/api/rooms", requireAuth(apiRooms))
	mux.HandleFunc("/api/rooms/kick", requireAuth(apiKick))
	mux.HandleFunc("/api/relay", requireAuth(apiRelayToggle))
	mux.HandleFunc("/api/rooms/lock", requireAuth(apiLockToggle))
	mux.HandleFunc("/api/rooms/ban", requireAuth(apiBan))
	mux.HandleFunc("/api/rooms/unban", requireAuth(apiUnban))
	mux.HandleFunc("/api/auth", requireAuth(apiAuthCheck))
	mux.HandleFunc("/api/stats", requireAuth(apiStats))
	mux.HandleFunc("/api/stun", requireAuth(apiStunProxy))
	mux.HandleFunc("/", serveStatic(*webDir))

	server := &http.Server{
		Addr:    *addr,
		Handler: mux,
	}

	// Graceful shutdown
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Println("Shutting down gracefully...")
		hub.syncBytesToStore()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	log.Printf("Server starting on %s (%s)", *addr, proto)
	if *tlsCert != "" && *tlsKey != "" {
		if err := server.ListenAndServeTLS(*tlsCert, *tlsKey); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	} else {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}
	log.Println("Server stopped")
}
