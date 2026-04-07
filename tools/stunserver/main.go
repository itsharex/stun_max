package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	magicCookie    uint32 = 0x2112A442
	bindingRequest uint16 = 0x0001
	bindingSuccess uint16 = 0x0101
	attrXorMapped  uint16 = 0x0020
	attrMapped     uint16 = 0x0001
	attrSoftware   uint16 = 0x8022
	headerSize            = 20
)

var softwareValue = []byte("stun-max")

// Stats tracking
var (
	totalRequests  int64
	totalErrors    int64
	startTime      = time.Now()
	recentClients  = &clientTracker{clients: make(map[string]*clientInfo)}
)

type clientInfo struct {
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	PublicAddr string   `json:"public_addr"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Requests  int64     `json:"requests"`
}

type clientTracker struct {
	clients map[string]*clientInfo
	mu      sync.RWMutex
}

func (ct *clientTracker) record(addr *net.UDPAddr) {
	key := addr.IP.String()
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if c, ok := ct.clients[key]; ok {
		c.LastSeen = time.Now()
		c.Requests++
		c.Port = addr.Port
		c.PublicAddr = addr.String()
	} else {
		ct.clients[key] = &clientInfo{
			IP:        addr.IP.String(),
			Port:      addr.Port,
			PublicAddr: addr.String(),
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Requests:  1,
		}
	}
}

func (ct *clientTracker) cleanup(maxAge time.Duration) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for key, c := range ct.clients {
		if c.LastSeen.Before(cutoff) {
			delete(ct.clients, key)
		}
	}
}

func (ct *clientTracker) snapshot() []clientInfo {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	result := make([]clientInfo, 0, len(ct.clients))
	for _, c := range ct.clients {
		result = append(result, *c)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].LastSeen.After(result[j].LastSeen)
	})
	return result
}

type StunStats struct {
	Uptime        string       `json:"uptime"`
	TotalRequests int64        `json:"total_requests"`
	TotalErrors   int64        `json:"total_errors"`
	UniqueClients int          `json:"unique_clients"`
	RecentClients []clientInfo `json:"recent_clients"`
	ListenAddr    string       `json:"listen_addr"`
}

func main() {
	addr := flag.String("addr", ":3478", "STUN listen address (UDP)")
	httpAddr := flag.String("http", ":3479", "HTTP stats API address")
	flag.Parse()

	pc, err := net.ListenPacket("udp", *addr)
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}
	defer pc.Close()

	fmt.Println("═══════════════════════════════════════")
	fmt.Println("  STUN Max - STUN Server")
	fmt.Println("═══════════════════════════════════════")
	fmt.Printf("  STUN UDP:   %s\n", *addr)
	fmt.Printf("  Stats HTTP: %s\n", *httpAddr)
	fmt.Println("═══════════════════════════════════════")

	// Periodic cleanup of old clients (keep 1 hour)
	go func() {
		for range time.Tick(5 * time.Minute) {
			recentClients.cleanup(1 * time.Hour)
		}
	}()

	// HTTP stats API
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			clients := recentClients.snapshot()
			stats := StunStats{
				Uptime:        time.Since(startTime).Round(time.Second).String(),
				TotalRequests: atomic.LoadInt64(&totalRequests),
				TotalErrors:   atomic.LoadInt64(&totalErrors),
				UniqueClients: len(clients),
				RecentClients: clients,
				ListenAddr:    *addr,
			}
			json.NewEncoder(w).Encode(stats)
		})
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "ok",
				"uptime": time.Since(startTime).Round(time.Second).String(),
				"requests": atomic.LoadInt64(&totalRequests),
			})
		})
		log.Printf("Stats HTTP starting on %s", *httpAddr)
		http.ListenAndServe(*httpAddr, mux)
	}()

	buf := make([]byte, 1500)
	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			atomic.AddInt64(&totalErrors, 1)
			continue
		}
		if n < headerSize {
			continue
		}

		msgType := binary.BigEndian.Uint16(buf[0:2])
		if msgType != bindingRequest {
			continue
		}

		atomic.AddInt64(&totalRequests, 1)

		udpAddr := raddr.(*net.UDPAddr)
		recentClients.record(udpAddr)

		txID := make([]byte, 12)
		copy(txID, buf[8:20])

		resp := buildBindingResponse(txID, udpAddr)

		if _, err := pc.WriteTo(resp, raddr); err != nil {
			log.Printf("Write error to %s: %v", raddr, err)
			atomic.AddInt64(&totalErrors, 1)
		}
	}
}

func buildBindingResponse(txID []byte, addr *net.UDPAddr) []byte {
	ip4 := addr.IP.To4()
	if ip4 == nil {
		return nil
	}

	xorMapped := make([]byte, 12)
	binary.BigEndian.PutUint16(xorMapped[0:2], attrXorMapped)
	binary.BigEndian.PutUint16(xorMapped[2:4], 8)
	xorMapped[4] = 0x00
	xorMapped[5] = 0x01
	binary.BigEndian.PutUint16(xorMapped[6:8], uint16(addr.Port)^uint16(magicCookie>>16))
	ipInt := binary.BigEndian.Uint32(ip4)
	binary.BigEndian.PutUint32(xorMapped[8:12], ipInt^magicCookie)

	mapped := make([]byte, 12)
	binary.BigEndian.PutUint16(mapped[0:2], attrMapped)
	binary.BigEndian.PutUint16(mapped[2:4], 8)
	mapped[4] = 0x00
	mapped[5] = 0x01
	binary.BigEndian.PutUint16(mapped[6:8], uint16(addr.Port))
	binary.BigEndian.PutUint32(mapped[8:12], ipInt)

	swPad := len(softwareValue)
	if swPad%4 != 0 {
		swPad += 4 - (swPad % 4)
	}
	software := make([]byte, 4+swPad)
	binary.BigEndian.PutUint16(software[0:2], attrSoftware)
	binary.BigEndian.PutUint16(software[2:4], uint16(len(softwareValue)))
	copy(software[4:], softwareValue)

	attrsLen := len(xorMapped) + len(mapped) + len(software)

	resp := make([]byte, headerSize+attrsLen)
	binary.BigEndian.PutUint16(resp[0:2], bindingSuccess)
	binary.BigEndian.PutUint16(resp[2:4], uint16(attrsLen))
	binary.BigEndian.PutUint32(resp[4:8], magicCookie)
	copy(resp[8:20], txID)

	offset := headerSize
	copy(resp[offset:], xorMapped)
	offset += len(xorMapped)
	copy(resp[offset:], mapped)
	offset += len(mapped)
	copy(resp[offset:], software)

	return resp
}
