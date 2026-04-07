package main

import (
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

// IPInfo holds geolocation and ASN data for an IP address.
type IPInfo struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
	ISP     string `json:"isp"`
	Org     string `json:"org,omitempty"`
	Summary string `json:"summary"` // e.g. "四川省成都市 电信"
}

// ip2region searcher (thread-safe when using content buffer mode)
var (
	ipSearcher   *xdb.Searcher
	ipSearcherMu sync.RWMutex
	ipCache      = &ipInfoCache{m: make(map[string]*IPInfo)}
)

type ipInfoCache struct {
	m  map[string]*IPInfo
	mu sync.RWMutex
}

func (c *ipInfoCache) get(ip string) (*IPInfo, bool) {
	c.mu.RLock()
	info, ok := c.m[ip]
	c.mu.RUnlock()
	return info, ok
}

func (c *ipInfoCache) set(ip string, info *IPInfo) {
	c.mu.Lock()
	c.m[ip] = info
	c.mu.Unlock()
}

// initIPDB initializes the ip2region offline database.
// Looks for ip2region.xdb in the current directory, then common paths.
func initIPDB(dbPath string) {
	searchPaths := []string{
		dbPath,
		"ip2region.xdb",
		"/opt/stun_max/ip2region.xdb",
		"/usr/local/share/ip2region.xdb",
	}

	var data []byte
	var usedPath string
	for _, p := range searchPaths {
		if p == "" {
			continue
		}
		d, err := os.ReadFile(p)
		if err == nil {
			data = d
			usedPath = p
			break
		}
	}

	if data == nil {
		log.Println("IP database not found — IP geolocation disabled")
		log.Println("  Download: https://github.com/lionsoul2014/ip2region/raw/master/data/ip2region_v4.xdb")
		log.Println("  Place at: /opt/stun_max/ip2region.xdb")
		return
	}

	searcher, err := xdb.NewWithBuffer(xdb.IPv4, data)
	if err != nil {
		log.Printf("IP database load failed: %v", err)
		return
	}

	ipSearcherMu.Lock()
	ipSearcher = searcher
	ipSearcherMu.Unlock()

	log.Printf("IP database loaded: %s (%.1f MB)", usedPath, float64(len(data))/1024/1024)
}

// lookupIP queries the offline ip2region database.
// ip2region returns format: "国家|区域|省份|城市|ISP"
// e.g. "中国|0|四川省|成都市|电信"
func lookupIP(ip string) *IPInfo {
	// Check cache
	if info, ok := ipCache.get(ip); ok {
		return info
	}

	// Skip private/loopback
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
		info := &IPInfo{IP: ip, Country: "Private", Summary: "内网地址"}
		ipCache.set(ip, info)
		return info
	}

	ipSearcherMu.RLock()
	searcher := ipSearcher
	ipSearcherMu.RUnlock()

	if searcher == nil {
		return nil
	}

	result, err := searcher.Search(ip)
	if err != nil {
		return nil
	}

	info := parseIP2Region(ip, result)
	ipCache.set(ip, info)
	return info
}

// parseIP2Region parses ip2region result string: "国家|区域|省份|城市|ISP"
func parseIP2Region(ip, result string) *IPInfo {
	parts := strings.Split(result, "|")
	for len(parts) < 5 {
		parts = append(parts, "")
	}

	// Clean "0" values (ip2region uses "0" for empty)
	for i := range parts {
		if parts[i] == "0" {
			parts[i] = ""
		}
	}

	country := parts[0]
	region := parts[2] // 省份
	city := parts[3]
	isp := parts[4]

	// Build summary
	var summaryParts []string
	if region != "" {
		summaryParts = append(summaryParts, region)
	}
	if city != "" && city != region {
		summaryParts = append(summaryParts, city)
	}
	if isp != "" {
		summaryParts = append(summaryParts, isp)
	}
	summary := strings.Join(summaryParts, " ")
	if summary == "" {
		summary = country
	}

	return &IPInfo{
		IP:      ip,
		Country: country,
		Region:  region,
		City:    city,
		ISP:     isp,
		Summary: summary,
	}
}

// lookupEndpoint extracts IP from "ip:port" and looks it up.
func lookupEndpoint(endpoint string) *IPInfo {
	if endpoint == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
	}
	return lookupIP(host)
}
