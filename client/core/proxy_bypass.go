package core

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// physicalIP caches the detected physical interface IP for socket binding.
var physicalIP net.IP

// initProxyBypass detects the real physical network interface and caches its IP.
// This allows bypassing TUN-mode proxies (Clash, V2Ray, etc.) by binding
// all sockets to the physical interface instead of the proxy's virtual interface.
func initProxyBypass() {
	ip := detectPhysicalIP()
	if ip != nil {
		physicalIP = ip
	}
}

// detectPhysicalIP finds the IP of the real physical network interface,
// skipping virtual/TUN interfaces created by proxy software.
func detectPhysicalIP() net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	// TUN/virtual/cellular interface name patterns to skip
	skipPrefixes := []string{
		"utun", "tun", "tap",          // macOS/Linux TUN
		"lo",                           // loopback
		"docker", "br-", "veth",       // Docker
		"virbr", "vboxnet", "vmnet",   // VM
		"wg",                          // WireGuard
		"tailscale", "ts",             // Tailscale
		"clash", "meta",               // Clash
		"wintun",                      // Windows WinTUN (V2Ray/Clash)
		"rmnet", "ccmni", "dummy",     // Android cellular/dummy
	}

	type candidate struct {
		ip     net.IP
		name   string
		flags  net.Flags
		isWifi bool
	}

	var candidates []candidate

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagPointToPoint != 0 {
			continue
		}

		nameLower := strings.ToLower(iface.Name)
		skip := false
		for _, prefix := range skipPrefixes {
			if strings.HasPrefix(nameLower, prefix) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		isWifi := strings.HasPrefix(nameLower, "wlan") || strings.HasPrefix(nameLower, "en0")

		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			// Skip CGNAT range (198.18.0.0/15) — proxy TUN
			if ip[0] == 198 && (ip[1] == 18 || ip[1] == 19) {
				continue
			}
			if ip[0] == 10 && len(iface.HardwareAddr) == 0 {
				continue
			}

			candidates = append(candidates, candidate{
				ip: ip, name: iface.Name, flags: iface.Flags, isWifi: isWifi,
			})
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	// Priority: WiFi > physical NIC with broadcast > any
	for _, c := range candidates {
		if c.isWifi {
			return c.ip
		}
	}
	for _, c := range candidates {
		if c.flags&net.FlagBroadcast != 0 {
			return c.ip
		}
	}
	return candidates[0].ip
}

// bypassDialer returns a net.Dialer that binds to the physical interface,
// bypassing any TUN-mode proxy.
func bypassDialer(timeout time.Duration) *net.Dialer {
	d := &net.Dialer{
		Timeout: timeout,
	}
	if physicalIP != nil {
		d.LocalAddr = &net.TCPAddr{IP: physicalIP}
	}
	return d
}

// bypassListenUDP creates a UDP socket bound to the physical interface.
func bypassListenUDP() (*net.UDPConn, error) {
	var laddr *net.UDPAddr
	if physicalIP != nil {
		laddr = &net.UDPAddr{IP: physicalIP, Port: 0}
	}
	return net.ListenUDP("udp4", laddr)
}

// BypassIP returns the detected physical interface IP, or empty string if none.
func BypassIP() string {
	if physicalIP != nil {
		return physicalIP.String()
	}
	return ""
}

// getLocalIP returns the local IP by checking which IP the system would use
// to reach a public address. Uses physical interface if available.
func getLocalIP() string {
	if physicalIP != nil {
		return physicalIP.String()
	}
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// formatBypassInfo returns a human-readable string about bypass status.
func formatBypassInfo() string {
	if physicalIP == nil {
		return "proxy bypass: disabled (no physical interface detected)"
	}
	return fmt.Sprintf("proxy bypass: enabled (bound to %s)", physicalIP)
}
