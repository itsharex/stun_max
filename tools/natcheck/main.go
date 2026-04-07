package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// ════════════════════════════════════════════════════════════════
// STUN 协议常量 (RFC 5389 / RFC 5780)
// ════════════════════════════════════════════════════════════════

const (
	stunMagicCookie    uint32 = 0x2112A442
	stunBindingRequest uint16 = 0x0001
	stunBindingResponse uint16 = 0x0101
	stunAttrMapped     uint16 = 0x0001 // MAPPED-ADDRESS
	stunAttrChangeReq  uint16 = 0x0003 // CHANGE-REQUEST (RFC 5780)
	stunAttrChangedAddr uint16 = 0x0005 // CHANGED-ADDRESS (RFC 3489 legacy)
	stunAttrXorMapped  uint16 = 0x0020 // XOR-MAPPED-ADDRESS
	stunAttrRespOrigin uint16 = 0x802B // RESPONSE-ORIGIN (RFC 5780)
	stunAttrOtherAddr  uint16 = 0x802C // OTHER-ADDRESS (RFC 5780)
	stunHeaderSize            = 20
	stunTimeout               = 3 * time.Second
)

// CHANGE-REQUEST 标志位
const (
	changeIP   uint32 = 0x04 // bit 29
	changePort uint32 = 0x02 // bit 30
)

// ANSI 颜色
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
// NAT 类型定义
// ════════════════════════════════════════════════════════════════

// 映射行为 (Mapping Behavior)
const (
	MapEndpointIndep = "端点无关映射"       // EIM: 同一源→任意目标，外部端口不变
	MapAddrDep       = "地址相关映射"       // ADM: 不同目标IP→不同外部端口
	MapAddrPortDep   = "地址+端口相关映射"   // APDM: 不同目标IP:Port→不同外部端口 (Symmetric)
)

// 过滤行为 (Filtering Behavior)
const (
	FilterEndpointIndep = "端点无关过滤" // EIF: 任意外部主机可发包进来
	FilterAddrDep       = "地址相关过滤" // ADF: 只有已联系过的IP可发包
	FilterAddrPortDep   = "地址+端口相关过滤" // APDF: 只有已联系过的IP:Port可发包
	FilterUnknown       = "未知(需要RFC5780服务器)"
)

// 经典 NAT 类型
const (
	NATOpen            = "开放网络 (NAT0)"
	NATFullCone        = "完全锥形 (NAT1)"
	NATRestrictedCone  = "受限锥形 (NAT2)"
	NATPortRestricted  = "端口受限锥形 (NAT3)"
	NATSymmetric       = "对称型 (NAT4)"
	NATSymFirewall     = "对称型防火墙"
	NATBlocked         = "UDP 被阻断"
)

// ════════════════════════════════════════════════════════════════
// 数据结构
// ════════════════════════════════════════════════════════════════

type STUNResult struct {
	Server     string
	PublicAddr string
	PublicIP   string
	PublicPort int
	Latency    time.Duration
	OtherAddr  string // OTHER-ADDRESS from RFC 5780 server
	Error      error
}

type PortAllocInfo struct {
	Pattern string // "保持端口", "顺序分配", "随机分配"
	Delta   int
	Ports   []int
}

type NATReport struct {
	LocalIP         string
	PhysicalIF      string
	PublicIP        string
	PublicPort      int
	Results         []STUNResult
	MappingBehavior string
	FilterBehavior  string
	NATType         string
	NATTypeShort    string // NAT0-NAT4
	PortConsistent  bool
	IPConsistent    bool
	HairpinOK       bool
	BindingLifetime time.Duration
	PortAlloc       PortAllocInfo
	Score           int
	Difficulty      string
	HolePunchProb   string
	RFC5780         bool // 是否使用了 RFC 5780 完整检测
}

// RFC 5780 服务器列表 (支持 OTHER-ADDRESS + CHANGE-REQUEST)
var rfc5780Servers = []string{
	"stunserver2024.stunprotocol.org:3478",
	"stun.voipgate.com:3478",
	"stun.sipgate.net:3478",
}

// 标准 STUN 服务器 (仅支持基本 Binding)
var standardServers = []string{
	"stun.cloudflare.com:3478",
	"stun.miwifi.com:3478",
	"stun.chat.bilibili.com:3478",
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun2.l.google.com:19302",
}

func main() {
	verbose := flag.Bool("v", false, "详细输出")
	fast := flag.Bool("fast", false, "跳过绑定生命周期测试 (更快)")
	flag.Parse()

	printBanner()

	report := runDiagnostics(*verbose, *fast)
	printReport(report)
}

// ════════════════════════════════════════════════════════════════
// 代理绕过 — 检测物理网卡
// ════════════════════════════════════════════════════════════════

func detectPhysicalIP() (net.IP, string) {
	skipPrefixes := []string{
		"utun", "tun", "tap", "lo", "docker", "br-", "veth",
		"virbr", "vboxnet", "vmnet", "wg", "tailscale", "ts",
		"clash", "meta", "wintun",
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, ""
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagPointToPoint != 0 {
			continue
		}

		nameLower := strings.ToLower(iface.Name)
		skip := false
		for _, p := range skipPrefixes {
			if strings.HasPrefix(nameLower, p) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

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
			// 跳过 198.18.0.0/15 (Clash/V2Ray TUN常用)
			if ip[0] == 198 && (ip[1] == 18 || ip[1] == 19) {
				continue
			}
			if iface.Flags&net.FlagBroadcast != 0 {
				return ip, iface.Name
			}
		}
	}
	return nil, ""
}

func listenBypass() (*net.UDPConn, net.IP, string) {
	physIP, ifName := detectPhysicalIP()
	var laddr *net.UDPAddr
	if physIP != nil {
		laddr = &net.UDPAddr{IP: physIP, Port: 0}
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil && physIP != nil {
		// 绑定失败，回退到默认
		conn, err = net.ListenUDP("udp4", nil)
		physIP = nil
		ifName = ""
	}
	if err != nil {
		return nil, physIP, ifName
	}
	return conn, physIP, ifName
}

// ════════════════════════════════════════════════════════════════
// STUN 协议实现
// ════════════════════════════════════════════════════════════════

func buildRequest(attrs ...[]byte) ([]byte, []byte) {
	// 计算属性总长度
	attrLen := 0
	for _, a := range attrs {
		attrLen += len(a)
	}

	req := make([]byte, stunHeaderSize+attrLen)
	binary.BigEndian.PutUint16(req[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(req[2:4], uint16(attrLen))
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	txID := make([]byte, 12)
	rand.Read(txID)
	copy(req[8:20], txID)

	// 追加属性
	offset := stunHeaderSize
	for _, a := range attrs {
		copy(req[offset:], a)
		offset += len(a)
	}
	return req, txID
}

func makeChangeRequest(flags uint32) []byte {
	attr := make([]byte, 8)
	binary.BigEndian.PutUint16(attr[0:2], stunAttrChangeReq)
	binary.BigEndian.PutUint16(attr[2:4], 4)
	binary.BigEndian.PutUint32(attr[4:8], flags)
	return attr
}

type stunResponse struct {
	MappedAddr string
	MappedIP   string
	MappedPort int
	OtherAddr  string // OTHER-ADDRESS
	OtherIP    string
	OtherPort  int
	RespOrigin string // RESPONSE-ORIGIN
	SourceAddr *net.UDPAddr // actual source address of response
}

func sendSTUN(conn *net.UDPConn, serverAddr *net.UDPAddr, req []byte, txID []byte) (*stunResponse, error) {
	conn.SetWriteDeadline(time.Now().Add(stunTimeout))
	if _, err := conn.WriteToUDP(req, serverAddr); err != nil {
		return nil, fmt.Errorf("发送: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(stunTimeout))
	buf := make([]byte, 1024)
	n, from, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("接收: %w", err)
	}

	if n < stunHeaderSize {
		return nil, fmt.Errorf("响应太短: %d 字节", n)
	}

	resp := buf[:n]
	msgType := binary.BigEndian.Uint16(resp[0:2])
	if msgType != stunBindingResponse {
		return nil, fmt.Errorf("非 Binding Response: 0x%04x", msgType)
	}
	if !bytes.Equal(resp[8:20], txID) {
		return nil, fmt.Errorf("事务ID不匹配")
	}

	msgLen := int(binary.BigEndian.Uint16(resp[2:4]))
	if stunHeaderSize+msgLen > n {
		return nil, fmt.Errorf("响应截断")
	}

	attrs := resp[stunHeaderSize : stunHeaderSize+msgLen]
	result := &stunResponse{SourceAddr: from}

	// 解析所有属性
	offset := 0
	for offset+4 <= len(attrs) {
		attrType := binary.BigEndian.Uint16(attrs[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(attrs[offset+2 : offset+4]))
		offset += 4
		if offset+attrLen > len(attrs) {
			break
		}

		switch attrType {
		case stunAttrXorMapped:
			ip, port := decodeAddr(attrs[offset:offset+attrLen], true)
			result.MappedIP = ip
			result.MappedPort = port
			result.MappedAddr = fmt.Sprintf("%s:%d", ip, port)
		case stunAttrMapped:
			if result.MappedAddr == "" { // XOR-MAPPED 优先
				ip, port := decodeAddr(attrs[offset:offset+attrLen], false)
				result.MappedIP = ip
				result.MappedPort = port
				result.MappedAddr = fmt.Sprintf("%s:%d", ip, port)
			}
		case stunAttrOtherAddr:
			ip, port := decodeAddr(attrs[offset:offset+attrLen], false)
			result.OtherIP = ip
			result.OtherPort = port
			result.OtherAddr = fmt.Sprintf("%s:%d", ip, port)
		case stunAttrChangedAddr:
			if result.OtherAddr == "" { // OTHER-ADDRESS 优先
				ip, port := decodeAddr(attrs[offset:offset+attrLen], false)
				result.OtherIP = ip
				result.OtherPort = port
				result.OtherAddr = fmt.Sprintf("%s:%d", ip, port)
			}
		case stunAttrRespOrigin:
			ip, port := decodeAddr(attrs[offset:offset+attrLen], false)
			result.RespOrigin = fmt.Sprintf("%s:%d", ip, port)
		}

		offset += attrLen
		if attrLen%4 != 0 {
			offset += 4 - (attrLen % 4)
		}
	}

	return result, nil
}

func decodeAddr(data []byte, xor bool) (string, int) {
	if len(data) < 8 {
		return "", 0
	}
	family := data[1]
	if family != 0x01 {
		return "", 0 // 仅支持 IPv4
	}
	rawPort := binary.BigEndian.Uint16(data[2:4])
	rawIP := binary.BigEndian.Uint32(data[4:8])

	var port uint16
	var ip uint32
	if xor {
		port = rawPort ^ uint16(stunMagicCookie>>16)
		ip = rawIP ^ stunMagicCookie
	} else {
		port = rawPort
		ip = rawIP
	}
	ipStr := fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
	return ipStr, int(port)
}

func querySTUN(conn *net.UDPConn, server string) (*stunResponse, time.Duration, error) {
	serverAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return nil, 0, err
	}
	req, txID := buildRequest()
	start := time.Now()
	resp, err := sendSTUN(conn, serverAddr, req, txID)
	latency := time.Since(start)
	return resp, latency, err
}

// ════════════════════════════════════════════════════════════════
// 诊断测试
// ════════════════════════════════════════════════════════════════

func runDiagnostics(verbose, fast bool) NATReport {
	report := NATReport{}

	// 检测物理网卡 (绕过代理)
	physIP, ifName := detectPhysicalIP()
	if physIP != nil {
		report.PhysicalIF = ifName
		fmt.Printf("  %s●%s 代理绕过: %s已启用%s — 绑定到 %s (%s)\n", cyan, reset, green, reset, physIP, ifName)
	} else {
		fmt.Printf("  %s●%s 代理绕过: %s未检测到物理网卡%s (使用系统默认路由)\n", cyan, reset, yellow, reset)
	}

	report.LocalIP = getLocalIP(physIP)
	fmt.Printf("  %s●%s 本机 IP:   %s%s%s\n", cyan, reset, bold, report.LocalIP, reset)
	fmt.Println()

	// ─── 测试 1: RFC 5780 完整检测 ─────────────────
	printSection(1, "RFC 5780 NAT 行为发现")

	rfc5780OK := false
	for _, srv := range rfc5780Servers {
		conn, _, _ := listenBypass()
		if conn == nil {
			continue
		}
		ok := tryRFC5780(conn, srv, &report, verbose)
		conn.Close()
		if ok {
			rfc5780OK = true
			break
		}
	}

	if !rfc5780OK {
		fmt.Printf("    %s⚠ 无可用 RFC 5780 服务器，使用多服务器探测替代%s\n\n", yellow, reset)
	}

	// ─── 测试 2: 多服务器映射行为检测 ──────────────
	printSection(2, "映射行为检测 (多服务器同 Socket)")

	conn, _, _ := listenBypass()
	if conn == nil {
		fmt.Printf("    %s✗ 无法创建 UDP 套接字%s\n", red, reset)
		report.NATType = NATBlocked
		report.NATTypeShort = "阻断"
		report.Score = 0
		return report
	}

	localPort := conn.LocalAddr().(*net.UDPAddr).Port
	fmt.Printf("    本机 UDP 端口: %s%d%s\n\n", bold, localPort, reset)

	// 从同一 socket 查询所有标准服务器
	var okResults []STUNResult
	seenIPs := map[string]bool{}
	for _, srv := range standardServers {
		resp, latency, err := querySTUN(conn, srv)
		r := STUNResult{Server: srv, Latency: latency, Error: err}
		if err == nil && resp != nil {
			r.PublicAddr = resp.MappedAddr
			r.PublicIP = resp.MappedIP
			r.PublicPort = resp.MappedPort
			if resp.OtherAddr != "" {
				r.OtherAddr = resp.OtherAddr
			}

			// 去重同 IP 服务器
			resolved, _ := net.ResolveUDPAddr("udp4", srv)
			ipKey := ""
			if resolved != nil {
				ipKey = resolved.IP.String()
			}
			if !seenIPs[ipKey] {
				seenIPs[ipKey] = true
				okResults = append(okResults, r)
			}

			latColor := green
			if latency > 200*time.Millisecond {
				latColor = yellow
			}
			fmt.Printf("    %s✓%s %-40s → %s%-21s%s  %s%s%s\n",
				green, reset, srv, bold, r.PublicAddr, reset, latColor, latency.Round(time.Millisecond), reset)
		} else if verbose {
			fmt.Printf("    %s✗%s %-40s %s%v%s\n", red, reset, srv, gray, err, reset)
		}
		report.Results = append(report.Results, r)
	}
	conn.Close()

	if len(okResults) == 0 {
		fmt.Printf("\n    %s✗ 所有 STUN 服务器均不可达 — UDP 可能被阻断%s\n", red, reset)
		report.NATType = NATBlocked
		report.NATTypeShort = "阻断"
		report.Score = 0
		return report
	}

	report.PublicIP = okResults[0].PublicIP
	report.PublicPort = okResults[0].PublicPort

	// 检查映射一致性
	ips := map[string]bool{}
	ports := map[int]bool{}
	for _, r := range okResults {
		ips[r.PublicIP] = true
		ports[r.PublicPort] = true
	}
	report.IPConsistent = len(ips) == 1
	report.PortConsistent = len(ports) == 1

	fmt.Printf("\n    同 Socket 映射分析:\n")
	if report.PortConsistent && report.IPConsistent {
		fmt.Printf("      %s✓%s 端口映射: %s端点无关%s (所有服务器返回相同端口)\n", green, reset, green, reset)
		if report.MappingBehavior == "" {
			report.MappingBehavior = MapEndpointIndep
		}
	} else if report.IPConsistent && !report.PortConsistent {
		fmt.Printf("      %s✗%s 端口映射: %s端点相关%s (不同目标返回不同端口)\n", red, reset, red, reset)
		uniquePorts := []int{}
		for p := range ports {
			uniquePorts = append(uniquePorts, p)
		}
		sort.Ints(uniquePorts)
		fmt.Printf("        %s观察到的端口: %v%s\n", gray, uniquePorts, reset)
		if report.MappingBehavior == "" {
			report.MappingBehavior = MapAddrPortDep
		}
	} else {
		fmt.Printf("      %s✗%s IP 映射: %s多出口%s (不同服务器返回不同IP)\n", yellow, reset, yellow, reset)
	}

	// ─── 测试 3: 端口分配模式 ─────────────────────
	printSection(3, "端口分配模式")
	report.PortAlloc = analyzePortAllocation(standardServers[0])

	switch report.PortAlloc.Pattern {
	case "保持端口":
		fmt.Printf("    %s●%s 分配模式: %s%s保持端口%s — NAT 保留原始本地端口号\n", cyan, reset, bold, green, reset)
	case "顺序分配":
		fmt.Printf("    %s●%s 分配模式: %s%s顺序分配%s (增量 ≈ %d) — 端口可预测\n", cyan, reset, bold, yellow, reset, report.PortAlloc.Delta)
	case "随机分配":
		fmt.Printf("    %s●%s 分配模式: %s%s随机分配%s — 端口不可预测\n", cyan, reset, bold, red, reset)
	default:
		fmt.Printf("    %s●%s 分配模式: %s无法确定%s\n", cyan, reset, gray, reset)
	}

	// ─── 测试 4: Hairpin NAT ─────────────────────
	printSection(4, "Hairpin NAT 回环测试")
	report.HairpinOK = testHairpin(okResults[0].PublicAddr)
	if report.HairpinOK {
		fmt.Printf("    %s✓%s Hairpin: %s支持%s — 可通过公网地址回环\n", green, reset, green, reset)
	} else {
		fmt.Printf("    %s─%s Hairpin: %s不支持%s (大多数 NAT 如此, 不影响打洞)\n", gray, reset, gray, reset)
	}

	// ─── 测试 5: 绑定生命周期 ────────────────────
	if !fast {
		printSection(5, "NAT 绑定生命周期")
		fmt.Printf("    %s等待 10 秒...%s", gray, reset)
		report.BindingLifetime = testBindingLifetime(standardServers[0])
		fmt.Print("\r                         \r")
		if report.BindingLifetime > 0 {
			fmt.Printf("    %s✓%s 绑定存活: %s>%s%s — 映射至少持续 %s\n", green, reset, green, report.BindingLifetime, reset, report.BindingLifetime)
		} else {
			fmt.Printf("    %s!%s 绑定存活: %s未知%s — 映射可能在 10 秒内过期\n", yellow, reset, yellow, reset)
		}
	}

	// 最终分类
	classifyNAT(&report)
	report.Score, report.Difficulty, report.HolePunchProb = scoreHolePunch(report)

	return report
}

// ════════════════════════════════════════════════════════════════
// RFC 5780 完整测试 (需要双 IP STUN 服务器)
// ════════════════════════════════════════════════════════════════

func tryRFC5780(conn *net.UDPConn, server string, report *NATReport, verbose bool) bool {
	fmt.Printf("    尝试 RFC 5780 服务器: %s%s%s\n", bold, server, reset)

	serverAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		fmt.Printf("      %s✗ 解析失败: %v%s\n", red, err, reset)
		return false
	}

	// Test I: 普通 Binding Request
	req1, txID1 := buildRequest()
	resp1, err := sendSTUN(conn, serverAddr, req1, txID1)
	if err != nil {
		fmt.Printf("      %s✗ Test I 失败: %v%s\n", red, err, reset)
		return false
	}

	if resp1.OtherAddr == "" {
		fmt.Printf("      %s⚠ 服务器不支持 OTHER-ADDRESS (非 RFC 5780)%s\n", yellow, reset)
		return false
	}

	fmt.Printf("      Test I:  映射地址 = %s%s%s\n", cyan, resp1.MappedAddr, reset)
	fmt.Printf("               OTHER-ADDRESS = %s%s%s\n", cyan, resp1.OtherAddr, reset)

	report.RFC5780 = true

	// === 映射行为测试 (§4.3) ===
	fmt.Printf("\n    %s映射行为测试 (Mapping Behavior):%s\n", bold, reset)

	// Test II: 发送到 OTHER-ADDRESS 的 IP, 但使用主端口
	altAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", resp1.OtherIP, serverAddr.Port))
	if err == nil {
		req2, txID2 := buildRequest()
		resp2, err := sendSTUN(conn, altAddr, req2, txID2)
		if err != nil {
			fmt.Printf("      Test II: %s超时 (目标: %s)%s\n", yellow, altAddr, reset)
		} else {
			fmt.Printf("      Test II: 映射地址 = %s%s%s (目标: %s)\n", cyan, resp2.MappedAddr, reset, altAddr)
			if resp2.MappedAddr == resp1.MappedAddr {
				report.MappingBehavior = MapEndpointIndep
				fmt.Printf("      结果:    %s%s端点无关映射 ✓%s\n", bold, green, reset)
			} else {
				// Test III: 发送到 OTHER-ADDRESS 的 IP:Port
				altAddr2, _ := net.ResolveUDPAddr("udp4", resp1.OtherAddr)
				req3, txID3 := buildRequest()
				resp3, err := sendSTUN(conn, altAddr2, req3, txID3)
				if err != nil {
					report.MappingBehavior = MapAddrPortDep
					fmt.Printf("      Test III: %s超时%s\n", yellow, reset)
					fmt.Printf("      结果:    %s%s地址+端口相关映射 (Symmetric)%s\n", bold, red, reset)
				} else {
					fmt.Printf("      Test III: 映射地址 = %s%s%s\n", cyan, resp3.MappedAddr, reset)
					if resp3.MappedAddr == resp2.MappedAddr {
						report.MappingBehavior = MapAddrDep
						fmt.Printf("      结果:    %s%s地址相关映射%s\n", bold, yellow, reset)
					} else {
						report.MappingBehavior = MapAddrPortDep
						fmt.Printf("      结果:    %s%s地址+端口相关映射 (Symmetric)%s\n", bold, red, reset)
					}
				}
			}
		}
	}

	// === 过滤行为测试 (§4.4) ===
	fmt.Printf("\n    %s过滤行为测试 (Filtering Behavior):%s\n", bold, reset)

	// Test II: CHANGE-REQUEST = change-IP + change-port
	reqF2, txIDF2 := buildRequest(makeChangeRequest(changeIP | changePort))
	_, errF2 := sendSTUN(conn, serverAddr, reqF2, txIDF2)
	if errF2 == nil {
		report.FilterBehavior = FilterEndpointIndep
		fmt.Printf("      Test II: %s%s收到响应 → 端点无关过滤 (Full Cone)%s\n", bold, green, reset)
	} else {
		fmt.Printf("      Test II: %s超时 (change-IP+port)%s\n", gray, reset)

		// Test III: CHANGE-REQUEST = change-port only
		reqF3, txIDF3 := buildRequest(makeChangeRequest(changePort))
		_, errF3 := sendSTUN(conn, serverAddr, reqF3, txIDF3)
		if errF3 == nil {
			report.FilterBehavior = FilterAddrDep
			fmt.Printf("      Test III: %s%s收到响应 → 地址相关过滤 (Restricted Cone)%s\n", bold, yellow, reset)
		} else {
			report.FilterBehavior = FilterAddrPortDep
			fmt.Printf("      Test III: %s超时 → %s地址+端口相关过滤 (Port Restricted)%s\n", gray, yellow, reset)
		}
	}

	return true
}

// ════════════════════════════════════════════════════════════════
// 端口分配分析
// ════════════════════════════════════════════════════════════════

func analyzePortAllocation(server string) PortAllocInfo {
	info := PortAllocInfo{}

	sampleCount := 5
	fmt.Printf("    采样 %d 个独立 Socket...\n\n", sampleCount)

	var localPorts []int
	for i := 0; i < sampleCount; i++ {
		conn, _, _ := listenBypass()
		if conn == nil {
			continue
		}
		resp, _, err := querySTUN(conn, server)
		lp := conn.LocalAddr().(*net.UDPAddr).Port
		conn.Close()
		if err == nil && resp != nil {
			info.Ports = append(info.Ports, resp.MappedPort)
			localPorts = append(localPorts, lp)
			fmt.Printf("      Socket %d: 本地 :%s%-5d%s → 公网 :%s%-5d%s", i+1, dim, lp, reset, bold, resp.MappedPort, reset)
			if i > 0 && len(info.Ports) >= 2 {
				delta := info.Ports[len(info.Ports)-1] - info.Ports[len(info.Ports)-2]
				fmt.Printf("  %s(Δ %+d)%s", gray, delta, reset)
			}
			fmt.Println()
		}
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Println()

	if len(info.Ports) < 3 {
		info.Pattern = "未知"
		return info
	}

	// 检查是否保持端口
	allSame := true
	for i := range info.Ports {
		if i < len(localPorts) && info.Ports[i] != localPorts[i] {
			allSame = false
			break
		}
	}
	if allSame {
		info.Pattern = "保持端口"
		return info
	}

	// 检查是否顺序分配
	sort.Ints(info.Ports)
	deltas := make([]int, 0, len(info.Ports)-1)
	for i := 1; i < len(info.Ports); i++ {
		deltas = append(deltas, info.Ports[i]-info.Ports[i-1])
	}

	avg := 0
	for _, d := range deltas {
		avg += d
	}
	avg /= len(deltas)

	maxDev := 0
	for _, d := range deltas {
		dev := d - avg
		if dev < 0 {
			dev = -dev
		}
		if dev > maxDev {
			maxDev = dev
		}
	}

	if avg >= 1 && avg <= 10 && maxDev <= 3 {
		info.Pattern = "顺序分配"
		info.Delta = avg
	} else {
		info.Pattern = "随机分配"
	}
	return info
}

// ════════════════════════════════════════════════════════════════
// Hairpin & 绑定生命周期
// ════════════════════════════════════════════════════════════════

func testHairpin(publicAddr string) bool {
	conn, _, _ := listenBypass()
	if conn == nil {
		return false
	}
	defer conn.Close()

	addr, err := net.ResolveUDPAddr("udp4", publicAddr)
	if err != nil {
		return false
	}

	token := make([]byte, 8)
	rand.Read(token)
	msg := append([]byte("HAIRPIN:"), token...)
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.WriteToUDP(msg, addr)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return false
	}
	return bytes.Contains(buf[:n], token)
}

func testBindingLifetime(server string) time.Duration {
	conn, _, _ := listenBypass()
	if conn == nil {
		return 0
	}
	defer conn.Close()

	resp1, _, err := querySTUN(conn, server)
	if err != nil || resp1 == nil {
		return 0
	}
	time.Sleep(10 * time.Second)
	resp2, _, err := querySTUN(conn, server)
	if err != nil || resp2 == nil {
		return 0
	}
	if resp1.MappedAddr == resp2.MappedAddr {
		return 10 * time.Second
	}
	return 0
}

// ════════════════════════════════════════════════════════════════
// NAT 分类
// ════════════════════════════════════════════════════════════════

func classifyNAT(report *NATReport) {
	// 检查是否在公网
	if report.LocalIP == report.PublicIP {
		if report.PortConsistent {
			report.NATType = NATOpen
			report.NATTypeShort = "NAT0"
		} else {
			report.NATType = NATSymFirewall
			report.NATTypeShort = "NAT4"
		}
		report.MappingBehavior = MapEndpointIndep
		if report.FilterBehavior == "" {
			report.FilterBehavior = FilterEndpointIndep
		}
		return
	}

	// 基于映射行为判断
	switch report.MappingBehavior {
	case MapEndpointIndep:
		// Cone NAT — 具体类型取决于过滤行为
		switch report.FilterBehavior {
		case FilterEndpointIndep:
			report.NATType = NATFullCone
			report.NATTypeShort = "NAT1"
		case FilterAddrDep:
			report.NATType = NATRestrictedCone
			report.NATTypeShort = "NAT2"
		case FilterAddrPortDep:
			report.NATType = NATPortRestricted
			report.NATTypeShort = "NAT3"
		default:
			// 无 RFC 5780 数据，保守估计
			if report.PortAlloc.Pattern == "保持端口" {
				report.NATType = NATFullCone
				report.NATTypeShort = "NAT1"
			} else {
				report.NATType = NATPortRestricted
				report.NATTypeShort = "NAT3"
			}
			report.FilterBehavior = FilterUnknown
		}
	case MapAddrDep, MapAddrPortDep:
		report.NATType = NATSymmetric
		report.NATTypeShort = "NAT4"
		if report.FilterBehavior == "" {
			report.FilterBehavior = FilterAddrPortDep
		}
	default:
		// 从端口一致性推断
		if report.PortConsistent {
			report.NATType = NATPortRestricted
			report.NATTypeShort = "NAT3"
			report.MappingBehavior = MapEndpointIndep
			report.FilterBehavior = FilterUnknown
		} else {
			report.NATType = NATSymmetric
			report.NATTypeShort = "NAT4"
			report.MappingBehavior = MapAddrPortDep
			report.FilterBehavior = FilterAddrPortDep
		}
	}
}

// ════════════════════════════════════════════════════════════════
// 打洞评分
// ════════════════════════════════════════════════════════════════

func scoreHolePunch(r NATReport) (int, string, string) {
	score := 0

	switch r.NATTypeShort {
	case "NAT0":
		score = 100
	case "NAT1":
		score = 95
	case "NAT2":
		score = 85
	case "NAT3":
		score = 65
	case "NAT4":
		score = 25
	default:
		score = 0
	}

	if r.NATTypeShort == "NAT4" {
		switch r.PortAlloc.Pattern {
		case "保持端口":
			score += 25
		case "顺序分配":
			score += 20
		}
	}

	if r.BindingLifetime > 0 {
		score += 5
	}
	if r.HairpinOK {
		score += 2
	}

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	var diff, prob string
	switch {
	case score >= 90:
		diff = "简单"
		prob = "极高"
	case score >= 75:
		diff = "简单"
		prob = "高"
	case score >= 60:
		diff = "中等"
		prob = "中等"
	case score >= 40:
		diff = "困难"
		prob = "中等"
	case score >= 20:
		diff = "很困难"
		prob = "低"
	case score > 0:
		diff = "极其困难"
		prob = "极低"
	default:
		diff = "不可能"
		prob = "无"
	}

	return score, diff, prob
}

// ════════════════════════════════════════════════════════════════
// 报告输出
// ════════════════════════════════════════════════════════════════

func printBanner() {
	fmt.Println()
	fmt.Printf("  %s%s╔════════════════════════════════════════════════════╗%s\n", bold, cyan, reset)
	fmt.Printf("  %s%s║%s  %s%s⚡ STUN Max — NAT 全类型诊断工具%s                 %s%s║%s\n", bold, cyan, reset, bold, white, reset, bold, cyan, reset)
	fmt.Printf("  %s%s║%s     RFC 5780 行为发现 + 代理绕过 + 打洞评估      %s%s║%s\n", bold, cyan, reset, bold, cyan, reset)
	fmt.Printf("  %s%s╚════════════════════════════════════════════════════╝%s\n", bold, cyan, reset)
	fmt.Println()
}

func printSection(num int, title string) {
	fmt.Printf("\n  %s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", dim, cyan, reset)
	fmt.Printf("  %s%s  测试 %d: %s%s\n", bold, cyan, num, title, reset)
	fmt.Printf("  %s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n\n", dim, cyan, reset)
}

func progressBar(value, max, width int) string {
	if max == 0 {
		return strings.Repeat("░", width)
	}
	filled := value * width / max
	if filled > width {
		filled = width
	}
	bar := ""
	for i := 0; i < width; i++ {
		if i < filled {
			c := red
			if value >= 80 {
				c = green
			} else if value >= 50 {
				c = yellow
			}
			bar += c + "█" + reset
		} else {
			bar += gray + "░" + reset
		}
	}
	return bar
}

func difficultyStars(d string) string {
	switch d {
	case "简单":
		return green + "★☆☆☆☆" + reset
	case "中等":
		return yellow + "★★☆☆☆" + reset
	case "困难":
		return yellow + "★★★☆☆" + reset
	case "很困难":
		return red + "★★★★☆" + reset
	case "极其困难":
		return red + "★★★★★" + reset
	case "不可能":
		return red + "★★★★★" + reset
	}
	return "☆☆☆☆☆"
}

func printReport(r NATReport) {
	fmt.Printf("\n\n  %s%s╔════════════════════════════════════════════════════╗%s\n", bold, cyan, reset)
	fmt.Printf("  %s%s║%s  %s%sNAT 诊断报告%s                                     %s%s║%s\n", bold, cyan, reset, bold, white, reset, bold, cyan, reset)
	fmt.Printf("  %s%s╚════════════════════════════════════════════════════╝%s\n\n", bold, cyan, reset)

	// ─── 网络信息 ────────────────────────────────
	fmt.Printf("  %s%s  网络信息%s\n", bold, white, reset)
	fmt.Printf("  %s────────────────────────────────────────────────────%s\n", gray, reset)
	fmt.Printf("    %-20s %s\n", "本机 IP:", r.LocalIP)
	if r.PhysicalIF != "" {
		fmt.Printf("    %-20s %s\n", "物理网卡:", r.PhysicalIF)
	}
	seen := map[string]bool{}
	for _, res := range r.Results {
		if res.Error == nil && !seen[res.PublicAddr] {
			seen[res.PublicAddr] = true
			fmt.Printf("    %-20s %s%s%s\n", "公网地址:", bold, res.PublicAddr, reset)
		}
	}
	fmt.Println()

	// ─── NAT 分类 ────────────────────────────────
	fmt.Printf("  %s%s  NAT 分类%s\n", bold, white, reset)
	fmt.Printf("  %s────────────────────────────────────────────────────%s\n", gray, reset)

	natColor := green
	switch r.NATTypeShort {
	case "NAT3":
		natColor = yellow
	case "NAT4", "阻断":
		natColor = red
	}

	fmt.Printf("    %-20s %s%s%s %s(%s)%s\n", "NAT 类型:", bold+natColor, r.NATType, reset, gray, r.NATTypeShort, reset)
	fmt.Printf("    %-20s %s\n", "映射行为:", r.MappingBehavior)
	fmt.Printf("    %-20s %s\n", "过滤行为:", r.FilterBehavior)
	if r.RFC5780 {
		fmt.Printf("    %-20s %s✓ RFC 5780 完整检测%s\n", "检测方法:", green, reset)
	} else {
		fmt.Printf("    %-20s %s多服务器映射探测 (过滤行为为推断)%s\n", "检测方法:", yellow, reset)
	}
	fmt.Printf("    %-20s %s\n", "端口分配:", portAllocStr(r.PortAlloc))

	mark := func(ok bool, y, n string) string {
		if ok {
			return green + "✓ " + y + reset
		}
		return gray + "─ " + n + reset
	}
	fmt.Printf("    %-20s %s\n", "Hairpin NAT:", mark(r.HairpinOK, "支持", "不支持"))
	if r.BindingLifetime > 0 {
		fmt.Printf("    %-20s %s✓ >%s%s\n", "绑定生命周期:", green, r.BindingLifetime, reset)
	}
	fmt.Println()

	// ─── 打洞评估 ────────────────────────────────
	fmt.Printf("  %s%s  P2P 打洞评估%s\n", bold, white, reset)
	fmt.Printf("  %s────────────────────────────────────────────────────%s\n", gray, reset)

	sColor := green
	if r.Score < 50 {
		sColor = red
	} else if r.Score < 75 {
		sColor = yellow
	}

	fmt.Printf("    综合评分:     %s %s%s%d/100%s\n", progressBar(r.Score, 100, 25), bold, sColor, r.Score, reset)
	fmt.Printf("    打洞难度:     %s  %s%s%s\n", difficultyStars(r.Difficulty), bold, r.Difficulty, reset)
	fmt.Printf("    成功概率:     %s%s%s\n", bold, r.HolePunchProb, reset)
	fmt.Println()

	// ─── 兼容矩阵 ────────────────────────────────
	fmt.Printf("  %s%s  与各类 NAT 对端的打洞兼容性%s\n", bold, white, reset)
	fmt.Printf("  %s────────────────────────────────────────────────────%s\n", gray, reset)
	printCompatibility(r)
	fmt.Println()

	// ─── 打洞策略 ────────────────────────────────
	fmt.Printf("  %s%s  STUN Max 打洞策略%s\n", bold, white, reset)
	fmt.Printf("  %s────────────────────────────────────────────────────%s\n", gray, reset)
	printStrategy(r)
	fmt.Println()

	// ─── 延迟统计 ────────────────────────────────
	printLatency(r)

	// ─── 建议 ────────────────────────────────────
	fmt.Printf("  %s%s  建议%s\n", bold, white, reset)
	fmt.Printf("  %s────────────────────────────────────────────────────%s\n", gray, reset)
	printAdvice(r)

	// ─── NAT 类型说明 ────────────────────────────
	fmt.Printf("  %s%s  NAT 类型速查表%s\n", bold, white, reset)
	fmt.Printf("  %s────────────────────────────────────────────────────%s\n", gray, reset)
	printNATTable(r.NATTypeShort)
	fmt.Println()
}

func portAllocStr(p PortAllocInfo) string {
	switch p.Pattern {
	case "保持端口":
		return green + "保持端口" + reset
	case "顺序分配":
		return yellow + fmt.Sprintf("顺序分配 (Δ=%d)", p.Delta) + reset
	case "随机分配":
		return red + "随机分配" + reset
	}
	return gray + "未知" + reset
}

func printCompatibility(r NATReport) {
	type row struct {
		peer, result, note string
		color              string
	}

	var matrix []row
	switch r.NATTypeShort {
	case "NAT0", "NAT1":
		matrix = []row{
			{"NAT1 完全锥形", "✓ 直连", "立即建立", green},
			{"NAT2 受限锥形", "✓ 直连", "初次联系后", green},
			{"NAT3 端口受限", "✓ 直连", "双方互发", green},
			{"NAT4 对称型 (顺序)", "✓ 直连", "端口预测", green},
			{"NAT4 对称型 (随机)", "✓ 直连", "Birthday 攻击", green},
		}
	case "NAT2":
		matrix = []row{
			{"NAT1 完全锥形", "✓ 直连", "立即建立", green},
			{"NAT2 受限锥形", "✓ 直连", "双方互发", green},
			{"NAT3 端口受限", "✓ 直连", "双方互发", green},
			{"NAT4 对称型 (顺序)", "~ 可能", "Birthday + 预测", yellow},
			{"NAT4 对称型 (随机)", "✗ 中继", "概率太低", red},
		}
	case "NAT3":
		matrix = []row{
			{"NAT1 完全锥形", "✓ 直连", "立即建立", green},
			{"NAT2 受限锥形", "✓ 直连", "双方互发", green},
			{"NAT3 端口受限", "✓ 直连", "双方互发", green},
			{"NAT4 对称型 (顺序)", "~ 可能", "Birthday 256 sockets ≈98%", yellow},
			{"NAT4 对称型 (随机)", "~ 可能", "Birthday 256 sockets ≈98%", yellow},
		}
	case "NAT4":
		if r.PortAlloc.Pattern == "顺序分配" {
			matrix = []row{
				{"NAT1 完全锥形", "✓ 直连", "对端接受任意来源", green},
				{"NAT2 受限锥形", "~ 可能", "端口预测", yellow},
				{"NAT3 端口受限", "~ 可能", "Birthday 256 sockets ≈98%", yellow},
				{"NAT4 对称型", "✗ 中继", "双方端口均不可预测", red},
			}
		} else {
			matrix = []row{
				{"NAT1 完全锥形", "✓ 直连", "对端接受任意来源", green},
				{"NAT2 受限锥形", "~ 可能", "Birthday 攻击", yellow},
				{"NAT3 端口受限", "~ 可能", "Birthday 256 sockets ≈98%", yellow},
				{"NAT4 对称型", "✗ 中继", "碰撞概率 ≈0.01%", red},
			}
		}
	default:
		matrix = []row{
			{"任何类型", "✗ 阻断", "UDP 不可用", red},
		}
	}

	fmt.Printf("    %-28s %-10s %s\n", "对端 NAT 类型", "结果", "说明")
	fmt.Printf("    %s─────────────────────────────────────────────────%s\n", gray, reset)
	for _, m := range matrix {
		fmt.Printf("    %-28s %s%-10s%s %s%s%s\n", m.peer, m.color, m.result, reset, gray, m.note, reset)
	}
}

func printStrategy(r NATReport) {
	type strat struct {
		name, desc string
		active     bool
	}

	isNAT4 := r.NATTypeShort == "NAT4"
	isNAT3 := r.NATTypeShort == "NAT3"

	strategies := []strat{
		{"Phase 1: 快速脉冲", "主 Socket 发送 20-40 个 PUNCH 包", r.NATTypeShort != "阻断"},
		{"Phase 2: Birthday 攻击", "256 个并行 Socket 各发 4 包", isNAT3 || isNAT4},
		{"Phase 3: 端口预测", fmt.Sprintf("扫描目标端口 ±%d 范围", func() int {
			if isNAT4 {
				return 50
			}
			return 20
		}()), isNAT4},
		{"Phase 4: 随机端口扫射", "Cone 端扫射 1024 个随机端口", isNAT3 && !isNAT4},
		{"回退: 服务器中继", "打洞失败后自动使用加密中继", true},
	}

	for _, s := range strategies {
		if s.active {
			fmt.Printf("    %s●%s %-24s %s%s%s\n", green, reset, s.name, gray, s.desc, reset)
		} else {
			fmt.Printf("    %s○%s %-24s %s%s (不需要)%s\n", gray, reset, s.name, gray, s.desc, reset)
		}
	}
}

func printLatency(r NATReport) {
	var latencies []time.Duration
	for _, res := range r.Results {
		if res.Error == nil {
			latencies = append(latencies, res.Latency)
		}
	}
	if len(latencies) == 0 {
		return
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	minL := latencies[0]
	maxL := latencies[len(latencies)-1]
	var sum time.Duration
	for _, l := range latencies {
		sum += l
	}
	avgL := sum / time.Duration(len(latencies))

	var variance float64
	for _, l := range latencies {
		d := float64(l.Nanoseconds()) - float64(avgL.Nanoseconds())
		variance += d * d
	}
	jitter := time.Duration(math.Sqrt(variance/float64(len(latencies)))) * time.Nanosecond

	fmt.Printf("  %s%s  STUN 延迟%s\n", bold, white, reset)
	fmt.Printf("  %s────────────────────────────────────────────────────%s\n", gray, reset)
	fmt.Printf("    最小: %s%-8s%s  平均: %s%-8s%s  最大: %s%-8s%s  抖动: %s%s%s\n",
		green, minL.Round(time.Millisecond), reset,
		cyan, avgL.Round(time.Millisecond), reset,
		func() string {
			if maxL > 300*time.Millisecond {
				return red
			}
			if maxL > 100*time.Millisecond {
				return yellow
			}
			return green
		}(), maxL.Round(time.Millisecond), reset,
		func() string {
			if jitter > 50*time.Millisecond {
				return red
			}
			if jitter > 20*time.Millisecond {
				return yellow
			}
			return green
		}(), jitter.Round(time.Millisecond), reset)
	fmt.Println()
}

func printAdvice(r NATReport) {
	switch {
	case r.Score >= 85:
		fmt.Printf("    %s✓ 你的网络非常适合 P2P 直连。%s\n", green, reset)
		fmt.Printf("    %s  与大多数对端的首次打洞即可成功。%s\n", green, reset)
	case r.Score >= 60:
		fmt.Printf("    %s~ 你的网络支持大部分 P2P 场景。%s\n", yellow, reset)
		fmt.Printf("    %s  与 Cone NAT 对端可直连，对称型对端可能需要中继。%s\n", yellow, reset)
	case r.Score >= 35:
		fmt.Printf("    %s! P2P 打洞有一定挑战。%s\n", yellow, reset)
		fmt.Printf("    %s  STUN Max 使用 Birthday 攻击 + 端口预测最大化成功率。%s\n", yellow, reset)
		fmt.Printf("    %s  与 NAT3 对端打洞成功率约 98%%（256 sockets Birthday 攻击）。%s\n", gray, reset)
	case r.Score > 0:
		fmt.Printf("    %s✗ P2P 打洞较为困难。%s\n", red, reset)
		fmt.Printf("    %s  大多数连接将使用服务器中继 (加密, 但延迟更高)。%s\n", red, reset)
		fmt.Printf("\n    %s改善建议:%s\n", bold, reset)
		fmt.Printf("    %s  • 尝试更换网络 (手机热点, 不同 WiFi)%s\n", gray, reset)
		fmt.Printf("    %s  • 检查路由器是否支持 UPnP 或 NAT-PMP%s\n", gray, reset)
		fmt.Printf("    %s  • 在路由器上设置端口转发%s\n", gray, reset)
	default:
		fmt.Printf("    %s✗ UDP 被阻断 — 无法进行 P2P 连接。%s\n", red, reset)
		fmt.Printf("    %s  所有数据将通过服务器中继 (TCP WebSocket)。%s\n", red, reset)
		fmt.Printf("    %s  • 检查防火墙/安全软件是否阻断 UDP%s\n", gray, reset)
		fmt.Printf("    %s  • 企业网络通常阻断 UDP — 请尝试其他网络%s\n", gray, reset)
	}
	fmt.Println()
}

func printNATTable(current string) {
	type natRow struct {
		short, name, mapping, filtering, p2p string
	}
	table := []natRow{
		{"NAT0", "开放网络", "无 NAT", "无过滤", "所有对端可直连"},
		{"NAT1", "完全锥形", "端点无关", "端点无关", "所有对端可直连"},
		{"NAT2", "受限锥形", "端点无关", "地址相关", "多数对端可直连"},
		{"NAT3", "端口受限", "端点无关", "地址+端口相关", "Cone对端可直连, NAT4需Birthday"},
		{"NAT4", "对称型", "地址+端口相关", "地址+端口相关", "仅Cone对端可直连, NAT4需中继"},
	}

	fmt.Printf("    %-6s %-12s %-14s %-18s %s\n", "类型", "名称", "映射行为", "过滤行为", "P2P 能力")
	fmt.Printf("    %s──────────────────────────────────────────────────────────────────────────%s\n", gray, reset)
	for _, t := range table {
		marker := " "
		style := gray
		if t.short == current {
			marker = green + "►" + reset
			style = bold
		}
		fmt.Printf("   %s %s%-6s %-12s %-14s %-18s %s%s\n",
			marker, style, t.short, t.name, t.mapping, t.filtering, t.p2p, reset)
	}
}

// ════════════════════════════════════════════════════════════════
// 工具函数
// ════════════════════════════════════════════════════════════════

func getLocalIP(physIP net.IP) string {
	if physIP != nil {
		return physIP.String()
	}
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return "未知"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func init() {
	_ = os.Stdout // ensure clean exit
}
