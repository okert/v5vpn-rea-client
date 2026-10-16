package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

const (
	defaultSOCKSPort = 2080
	defaultHTTPPort  = 2081
)

// ProxyManager is a local SOCKS5 + HTTP proxy. It does not change the system
// gateway, routes, DNS, or system proxy settings. A connection is forwarded
// only when its destination falls inside a gateway-authorized resource.
type ProxyManager struct {
	GatewayIP   string
	GatewayPort int
	SessionID   string
	Listeners   map[string]net.Listener
	Resources   []protocol.VPNResource
	Rules       []routeRule
	SOCKSAddr   string
	HTTPAddr    string
	Logger      func(level string, format string, args ...any)
	mu          sync.Mutex
	closed      bool
}

type routeRule struct {
	name  string
	mapID string
	start uint32
	end   uint32
	ports [][2]int
}

// NewProxyManager creates a new proxy manager.
func NewProxyManager(gwIP string, gwPort int, sessionID string, logger func(string, string, ...any)) *ProxyManager {
	if logger == nil {
		logger = func(string, string, ...any) {}
	}
	return &ProxyManager{
		GatewayIP:   gwIP,
		GatewayPort: gwPort,
		SessionID:   sessionID,
		Listeners:   make(map[string]net.Listener),
		Logger:      logger,
	}
}

// StartProxies builds allow-rules from the gateway resource list and listens
// on 127.0.0.1 only. Wide ranges such as port "1-65535" stay as ranges; they
// are never expanded into one socket per port.
func (pm *ProxyManager) StartProxies(resources []protocol.TCPUDPResource) ([]protocol.VPNResource, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	rules := compileRules(resources)
	pm.Rules = rules

	socksLn, err := listenLocal(defaultSOCKSPort)
	if err != nil {
		return nil, fmt.Errorf("bind local SOCKS5 proxy: %w", err)
	}
	httpLn, err := listenLocal(defaultHTTPPort)
	if err != nil {
		_ = socksLn.Close()
		return nil, fmt.Errorf("bind local HTTP proxy: %w", err)
	}

	pm.Listeners["socks"] = socksLn
	pm.Listeners["http"] = httpLn
	pm.SOCKSAddr = socksLn.Addr().String()
	pm.HTTPAddr = httpLn.Addr().String()

	mapped := describeResources(resources, pm.SOCKSAddr, pm.HTTPAddr)
	pm.Resources = mapped
	pm.Logger("SUCCESS", "Local proxy only (system routes unchanged). SOCKS5 %s, HTTP %s, %d authorized targets",
		pm.SOCKSAddr, pm.HTTPAddr, len(rules))

	go pm.acceptSOCKS(socksLn)
	go pm.serveHTTP(httpLn)
	return mapped, nil
}

func listenLocal(prefer int) (net.Listener, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", prefer))
	if err == nil {
		return ln, nil
	}
	return net.Listen("tcp", "127.0.0.1:0")
}

func describeResources(resources []protocol.TCPUDPResource, socksAddr, httpAddr string) []protocol.VPNResource {
	var mapped []protocol.VPNResource
	for _, res := range resources {
		targets := resourceTargets(res)
		if len(targets) == 0 {
			targets = []string{"(no address)"}
		}
		for _, target := range targets {
			mapped = append(mapped, protocol.VPNResource{
				Name:       res.Name,
				Protocol:   "SOCKS5/HTTP",
				RemoteIP:   target,
				RemotePort: displayPorts(res.Port),
				LocalProxy: "socks5://" + socksAddr,
				Status:     "Listening",
				MapID:      res.MapID,
				AccessURL:  "http://" + httpAddr,
			})
		}
	}
	return mapped
}

func resourceTargets(res protocol.TCPUDPResource) []string {
	var targets []string
	for _, ipCfg := range res.IPConfigs {
		addr := strings.TrimSpace(ipCfg.Addr)
		if addr == "" {
			continue
		}
		targets = append(targets, addr)
	}
	return targets
}

func displayPorts(port string) string {
	port = strings.TrimSpace(port)
	if port == "" || port == "1-65535" {
		return "all"
	}
	return port
}

func compileRules(resources []protocol.TCPUDPResource) []routeRule {
	var rules []routeRule
	for _, res := range resources {
		ports := parsePorts(res.Port)
		for _, ipCfg := range res.IPConfigs {
			start, end, ok := parseIPv4Range(ipCfg.Addr)
			if !ok {
				continue
			}
			rules = append(rules, routeRule{
				name:  res.Name,
				mapID: res.MapID,
				start: start,
				end:   end,
				ports: ports,
			})
		}
	}
	return rules
}

func parsePorts(spec string) [][2]int {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return [][2]int{{1, 65535}}
	}
	var out [][2]int
	for _, part := range strings.FieldsFunc(spec, func(r rune) bool { return r == ';' || r == ',' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			start, err1 := strconv.Atoi(strings.TrimSpace(lo))
			end, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 == nil && err2 == nil && start > 0 && end >= start && end <= 65535 {
				out = append(out, [2]int{start, end})
			}
			continue
		}
		n, err := strconv.Atoi(part)
		if err == nil && n > 0 && n <= 65535 {
			out = append(out, [2]int{n, n})
		}
	}
	if len(out) == 0 {
		return [][2]int{{1, 65535}}
	}
	return out
}

func parseIPv4Range(addr string) (uint32, uint32, bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return 0, 0, false
	}
	if strings.Contains(addr, "/") {
		ip, network, err := net.ParseCIDR(addr)
		if err != nil || ip.To4() == nil {
			return 0, 0, false
		}
		ones, bits := network.Mask.Size()
		if bits != 32 {
			return 0, 0, false
		}
		base := ipv4Num(network.IP.To4())
		size := uint32(1) << uint(32-ones)
		if ones == 32 {
			size = 1
		}
		return base, base + size - 1, true
	}
	left := addr
	right := addr
	if a, b, ok := strings.Cut(addr, "-"); ok {
		left, right = strings.TrimSpace(a), strings.TrimSpace(b)
	}
	start := net.ParseIP(left).To4()
	end := net.ParseIP(right).To4()
	if start == nil || end == nil {
		return 0, 0, false
	}
	s, e := ipv4Num(start), ipv4Num(end)
	if e < s {
		s, e = e, s
	}
	return s, e, true
}

func ipv4Num(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func portAllowed(port int, ranges [][2]int) bool {
	for _, r := range ranges {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}

// lookup returns the gateway MapID and the IPv4 to CONNECT for an authorized target.
func (pm *ProxyManager) lookup(host string, port int) (string, string, bool) {
	host = strings.TrimSpace(host)
	if host == "" || port <= 0 || port > 65535 {
		return "", "", false
	}
	candidates := []net.IP{}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			candidates = append(candidates, ip4)
		}
	} else {
		ips, err := net.LookupIP(host)
		if err != nil {
			return "", "", false
		}
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				candidates = append(candidates, ip4)
			}
		}
	}

	pm.mu.Lock()
	rules := pm.Rules
	pm.mu.Unlock()

	var best *routeRule
	var bestIP net.IP
	bestSpan := uint64(^uint32(0)) + 1
	for _, ip := range candidates {
		n := ipv4Num(ip)
		for i := range rules {
			rule := &rules[i]
			if n < rule.start || n > rule.end || !portAllowed(port, rule.ports) {
				continue
			}
			span := uint64(rule.end - rule.start)
			if span < bestSpan {
				best = rule
				bestIP = ip
				bestSpan = span
			}
		}
	}
	if best == nil {
		return "", "", false
	}
	return bestIP.String(), best.mapID, true
}

func (pm *ProxyManager) acceptSOCKS(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			pm.mu.Lock()
			isClosed := pm.closed
			pm.mu.Unlock()
			if isClosed {
				return
			}
			pm.Logger("WARN", "SOCKS accept error: %v", err)
			return
		}
		go pm.serveSOCKS(conn)
	}
}

func (pm *ProxyManager) serveSOCKS(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 512)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 5 {
		return
	}
	nmethods := int(buf[1])
	if nmethods == 0 || nmethods > 255 {
		return
	}
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[0] != 5 || buf[1] != 1 {
		_, _ = conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch buf[3] {
	case 1:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 3:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		n := int(buf[0])
		if n == 0 || n > 255 {
			return
		}
		if _, err := io.ReadFull(conn, buf[:n]); err != nil {
			return
		}
		host = string(buf[:n])
	case 4:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		return
	}
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(buf[:2]))

	ip, mapID, ok := pm.lookup(host, port)
	if !ok {
		pm.Logger("WARN", "SOCKS rejected %s:%d (not in authorized resources)", host, port)
		_, _ = conn.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	remote, err := pm.dialTunnel(ip, port, mapID)
	if err != nil {
		pm.Logger("ERROR", "SOCKS tunnel %s:%d failed: %v", ip, port, err)
		_, _ = conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	pipe(conn, remote)
}

func (pm *ProxyManager) serveHTTP(ln net.Listener) {
	srv := &http.Server{Handler: http.HandlerFunc(pm.handleHTTP)}
	_ = srv.Serve(ln)
}

func (pm *ProxyManager) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host, portStr, err := splitHostPortDefault(r.Host, r.URL)
	if err != nil {
		http.Error(w, "bad request target", http.StatusBadRequest)
		return
	}
	port, _ := strconv.Atoi(portStr)
	ip, mapID, ok := pm.lookup(host, port)
	if !ok {
		pm.Logger("WARN", "HTTP proxy rejected %s:%d (not in authorized resources)", host, port)
		http.Error(w, "destination is not an authorized VPN resource", http.StatusForbidden)
		return
	}
	remote, err := pm.dialTunnel(ip, port, mapID)
	if err != nil {
		pm.Logger("ERROR", "HTTP tunnel %s:%d failed: %v", ip, port, err)
		http.Error(w, "vpn tunnel failed", http.StatusBadGateway)
		return
	}
	defer remote.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	if r.Method == http.MethodConnect {
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		pipe(client, remote)
		return
	}

	r.RequestURI = ""
	r.URL.Scheme = ""
	r.URL.Host = ""
	r.Header.Del("Proxy-Connection")
	if err := r.Write(remote); err != nil {
		return
	}
	pipe(rw, remote)
}

func splitHostPortDefault(hostHeader string, u *url.URL) (string, string, error) {
	target := hostHeader
	if u != nil && u.Host != "" {
		target = u.Host
	}
	if target == "" {
		return "", "", fmt.Errorf("empty host")
	}
	if h, p, err := net.SplitHostPort(target); err == nil {
		return h, p, nil
	}
	def := "80"
	if u != nil && u.Scheme == "https" {
		def = "443"
	}
	return target, def, nil
}

func (pm *ProxyManager) dialTunnel(targetIP string, targetPort int, mapID string) (net.Conn, error) {
	gwAddr := fmt.Sprintf("%s:%d", pm.GatewayIP, pm.GatewayPort)
	remoteConn, err := tls.Dial("tcp", gwAddr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return nil, err
	}

	cookie := fmt.Sprintf("Cookie: VSG_SESSIONID=%s\r\n", pm.SessionID)
	if mapID != "" {
		cookie = fmt.Sprintf("Cookie: MapID=%s; VSG_SESSIONID=%s\r\n", mapID, pm.SessionID)
	}
	connectReq := fmt.Sprintf("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n%sUser-Agent: LeadSec VPN Client\r\n\r\n",
		targetIP, targetPort, targetIP, targetPort, cookie)
	if _, err := remoteConn.Write([]byte(connectReq)); err != nil {
		_ = remoteConn.Close()
		return nil, err
	}
	reader := bufio.NewReader(remoteConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		_ = remoteConn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = remoteConn.Close()
		return nil, fmt.Errorf("gateway rejected CONNECT: %s", resp.Status)
	}
	pm.Logger("SUCCESS", "Tunnel established to %s:%d", targetIP, targetPort)
	return &bufferedConn{Conn: remoteConn, r: reader}, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func pipe(a io.ReadWriter, b io.ReadWriter) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		closeWrite(a)
	}()
	wg.Wait()
}

func closeWrite(c io.ReadWriter) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// Stop closes all active proxy listeners.
func (pm *ProxyManager) Stop() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.closed = true
	for key, ln := range pm.Listeners {
		pm.Logger("INFO", "Closing proxy listener for %s", key)
		_ = ln.Close()
	}
	pm.Listeners = make(map[string]net.Listener)
}
