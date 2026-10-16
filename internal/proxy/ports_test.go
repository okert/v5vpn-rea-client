package proxy

import (
	"net"
	"testing"

	"github.com/hygkui/v5vpn-rea-client/internal/protocol"
)

func TestParsePortsRange(t *testing.T) {
	got := parsePorts("1-65535")
	if len(got) != 1 || got[0] != [2]int{1, 65535} {
		t.Fatalf("range: %#v", got)
	}
	got = parsePorts("443;8080")
	if len(got) != 2 || got[0] != [2]int{443, 443} || got[1] != [2]int{8080, 8080} {
		t.Fatalf("list: %#v", got)
	}
}

func TestParseIPv4Range(t *testing.T) {
	start, end, ok := parseIPv4Range("10.1.2.3-10.1.2.9")
	if !ok || start != ipv4Num(net.ParseIP("10.1.2.3")) || end != ipv4Num(net.ParseIP("10.1.2.9")) {
		t.Fatalf("range parse %v %v %v", start, end, ok)
	}
	start, end, ok = parseIPv4Range("10.1.2.3/32")
	if !ok || start != end {
		t.Fatalf("cidr /32 %v %v %v", start, end, ok)
	}
}

func TestLookupMostSpecific(t *testing.T) {
	pm := NewProxyManager("127.0.0.1", 1, "sid", nil)
	pm.Rules = []routeRule{
		{name: "wide", mapID: "wide", start: ipv4Num(net.ParseIP("10.0.0.0")), end: ipv4Num(net.ParseIP("10.255.255.255")), ports: parsePorts("1-65535")},
		{name: "host", mapID: "host", start: ipv4Num(net.ParseIP("10.1.2.3")), end: ipv4Num(net.ParseIP("10.1.2.3")), ports: parsePorts("443")},
	}
	ip, id, ok := pm.lookup("10.1.2.3", 443)
	if !ok || ip != "10.1.2.3" || id != "host" {
		t.Fatalf("specific match: %s %s %v", ip, id, ok)
	}
	ip, id, ok = pm.lookup("10.1.2.3", 80)
	if !ok || id != "wide" {
		t.Fatalf("wide port match: %s %s %v", ip, id, ok)
	}
	ip, id, ok = pm.lookup("10.9.9.9", 22)
	if !ok || id != "wide" || ip != "10.9.9.9" {
		t.Fatalf("wide match: %s %s %v", ip, id, ok)
	}
	if _, _, ok = pm.lookup("1.2.3.4", 443); ok {
		t.Fatal("unauthorized address matched")
	}
}

func TestCompileWidePortResource(t *testing.T) {
	rules := compileRules([]protocol.TCPUDPResource{{
		Name:      "host",
		MapID:     "abc",
		Port:      "1-65535",
		IPConfigs: []protocol.TCPUDPIp{{Addr: "10.1.2.3-10.1.2.3"}},
	}})
	if len(rules) != 1 || rules[0].mapID != "abc" || rules[0].ports[0] != [2]int{1, 65535} {
		t.Fatalf("%#v", rules)
	}
}
