//go:build linux

package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// These tests build a miniature of the real network out of Linux namespaces and check what the firewall really
// does to packets. They need root, ip, nft and python3, and skip otherwise.
//
//	D1 10.77.0.3 ─┐
//	D2 10.77.0.4 ─┼─ hub bridge ─ gamebond0 [S server] eth0 ─ T upstream (1.1.1.1, 2.2.2.2)
//	C  10.77.0.2 ─┘
//
// The devices have /32 addresses and reach each other only through the server, as with the real TUN.

const nsPrefix = "gbfw"

type topo struct {
	t *testing.T
}

func sh(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func in(t *testing.T, ns string, args ...string) string {
	t.Helper()
	return sh(t, append([]string{"ip", "netns", "exec", nsPrefix + ns}, args...)...)
}

func needTools(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	for _, tool := range []string{"ip", "nft", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " is not installed")
		}
	}
	if err := exec.Command("ip", "netns", "add", nsPrefix+"probe").Run(); err != nil {
		t.Skip("cannot create network namespaces here")
	}
	exec.Command("ip", "netns", "del", nsPrefix+"probe").Run()
}

type listener struct{ cmd *exec.Cmd }

func buildTopology(t *testing.T) {
	needTools(t)
	for _, ns := range []string{"S", "H", "D1", "D2", "C", "T"} {
		exec.Command("ip", "netns", "del", nsPrefix+ns).Run()
		sh(t, "ip", "netns", "add", nsPrefix+ns)
	}
	t.Cleanup(func() {
		exec.Command("pkill", "-f", "gbfw-listener").Run()
		for _, ns := range []string{"S", "H", "D1", "D2", "C", "T"} {
			exec.Command("ip", "netns", "del", nsPrefix+ns).Run()
		}
	})
	// server <-> hub
	sh(t, "ip", "link", "add", "gamebond0", "netns", nsPrefix+"S", "type", "veth", "peer", "name", "sh0", "netns", nsPrefix+"H")
	// server <-> upstream
	sh(t, "ip", "link", "add", "eth0", "netns", nsPrefix+"S", "type", "veth", "peer", "name", "tup", "netns", nsPrefix+"T")
	// hub <-> devices
	for _, d := range []struct{ ns, port string }{{"D1", "hd1"}, {"D2", "hd2"}, {"C", "hc"}} {
		sh(t, "ip", "link", "add", "eth0", "netns", nsPrefix+d.ns, "type", "veth", "peer", "name", d.port, "netns", nsPrefix+"H")
	}
	in(t, "H", "ip", "link", "add", "br0", "type", "bridge")
	for _, p := range []string{"sh0", "hd1", "hd2", "hc"} {
		in(t, "H", "ip", "link", "set", p, "master", "br0")
		in(t, "H", "ip", "link", "set", p, "up")
	}
	in(t, "H", "ip", "link", "set", "br0", "up")
	in(t, "S", "ip", "addr", "add", "10.77.0.1/24", "dev", "gamebond0")
	in(t, "S", "ip", "link", "set", "gamebond0", "up")
	in(t, "S", "ip", "addr", "add", "198.51.100.2/24", "dev", "eth0")
	in(t, "S", "ip", "link", "set", "eth0", "up")
	in(t, "S", "ip", "link", "set", "lo", "up")
	in(t, "S", "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0")
	in(t, "T", "ip", "addr", "add", "198.51.100.1/24", "dev", "tup")
	in(t, "T", "ip", "link", "set", "tup", "up")
	in(t, "T", "ip", "link", "set", "lo", "up")
	for _, a := range []string{"1.1.1.1/32", "2.2.2.2/32"} {
		in(t, "T", "ip", "addr", "add", a, "dev", "lo")
	}
	in(t, "T", "ip", "route", "add", "10.77.0.0/24", "via", "198.51.100.2")
	in(t, "T", "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")
	in(t, "S", "ip", "route", "add", "1.1.1.1/32", "via", "198.51.100.1")
	in(t, "S", "ip", "route", "add", "2.2.2.2/32", "via", "198.51.100.1")
	for ns, ip := range map[string]string{"D1": "10.77.0.3", "D2": "10.77.0.4", "C": "10.77.0.2"} {
		in(t, ns, "ip", "addr", "add", ip+"/32", "dev", "eth0")
		in(t, ns, "ip", "link", "set", "eth0", "up")
		in(t, ns, "ip", "link", "set", "lo", "up")
		in(t, ns, "ip", "route", "add", "10.77.0.1/32", "dev", "eth0")
		in(t, ns, "ip", "route", "add", "default", "via", "10.77.0.1")
	}
	// The listeners: a TCP server per address and port that accepts and closes.
	listen(t, "T", "1.1.1.1", 80, 443, 853, 8081)
	listen(t, "T", "2.2.2.2", 80)
	listen(t, "S", "10.77.0.1", 9999)
	listen(t, "D2", "10.77.0.4", 7000)
	listen(t, "D1", "10.77.0.3", 6000)
	time.Sleep(400 * time.Millisecond)
}

const listenerScript = `
import socket, sys, threading, time
# gbfw-listener
ip = sys.argv[1]
for p in sys.argv[2:]:
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, int(p))); s.listen(16)
    def serve(s=s):
        while True:
            c, _ = s.accept(); c.close()
    threading.Thread(target=serve, daemon=True).start()
time.sleep(600)
`

func listen(t *testing.T, ns, ip string, ports ...int) {
	t.Helper()
	args := []string{"netns", "exec", nsPrefix + ns, "python3", "-c", listenerScript, ip}
	for _, p := range ports {
		args = append(args, fmt.Sprint(p))
	}
	cmd := exec.Command("ip", args...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
}

const connectScript = `
import socket, sys
src, dst, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
s = socket.socket(); s.settimeout(1.2)
s.bind((src, 0))
try:
    s.connect((dst, port)); print("OK")
except Exception as e:
    print("FAIL")
`

// connects reports whether a new TCP connection from src (in namespace ns) to dst:port succeeds.
func connects(t *testing.T, ns, src, dst string, port int) bool {
	t.Helper()
	out := in(t, ns, "python3", "-c", connectScript, src, dst, fmt.Sprint(port))
	return strings.TrimSpace(out) == "OK"
}

func expect(t *testing.T, what string, got, want bool) {
	t.Helper()
	if got != want {
		t.Errorf("%s: connection succeeded=%v, want %v", what, got, want)
	}
}

const udpResponder = `
import socket, sys
# gbfw-udp
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((sys.argv[1], int(sys.argv[2])))
while True:
    data, peer = s.recvfrom(512)
    s.sendto(b"FILTER", peer)
`

const udpAskScript = `
import socket, sys
src, dst = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1.0); s.bind((src, 0))
s.sendto(b"q", (dst, 53))
try:
    print(s.recvfrom(512)[0].decode())
except Exception:
    print("")
`

// dnsAsk sends a UDP datagram to dst:53 from a device and returns what answered, or "".
func dnsAsk(t *testing.T, ns, src, dst string) string {
	t.Helper()
	return strings.TrimSpace(in(t, ns, "python3", "-c", udpAskScript, src, dst))
}

// onS runs the manager against the server namespace's nft.
type nsRunner struct{}

func (nsRunner) Run(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
	return ExecRunner{}.Run(ctx, stdin, "ip", append([]string{"netns", "exec", nsPrefix + "S", name}, args...)...)
}

func apply(t *testing.T, m *Manager, cfg string) {
	t.Helper()
	if err := m.Apply(context.Background(), parse(t, cfg)); err != nil {
		t.Fatal(err)
	}
}

func TestFirewallBehaviourInRealNamespaces(t *testing.T) {
	buildTopology(t)
	m := NewManager(nsRunner{})
	d1, d2, c := "10.77.0.3", "10.77.0.4", "10.77.0.2"

	// Baseline: with no firewall everything works, including device to device.
	expect(t, "baseline D1 -> T:80", connects(t, "D1", d1, "1.1.1.1", 80), true)
	expect(t, "baseline D1 -> D2", connects(t, "D1", d1, d2, 7000), true)

	t.Run("enabled with defaults changes nothing a user would notice", func(t *testing.T) {
		apply(t, m, `{"enabled":true}`)
		expect(t, "D1 -> T:80", connects(t, "D1", d1, "1.1.1.1", 80), true)
		expect(t, "D1 -> D2", connects(t, "D1", d1, d2, 7000), true)
		expect(t, "D1 -> server's own service", connects(t, "D1", d1, "10.77.0.1", 9999), false)
	})

	t.Run("rules apply to new connections in order, and replies are automatic", func(t *testing.T) {
		apply(t, m, `{"enabled":true,"rules":[
		  {"id":"allow-d1-80","enabled":true,"action":"allow","source":"10.77.0.3","proto":"tcp","ports":["80"]},
		  {"id":"deny-80","enabled":true,"action":"deny","proto":"tcp","ports":["80"]},
		  {"id":"deny-8081","enabled":true,"action":"deny","proto":"tcp","ports":["8000-8100"],"dest":"1.1.1.0/24"}]}`)
		expect(t, "D1 -> T:80 (the allow rule is first)", connects(t, "D1", d1, "1.1.1.1", 80), true)
		expect(t, "D2 -> T:80 (denied)", connects(t, "D2", d2, "1.1.1.1", 80), false)
		expect(t, "D1 -> T:443 (no rule, default allow)", connects(t, "D1", d1, "1.1.1.1", 443), true)
		expect(t, "D1 -> T:8081 (port range deny)", connects(t, "D1", d1, "1.1.1.1", 8081), false)
		expect(t, "D1 -> 2.2.2.2:80 (the allow rule is first)", connects(t, "D1", d1, "2.2.2.2", 80), true)
		st := m.Status(context.Background())
		if st.Counters["deny-80"].Packets == 0 || st.Counters["allow-d1-80"].Packets == 0 || st.Counters["deny-8081"].Packets == 0 {
			t.Errorf("rule counters must show what matched: %+v", st.Counters)
		}
	})

	t.Run("default outbound deny only lets listed traffic out", func(t *testing.T) {
		apply(t, m, `{"enabled":true,"default_outbound":"deny","rules":[{"id":"web","enabled":true,"action":"allow","source":"10.77.0.3","proto":"tcp","ports":["80"]}]}`)
		expect(t, "D1 -> T:80", connects(t, "D1", d1, "1.1.1.1", 80), true)
		expect(t, "D1 -> T:443", connects(t, "D1", d1, "1.1.1.1", 443), false)
		expect(t, "D2 -> T:80", connects(t, "D2", d2, "1.1.1.1", 80), false)
	})

	t.Run("segmentation isolates devices and zones open exceptions one way", func(t *testing.T) {
		apply(t, m, `{"enabled":true,"segmentation":{"isolate_devices":true,"allow":[{"from":"gaming","to":"lab"}]},
		  "zones":[{"name":"gaming","members":["10.77.0.3"]},{"name":"lab","members":["10.77.0.4"]}]}`)
		expect(t, "D1 -> internet is untouched", connects(t, "D1", d1, "1.1.1.1", 80), true)
		expect(t, "D1 (gaming) -> D2 (lab) is the exception", connects(t, "D1", d1, d2, 7000), true)
		expect(t, "D2 (lab) -> D1 (gaming) is not", connects(t, "D2", d2, d1, 6000), false)
		expect(t, "D2 -> client PC", connects(t, "D2", d2, c, 1), false)
	})

	t.Run("country block cuts a country at once, allow-only keeps only the listed ones", func(t *testing.T) {
		m.Geo = func(codes []string) []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")} }
		apply(t, m, `{"enabled":true,"countries":{"mode":"block","codes":["AU"],"direction":"outbound"}}`)
		expect(t, "D1 -> 1.1.1.1 (blocked country)", connects(t, "D1", d1, "1.1.1.1", 80), false)
		expect(t, "D1 -> 2.2.2.2 (elsewhere)", connects(t, "D1", d1, "2.2.2.2", 80), true)
		apply(t, m, `{"enabled":true,"countries":{"mode":"allow","codes":["AU"],"direction":"outbound"}}`)
		expect(t, "allow-only: D1 -> 1.1.1.1 (listed)", connects(t, "D1", d1, "1.1.1.1", 80), true)
		expect(t, "allow-only: D1 -> 2.2.2.2 (not listed)", connects(t, "D1", d1, "2.2.2.2", 80), false)
		m.Geo = func([]string) []netip.Prefix { return nil } // lists not loaded
		apply(t, m, `{"enabled":true,"countries":{"mode":"allow","codes":["AU"],"direction":"outbound"}}`)
		expect(t, "allow-only with no data must not black-hole everything", connects(t, "D1", d1, "2.2.2.2", 80), true)
		if w := m.Status(context.Background()).Warnings; len(w) == 0 {
			t.Error("and the operator must be told")
		}
	})

	t.Run("prevention blocks an address at once, survives a rule change and can be lifted", func(t *testing.T) {
		apply(t, m, `{"enabled":true}`)
		expect(t, "before", connects(t, "D1", d1, "1.1.1.1", 80), true)
		if err := m.BlockAddress(context.Background(), d1, time.Minute); err != nil {
			t.Fatal(err)
		}
		expect(t, "D1 blocked", connects(t, "D1", d1, "1.1.1.1", 80), false)
		expect(t, "D2 unaffected", connects(t, "D2", d2, "1.1.1.1", 80), true)
		apply(t, m, `{"enabled":true,"default_outbound":"allow"}`)
		expect(t, "D1 still blocked after the rules were replaced", connects(t, "D1", d1, "1.1.1.1", 80), false)
		m.UnblockAddress(context.Background(), d1)
		expect(t, "D1 after unblock", connects(t, "D1", d1, "1.1.1.1", 80), true)
		if err := m.BlockAddress(context.Background(), c, time.Minute); err == nil {
			t.Error("the client PC must never be blockable")
		}
	})

	t.Run("DNS over TLS can be blocked", func(t *testing.T) {
		apply(t, m, `{"enabled":true,"block_dot":true}`)
		expect(t, "D1 -> T:853", connects(t, "D1", d1, "1.1.1.1", 853), false)
		expect(t, "D1 -> T:443", connects(t, "D1", d1, "1.1.1.1", 443), true)
	})

	t.Run("forcing DNS sends every device's port 53 questions to the filter", func(t *testing.T) {
		exec.Command("pkill", "-f", "gbfw-udp").Run()
		udp := exec.Command("ip", "netns", "exec", nsPrefix+"S", "python3", "-c", udpResponder, "10.77.0.1", "53")
		if err := udp.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { udp.Process.Kill() })
		time.Sleep(300 * time.Millisecond)
		apply(t, m, `{"enabled":true}`)
		if got := dnsAsk(t, "D1", d1, "1.1.1.1"); got != "" {
			t.Errorf("without forcing, a question to 1.1.1.1 goes to 1.1.1.1 (no resolver there), got %q", got)
		}
		if got := dnsAsk(t, "D1", d1, "10.77.0.1"); got != "FILTER" {
			t.Errorf("a question to the server's own address reaches the filter, got %q", got)
		}
		apply(t, m, `{"enabled":true,"force_dns":true}`)
		if got := dnsAsk(t, "D1", d1, "1.1.1.1"); got != "FILTER" {
			t.Errorf("forced: a question to 1.1.1.1 must be answered by the filter, got %q", got)
		}
		if got := dnsAsk(t, "D2", d2, "9.9.9.9"); got != "FILTER" {
			t.Errorf("forced: a question to any other resolver too, got %q", got)
		}
		expect(t, "forcing DNS does not touch other traffic", connects(t, "D1", d1, "1.1.1.1", 80), true)
		apply(t, m, `{"enabled":true}`)
		if got := dnsAsk(t, "D1", d1, "1.1.1.1"); got != "" {
			t.Errorf("switching it off restores the normal path, got %q", got)
		}
	})

	t.Run("a strict inbound default stops new connections from the internet", func(t *testing.T) {
		apply(t, m, `{"enabled":true}`)
		expect(t, "T -> D1 (allowed by default, as with reverse port forwarding)", connects(t, "T", "1.1.1.1", d1, 6000), true)
		apply(t, m, `{"enabled":true,"default_inbound":"deny","rules":[{"id":"in-ok","enabled":true,"action":"allow","direction":"inbound","proto":"tcp","ports":["7000"],"dest":"10.77.0.4"}]}`)
		expect(t, "T -> D1 (denied)", connects(t, "T", "1.1.1.1", d1, 6000), false)
		expect(t, "T -> D2:7000 (the rule opens it)", connects(t, "T", "1.1.1.1", d2, 7000), true)
		expect(t, "D1 -> T still works: the reply is not a new inbound connection", connects(t, "D1", d1, "1.1.1.1", 80), true)
	})

	t.Run("switching the firewall off removes every rule", func(t *testing.T) {
		apply(t, m, `{"enabled":true,"default_outbound":"deny"}`)
		expect(t, "denied", connects(t, "D1", d1, "1.1.1.1", 80), false)
		apply(t, m, `{"enabled":false}`)
		expect(t, "after off", connects(t, "D1", d1, "1.1.1.1", 80), true)
		if out := in(t, "S", "nft", "list", "tables"); strings.Contains(out, Table) {
			t.Errorf("the table must be gone: %s", out)
		}
	})
}
