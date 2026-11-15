//go:build linux

package lab

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DockerOptions configures isolated per-node containers. Runtime must name a
// configured sandbox runtime such as runsc; this backend never falls back to
// runc or host execution.
type DockerOptions struct {
	SocketPath       string
	ShaperSocketPath string
	Runtime          string
	NodeImage        string
	Prefix           string
	DefaultMemoryMiB uint32
	MaxPIDs          int64
}

type DockerBackend struct {
	api          *dockerAPI
	shaper       *http.Client
	opts         DockerOptions
	mu           sync.Mutex
	networkSlots map[int]bool
	nextNetwork  int
}

func NewDockerBackend(ctx context.Context, options DockerOptions) (*DockerBackend, error) {
	if options.SocketPath == "" {
		options.SocketPath = "/var/run/docker.sock"
	}
	if options.Runtime == "" || options.NodeImage == "" || options.ShaperSocketPath == "" {
		return nil, errors.New("lab Docker backend requires an explicit sandbox runtime, node image, and host-shaper socket")
	}
	if options.Prefix == "" {
		options.Prefix = "gb-lab"
	}
	if options.DefaultMemoryMiB == 0 {
		options.DefaultMemoryMiB = 256
	}
	if options.MaxPIDs <= 0 {
		options.MaxPIDs = 128
	}
	api, err := newDockerAPI(ctx, options.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to Docker Engine: %w", err)
	}
	shaperTransport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", options.ShaperSocketPath)
	}, DisableKeepAlives: true}
	return &DockerBackend{api: api, shaper: &http.Client{Transport: shaperTransport, Timeout: 0}, opts: options, networkSlots: make(map[int]bool)}, nil
}

func (b *DockerBackend) StartNode(ctx context.Context, runID string, node Node) (NodeProcess, error) {
	name := b.name("node", runID+"/"+node.ID)
	memory := node.Resources.MemoryMiB
	if memory == 0 {
		memory = b.opts.DefaultMemoryMiB
	}
	shares := node.Resources.CPUShares
	if shares == 0 {
		shares = 1024
	}
	pids := b.opts.MaxPIDs
	config := map[string]any{
		"Image":      b.opts.NodeImage,
		"User":       "0:0",
		"Cmd":        []string{"init"},
		"Entrypoint": []string{"/usr/local/bin/gamebond-labnode"},
		"Labels":     map[string]string{"gamebond.lab": "true", "gamebond.run": runID, "gamebond.node": node.ID},
		"HostConfig": map[string]any{
			"Runtime":        b.opts.Runtime,
			"NetworkMode":    "none",
			"CapDrop":        []string{"ALL"},
			"CapAdd":         []string{"NET_ADMIN", "NET_RAW"},
			"SecurityOpt":    []string{"no-new-privileges:true"},
			"ReadonlyRootfs": true,
			"PidsLimit":      pids,
			"Memory":         int64(memory) * 1024 * 1024,
			"CPUShares":      shares,
			"Tmpfs": map[string]string{
				"/run":              "rw,noexec,nosuid,size=16m",
				"/tmp":              "rw,noexec,nosuid,size=32m",
				"/etc/gamebond-lab": "rw,noexec,nosuid,size=2m",
				"/var/lib/frr":      "rw,noexec,nosuid,size=16m",
				"/var/lib/snmp":     "rw,noexec,nosuid,size=4m",
				"/etc/frr":          "rw,nosuid,size=8m",
				"/var/run/frr":      "rw,nosuid,size=8m",
				"/var/log":          "rw,noexec,nosuid,size=16m",
			},
		},
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := b.api.json(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), config, &created); err != nil {
		return nil, fmt.Errorf("create sandbox for node %s: %w", node.ID, err)
	}
	if created.ID == "" {
		return nil, errors.New("Docker Engine returned an empty node container id")
	}
	p := &dockerNode{backend: b, id: created.ID, name: name, runID: runID, node: node, ifaceNames: map[string]string{}, attached: map[string]string{}, attachedIP: map[string]string{}}
	if err := b.api.empty(ctx, http.MethodPost, "/containers/"+created.ID+"/start", nil); err != nil {
		_ = b.api.empty(context.Background(), http.MethodDelete, "/containers/"+created.ID+"?force=true&v=true", nil)
		return nil, fmt.Errorf("start sandbox for node %s: %w", node.ID, err)
	}
	return p, nil
}

func (b *DockerBackend) Connect(ctx context.Context, runID string, link Link, a, other NodeProcess) (VirtualLink, error) {
	na, ok := a.(*dockerNode)
	if !ok {
		return nil, errors.New("Docker backend received a foreign node process")
	}
	nb, ok := other.(*dockerNode)
	if !ok {
		return nil, errors.New("Docker backend received a foreign node process")
	}
	if na.runID != runID || nb.runID != runID {
		return nil, errors.New("link endpoints belong to a different run")
	}
	name := b.name("link", runID+"/"+link.ID)
	index, err := b.allocateNetwork()
	if err != nil {
		return nil, err
	}
	releaseSlot := true
	defer func() {
		if releaseSlot {
			b.releaseNetwork(index)
		}
	}()
	base := netip.MustParseAddr("198.18.0.0").As4()
	address := binary.BigEndian.Uint32(base[:]) + uint32(index*8)
	var subnet [4]byte
	binary.BigEndian.PutUint32(subnet[:], address)
	var gateway [4]byte
	binary.BigEndian.PutUint32(gateway[:], address+1)
	networkConfig := map[string]any{
		"Name": name, "Driver": "bridge", "Internal": true,
		"EnableIPv6": false,
		"IPAM":       map[string]any{"Driver": "default", "Config": []any{map[string]string{"Subnet": netip.PrefixFrom(netip.AddrFrom4(subnet), 29).String(), "Gateway": netip.AddrFrom4(gateway).String()}}},
		"Labels":     map[string]string{"gamebond.lab": "true", "gamebond.run": runID, "gamebond.link": link.ID},
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := b.api.json(ctx, http.MethodPost, "/networks/create", networkConfig, &created); err != nil {
		return nil, fmt.Errorf("create isolated network for link %s: %w", link.ID, err)
	}
	if created.ID == "" {
		return nil, errors.New("Docker Engine returned an empty link network id")
	}
	cleanup := func(err error) (VirtualLink, error) {
		_ = b.api.empty(context.Background(), http.MethodDelete, "/networks/"+created.ID, nil)
		return nil, err
	}
	attach := func(node *dockerNode, endpoint Endpoint) error {
		node.mu.Lock()
		_, exists := node.attached[endpoint.Interface]
		node.mu.Unlock()
		if exists {
			return fmt.Errorf("interface %s is already attached", endpoint.Interface)
		}
		var response map[string]any
		body := map[string]any{"Container": node.id, "EndpointConfig": map[string]any{"Aliases": []string{node.node.ID}}}
		if err := b.api.json(ctx, http.MethodPost, "/networks/"+created.ID+"/connect", body, &response); err != nil {
			return err
		}
		var inspect struct {
			NetworkSettings struct {
				Networks map[string]struct {
					IPAddress string `json:"IPAddress"`
				} `json:"Networks"`
			} `json:"NetworkSettings"`
		}
		if err := b.api.json(ctx, http.MethodGet, "/containers/"+node.id+"/json", nil, &inspect); err != nil {
			return err
		}
		node.mu.Lock()
		defer node.mu.Unlock()
		if _, exists := node.attached[endpoint.Interface]; exists {
			return fmt.Errorf("interface %s is already attached", endpoint.Interface)
		}
		linuxName := "eth" + strconv.Itoa(node.nextIf)
		node.nextIf++
		node.attached[endpoint.Interface] = linuxName
		if netState, ok := inspect.NetworkSettings.Networks[name]; ok && netState.IPAddress != "" {
			node.attachedIP[endpoint.Interface] = netState.IPAddress + "/29"
		}
		return nil
	}
	if err := attach(na, link.A); err != nil {
		_ = b.api.empty(context.Background(), http.MethodPost, "/networks/"+created.ID+"/disconnect", map[string]any{"Container": na.id, "Force": true})
		return cleanup(fmt.Errorf("attach node %s to link %s: %w", na.node.ID, link.ID, err))
	}
	if err := attach(nb, link.B); err != nil {
		_ = b.api.empty(context.Background(), http.MethodPost, "/networks/"+created.ID+"/disconnect", map[string]any{"Container": na.id, "Force": true})
		return cleanup(fmt.Errorf("attach node %s to link %s: %w", nb.node.ID, link.ID, err))
	}
	virtual := &dockerLink{backend: b, networkID: created.ID, slot: index, a: na, b: nb, endpointA: link.A, endpointB: link.B, impairment: link.Impairment, up: true}
	if err := virtual.SetImpairment(ctx, link.Impairment); err != nil {
		_ = virtual.Close(context.Background())
		return nil, err
	}
	releaseSlot = false
	return virtual, nil
}

func (b *DockerBackend) allocateNetwork() (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := 0; i < 8192; i++ {
		slot := (b.nextNetwork + i) % 8192
		if !b.networkSlots[slot] {
			b.networkSlots[slot] = true
			b.nextNetwork = (slot + 1) % 8192
			return slot, nil
		}
	}
	return 0, errors.New("single-host lab exhausted its isolated link subnet pool")
}

func (b *DockerBackend) releaseNetwork(slot int) {
	b.mu.Lock()
	delete(b.networkSlots, slot)
	b.mu.Unlock()
}

func (b *DockerBackend) name(kind, key string) string {
	sum := sha256.Sum256([]byte(key))
	return b.opts.Prefix + "-" + kind[:1] + "-" + hex.EncodeToString(sum[:10])
}

type dockerNode struct {
	backend         *DockerBackend
	id, name, runID string
	node            Node
	mu              sync.Mutex
	attached        map[string]string // interface id -> Docker-created eth name
	attachedIP      map[string]string // interface id -> Docker-assigned address to remove
	ifaceNames      map[string]string // interface id -> configured name
	nextIf          int
	started         bool
}

func (n *dockerNode) Start(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.started {
		return nil
	}
	if err := n.configureInterfaces(ctx); err != nil {
		return err
	}
	files := map[string][]byte{}
	interfaces := make([]string, 0, len(n.node.Interfaces))
	for _, in := range n.node.Interfaces {
		interfaces = append(interfaces, interfaceTarget(in))
	}
	metadata, err := json.Marshal(map[string]any{"id": n.node.ID, "role": n.node.Role, "daemons": n.node.Daemons, "interfaces": interfaces})
	if err != nil {
		return err
	}
	files["node.json"] = metadata
	for daemon, config := range n.node.DaemonConfig {
		files[daemon+".conf"] = []byte(config)
	}
	if err := n.backend.api.putArchive(ctx, n.id, "/etc/gamebond-lab", files); err != nil {
		return fmt.Errorf("write node configuration: %w", err)
	}
	if _, err := n.backend.api.exec(ctx, n.id, []string{"/usr/local/bin/gamebond-labnode", "release"}, false); err != nil {
		return fmt.Errorf("start node daemons: %w", err)
	}
	n.started = true
	return nil
}

func (n *dockerNode) configureInterfaces(ctx context.Context) error {
	if _, err := n.backend.api.exec(ctx, n.id, []string{"ip", "link", "set", "lo", "up"}, false); err != nil {
		return err
	}
	// Rename attached interfaces through temporary names to support swaps such
	// as eth0<->eth1 without a transient collision.
	attachedIDs := make([]string, 0, len(n.attached))
	for id := range n.attached {
		attachedIDs = append(attachedIDs, id)
	}
	sortStrings(attachedIDs)
	temp := map[string]string{}
	for i, id := range attachedIDs {
		old := n.attached[id]
		name := fmt.Sprintf("gbtmp%d", i)
		if _, err := n.backend.api.exec(ctx, n.id, []string{"ip", "link", "set", "dev", old, "name", name}, false); err != nil {
			return fmt.Errorf("stage interface %s rename: %w", id, err)
		}
		temp[id] = name
	}
	for id, address := range n.attachedIP {
		if iface := temp[id]; iface != "" {
			_, _ = n.backend.api.exec(ctx, n.id, []string{"ip", "address", "del", address, "dev", iface}, false)
		}
	}
	for _, in := range n.node.Interfaces {
		if _, linked := temp[in.ID]; linked {
			continue
		}
		name := interfaceTarget(in)
		if _, err := n.backend.api.exec(ctx, n.id, []string{"ip", "link", "add", "name", name, "type", "dummy"}, false); err != nil {
			return fmt.Errorf("create unlinked interface %s: %w", in.ID, err)
		}
	}
	for _, in := range n.node.Interfaces {
		name := interfaceTarget(in)
		if old, linked := temp[in.ID]; linked {
			if _, err := n.backend.api.exec(ctx, n.id, []string{"ip", "link", "set", "dev", old, "name", name}, false); err != nil {
				return fmt.Errorf("rename interface %s: %w", in.ID, err)
			}
		}
		n.ifaceNames[in.ID] = name
		if in.MAC != "" {
			if _, err := n.backend.api.exec(ctx, n.id, []string{"ip", "link", "set", "dev", name, "address", in.MAC}, false); err != nil {
				return fmt.Errorf("set interface %s MAC: %w", in.ID, err)
			}
		}
		if in.MTU != 0 {
			if _, err := n.backend.api.exec(ctx, n.id, []string{"ip", "link", "set", "dev", name, "mtu", strconv.Itoa(in.MTU)}, false); err != nil {
				return fmt.Errorf("set interface %s MTU: %w", in.ID, err)
			}
		}
		for _, address := range in.Addresses {
			if _, err := n.backend.api.exec(ctx, n.id, []string{"ip", "address", "add", address, "dev", name}, false); err != nil {
				return fmt.Errorf("address interface %s: %w", in.ID, err)
			}
		}
		if _, err := n.backend.api.exec(ctx, n.id, []string{"ip", "link", "set", "dev", name, "up"}, false); err != nil {
			return fmt.Errorf("bring interface %s up: %w", in.ID, err)
		}
	}
	if n.node.Role == "router" {
		if _, err := n.backend.api.exec(ctx, n.id, []string{"sysctl", "-w", "net.ipv4.ip_forward=1"}, false); err != nil {
			return err
		}
	}
	if len(n.attached) > 0 {
		_, _ = n.backend.api.exec(ctx, n.id, []string{"ip", "route", "flush", "default"}, false)
	}
	return nil
}

func interfaceTarget(in Interface) string {
	if in.Name != "" {
		return in.Name
	}
	return in.ID
}

func (n *dockerNode) Pause(ctx context.Context) error {
	return n.backend.api.empty(ctx, http.MethodPost, "/containers/"+n.id+"/pause", nil)
}
func (n *dockerNode) Resume(ctx context.Context) error {
	return n.backend.api.empty(ctx, http.MethodPost, "/containers/"+n.id+"/unpause", nil)
}
func (n *dockerNode) Restart(ctx context.Context) error {
	if err := n.backend.api.empty(ctx, http.MethodPost, "/containers/"+n.id+"/restart?t=5", nil); err != nil {
		return err
	}
	n.mu.Lock()
	n.started = false
	n.mu.Unlock()
	return n.Start(ctx)
}
func (n *dockerNode) Close(ctx context.Context) error {
	return n.backend.api.empty(ctx, http.MethodDelete, "/containers/"+n.id+"?force=true&v=true", nil)
}
func (n *dockerNode) Console(ctx context.Context) (io.ReadWriteCloser, error) {
	return n.backend.api.console(ctx, n.id)
}
func (n *dockerNode) Stats(ctx context.Context) (map[string]any, error) {
	var inspect struct {
		State struct {
			Status  string `json:"Status"`
			Running bool   `json:"Running"`
		} `json:"State"`
	}
	if err := n.backend.api.json(ctx, http.MethodGet, "/containers/"+n.id+"/json", nil, &inspect); err != nil {
		return nil, err
	}
	var cpuPercent, memoryUsage, memoryLimit, memoryPercent float64
	raw, _, statsErr := n.backend.api.request(ctx, http.MethodGet, "/containers/"+n.id+"/stats?stream=false", nil, "application/json")
	if statsErr == nil {
		var stats struct {
			CPUStats struct {
				CPUUsage struct {
					Total uint64 `json:"total_usage"`
				} `json:"cpu_usage"`
				System uint64 `json:"system_cpu_usage"`
				Online int    `json:"online_cpus"`
			} `json:"cpu_stats"`
			PreCPUStats struct {
				CPUUsage struct {
					Total uint64 `json:"total_usage"`
				} `json:"cpu_usage"`
				System uint64 `json:"system_cpu_usage"`
			} `json:"precpu_stats"`
			Memory struct {
				Usage uint64 `json:"usage"`
				Limit uint64 `json:"limit"`
			} `json:"memory_stats"`
		}
		if json.Unmarshal(raw, &stats) == nil {
			memoryUsage, memoryLimit = float64(stats.Memory.Usage), float64(stats.Memory.Limit)
			if memoryLimit > 0 {
				memoryPercent = memoryUsage / memoryLimit * 100
			}
			dCPU, dSystem := stats.CPUStats.CPUUsage.Total-stats.PreCPUStats.CPUUsage.Total, stats.CPUStats.System-stats.PreCPUStats.System
			if dSystem > 0 {
				online := stats.CPUStats.Online
				if online < 1 {
					online = 1
				}
				cpuPercent = float64(dCPU) / float64(dSystem) * float64(online) * 100
			}
		}
	}
	daemons, err := n.backend.api.exec(ctx, n.id, []string{"/usr/local/bin/gamebond-labnode", "status"}, false)
	if err != nil {
		daemons = []byte(err.Error())
	}
	return map[string]any{"state": inspect.State.Status, "running": inspect.State.Running, "daemons": strings.TrimSpace(string(daemons)), "cpu_percent": cpuPercent, "memory_usage_bytes": memoryUsage, "memory_limit_bytes": memoryLimit, "memory_percent": memoryPercent}, nil
}
func (n *dockerNode) Check(ctx context.Context, check Assertion) (AssertionResult, error) {
	var cmd []string
	switch check.Kind {
	case "ping":
		cmd = []string{"ping", "-c", "1", "-W", "2", check.Target}
	case "traceroute":
		cmd = []string{"traceroute", "-m", "12", "-w", "1", check.Target}
	case "ospf-neighbor":
		cmd = []string{"vtysh", "-c", "show ip ospf neighbor"}
	case "bgp-neighbor":
		cmd = []string{"vtysh", "-c", "show bgp summary"}
	case "interface-up":
		name := ""
		for _, in := range n.node.Interfaces {
			if in.ID == check.Target || in.Name == check.Target {
				name = interfaceTarget(in)
				break
			}
		}
		if name == "" {
			return AssertionResult{}, fmt.Errorf("unknown interface %s", check.Target)
		}
		cmd = []string{"ip", "-o", "link", "show", "dev", name}
	default:
		return AssertionResult{}, errors.New("unsupported assertion kind")
	}
	out, err := n.backend.api.exec(ctx, n.id, cmd, false)
	passed := err == nil
	if check.Kind == "ospf-neighbor" || check.Kind == "bgp-neighbor" {
		passed = passed && (check.Target == "" || strings.Contains(string(out), check.Target))
	}
	if check.Expected != "" {
		passed = passed && strings.Contains(string(out), check.Expected)
	}
	return AssertionResult{Passed: passed, Details: strings.TrimSpace(string(out))}, nil
}

type dockerLink struct {
	backend              *DockerBackend
	networkID            string
	slot                 int
	a, b                 *dockerNode
	endpointA, endpointB Endpoint
	mu                   sync.Mutex
	impairment           Impairment
	endpointFaults       [2]Impairment
	up                   bool
	lastSample           time.Time
	lastRXBytes          uint64
}

func (l *dockerLink) SetImpairment(ctx context.Context, impairment Impairment) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	old := l.impairment
	oldFaults := l.endpointFaults
	endpoints := []struct {
		node *dockerNode
		ep   Endpoint
	}{{l.a, l.endpointA}, {l.b, l.endpointB}}
	for i, endpoint := range endpoints {
		if err := l.applyOne(ctx, endpoint.node, endpoint.ep, combineImpairment(impairment, l.endpointFaults[i])); err != nil {
			_ = l.applyOne(context.Background(), l.a, l.endpointA, combineImpairment(old, oldFaults[0]))
			_ = l.applyOne(context.Background(), l.b, l.endpointB, combineImpairment(old, oldFaults[1]))
			return fmt.Errorf("shape link %s: %w", l.networkID, err)
		}
	}
	l.impairment = impairment
	return nil
}

func combineImpairment(base, fault Impairment) Impairment {
	out := base
	out.LatencyMS += fault.LatencyMS
	out.JitterMS += fault.JitterMS
	out.LossPct = 100 * (1 - (1-base.LossPct/100)*(1-fault.LossPct/100))
	out.CorruptPct = 100 * (1 - (1-base.CorruptPct/100)*(1-fault.CorruptPct/100))
	if fault.BandwidthBPS > 0 && (out.BandwidthBPS == 0 || fault.BandwidthBPS < out.BandwidthBPS) {
		out.BandwidthBPS = fault.BandwidthBPS
	}
	return out
}

func (l *dockerLink) SetEndpointFault(ctx context.Context, nodeID, interfaceID string, fault Impairment) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	index, node, endpoint := -1, l.a, l.endpointA
	if l.endpointA.Node == nodeID && l.endpointA.Interface == interfaceID {
		index = 0
	}
	if l.endpointB.Node == nodeID && l.endpointB.Interface == interfaceID {
		index, node, endpoint = 1, l.b, l.endpointB
	}
	if index < 0 {
		return errors.New("interface is not an endpoint of this link")
	}
	previous := l.endpointFaults[index]
	l.endpointFaults[index] = fault
	if err := l.applyOne(ctx, node, endpoint, combineImpairment(l.impairment, fault)); err != nil {
		l.endpointFaults[index] = previous
		_ = l.applyOne(context.Background(), node, endpoint, combineImpairment(l.impairment, previous))
		return err
	}
	return nil
}
func (l *dockerLink) applyOne(ctx context.Context, n *dockerNode, ep Endpoint, impairment Impairment) error {
	iface := n.interfaceName(ep.Interface)
	request, err := json.Marshal(hostShapeRequest{ContainerID: n.id, Interface: iface, Impairment: impairment})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://labd/shape", bytes.NewReader(request))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := l.backend.shaper.Do(req)
	if err != nil {
		return fmt.Errorf("contact host network shaper: %w", err)
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
	if readErr != nil {
		return readErr
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("host network shaper rejected qdisc: %s", strings.TrimSpace(string(body)))
	}
	return nil
}
func (l *dockerLink) SetUp(ctx context.Context, up bool) error {
	verb := "down"
	if up {
		verb = "up"
	}
	if _, err := l.backend.api.exec(ctx, l.a.id, []string{"ip", "link", "set", "dev", l.a.interfaceName(l.endpointA.Interface), verb}, false); err != nil {
		return err
	}
	if _, err := l.backend.api.exec(ctx, l.b.id, []string{"ip", "link", "set", "dev", l.b.interfaceName(l.endpointB.Interface), verb}, false); err != nil {
		previous := "up"
		if !l.up {
			previous = "down"
		}
		_, _ = l.backend.api.exec(context.Background(), l.a.id, []string{"ip", "link", "set", "dev", l.a.interfaceName(l.endpointA.Interface), previous}, false)
		return err
	}
	l.mu.Lock()
	l.up = up
	l.mu.Unlock()
	return nil
}
func (l *dockerLink) Stats(ctx context.Context) (map[string]any, error) {
	read := func(n *dockerNode, ep Endpoint) (map[string]uint64, error) {
		iface := n.interfaceName(ep.Interface)
		out, err := n.backend.api.exec(ctx, n.id, []string{"cat", "/sys/class/net/" + iface + "/statistics/tx_bytes", "/sys/class/net/" + iface + "/statistics/rx_bytes", "/sys/class/net/" + iface + "/statistics/tx_packets", "/sys/class/net/" + iface + "/statistics/rx_packets"}, false)
		if err != nil {
			return nil, err
		}
		fields := strings.Fields(string(out))
		if len(fields) != 4 {
			return nil, errors.New("invalid interface counters")
		}
		values := map[string]uint64{}
		for i, k := range []string{"tx_bytes", "rx_bytes", "tx_packets", "rx_packets"} {
			v, e := strconv.ParseUint(fields[i], 10, 64)
			if e != nil {
				return nil, e
			}
			values[k] = v
		}
		return values, nil
	}
	a, err := read(l.a, l.endpointA)
	if err != nil {
		return nil, err
	}
	b, err := read(l.b, l.endpointB)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	imp, up, faults := l.impairment, l.up, l.endpointFaults
	rxBytes := a["rx_bytes"] + b["rx_bytes"]
	now := time.Now()
	var bps float64
	if !l.lastSample.IsZero() && now.After(l.lastSample) && rxBytes >= l.lastRXBytes {
		bps = float64(rxBytes-l.lastRXBytes) * 8 / now.Sub(l.lastSample).Seconds()
	}
	l.lastSample, l.lastRXBytes = now, rxBytes
	l.mu.Unlock()
	return map[string]any{"up": up, "bps": bps, "a": a, "b": b, "impairment": imp, "interface_faults": map[string]Impairment{l.endpointA.Node + "/" + l.endpointA.Interface: faults[0], l.endpointB.Node + "/" + l.endpointB.Interface: faults[1]}}, nil
}
func (l *dockerLink) Capture(ctx context.Context, w io.Writer, duration time.Duration) error {
	seconds := int(math.Ceil(duration.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(seconds+3)*time.Second)
	defer cancel()
	data, err := l.backend.api.execBytes(ctx, l.a.id, []string{"timeout", "--signal=INT", strconv.Itoa(seconds) + "s", "tcpdump", "-U", "-s", "0", "-w", "-", "-i", l.a.interfaceName(l.endpointA.Interface)}, true)
	if err != nil && !strings.Contains(err.Error(), "exit code 124") {
		return err
	}
	_, err = w.Write(data)
	return err
}
func (l *dockerLink) Close(ctx context.Context) error {
	err := l.backend.api.empty(ctx, http.MethodDelete, "/networks/"+l.networkID, nil)
	if err == nil {
		l.backend.releaseNetwork(l.slot)
	}
	return err
}

func (n *dockerNode) interfaceName(id string) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if name := n.ifaceNames[id]; name != "" {
		return name
	}
	if in, ok := n.attached[id]; ok {
		return in
	}
	return id
}

type dockerAPI struct {
	client     *http.Client
	apiVersion string
	socketPath string
}

func newDockerAPI(ctx context.Context, socket string) (*dockerAPI, error) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
	}, DisableKeepAlives: true}
	a := &dockerAPI{client: &http.Client{Transport: transport, Timeout: 0}, socketPath: socket}
	b, _, err := a.request(ctx, http.MethodGet, "/version", nil, "application/json")
	if err != nil {
		return nil, err
	}
	var version struct {
		APIVersion string `json:"ApiVersion"`
	}
	if json.Unmarshal(b, &version) != nil || version.APIVersion == "" {
		return nil, errors.New("Docker Engine version response is invalid")
	}
	a.apiVersion = "/v" + version.APIVersion
	// Engine API 1.41 is the minimum used here (Docker 20.10).
	parts := strings.Split(version.APIVersion, ".")
	if len(parts) == 2 {
		major, _ := strconv.Atoi(parts[0])
		minor, _ := strconv.Atoi(parts[1])
		if major == 1 && minor < 41 {
			return nil, fmt.Errorf("Docker Engine API %s is older than required 1.41", version.APIVersion)
		}
	}
	return a, nil
}
func (a *dockerAPI) request(ctx context.Context, method, endpoint string, body []byte, contentType string) ([]byte, int, error) {
	if strings.HasPrefix(endpoint, "http://") {
		endpoint = strings.TrimPrefix(endpoint, "http://docker")
	}
	pathName := endpoint
	if !strings.HasPrefix(pathName, "/version") && !strings.HasPrefix(pathName, "/_ping") {
		pathName = a.apiVersion + pathName
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+pathName, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 24<<20))
	if readErr != nil {
		return nil, resp.StatusCode, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var msg struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &msg)
		if msg.Message == "" {
			msg.Message = strings.TrimSpace(string(raw))
		}
		return raw, resp.StatusCode, fmt.Errorf("Docker Engine %s %s: %s (HTTP %d)", method, endpoint, msg.Message, resp.StatusCode)
	}
	return raw, resp.StatusCode, nil
}
func (a *dockerAPI) json(ctx context.Context, method, path string, v any, out any) error {
	var data []byte
	var err error
	if v != nil {
		data, err = json.Marshal(v)
		if err != nil {
			return err
		}
	}
	raw, _, err := a.request(ctx, method, path, data, "application/json")
	if err != nil {
		return err
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return err
		}
	}
	return nil
}
func (a *dockerAPI) empty(ctx context.Context, method, path string, v any) error {
	if v == nil {
		_, _, err := a.request(ctx, method, path, nil, "application/json")
		return err
	}
	return a.json(ctx, method, path, v, nil)
}
func (a *dockerAPI) putArchive(ctx context.Context, container, dest string, files map[string][]byte) error {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, data := range files {
		if path.Base(name) != name {
			return errors.New("invalid container config filename")
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	_, _, err := a.request(ctx, http.MethodPut, "/containers/"+container+"/archive?path="+url.QueryEscape(dest), buf.Bytes(), "application/x-tar")
	return err
}
func (a *dockerAPI) exec(ctx context.Context, container string, command []string, detach bool) ([]byte, error) {
	return a.execBytes(ctx, container, command, detach)
}
func (a *dockerAPI) execBytes(ctx context.Context, container string, command []string, detach bool) ([]byte, error) {
	var created struct {
		ID string `json:"Id"`
	}
	body := map[string]any{"AttachStdin": false, "AttachStdout": !detach, "AttachStderr": !detach, "Tty": false, "Cmd": command, "Privileged": false}
	if err := a.json(ctx, http.MethodPost, "/containers/"+container+"/exec", body, &created); err != nil {
		return nil, err
	}
	if created.ID == "" {
		return nil, errors.New("Docker Engine returned an empty exec id")
	}
	start := map[string]any{"Detach": detach, "Tty": false}
	raw, _, err := a.request(ctx, http.MethodPost, "/exec/"+created.ID+"/start", mustJSON(start), "application/json")
	if err != nil {
		return nil, err
	}
	if detach {
		return raw, nil
	}
	stdout, stderr, err := decodeDockerStream(raw)
	if err != nil {
		return nil, err
	}
	var state struct {
		ExitCode int  `json:"ExitCode"`
		Running  bool `json:"Running"`
	}
	if err := a.json(ctx, http.MethodGet, "/exec/"+created.ID+"/json", nil, &state); err != nil {
		return stdout, err
	}
	if state.ExitCode != 0 {
		return stdout, fmt.Errorf("command %q failed (exit code %d): %s", strings.Join(command, " "), state.ExitCode, strings.TrimSpace(string(stderr)))
	}
	return stdout, nil
}

type dockerConsole struct {
	net.Conn
	reader *bufio.Reader
}

func (c *dockerConsole) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (a *dockerAPI) console(ctx context.Context, container string) (io.ReadWriteCloser, error) {
	var created struct {
		ID string `json:"Id"`
	}
	body := map[string]any{"AttachStdin": true, "AttachStdout": true, "AttachStderr": true, "Tty": true, "Cmd": []string{"/bin/bash", "--login"}, "Env": []string{"TERM=xterm-256color"}, "Privileged": false}
	if err := a.json(ctx, http.MethodPost, "/containers/"+container+"/exec", body, &created); err != nil {
		return nil, err
	}
	if created.ID == "" {
		return nil, errors.New("Docker Engine returned an empty console exec id")
	}
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", a.socketPath)
	if err != nil {
		return nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	start, _ := json.Marshal(map[string]any{"Detach": false, "Tty": true})
	if _, err = fmt.Fprintf(conn, "POST %s/exec/%s/start HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: %d\r\n\r\n", a.apiVersion, created.ID, len(start)); err != nil {
		return nil, err
	}
	if _, err = conn.Write(start); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		return nil, fmt.Errorf("Docker Engine console attach failed (HTTP %d): %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	_ = conn.SetDeadline(time.Time{})
	closeOnError = false
	return &dockerConsole{Conn: conn, reader: reader}, nil
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func decodeDockerStream(raw []byte) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	for len(raw) > 0 {
		if len(raw) < 8 {
			return nil, nil, errors.New("truncated Docker exec stream")
		}
		kind := raw[0]
		n := int(binary.BigEndian.Uint32(raw[4:8]))
		raw = raw[8:]
		if n < 0 || n > len(raw) {
			return nil, nil, errors.New("invalid Docker exec stream frame")
		}
		switch kind {
		case 1:
			_, _ = stdout.Write(raw[:n])
		case 2:
			_, _ = stderr.Write(raw[:n])
		default:
			return nil, nil, fmt.Errorf("unexpected Docker exec stream type %d", kind)
		}
		raw = raw[n:]
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}
func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}
