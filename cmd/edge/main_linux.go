//go:build linux

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Dankular/GameBond.Core/bond"
	"github.com/Dankular/GameBond.Core/hwmon"
	"github.com/Dankular/GameBond.Core/stream"
	"github.com/Dankular/GameBond.Server/adminportal"
	"github.com/Dankular/GameBond.Server/edge"
	"github.com/Dankular/GameBond.Server/l2gw"
	"github.com/Dankular/GameBond.Server/lab"
	"github.com/Dankular/GameBond.Server/security"
)

func run() (runErr error) {
	configPath := flag.String("config", "/run/config/server.json", "validated server config")
	keyPath := flag.String("key", "/run/secrets/gamebond.key", "read-only key file")
	flag.Parse()
	var syslogExporter *edge.RemoteSyslog
	syslogCollector := os.Getenv("GAMEBOND_SYSLOG_ADDR")
	if syslogCollector != "" {
		syslogExporter, runErr = edge.OpenRemoteSyslogWithCAFile(syslogCollector, "gamebond-edge", os.Getenv("GAMEBOND_SYSLOG_CA_FILE"))
		if runErr != nil {
			return fmt.Errorf("open remote syslog exporter: %w", runErr)
		}
		log.SetOutput(io.MultiWriter(os.Stderr, syslogExporter))
	}
	defer func() {
		if syslogExporter == nil {
			return
		}
		if runErr != nil {
			log.Printf("edge process stopped: %v", runErr)
		}
		if err := syslogExporter.Close(); runErr == nil && err != nil {
			runErr = fmt.Errorf("close remote syslog exporter: %w", err)
		}
	}()
	if os.Getenv("GAMEBOND_NATIVE_EDGE") != "1" {
		return fmt.Errorf("native edge requires explicit GAMEBOND_NATIVE_EDGE=1 in its container")
	}
	file, err := os.Open(*configPath)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}
	if info.Size() > 1024*1024 {
		file.Close()
		return fmt.Errorf("server config exceeds size limit")
	}
	file.Close()
	data, err := os.ReadFile(*configPath)
	if err != nil {
		return err
	}
	c, options, address, session, err := edge.DecodeConfig(data)
	if err != nil {
		return err
	}
	key, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	if len(key) != 32 {
		return fmt.Errorf("key file must contain exactly 32 bytes")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if syslogExporter != nil {
		fmt.Fprintf(os.Stdout, "{\"status\":\"syslog\",\"collector\":%q}\n", syslogCollector)
	}
	go controlLoop(ctx, *configPath)
	var observers []func(map[string]any)
	var restart atomic.Bool
	// Firewall, DNS filter and intrusion detection. The manager always exists so a section saved from the portal
	// takes effect at once; with no "security" key everything stays off.
	sec := security.New(security.Options{GeoDir: "/tmp/gamebond-geo", Tunnel: c.TunName, InspectionDir: "/var/lib/gamebond-inspection"})
	if err := sec.Apply(ctx, c.Security); err != nil {
		log.Printf("security settings were not applied: %v", err)
	}
	go sec.Run(ctx)
	edge.SetTap(sec.Tap)
	defer edge.SetTap(nil)
	edge.SetDNSFilter(&l2gw.DNSHook{
		On:     func() bool { return sec.Settings().DNSFilter.Enabled },
		Handle: func(client netip.Addr, req []byte, tcp bool) []byte { return sec.DNS.Handle(ctx, client, req, tcp) },
	})
	defer edge.SetDNSFilter(nil)
	if len(c.Admin) > 0 && string(c.Admin) != "null" {
		settings, err := adminportal.ParseSettings(c.Admin)
		if err != nil {
			return err
		}
		if settings.Enabled {
			var labManagerFactory func(string) (*lab.Manager, error)
			if socket := os.Getenv("GAMEBOND_LAB_DOCKER_SOCKET"); socket != "" {
				backend, backendErr := lab.NewDockerBackend(ctx, lab.DockerOptions{SocketPath: socket, ShaperSocketPath: os.Getenv("GAMEBOND_LAB_SHAPER_SOCKET"), Runtime: os.Getenv("GAMEBOND_LAB_RUNTIME"), NodeImage: os.Getenv("GAMEBOND_LAB_NODE_IMAGE")})
				if backendErr != nil {
					return fmt.Errorf("configure lab runtime: %w", backendErr)
				}
				labManagerFactory = func(team string) (*lab.Manager, error) {
					return lab.NewManager(backend, lab.Limits{Nodes: 32, CPUShares: 32768, MemoryMiB: 8192})
				}
			}
			hardware, err := hwmon.NewPlatform(ctx, hwmon.Options{})
			if err != nil {
				return err
			}
			defer hardware.Close()
			resources, err := hwmon.StartService(ctx, hardware.Sample, 1500*time.Millisecond)
			if err != nil {
				return err
			}
			defer resources.Close()
			var mu sync.Mutex
			var latest map[string]any
			observers = append(observers, func(stats map[string]any) {
				mu.Lock()
				latest = mergeStats(latest, stats)
				mu.Unlock()
			})
			portal := adminportal.New(adminportal.Options{Settings: settings, Security: securityAPI{sec}, ConfigPath: *configPath, LabDirectory: "/var/lib/gamebond-labs", LabManagerFactory: labManagerFactory, Hardware: resources.Snapshot,
				GatewaySocketPath: os.Getenv("GAMEBOND_GATEWAY_SOCKET"),
				Snapshot: func() any {
					mu.Lock()
					defer mu.Unlock()
					snapshot := edge.AdminSnapshot(c, latest, time.Now())
					if syslogExporter != nil {
						snapshot["syslog_export"] = map[string]any{"enabled": true, "collector": syslogCollector, "dropped_messages": syslogExporter.Drops()}
					}
					return snapshot
				},
				Validate: func(path string) error {
					raw, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					_, _, _, _, err = edge.DecodeConfig(raw)
					return err
				},
				RequestRestart: func() { restart.Store(true); stop() }})
			if err := portal.Start(); err != nil {
				return fmt.Errorf("admin portal: %w", err)
			}
			defer portal.Close()
			portal.Note("admin portal started")
			fmt.Fprintf(os.Stdout, "{\"status\":\"admin_portal\",\"bind\":[%q,%d],\"tls\":%t}\n", settings.Host, portal.Port, settings.TLSCert != "")
		}
	}
	if addr := os.Getenv("GAMEBOND_METRICS_ADDR"); addr != "" {
		metrics := &edge.MetricsHandler{}
		l, err := edge.ServeMetrics(addr, metrics)
		if err != nil {
			return err
		}
		defer l.Close()
		observers = append(observers, metrics.Observe)
		fmt.Fprintf(os.Stdout, "{\"status\":\"metrics\",\"bind\":%q}\n", l.Addr().String())
	}
	if os.Getenv("GAMEBOND_STREAM") != "0" {
		go serveStreamGateway(ctx)
	}
	if c.L2 != nil && c.L2.Enabled && c.L2.SegmentSocketPath != "" && c.L2.Bridge == nil {
		token, tokenErr := loadSegmentToken(c.L2.SegmentTokenFile)
		if tokenErr != nil {
			return tokenErr
		}
		identity := "session-" + hex.EncodeToString(session)
		fabric, fabricErr := edge.NewRemoteSegmentFabricContext(ctx, c.L2.SegmentID, c.L2.SegmentSocketPath, identity, token)
		if fabricErr != nil {
			return fabricErr
		}
		err = edge.RunWithSegmentFabric(ctx, c, options, address, session, key, os.Stdout, fabric, observers...)
	} else if c.L2 != nil && c.L2.Enabled && c.L2.SegmentID != "" && c.L2.Bridge != nil {
		err = runSegmentBrokerNode(ctx, c, options, address, session, key, os.Stdout, observers...)
	} else {
		err = edge.Run(ctx, c, options, address, session, key, os.Stdout, observers...)
	}
	if restart.Load() {
		// The container entrypoint relaunches on exit status 75.
		return restartRequested{}
	}
	return err
}

type segmentRunResult struct {
	role string
	err  error
}

func runSegmentBrokerNode(parent context.Context, c edge.Config, options bond.SessionOptions, address netip.AddrPort, session, key []byte, output io.Writer, observers ...func(map[string]any)) error {
	switchConfig, err := edge.RSTPSwitchConfig(c.L2.RSTP)
	if err != nil {
		return err
	}
	switchConfig.MVR = c.L2.MVR
	fabric, err := edge.NewNamedSegmentFabricChecked(c.L2.SegmentID, switchConfig)
	if err != nil {
		return fmt.Errorf("segment switch config: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	results := make(chan segmentRunResult, 3)
	active := 2
	var authorizations map[string]edge.SegmentSocketAuthorization
	var localAuthorization edge.SegmentSocketAuthorization
	var eapolTaps *edge.SegmentEAPOLTaps
	if c.L2.SegmentSocketPath != "" {
		loaded, err := loadSegmentAuthorizations(c.L2)
		if err != nil {
			return err
		}
		authorizations = loaded
		var adminToken []byte
		if c.L2.SegmentAdminTokenFile != "" {
			adminToken, err = loadSegmentToken(c.L2.SegmentAdminTokenFile)
			if err != nil {
				return err
			}
		}
		for identity, authorization := range authorizations {
			if authorization.Port.MACAuth && len(adminToken) == 0 {
				return fmt.Errorf("segment member %q enables mac_auth but l2.segment_admin_token_file is missing", identity)
			}
		}
		eapolTaps, err = edge.StartSegmentEAPOLTaps(fabric, authorizations, c.L2.FrameMTU)
		if err != nil {
			return err
		}
		defer eapolTaps.Close()
		localIdentity := "session-" + hex.EncodeToString(session)
		var ok bool
		localAuthorization, ok = authorizations[localIdentity]
		if !ok {
			return fmt.Errorf("segment member authorization is missing local broker session %q", localIdentity)
		}
		active++
		go func() {
			results <- segmentRunResult{role: "broker", err: edge.ServeSegmentSocketWithAdminToken(ctx, c.L2.SegmentSocketPath, fabric, authorizations, adminToken)}
		}()
		if err := waitForSegmentSocket(ctx, c.L2.SegmentSocketPath, 10*time.Second); err != nil {
			cancel()
			for i := 0; i < active-1; i++ {
				<-results
			}
			return err
		}
	}
	sessionConfig := c
	sessionL2 := *c.L2
	sessionL2.Bridge = nil
	if c.L2.SegmentSocketPath != "" {
		sessionL2.TunnelVLAN = localAuthorization.Port.VLAN
		sessionL2.MACLimit = localAuthorization.Port.MACLimit
		sessionL2.BroadcastPPS = localAuthorization.Port.BroadcastPPS
		sessionL2.MulticastPPS = localAuthorization.Port.MulticastPPS
		sessionL2.UnknownUnicastPPS = localAuthorization.Port.UnknownUnicastPPS
		sessionL2.BPDUGuardTunnel = localAuthorization.Port.BPDUGuard
		sessionL2.RAGuardTunnel = localAuthorization.Port.RAGuard
		sessionL2.IPv4SourceGuardTunnel = localAuthorization.Port.IPv4SourceGuard
		sessionL2.IPv6SourceGuardTunnel = localAuthorization.Port.IPv6SourceGuard
		sessionL2.MulticastRouterTunnel = localAuthorization.Port.MulticastRouter
	}
	sessionConfig.L2 = &sessionL2
	go func() {
		results <- segmentRunResult{role: "gateway", err: edge.RunWithSegmentGateway(ctx, c, output, fabric, observers...)}
	}()
	go func() {
		results <- segmentRunResult{role: "session", err: edge.RunWithSegmentFabric(ctx, sessionConfig, options, address, session, key, output, fabric, observers...)}
	}()
	first := <-results
	cancel()
	finalErr := first.err
	for i := 1; i < active; i++ {
		result := <-results
		if finalErr == nil && result.err != nil {
			finalErr = fmt.Errorf("segment %s stopped: %w", result.role, result.err)
		}
	}
	if first.err != nil {
		return fmt.Errorf("segment %s stopped: %w", first.role, first.err)
	}
	return finalErr
}

func loadSegmentAuthorizations(l2 *edge.L2Config) (map[string]edge.SegmentSocketAuthorization, error) {
	file, err := openSecretFile(l2.SegmentMembersFile, 1024*1024)
	if err != nil {
		return nil, fmt.Errorf("segment member authorization: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var members []edge.L2SegmentMember
	if err := decoder.Decode(&members); err != nil {
		return nil, fmt.Errorf("segment member authorization: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("segment member authorization: trailing JSON data")
	}
	if len(members) == 0 || len(members) > 1024 {
		return nil, errors.New("segment member authorization: expected 1..1024 members")
	}
	authorizations := make(map[string]edge.SegmentSocketAuthorization, len(members))
	saviPrefixes := configuredSegmentSAVIPrefixes(l2)
	seenTokens := make(map[string]bool, len(members))
	rstpParticipantCount := 0
	seenTaps := make(map[string]bool, len(members)+len(l2.KernelVXLANAttachments)+2)
	reserveTap := func(name, owner string) error {
		if name == "" {
			return nil
		}
		if seenTaps[name] {
			return fmt.Errorf("segment TAP name %q is used by more than one attachment (%s)", name, owner)
		}
		seenTaps[name] = true
		return nil
	}
	if err := reserveTap(l2.TapName, "the primary edge TAP"); err != nil {
		return nil, err
	}
	if l2.Monitor != nil {
		if err := reserveTap(l2.Monitor.TapName, "the monitor TAP"); err != nil {
			return nil, err
		}
	}
	for _, attachment := range l2.KernelVXLANAttachments {
		if err := reserveTap(attachment.TapName, "kernel VXLAN attachment "+attachment.ID); err != nil {
			return nil, err
		}
	}
	for i, member := range members {
		if !strings.HasPrefix(member.Identity, "session-") || len(member.Identity) != len("session-")+32 {
			return nil, fmt.Errorf("segment member authorization[%d]: identity must be session- followed by a 32-character session ID", i)
		}
		if _, err := hex.DecodeString(strings.TrimPrefix(member.Identity, "session-")); err != nil {
			return nil, fmt.Errorf("segment member authorization[%d]: identity contains an invalid session ID", i)
		}
		if _, exists := authorizations[member.Identity]; exists {
			return nil, fmt.Errorf("segment member authorization[%d]: duplicate identity %q", i, member.Identity)
		}
		token, err := hex.DecodeString(member.TokenHex)
		if err != nil || len(token) < 32 || len(token) > 128 {
			return nil, fmt.Errorf("segment member authorization[%d]: token_hex must encode 32..128 bytes", i)
		}
		if seenTokens[string(token)] {
			return nil, fmt.Errorf("segment member authorization[%d]: each identity needs a distinct token", i)
		}
		seenTokens[string(token)] = true
		if err := member.VLAN.Validate(); err != nil {
			return nil, fmt.Errorf("segment member authorization[%d] VLAN: %w", i, err)
		}
		if member.VLAN.AccessVLAN == 0 && len(member.VLAN.AllowedVLANs) == 0 {
			return nil, fmt.Errorf("segment member authorization[%d]: vlan must specify an access VLAN or trunk allow-list", i)
		}
		staticBindings, err := parseSegmentSourceBindings(member)
		if err != nil {
			return nil, fmt.Errorf("segment member authorization[%d] static_source_bindings: %w", i, err)
		}
		pvlanRole, err := parseSegmentPVLAN(member.PrivateVLAN, member.PrivateVLANRole, member.PVLANCommunity)
		if err != nil {
			return nil, fmt.Errorf("segment member authorization[%d]: %w", i, err)
		}
		if member.PVLANPrimaryVLAN == 0 && member.PVLANSecondaryVLAN != 0 {
			return nil, fmt.Errorf("segment member authorization[%d]: private_vlan_secondary_vlan requires private_vlan_primary_vlan", i)
		}
		if member.MACLimit < 0 || member.MACLimit > 4096 || member.BroadcastPPS < 0 || member.MulticastPPS < 0 || member.UnknownUnicastPPS < 0 {
			return nil, fmt.Errorf("segment member authorization[%d]: invalid port limits", i)
		}
		if member.MACAuth && l2.Bridge == nil {
			return nil, fmt.Errorf("segment member authorization[%d]: mac_auth requires a per-member eapol_tap_name and l2.bridge gateway", i)
		}
		if member.RSTPParticipant {
			rstpParticipantCount++
			if l2.RSTP == nil {
				return nil, fmt.Errorf("segment member authorization[%d]: rstp_participant requires l2.rstp", i)
			}
			if member.BPDUGuard {
				return nil, fmt.Errorf("segment member authorization[%d]: rstp_participant cannot be combined with bpdu_guard", i)
			}
		} else if member.RSTPEdge || member.RSTPSharedLink || member.RSTPPathCost != 0 {
			return nil, fmt.Errorf("segment member authorization[%d]: RSTP port settings require rstp_participant", i)
		}
		if member.MACAuth {
			if member.VLAN.AccessVLAN == 0 || len(member.VLAN.AllowedVLANs) != 0 || member.VLAN.NativeVLAN != 0 || len(member.EAPOLTapName) == 0 || len(member.EAPOLTapName) > 15 || strings.ContainsAny(member.EAPOLTapName, " /\t\r\n\x00") {
				return nil, fmt.Errorf("segment member authorization[%d]: mac_auth requires an access VLAN and a valid per-member eapol_tap_name", i)
			}
			if err := reserveTap(member.EAPOLTapName, "EAPOL authenticator for "+member.Identity); err != nil {
				return nil, fmt.Errorf("segment member authorization[%d]: %w", i, err)
			}
		} else if member.EAPOLTapName != "" {
			return nil, fmt.Errorf("segment member authorization[%d]: eapol_tap_name requires mac_auth", i)
		}
		mirrorIngress, mirrorEgress := false, false
		if l2.Monitor != nil {
			mirrorIngress, mirrorEgress = l2.Monitor.TunnelIngress, l2.Monitor.TunnelEgress
		}
		var ipv6SourcePrefixes []bond.L2SourcePrefix
		if member.IPv6SourceGuard {
			for _, prefix := range saviPrefixes {
				if segmentPortAdmitsVLAN(member.VLAN, prefix.VLAN) {
					ipv6SourcePrefixes = append(ipv6SourcePrefixes, prefix)
				}
			}
		}
		authorizations[member.Identity] = edge.SegmentSocketAuthorization{Token: token, EAPOLTapName: member.EAPOLTapName, MirrorIngress: mirrorIngress, MirrorEgress: mirrorEgress, Port: bond.L2PortConfig{
			Name: member.Identity, VLAN: member.VLAN, MACLimit: member.MACLimit,
			BroadcastPPS: member.BroadcastPPS, MulticastPPS: member.MulticastPPS,
			UnknownUnicastPPS: member.UnknownUnicastPPS, BPDUGuard: member.BPDUGuard, RAGuard: member.RAGuard, IPv4SourceGuard: member.IPv4SourceGuard, IPv6SourceGuard: member.IPv6SourceGuard, MulticastRouter: member.MulticastRouter,
			StaticSourceBindings: staticBindings, IPv6SourcePrefixes: ipv6SourcePrefixes,
			MACAuth:         member.MACAuth,
			RSTPParticipant: member.RSTPParticipant, RSTPEdge: member.RSTPEdge,
			RSTPSharedLink: member.RSTPSharedLink, RSTPPathCost: member.RSTPPathCost,
			PrivateVLAN: member.PrivateVLAN, PrivateVLANRole: pvlanRole, PVLANCommunity: member.PVLANCommunity,
			PVLANPrimaryVLAN: member.PVLANPrimaryVLAN, PVLANSecondaryVLAN: member.PVLANSecondaryVLAN,
		}}
	}
	var mappedPVLANPorts []bond.L2PortConfig
	hasMappedPVLAN := false
	for _, authorization := range authorizations {
		if authorization.Port.PVLANPrimaryVLAN != 0 {
			hasMappedPVLAN = true
		}
		mappedPVLANPorts = append(mappedPVLANPorts, authorization.Port)
	}
	if hasMappedPVLAN {
		if l2.Bridge == nil {
			return nil, errors.New("primary/secondary PVLAN mapping requires an l2.bridge gateway")
		}
		for _, entry := range l2.Bridge.VLANs {
			if entry.Gateway != nil {
				gatewayPort := bond.L2PortConfig{Name: fmt.Sprintf("gateway-vlan-%d", entry.VLANID), VLAN: bond.L2VLANPolicy{AccessVLAN: entry.VLANID}}
				if entry.Gateway.PrivateVLAN != 0 {
					gatewayPort.PrivateVLAN, gatewayPort.PrivateVLANRole, gatewayPort.PVLANPrimaryVLAN = entry.Gateway.PrivateVLAN, bond.L2PVLANPromiscuous, entry.VLANID
				}
				mappedPVLANPorts = append(mappedPVLANPorts, gatewayPort)
			}
		}
		if len(l2.Bridge.VLANs) == 0 {
			gatewayPort := bond.L2PortConfig{Name: "gateway", VLAN: l2.ExitVLAN}
			if l2.Bridge.PrivateVLAN != 0 {
				gatewayPort.PrivateVLAN, gatewayPort.PrivateVLANRole, gatewayPort.PVLANPrimaryVLAN = l2.Bridge.PrivateVLAN, bond.L2PVLANPromiscuous, l2.ExitVLAN.AccessVLAN
			}
			mappedPVLANPorts = append(mappedPVLANPorts, gatewayPort)
		}
		if err := bond.ValidatePVLANPorts(mappedPVLANPorts); err != nil {
			return nil, fmt.Errorf("segment PVLAN configuration: %w", err)
		}
	}
	if l2.RSTP != nil && rstpParticipantCount == 0 {
		return nil, errors.New("l2.rstp requires at least one segment member with rstp_participant enabled")
	}
	if len(l2.Bridge.VLANs) == 0 {
		gatewayVLAN := l2.ExitVLAN.AccessVLAN
		if gatewayVLAN == 0 {
			return nil, errors.New("segment broker with one gateway requires l2.exit_vlan.access_vlan")
		}
		for identity, authorization := range authorizations {
			if !segmentPortAdmitsVLAN(authorization.Port.VLAN, gatewayVLAN) {
				return nil, fmt.Errorf("segment member %q does not admit gateway VLAN %d", identity, gatewayVLAN)
			}
		}
	}
	if l2.MVR != nil {
		mvrPorts := make([]bond.L2PortConfig, 0, len(authorizations)+len(l2.Bridge.VLANs)+1)
		for _, authorization := range authorizations {
			mvrPorts = append(mvrPorts, authorization.Port)
		}
		if len(l2.Bridge.VLANs) > 0 {
			for _, entry := range l2.Bridge.VLANs {
				gatewayPort := bond.L2PortConfig{Name: fmt.Sprintf("gateway-vlan-%d", entry.VLANID), VLAN: bond.L2VLANPolicy{AccessVLAN: entry.VLANID}, MulticastRouter: true}
				if entry.Gateway != nil && entry.Gateway.PrivateVLAN != 0 {
					gatewayPort.PrivateVLAN, gatewayPort.PrivateVLANRole, gatewayPort.PVLANPrimaryVLAN = entry.Gateway.PrivateVLAN, bond.L2PVLANPromiscuous, entry.VLANID
				}
				mvrPorts = append(mvrPorts, gatewayPort)
			}
		} else {
			gatewayPort := bond.L2PortConfig{Name: "gateway", VLAN: l2.ExitVLAN, MulticastRouter: true}
			if l2.Bridge.PrivateVLAN != 0 {
				gatewayPort.PrivateVLAN, gatewayPort.PrivateVLANRole, gatewayPort.PVLANPrimaryVLAN = l2.Bridge.PrivateVLAN, bond.L2PVLANPromiscuous, l2.ExitVLAN.AccessVLAN
			}
			mvrPorts = append(mvrPorts, gatewayPort)
		}
		if err := (bond.L2SwitchConfig{MVR: l2.MVR, Ports: mvrPorts}).Validate(); err != nil {
			return nil, fmt.Errorf("segment MVR configuration: %w", err)
		}
	}
	return authorizations, nil
}

func configuredSegmentSAVIPrefixes(l2 *edge.L2Config) []bond.L2SourcePrefix {
	if l2 == nil || l2.Bridge == nil {
		return nil
	}
	var prefixes []bond.L2SourcePrefix
	appendPrefix := func(vlan uint16, value string) {
		prefix, err := netip.ParsePrefix(value)
		if err == nil && prefix.Addr().Is6() && !prefix.Addr().Is4In6() && prefix.Bits() == 64 {
			prefixes = append(prefixes, bond.L2SourcePrefix{VLAN: vlan, Prefix: prefix.Masked()})
		}
	}
	if len(l2.Bridge.VLANs) != 0 {
		for _, entry := range l2.Bridge.VLANs {
			if entry.Gateway != nil {
				appendPrefix(entry.VLANID, entry.Gateway.IPv6Address)
			}
		}
	} else if l2.ExitVLAN.AccessVLAN != 0 {
		appendPrefix(l2.ExitVLAN.AccessVLAN, l2.Bridge.IPv6Address)
	}
	return prefixes
}

func parseSegmentSourceBindings(member edge.L2SegmentMember) ([]bond.L2SourceBinding, error) {
	if len(member.StaticSourceBindings) == 0 {
		return nil, nil
	}
	bindings := make([]bond.L2SourceBinding, 0, len(member.StaticSourceBindings))
	seen := make(map[string]struct{}, len(member.StaticSourceBindings))
	for i, configured := range member.StaticSourceBindings {
		ip, err := netip.ParseAddr(configured.IP)
		if err != nil || !ip.IsValid() || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip == netip.MustParseAddr("255.255.255.255") {
			return nil, fmt.Errorf("binding[%d] ip must be a unicast IPv4 or IPv6 address", i)
		}
		if ip.Is4() && !member.IPv4SourceGuard || ip.Is6() && !member.IPv6SourceGuard {
			return nil, fmt.Errorf("binding[%d] requires the matching IPv%d source guard", i, map[bool]int{true: 4, false: 6}[ip.Is4()])
		}
		parsedMAC, err := net.ParseMAC(configured.MAC)
		if err != nil || len(parsedMAC) != 6 || parsedMAC[0]&1 != 0 || isZeroEthernetMAC(parsedMAC) {
			return nil, fmt.Errorf("binding[%d] mac must be a unicast six-byte Ethernet address", i)
		}
		var binding bond.L2SourceBinding
		binding.IP = ip
		copy(binding.MAC[:], parsedMAC)
		if member.VLAN.ServiceVLAN != 0 {
			if configured.VLAN != 0 {
				return nil, fmt.Errorf("binding[%d] must use outer_vlan and inner_vlan for Q-in-Q", i)
			}
			outer, inner := configured.OuterVLAN, configured.InnerVLAN
			if outer == 0 && inner == 0 && member.VLAN.CustomerVLAN != 0 {
				outer, inner = member.VLAN.ServiceVLAN, member.VLAN.CustomerVLAN
			}
			if outer == 0 || inner == 0 || outer != member.VLAN.ServiceVLAN || member.VLAN.CustomerVLAN != 0 && inner != member.VLAN.CustomerVLAN || member.VLAN.CustomerVLAN == 0 && !containsVLAN(member.VLAN.AllowedCustomerVLANs, inner) {
				return nil, fmt.Errorf("binding[%d] outer_vlan/inner_vlan is not admitted by the member Q-in-Q policy", i)
			}
			binding.OuterVLAN, binding.InnerVLAN = outer, inner
		} else {
			if configured.OuterVLAN != 0 || configured.InnerVLAN != 0 {
				return nil, fmt.Errorf("binding[%d] outer_vlan and inner_vlan require a Q-in-Q member", i)
			}
			vlan := configured.VLAN
			if vlan == 0 {
				vlan = member.VLAN.AccessVLAN
				if vlan == 0 {
					vlan = member.VLAN.NativeVLAN
				}
			}
			if vlan == 0 || member.VLAN.AccessVLAN != 0 && vlan != member.VLAN.AccessVLAN || member.VLAN.AccessVLAN == 0 && !containsVLAN(member.VLAN.AllowedVLANs, vlan) {
				return nil, fmt.Errorf("binding[%d] vlan is not admitted by the member VLAN policy", i)
			}
			binding.VLAN = vlan
		}
		key := fmt.Sprintf("%d/%d/%d/%s", binding.VLAN, binding.OuterVLAN, binding.InnerVLAN, binding.IP)
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("binding[%d] duplicates an IP/VLAN binding", i)
		}
		seen[key] = struct{}{}
		bindings = append(bindings, binding)
	}
	return bindings, nil
}

func isZeroEthernetMAC(mac net.HardwareAddr) bool {
	for _, octet := range mac {
		if octet != 0 {
			return false
		}
	}
	return true
}

func containsVLAN(vlans []uint16, wanted uint16) bool {
	for _, vlan := range vlans {
		if vlan == wanted {
			return true
		}
	}
	return false
}

func parseSegmentPVLAN(vlan uint16, role string, community uint16) (bond.L2PrivateVLANRole, error) {
	pvlanRole, err := parseSegmentPVLANRole(role)
	if err != nil {
		return bond.L2PVLANNone, err
	}
	if vlan > 4094 || (vlan == 0 && pvlanRole != bond.L2PVLANNone) || (vlan != 0 && pvlanRole == bond.L2PVLANNone) {
		return bond.L2PVLANNone, errors.New("private_vlan and private_vlan_role must be configured together with a VLAN ID in 1..4094")
	}
	if pvlanRole == bond.L2PVLANCommunity {
		if community == 0 || community > 4094 {
			return bond.L2PVLANNone, errors.New("community role requires private_vlan_community in 1..4094")
		}
	} else if community != 0 {
		return bond.L2PVLANNone, errors.New("private_vlan_community is only valid for community role")
	}
	return pvlanRole, nil
}

func parseSegmentPVLANRole(role string) (bond.L2PrivateVLANRole, error) {
	switch role {
	case "", "none":
		return bond.L2PVLANNone, nil
	case "promiscuous":
		return bond.L2PVLANPromiscuous, nil
	case "isolated":
		return bond.L2PVLANIsolated, nil
	case "community":
		return bond.L2PVLANCommunity, nil
	default:
		return bond.L2PVLANNone, fmt.Errorf("private_vlan_role must be promiscuous, isolated, community, or none")
	}
}

func segmentPortAdmitsVLAN(policy bond.L2VLANPolicy, vlan uint16) bool {
	if policy.AccessVLAN != 0 {
		return policy.AccessVLAN == vlan
	}
	for _, allowed := range policy.AllowedVLANs {
		if allowed == vlan {
			return true
		}
	}
	return false
}

func loadSegmentToken(path string) ([]byte, error) {
	file, err := openSecretFile(path, 256)
	if err != nil {
		return nil, fmt.Errorf("segment attachment token: %w", err)
	}
	defer file.Close()
	value, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("segment attachment token: %w", err)
	}
	token, err := hex.DecodeString(strings.TrimSpace(string(value)))
	if err != nil || len(token) < 32 || len(token) > 128 {
		return nil, errors.New("segment attachment token must be 64..256 hexadecimal characters")
	}
	return token, nil
}

func openSecretFile(path string, maxSize int64) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("path must be absolute")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxSize {
		file.Close()
		return nil, errors.New("file must be a regular owner-only file within the size limit")
	}
	return file, nil
}

func waitForSegmentSocket(ctx context.Context, path string, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	var lastErr error
	for {
		conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
		if err == nil {
			// An invalid zero-length control header makes the broker handler exit
			// immediately instead of occupying an attachment slot until timeout.
			_, _ = conn.Write([]byte{0, 0, 0, 0})
			_ = conn.Close()
			time.Sleep(25 * time.Millisecond)
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("segment broker socket did not become ready: %w", lastErr)
		case <-tick.C:
		}
	}
}

func mergeStats(previous, next map[string]any) map[string]any {
	merged := make(map[string]any, len(previous)+len(next))
	for key, value := range previous {
		merged[key] = value
	}
	for key, value := range next {
		if incoming, ok := value.(map[string]any); ok {
			if existing, ok := merged[key].(map[string]any); ok {
				merged[key] = mergeStats(existing, incoming)
				continue
			}
		}
		merged[key] = value
	}
	return merged
}

// securityAPI adapts the manager to the portal, returning the normalised settings that go into the config file.
type securityAPI struct{ m *security.Manager }

func (a securityAPI) Overview(ctx context.Context) any { return a.m.Overview(ctx) }
func (a securityAPI) Catalog() any                     { return a.m.Catalog() }
func (a securityAPI) Apply(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	if err := a.m.Apply(ctx, raw); err != nil {
		return nil, err
	}
	return a.m.Settings().JSON(), nil
}
func (a securityAPI) Do(ctx context.Context, action string, args map[string]any) (any, error) {
	return a.m.Do(ctx, action, args)
}

// restartRequested ends the process with the admin portal's restart status.
type restartRequested struct{}

func (restartRequested) Error() string { return "restart requested from the admin portal" }
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if _, ok := err.(restartRequested); ok {
			os.Exit(adminportal.RestartExitCode)
		}
		os.Exit(1)
	}
}

// serveStreamGateway terminates the bond-aware stream transport on the tunnel
// address: the client's userspace stack opens streams to 10.77.0.1:4436 and this
// relays them to the internet, so TCP loss recovery runs across both links
// instead of end to end.
func serveStreamGateway(ctx context.Context) {
	var pc net.PacketConn
	for pc == nil {
		var err error
		if pc, err = net.ListenPacket("udp4", "10.77.0.1:4436"); err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	ep := stream.NewEndpoint(pc, nil, stream.Config{ReorderHint: func() time.Duration { return 25 * time.Millisecond }})
	go func() { <-ctx.Done(); ep.Close() }()
	fmt.Fprintln(os.Stdout, `{"status":"stream_gateway","bind":"10.77.0.1:4436"}`)
	(&stream.Gateway{Ep: ep, Dial: stream.SafeDial}).Serve()
}

// drainFile is written by the update probe: while it exists the Layer 2 gateway refuses new flows,
// so devices move to the other exit and the flows still open finish on this one.
const drainFile = "/tmp/gamebond-draining"

// flowsFile holds the number of flows the gateway carries, refreshed every second.
const flowsFile = "/tmp/gamebond-flows"

// controlLoop is the exit's local control surface: SIGHUP reloads the Layer 2 hosts and policy from
// the config file, and the drain file toggles draining.
func controlLoop(ctx context.Context, configPath string) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	draining := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			raw, err := os.ReadFile(configPath)
			if err == nil {
				err = edge.ReloadL2(raw)
			}
			if err != nil {
				fmt.Fprintf(os.Stdout, "{\"status\":\"l2_reload_failed\",\"error\":%q}\n", err.Error())
			} else {
				fmt.Fprintln(os.Stdout, `{"status":"l2_reloaded"}`)
			}
		case <-tick.C:
			// The probe reads this to know when the exit is empty.
			if n := edge.L2Flows(); n >= 0 {
				os.WriteFile(flowsFile, []byte(strconv.Itoa(n)+"\n"), 0o644)
			}
			_, err := os.Stat(drainFile)
			if want := err == nil; want != draining && edge.SetL2Draining(want) {
				draining = want
				fmt.Fprintf(os.Stdout, "{\"status\":\"l2_draining\",\"on\":%t}\n", want)
			}
		}
	}
}
