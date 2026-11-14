//go:build linux

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

const (
	portAuthUnit      = "gamebond-hostapd@"
	portAuthEventUnit = "gamebond-8021x-events@"
	portAuthDir       = "/etc/gamebond/8021x/ports"
	portAuthMarker    = "# GameBond managed wired 802.1X port "
)

type PortAuthSnapshot struct {
	Enabled bool                   `json:"enabled"`
	Active  bool                   `json:"active"`
	Ports   []PortAuthPortSnapshot `json:"ports,omitempty"`
	Error   string                 `json:"error,omitempty"`
}

type PortAuthPortSnapshot struct {
	Interface           string   `json:"interface"`
	AuthenticatorActive bool     `json:"authenticator_active"`
	EventMonitorActive  bool     `json:"event_monitor_active"`
	AuthorizedClients   []string `json:"authorized_clients,omitempty"`
	Error               string   `json:"error,omitempty"`
}

func renderPortAuthFiles(cfg layer2.Config) (map[string][]byte, error) {
	files := make(map[string][]byte, len(cfg.PortAuth)*2)
	interfaces := make(map[string]string, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		interfaces[iface.ID] = iface.Name
	}
	for _, policy := range cfg.PortAuth {
		secret, err := readRadiusCredential(policy.SecretFile, 16, 128)
		if err != nil {
			return nil, fmt.Errorf("802.1X port %s secret: %w", policy.Interface, err)
		}
		config, err := layer2.RenderPortAuthHostapdConfig(cfg, policy.Interface, secret)
		if err != nil {
			return nil, err
		}
		files[filepath.Join(portAuthDir, policy.Interface+".conf")] = config
		files[filepath.Join(portAuthDir, policy.Interface+".env")] = []byte("GB_INTERFACE=" + interfaces[policy.Interface] + "\n")
	}
	return files, nil
}

func validatePortAuthHost(ctx context.Context, runner Runner, cfg layer2.Config) error {
	if len(cfg.PortAuth) == 0 {
		return nil
	}
	for _, tool := range []string{"hostapd", "hostapd_cli", "nft", "systemctl"} {
		if !runner.Available(tool) {
			return fmt.Errorf("802.1X control requires %s", tool)
		}
	}
	for _, unit := range []string{"gamebond-hostapd@.service", "gamebond-8021x-events@.service"} {
		result, err := runner.Run(ctx, "systemctl", "show", "--property=LoadState", "--value", unit)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", unit, err)
		}
		if strings.TrimSpace(string(result.Stdout)) != "loaded" {
			return fmt.Errorf("%s is not installed; install the GameBond wired 802.1X units and reload systemd", unit)
		}
	}
	if err := validatePortAuthNASAddresses(ctx, runner, cfg); err != nil {
		return err
	}
	if _, err := renderPortAuthFiles(cfg); err != nil {
		return err
	}
	return nil
}

func validatePortAuthNASAddresses(ctx context.Context, runner Runner, cfg layer2.Config) error {
	bridges := make(map[string]layer2.Bridge, len(cfg.Bridges))
	for _, bridge := range cfg.Bridges {
		bridges[bridge.ID] = bridge
	}
	for _, policy := range cfg.PortAuth {
		bridgeID := ""
		for _, bridge := range cfg.Bridges {
			for _, port := range bridge.Ports {
				if port.Interface == policy.Interface {
					bridgeID = bridge.ID
					break
				}
			}
			if bridgeID != "" {
				break
			}
		}
		bridge := bridges[bridgeID]
		result, err := runner.Run(ctx, "ip", "-j", "address", "show", "dev", bridge.Name)
		if err != nil {
			return fmt.Errorf("inspect 802.1X NAS address on bridge %s: %w", bridge.Name, err)
		}
		var links []struct {
			Addresses []struct {
				Local string `json:"local"`
			} `json:"addr_info"`
		}
		if err := json.Unmarshal(result.Stdout, &links); err != nil {
			return fmt.Errorf("decode addresses on 802.1X bridge %s: %w", bridge.Name, err)
		}
		wanted, _ := netip.ParseAddr(policy.NASAddress)
		found := false
		for _, link := range links {
			for _, address := range link.Addresses {
				if got, err := netip.ParseAddr(address.Local); err == nil && got == wanted {
					found = true
				}
			}
		}
		if !found {
			return fmt.Errorf("802.1X NAS address %s is not assigned to managed bridge %s", policy.NASAddress, bridge.Name)
		}
	}
	return nil
}

func writePortAuthFiles(files map[string][]byte) error {
	if err := os.MkdirAll(portAuthDir, 0700); err != nil {
		return err
	}
	dirInfo, err := os.Lstat(portAuthDir)
	if err != nil {
		return err
	}
	dirStat, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !dirInfo.IsDir() || !ok || dirStat.Uid != 0 || dirInfo.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("802.1X config directory must be a root-owned directory with mode 0700 or stricter")
	}
	for path, data := range files {
		if !strings.HasPrefix(string(data), portAuthMarker) && !strings.HasPrefix(string(data), "GB_INTERFACE=") {
			return fmt.Errorf("refusing to write unmarked 802.1X file %s", path)
		}
		if info, err := os.Lstat(path); err == nil {
			fileStat, ownerOK := info.Sys().(*syscall.Stat_t)
			if !info.Mode().IsRegular() || !ownerOK || fileStat.Uid != 0 || info.Mode().Perm()&0077 != 0 {
				return fmt.Errorf("refusing to replace unsafe 802.1X file %s", path)
			}
			prior, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if !strings.HasPrefix(string(prior), portAuthMarker) && !strings.HasPrefix(string(prior), "GB_INTERFACE=") {
				return fmt.Errorf("refusing to replace unmanaged 802.1X file %s", path)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		f, err := os.CreateTemp(portAuthDir, ".8021x-*.tmp")
		if err != nil {
			return err
		}
		temp := f.Name()
		if err = f.Chmod(0600); err == nil {
			_, err = f.Write(data)
		}
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			_ = os.Remove(temp)
			return err
		}
		if closeErr != nil {
			_ = os.Remove(temp)
			return closeErr
		}
		if err = os.Rename(temp, path); err != nil {
			_ = os.Remove(temp)
			return err
		}
	}
	keep := map[string]bool{}
	for path := range files {
		keep[filepath.Base(path)] = true
	}
	entries, err := os.ReadDir(portAuthDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if keep[name] || entry.IsDir() || !(strings.HasSuffix(name, ".conf") || strings.HasSuffix(name, ".env")) {
			continue
		}
		path := filepath.Join(portAuthDir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		fileStat, ownerOK := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || !ownerOK || fileStat.Uid != 0 || info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("refusing to inspect unsafe 802.1X file %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		managed := strings.HasPrefix(string(data), portAuthMarker) || strings.HasPrefix(string(data), "GB_INTERFACE=")
		if managed {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyPortAuthTransition(ctx context.Context, runner Runner, previous, desired layer2.Config) error {
	if len(previous.PortAuth) == 0 && len(desired.PortAuth) == 0 {
		return nil
	}
	files, err := renderPortAuthFiles(desired)
	if err != nil {
		return err
	}
	if err := writePortAuthFiles(files); err != nil {
		return err
	}
	return reconcilePortAuthServices(ctx, runner, previous, desired)
}

func pausePortAuthServices(ctx context.Context, runner Runner, cfg layer2.Config) error {
	ids := make([]string, 0, len(cfg.PortAuth))
	for id := range portAuthIDs(cfg) {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, err := runner.Run(ctx, "systemctl", "stop", portAuthEventUnit+id+".service"); err != nil {
			return fmt.Errorf("stop wired 802.1X event monitor for %s: %w", id, err)
		}
		if _, err := runner.Run(ctx, "systemctl", "stop", portAuthUnit+id+".service"); err != nil {
			return fmt.Errorf("stop wired 802.1X authenticator for %s: %w", id, err)
		}
	}
	return nil
}

func reconcilePortAuthServices(ctx context.Context, runner Runner, previous, desired layer2.Config) error {
	previousIDs := portAuthIDs(previous)
	desiredIDs := portAuthIDs(desired)
	ids := make([]string, 0, len(previousIDs)+len(desiredIDs))
	seen := map[string]bool{}
	for id := range previousIDs {
		seen[id] = true
		ids = append(ids, id)
	}
	for id := range desiredIDs {
		if !seen[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		if desiredIDs[id] {
			if _, err := runner.Run(ctx, "systemctl", "restart", portAuthUnit+id+".service"); err != nil {
				return fmt.Errorf("start wired 802.1X authenticator for %s: %w", id, err)
			}
			if _, err := runner.Run(ctx, "systemctl", "restart", portAuthEventUnit+id+".service"); err != nil {
				return fmt.Errorf("start wired 802.1X event monitor for %s: %w", id, err)
			}
		} else {
			if _, err := runner.Run(ctx, "systemctl", "stop", portAuthEventUnit+id+".service"); err != nil {
				return fmt.Errorf("stop wired 802.1X event monitor for %s: %w", id, err)
			}
			if _, err := runner.Run(ctx, "systemctl", "stop", portAuthUnit+id+".service"); err != nil {
				return fmt.Errorf("stop wired 802.1X authenticator for %s: %w", id, err)
			}
		}
	}
	return nil
}

func portAuthIDs(cfg layer2.Config) map[string]bool {
	ids := make(map[string]bool, len(cfg.PortAuth))
	for _, policy := range cfg.PortAuth {
		ids[policy.Interface] = true
	}
	return ids
}

func verifyPortAuth(ctx context.Context, runner Runner, cfg layer2.Config) error {
	for _, policy := range cfg.PortAuth {
		for _, unit := range []string{portAuthUnit + policy.Interface + ".service", portAuthEventUnit + policy.Interface + ".service"} {
			if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", unit); err != nil {
				return fmt.Errorf("802.1X service %s is not active: %w", unit, err)
			}
		}
	}
	return nil
}

func snapshotPortAuth(ctx context.Context, runner Runner, cfg layer2.Config) PortAuthSnapshot {
	status := PortAuthSnapshot{Enabled: len(cfg.PortAuth) > 0}
	if !status.Enabled {
		return status
	}
	setResult, setErr := runner.Run(ctx, "nft", "-j", "list", "set", "bridge", "gamebond_8021x", "authenticated_clients")
	clientsByPort := map[string][]string{}
	if setErr == nil {
		clientsByPort, setErr = parsePortAuthClients(setResult.Stdout, cfg)
	}
	if setErr != nil {
		status.Error = "cannot inspect active 802.1X authorizations: " + setErr.Error()
	}
	status.Active = true
	if setErr != nil {
		status.Active = false
	}
	for _, policy := range cfg.PortAuth {
		port := PortAuthPortSnapshot{Interface: policy.Interface}
		for _, iface := range cfg.Interfaces {
			if iface.ID == policy.Interface {
				port.Interface = iface.Name
				break
			}
		}
		port.AuthorizedClients = clientsByPort[port.Interface]
		_, authErr := runner.Run(ctx, "systemctl", "is-active", "--quiet", portAuthUnit+policy.Interface+".service")
		port.AuthenticatorActive = authErr == nil
		_, eventErr := runner.Run(ctx, "systemctl", "is-active", "--quiet", portAuthEventUnit+policy.Interface+".service")
		port.EventMonitorActive = eventErr == nil
		if authErr != nil || eventErr != nil {
			status.Active = false
			port.Error = "authenticator or fail-closed event monitor is inactive"
		} else if setErr != nil {
			port.Error = "cannot inspect active authorizations"
		}
		status.Ports = append(status.Ports, port)
	}
	if !status.Active {
		status.Error = "one or more 802.1X per-port services are inactive"
	}
	return status
}

func parsePortAuthClients(data []byte, cfg layer2.Config) (map[string][]string, error) {
	if len(data) > 128*1024 {
		return nil, errors.New("authorization set output exceeds 128 KiB")
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("invalid nftables JSON: %w", err)
	}
	root, ok := decoded.(map[string]any)
	if !ok {
		return nil, errors.New("nftables output is not an object")
	}
	entries, ok := root["nftables"].([]any)
	if !ok {
		return nil, errors.New("nftables output has no object list")
	}
	setFound := false
	for _, item := range entries {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		set, ok := row["set"].(map[string]any)
		if ok && set["family"] == "bridge" && set["table"] == "gamebond_8021x" && set["name"] == "authenticated_clients" {
			setFound = true
		}
	}
	if !setFound {
		return nil, errors.New("nftables output does not describe the managed authorization set")
	}
	allowedPorts := map[string]bool{}
	for _, policy := range cfg.PortAuth {
		for _, iface := range cfg.Interfaces {
			if iface.ID == policy.Interface {
				allowedPorts[iface.Name] = true
			}
		}
	}
	filterPorts := len(cfg.PortAuth) > 0
	clients := map[string][]string{}
	concatCount, validCount := 0, 0
	var walk func(any)
	walk = func(node any) {
		switch value := node.(type) {
		case map[string]any:
			if concat, ok := value["concat"].([]any); ok {
				concatCount++
				iface, mac := "", ""
				for _, part := range concat {
					if object, ok := part.(map[string]any); ok {
						for key, raw := range object {
							if text, ok := raw.(string); ok {
								if key == "string" || key == "ifname" {
									iface = text
								}
								if key == "ether_addr" {
									mac = strings.ToLower(text)
								}
							}
						}
					}
				}
				parsed, err := net.ParseMAC(mac)
				if validPortAuthIfName(iface) && err == nil && len(parsed) == 6 && parsed[0]&1 == 0 {
					validCount++
					if filterPorts && !allowedPorts[iface] {
						break
					}
					clients[iface] = append(clients[iface], strings.ToLower(parsed.String()))
				}
			}
			for _, child := range value {
				walk(child)
			}
		case []any:
			for _, child := range value {
				walk(child)
			}
		}
	}
	walk(decoded)
	if concatCount != validCount {
		return nil, errors.New("nftables authorization set contains an unrecognized element")
	}
	for iface := range clients {
		sort.Strings(clients[iface])
	}
	return clients, nil
}

// HandlePortAuthEvent applies only known hostapd authorization events. Unknown
// events are ignored; malformed or mismatched known events fail closed.
func HandlePortAuthEvent(ctx context.Context, runner Runner, cfg layer2.Config, iface, event, mac string) error {
	var authorize bool
	switch event {
	case "CTRL-EVENT-EAP-SUCCESS", "CTRL-EVENT-EAP-SUCCESS2":
		authorize = true
	case "CTRL-EVENT-EAP-FAILURE", "AP-STA-DISCONNECTED", "CTRL-EVENT-EAP-STARTED":
		authorize = false
	default:
		return nil
	}
	update, err := layer2.RenderPortAuthClientUpdate(cfg, iface, mac, authorize)
	if err != nil {
		return err
	}
	input, ok := runner.(InputRunner)
	if !ok {
		return errors.New("gateway runner does not support 802.1X nftables updates")
	}
	result, err := runner.Run(ctx, "nft", "-j", "list", "set", "bridge", "gamebond_8021x", "authenticated_clients")
	if err != nil {
		if flushErr := flushAllPortAuth(ctx, input, err); flushErr != nil {
			return flushErr
		}
		return fmt.Errorf("inspect 802.1X client authorization before event: %w", err)
	}
	clients, err := parsePortAuthClients(result.Stdout, cfg)
	if err != nil {
		if flushErr := flushAllPortAuth(ctx, input, err); flushErr != nil {
			return flushErr
		}
		return fmt.Errorf("decode 802.1X client authorization before event: %w", err)
	}
	current := clients[iface]
	normalized, _ := net.ParseMAC(mac)
	station := strings.ToLower(normalized.String())
	if authorize {
		if len(current) > 1 || len(current) == 1 && current[0] != station {
			if flushErr := FlushPortAuthInterface(ctx, runner, iface); flushErr != nil {
				return fmt.Errorf("802.1X exclusive port %s already has an authenticated station and revocation failed: %w", iface, flushErr)
			}
			return fmt.Errorf("802.1X exclusive port %s already has an authenticated station; all authorization was revoked", iface)
		}
		if len(current) == 1 {
			_, err = input.RunInput(ctx, "nft", update, "-exist", "-f", "-")
		} else {
			// Do not use -exist for the first station. The authorized_ports
			// element is the atomic one-station gate: concurrent successes
			// cannot both commit their client element.
			_, err = input.RunInput(ctx, "nft", update, "-f", "-")
		}
	} else {
		if len(current) == 0 || len(current) == 1 && current[0] != station {
			return nil
		}
		if len(current) > 1 {
			if flushErr := FlushPortAuthInterface(ctx, runner, iface); flushErr != nil {
				return fmt.Errorf("revoke invalid multi-station 802.1X state on %s: %w", iface, flushErr)
			}
			return fmt.Errorf("invalid multi-station 802.1X state on exclusive port %s was revoked", iface)
		}
		_, err = input.RunInput(ctx, "nft", update, "-exist", "-f", "-")
	}
	if err != nil {
		if authorize {
			flushErr := FlushPortAuthInterface(ctx, runner, iface)
			if flushErr != nil {
				return fmt.Errorf("update 802.1X client authorization (%v) and fail-closed revocation failed: %w", err, flushErr)
			}
		}
		return fmt.Errorf("update 802.1X client authorization: %w", err)
	}
	return nil
}

func flushPortAuthClients(ctx context.Context, runner Runner, cfg layer2.Config, interfaceID string) error {
	iface, exists := findLayer2Interface(cfg, interfaceID)
	if !exists {
		return fmt.Errorf("interface %q is not configured for 802.1X", interfaceID)
	}
	return FlushPortAuthInterface(ctx, runner, iface.Name)
}

func FlushPortAuthInterface(ctx context.Context, runner Runner, interfaceName string) error {
	if !validPortAuthIfName(interfaceName) {
		return fmt.Errorf("invalid interface name %q", interfaceName)
	}
	input, ok := runner.(InputRunner)
	if !ok {
		return errors.New("gateway runner does not support 802.1X nftables updates")
	}
	result, err := runner.Run(ctx, "nft", "-j", "list", "set", "bridge", "gamebond_8021x", "authenticated_clients")
	if err != nil {
		return flushAllPortAuth(ctx, input, err)
	}
	clients, err := parsePortAuthClients(result.Stdout, layer2.Config{})
	if err != nil {
		return flushAllPortAuth(ctx, input, err)
	}
	var script strings.Builder
	for _, mac := range clients[interfaceName] {
		script.WriteString(fmt.Sprintf("delete element bridge gamebond_8021x authenticated_clients { %q . %s }\n", interfaceName, mac))
	}
	script.WriteString(fmt.Sprintf("delete element bridge gamebond_8021x authorized_ports { %q }\n", interfaceName))
	_, err = input.RunInput(ctx, "nft", []byte(script.String()), "-exist", "-f", "-")
	if err != nil {
		return fmt.Errorf("flush 802.1X authorization state for %s: %w", interfaceName, err)
	}
	return nil
}

func flushAllPortAuth(ctx context.Context, input InputRunner, cause error) error {
	_, err := input.RunInput(ctx, "nft", []byte("flush set bridge gamebond_8021x authenticated_clients\nflush set bridge gamebond_8021x authorized_ports\n"), "-exist", "-f", "-")
	if err != nil {
		return fmt.Errorf("inspect 802.1X authorizations (%v) and flush all fallback failed: %w", cause, err)
	}
	return nil
}

// FlushPortAuthClients revokes the live 802.1X authorizations for one managed
// port. It is used during that port's event-monitor startup and shutdown.
func FlushPortAuthClients(ctx context.Context, runner Runner, cfg layer2.Config, interfaceID string) error {
	return flushPortAuthClients(ctx, runner, cfg, interfaceID)
}

func validPortAuthIfName(value string) bool {
	if len(value) == 0 || len(value) > 15 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.:-", r)) {
			return false
		}
	}
	return true
}

func findLayer2Interface(cfg layer2.Config, id string) (layer2.Interface, bool) {
	for _, iface := range cfg.Interfaces {
		if iface.ID == id {
			return iface, true
		}
	}
	return layer2.Interface{}, false
}
