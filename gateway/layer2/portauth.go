package layer2

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

const (
	portAuthTableName   = "gamebond_8021x"
	portAuthTableMarker = "gamebond-8021x:v1"
)

// RenderPortAuthTable creates a fail-closed bridge filter for 802.1X-managed
// ports. Ingress is bound to an authenticated (port, MAC) pair. Egress unicast
// is bound to the same pair, while group traffic is admitted only after the
// explicitly-exclusive physical port has one authorized station.
func RenderPortAuthTable(cfg Config) ([]byte, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if len(cfg.PortAuth) == 0 {
		return nil, nil
	}
	interfaces := make(map[string]string, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		interfaces[iface.ID] = iface.Name
	}
	ports := make([]string, 0, len(cfg.PortAuth))
	for _, policy := range cfg.PortAuth {
		ports = append(ports, interfaces[policy.Interface])
	}
	sort.Strings(ports)
	var script strings.Builder
	fmt.Fprintf(&script, "add table bridge %s { comment \"%s\"; }\n", portAuthTableName, portAuthTableMarker)
	fmt.Fprintf(&script, "add set bridge %s protected_ports { type ifname; elements = { %s }; }\n", portAuthTableName, quoteIfNames(ports))
	fmt.Fprintf(&script, "add set bridge %s authorized_ports { type ifname; }\n", portAuthTableName)
	fmt.Fprintf(&script, "add set bridge %s authenticated_clients { type ifname . ether_addr; }\n", portAuthTableName)
	fmt.Fprintf(&script, "add chain bridge %s input { type filter hook input priority -300; policy accept; }\n", portAuthTableName)
	fmt.Fprintf(&script, "add chain bridge %s forward { type filter hook forward priority -300; policy accept; }\n", portAuthTableName)
	fmt.Fprintf(&script, "add chain bridge %s egress { type filter hook postrouting priority -300; policy accept; }\n", portAuthTableName)
	fmt.Fprintf(&script, "add rule bridge %s input iifname @protected_ports ether type 0x888e accept comment \"gamebond-8021x:eapol-host\"\n", portAuthTableName)
	fmt.Fprintf(&script, "add rule bridge %s input iifname . ether saddr @authenticated_clients accept comment \"gamebond-8021x:authorized-host\"\n", portAuthTableName)
	fmt.Fprintf(&script, "add rule bridge %s input iifname @protected_ports drop comment \"gamebond-8021x:unauthorized-host\"\n", portAuthTableName)
	fmt.Fprintf(&script, "add rule bridge %s forward iifname @protected_ports ether type 0x888e accept comment \"gamebond-8021x:eapol-in\"\n", portAuthTableName)
	fmt.Fprintf(&script, "add rule bridge %s forward iifname . ether saddr @authenticated_clients accept comment \"gamebond-8021x:authorized-in\"\n", portAuthTableName)
	fmt.Fprintf(&script, "add rule bridge %s forward iifname @protected_ports drop comment \"gamebond-8021x:unauthorized-in\"\n", portAuthTableName)
	fmt.Fprintf(&script, "add rule bridge %s egress oifname @protected_ports ether type 0x888e accept comment \"gamebond-8021x:eapol-out\"\n", portAuthTableName)
	fmt.Fprintf(&script, "add rule bridge %s egress oifname . ether daddr @authenticated_clients accept comment \"gamebond-8021x:authorized-out\"\n", portAuthTableName)
	fmt.Fprintf(&script, "add rule bridge %s egress oifname @authorized_ports ether daddr & 01:00:00:00:00:00 != 00:00:00:00:00:00 accept comment \"gamebond-8021x:authorized-group-out\"\n", portAuthTableName)
	fmt.Fprintf(&script, "add rule bridge %s egress oifname @protected_ports drop comment \"gamebond-8021x:unauthorized-out\"\n", portAuthTableName)
	return []byte(script.String()), nil
}

func portAuthRuleComments() []string {
	return []string{
		"gamebond-8021x:authorized-group-out",
		"gamebond-8021x:authorized-host",
		"gamebond-8021x:authorized-in",
		"gamebond-8021x:authorized-out",
		"gamebond-8021x:eapol-host",
		"gamebond-8021x:eapol-in",
		"gamebond-8021x:eapol-out",
		"gamebond-8021x:unauthorized-host",
		"gamebond-8021x:unauthorized-in",
		"gamebond-8021x:unauthorized-out",
	}
}

func portAuthRuleChains() map[string]string {
	return map[string]string{
		"gamebond-8021x:eapol-host":           "input",
		"gamebond-8021x:authorized-host":      "input",
		"gamebond-8021x:unauthorized-host":    "input",
		"gamebond-8021x:eapol-in":             "forward",
		"gamebond-8021x:authorized-in":        "forward",
		"gamebond-8021x:unauthorized-in":      "forward",
		"gamebond-8021x:eapol-out":            "egress",
		"gamebond-8021x:authorized-out":       "egress",
		"gamebond-8021x:authorized-group-out": "egress",
		"gamebond-8021x:unauthorized-out":     "egress",
	}
}

// RenderPortAuthClientUpdate returns one atomic set operation for a validated
// hostapd authentication event. The pair must be configured as a protected port.
func RenderPortAuthClientUpdate(cfg Config, interfaceName, mac string, authorized bool) ([]byte, error) {
	if _, err := RenderPortAuthTable(cfg); err != nil {
		return nil, err
	}
	allowed := false
	for _, policy := range cfg.PortAuth {
		iface, ok := findInterface(cfg.Interfaces, policy.Interface)
		if ok && iface.Name == interfaceName {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("interface %q is not configured for 802.1X", interfaceName)
	}
	parsed, err := net.ParseMAC(mac)
	if err != nil || len(parsed) != 6 || parsed[0]&1 != 0 {
		return nil, errors.New("802.1X station address must be a unicast Ethernet MAC")
	}
	operation := "delete"
	if authorized {
		operation = "add"
	}
	return []byte(fmt.Sprintf("%s element bridge %s authenticated_clients { %q . %s }\n%s element bridge %s authorized_ports { %q }\n", operation, portAuthTableName, interfaceName, strings.ToLower(parsed.String()), operation, portAuthTableName, interfaceName)), nil
}

// RenderPortAuthHostapdConfig renders the wired hostapd authenticator config
// for one protected port. The shared secret is supplied by the privileged
// gateway after validating its root-only credential file.
func RenderPortAuthHostapdConfig(cfg Config, interfaceID, secret string) ([]byte, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	var policy *PortAuth
	for i := range cfg.PortAuth {
		if cfg.PortAuth[i].Interface == interfaceID {
			policy = &cfg.PortAuth[i]
			break
		}
	}
	if policy == nil {
		return nil, fmt.Errorf("interface %q is not configured for 802.1X", interfaceID)
	}
	if len(secret) < 16 || len(secret) > 128 {
		return nil, errors.New("802.1X RADIUS secret must contain 16..128 safe ASCII characters")
	}
	for _, r := range secret {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!@%_+=,:./-", r)) {
			return nil, errors.New("802.1X RADIUS secret contains unsupported characters")
		}
	}
	iface, ok := findInterface(cfg.Interfaces, interfaceID)
	if !ok {
		return nil, fmt.Errorf("interface %q is not configured", interfaceID)
	}
	var output strings.Builder
	fmt.Fprintf(&output, "# GameBond managed wired 802.1X port %s v1\n", interfaceID)
	output.WriteString("driver=wired\nieee8021x=1\nuse_pae_group_addr=1\n")
	fmt.Fprintf(&output, "interface=%s\n", iface.Name)
	fmt.Fprintf(&output, "ctrl_interface=DIR=/run/gamebond-hostapd/%s GROUP=0\n", interfaceID)
	fmt.Fprintf(&output, "nas_identifier=%s\n", policy.NASID)
	fmt.Fprintf(&output, "own_ip_addr=%s\n", policy.NASAddress)
	fmt.Fprintf(&output, "auth_server_addr=%s\nauth_server_port=%d\nauth_server_shared_secret=%s\n", policy.RadiusServer, policy.RadiusPort, secret)
	if policy.ReauthSeconds > 0 {
		fmt.Fprintf(&output, "eap_reauth_period=%d\n", policy.ReauthSeconds)
	}
	return []byte(output.String()), nil
}

func quoteIfNames(values []string) string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = fmt.Sprintf("%q", value)
	}
	return strings.Join(quoted, ", ")
}
