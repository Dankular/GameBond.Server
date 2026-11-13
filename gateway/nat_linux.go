//go:build linux

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const natTableName = "gamebond_nat"

// NATConfig describes GameBond-owned IPv4 translation rules.
type NATConfig struct {
	Enabled bool      `json:"enabled"`
	Rules   []NATRule `json:"rules,omitempty"`
}

// NATRule supports the requested SNAT, DNAT, masquerade, pool, and 1:1 forms.
type NATRule struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	WANInterfaceID  string `json:"wan_interface_id"`
	Protocol        string `json:"protocol,omitempty"`
	SourceCIDR      string `json:"source_cidr,omitempty"`
	DestinationCIDR string `json:"destination_cidr,omitempty"`
	SourcePort      uint16 `json:"source_port,omitempty"`
	DestinationPort uint16 `json:"destination_port,omitempty"`
	TargetAddress   string `json:"target_address,omitempty"`
	TargetPort      uint16 `json:"target_port,omitempty"`
	PoolStart       string `json:"pool_start,omitempty"`
	PoolEnd         string `json:"pool_end,omitempty"`
	InternalAddress string `json:"internal_address,omitempty"`
	ExternalAddress string `json:"external_address,omitempty"`
}

type NATRuleCounter struct {
	ID      string `json:"id"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type NATSnapshot struct {
	Enabled      bool             `json:"enabled"`
	TablePresent bool             `json:"table_present"`
	Rules        []NATRuleCounter `json:"rules"`
	Error        string           `json:"error,omitempty"`
}

func snapshotNAT(ctx context.Context, runner Runner, enabled bool) NATSnapshot {
	snapshot := NATSnapshot{Enabled: enabled, Rules: []NATRuleCounter{}}
	if !enabled {
		return snapshot
	}
	result, err := runner.Run(ctx, "nft", "-j", "list", "table", "inet", natTableName)
	if err != nil {
		snapshot.Error = err.Error()
		return snapshot
	}
	snapshot.TablePresent = true
	var document struct {
		Nftables []struct {
			Rule *struct {
				Family  string                       `json:"family"`
				Table   string                       `json:"table"`
				Comment string                       `json:"comment"`
				Expr    []map[string]json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(result.Stdout, &document); err != nil {
		snapshot.Error = fmt.Sprintf("parse nft NAT counters: %v", err)
		return snapshot
	}
	counters := make(map[string]*NATRuleCounter)
	for _, row := range document.Nftables {
		if row.Rule == nil || row.Rule.Family != "inet" || row.Rule.Table != natTableName {
			continue
		}
		id := strings.TrimPrefix(row.Rule.Comment, "gamebond:")
		var packets, bytes uint64
		for _, expr := range row.Rule.Expr {
			if raw, ok := expr["comment"]; ok && id == "" {
				var comment string
				if json.Unmarshal(raw, &comment) == nil {
					id = strings.TrimPrefix(comment, "gamebond:")
				}
			}
			if raw, ok := expr["counter"]; ok {
				var counter struct {
					Packets uint64 `json:"packets"`
					Bytes   uint64 `json:"bytes"`
				}
				if json.Unmarshal(raw, &counter) == nil {
					packets += counter.Packets
					bytes += counter.Bytes
				}
			}
		}
		if id == "" {
			continue
		}
		counter := counters[id]
		if counter == nil {
			counter = &NATRuleCounter{ID: id}
			counters[id] = counter
		}
		counter.Packets += packets
		counter.Bytes += bytes
	}
	for _, counter := range counters {
		snapshot.Rules = append(snapshot.Rules, *counter)
	}
	sort.Slice(snapshot.Rules, func(i, j int) bool { return snapshot.Rules[i].ID < snapshot.Rules[j].ID })
	return snapshot
}

func (c NATConfig) Validate(interfaces []Interface) error {
	if len(c.Rules) > 512 {
		return errors.New("rules may contain at most 512 entries")
	}
	byID := make(map[string]Interface, len(interfaces))
	for _, iface := range interfaces {
		byID[iface.ID] = iface
	}
	seen := make(map[string]struct{}, len(c.Rules))
	for i, rule := range c.Rules {
		field := fmt.Sprintf("rules[%d]", i)
		if !validID(rule.ID) {
			return fmt.Errorf("%s.id is invalid", field)
		}
		if _, exists := seen[rule.ID]; exists {
			return fmt.Errorf("%s.id %q is duplicated", field, rule.ID)
		}
		seen[rule.ID] = struct{}{}
		iface, ok := byID[rule.WANInterfaceID]
		if !ok || iface.Role != "wan" {
			return fmt.Errorf("%s.wan_interface_id must reference a configured WAN interface", field)
		}
		if rule.Protocol != "" && rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "icmp" {
			return fmt.Errorf("%s.protocol must be tcp, udp, icmp, or empty", field)
		}
		for name, value := range map[string]string{"source_cidr": rule.SourceCIDR, "destination_cidr": rule.DestinationCIDR} {
			if value == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(value)
			if err != nil || !prefix.Addr().Is4() || prefix.Masked().String() != value {
				return fmt.Errorf("%s.%s must be a canonical IPv4 prefix", field, name)
			}
		}
		if (rule.SourcePort != 0 || rule.DestinationPort != 0 || rule.TargetPort != 0) && rule.Protocol != "tcp" && rule.Protocol != "udp" {
			return fmt.Errorf("%s port matches require tcp or udp", field)
		}
		switch rule.Type {
		case "snat":
			if !validIPv4(rule.TargetAddress) || rule.PoolStart != "" || rule.InternalAddress != "" || rule.ExternalAddress != "" {
				return fmt.Errorf("%s snat requires target_address and no pool or 1:1 fields", field)
			}
		case "dnat":
			if !validIPv4(rule.TargetAddress) || rule.PoolStart != "" || rule.InternalAddress != "" || rule.ExternalAddress != "" {
				return fmt.Errorf("%s dnat requires target_address and no pool or 1:1 fields", field)
			}
			if rule.SourcePort != 0 {
				return fmt.Errorf("%s dnat uses destination_port for the public match and target_port for the internal port", field)
			}
		case "masquerade":
			if rule.TargetAddress != "" || rule.PoolStart != "" || rule.InternalAddress != "" || rule.ExternalAddress != "" || rule.TargetPort != 0 {
				return fmt.Errorf("%s masquerade does not accept address or target port fields", field)
			}
		case "pool":
			if !validIPv4(rule.PoolStart) || !validIPv4(rule.PoolEnd) || ipv4Less(rule.PoolEnd, rule.PoolStart) || rule.TargetAddress != "" || rule.InternalAddress != "" || rule.ExternalAddress != "" {
				return fmt.Errorf("%s pool requires an ordered IPv4 pool_start and pool_end", field)
			}
		case "one_to_one":
			if !validIPv4(rule.InternalAddress) || !validIPv4(rule.ExternalAddress) || rule.TargetAddress != "" || rule.PoolStart != "" || rule.PoolEnd != "" || rule.SourceCIDR != "" || rule.DestinationCIDR != "" || rule.SourcePort != 0 || rule.DestinationPort != 0 || rule.TargetPort != 0 || rule.Protocol != "" {
				return fmt.Errorf("%s one_to_one requires internal_address and external_address and does not accept protocol or port fields", field)
			}
		default:
			return fmt.Errorf("%s.type must be snat, dnat, masquerade, pool, or one_to_one", field)
		}
		if rule.Type != "dnat" && rule.TargetPort != 0 {
			return fmt.Errorf("%s.target_port is only valid for dnat", field)
		}
	}
	if !c.Enabled && len(c.Rules) != 0 {
		return errors.New("rules must be empty when NAT is disabled")
	}
	return nil
}

func validIPv4(value string) bool {
	addr, err := netip.ParseAddr(value)
	return err == nil && addr.Is4() && !addr.IsUnspecified() && !addr.IsMulticast()
}

func ipv4Less(a, b string) bool {
	left, _ := netip.ParseAddr(a)
	right, _ := netip.ParseAddr(b)
	return left.Compare(right) <= 0
}

// renderNATScript returns one atomic nft transaction for the owned table.
func renderNATScript(cfg NATConfig, interfaces []Interface, replace bool) (string, error) {
	if !cfg.Enabled && !replace {
		return "", nil
	}
	if !cfg.Enabled {
		return "delete table inet " + natTableName + "\n", nil
	}
	wanNames := make(map[string]string, len(interfaces))
	for _, iface := range interfaces {
		if iface.Role == "wan" {
			wanNames[iface.ID] = iface.Name
		}
	}
	var b strings.Builder
	if replace {
		b.WriteString("delete table inet " + natTableName + "\n")
	}
	b.WriteString("add table inet " + natTableName + "\n")
	b.WriteString("add chain inet " + natTableName + " prerouting { type nat hook prerouting priority dstnat; policy accept; }\n")
	b.WriteString("add chain inet " + natTableName + " postrouting { type nat hook postrouting priority srcnat; policy accept; }\n")
	for _, rule := range cfg.Rules {
		wan := wanNames[rule.WANInterfaceID]
		if wan == "" {
			return "", fmt.Errorf("NAT rule %q references missing WAN", rule.ID)
		}
		comment := " comment \"gamebond:" + rule.ID + "\""
		if rule.Type == "one_to_one" {
			b.WriteString("add rule inet " + natTableName + " postrouting oifname \"" + wan + "\" ip saddr " + rule.InternalAddress + " counter" + comment + " snat to " + rule.ExternalAddress + "\n")
			b.WriteString("add rule inet " + natTableName + " prerouting iifname \"" + wan + "\" ip daddr " + rule.ExternalAddress + " counter" + comment + " dnat to " + rule.InternalAddress + "\n")
			continue
		}
		var match strings.Builder
		if rule.Type == "dnat" {
			match.WriteString("add rule inet " + natTableName + " prerouting iifname \"" + wan + "\"")
		} else {
			match.WriteString("add rule inet " + natTableName + " postrouting oifname \"" + wan + "\"")
		}
		if rule.SourceCIDR != "" {
			match.WriteString(" ip saddr " + rule.SourceCIDR)
		}
		if rule.DestinationCIDR != "" {
			match.WriteString(" ip daddr " + rule.DestinationCIDR)
		}
		if rule.Protocol != "" {
			match.WriteString(" meta l4proto " + rule.Protocol)
			if rule.SourcePort != 0 {
				match.WriteString(" " + rule.Protocol + " sport " + strconv.Itoa(int(rule.SourcePort)))
			}
			if rule.DestinationPort != 0 {
				match.WriteString(" " + rule.Protocol + " dport " + strconv.Itoa(int(rule.DestinationPort)))
			}
		}
		match.WriteString(" counter" + comment)
		switch rule.Type {
		case "snat":
			match.WriteString(" snat to " + rule.TargetAddress)
		case "dnat":
			match.WriteString(" dnat to " + rule.TargetAddress)
			if rule.TargetPort != 0 {
				match.WriteString(":" + strconv.Itoa(int(rule.TargetPort)))
			}
		case "masquerade":
			match.WriteString(" masquerade")
		case "pool":
			match.WriteString(" snat to " + rule.PoolStart + "-" + rule.PoolEnd)
		}
		match.WriteString("\n")
		b.WriteString(match.String())
	}
	return b.String(), nil
}

func natTableExists(ctx context.Context, runner Runner) (bool, error) {
	result, err := runner.Run(ctx, "nft", "-j", "list", "tables")
	if err != nil {
		return false, err
	}
	var document struct {
		Nftables []struct {
			Table *struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(result.Stdout, &document); err != nil {
		return false, fmt.Errorf("parse nft table inventory: %w", err)
	}
	for _, row := range document.Nftables {
		if row.Table != nil && row.Table.Family == "inet" && row.Table.Name == natTableName {
			return true, nil
		}
	}
	return false, nil
}

func applyNATScript(ctx context.Context, runner Runner, script string, check bool) error {
	if strings.TrimSpace(script) == "" {
		return nil
	}
	path := filepath.Join("/run/gamebond", "nat-transaction.nft")
	file, err := os.CreateTemp(filepath.Dir(path), ".nat-*.nft")
	if err != nil {
		return fmt.Errorf("create temporary NAT transaction: %w", err)
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.WriteString(script); err != nil {
		_ = file.Close()
		return fmt.Errorf("write NAT transaction: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync NAT transaction: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close NAT transaction: %w", err)
	}
	args := []string{"-f", name}
	if check {
		args = []string{"-c", "-f", name}
	}
	if _, err := runner.Run(ctx, "nft", args...); err != nil {
		return err
	}
	return nil
}

func sortedNATRuleIDs(rules []NATRule) []string {
	ids := make([]string, 0, len(rules))
	for _, rule := range rules {
		ids = append(ids, rule.ID)
	}
	sort.Strings(ids)
	return ids
}
