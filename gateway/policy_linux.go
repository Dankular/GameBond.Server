//go:build linux

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type RoutingConfig struct {
	Enabled  bool          `json:"enabled"`
	Policies []RoutePolicy `json:"policies,omitempty"`
}

type RoutePolicy struct {
	ID                string `json:"id"`
	SourceCIDR        string `json:"source_cidr"`
	DestinationCIDR   string `json:"destination_cidr,omitempty"`
	EgressInterfaceID string `json:"egress_interface_id"`
	Gateway           string `json:"gateway,omitempty"`
	Table             uint32 `json:"table"`
	Priority          uint32 `json:"priority"`
}

type RoutePolicyStatus struct {
	ID     string `json:"id"`
	Active bool   `json:"active"`
	Rule   bool   `json:"rule_present"`
	Route  bool   `json:"route_present"`
	Error  string `json:"error,omitempty"`
}

type RoutingSnapshot struct {
	Enabled  bool                `json:"enabled"`
	Policies []RoutePolicyStatus `json:"policies"`
}

func (c RoutingConfig) Validate(interfaces []Interface) error {
	if len(c.Policies) > 128 {
		return errors.New("policies may contain at most 128 entries")
	}
	byID := make(map[string]Interface, len(interfaces))
	for _, iface := range interfaces {
		byID[iface.ID] = iface
	}
	ids, tables, priorities := map[string]bool{}, map[uint32]bool{}, map[uint32]bool{}
	for i, policy := range c.Policies {
		field := fmt.Sprintf("policies[%d]", i)
		if !validID(policy.ID) || ids[policy.ID] {
			return fmt.Errorf("%s.id is invalid or duplicated", field)
		}
		ids[policy.ID] = true
		source, err := netip.ParsePrefix(policy.SourceCIDR)
		if err != nil || source != source.Masked() {
			return fmt.Errorf("%s.source_cidr must be a canonical IPv4 or IPv6 prefix", field)
		}
		if policy.DestinationCIDR != "" {
			destination, err := netip.ParsePrefix(policy.DestinationCIDR)
			if err != nil || destination != destination.Masked() || destination.Addr().Is4() != source.Addr().Is4() {
				return fmt.Errorf("%s.destination_cidr must be canonical and use the source prefix address family", field)
			}
		}
		iface, ok := byID[policy.EgressInterfaceID]
		if !ok || (iface.Role != "wan" && iface.Role != "vpn") {
			return fmt.Errorf("%s.egress_interface_id must reference a configured WAN or VPN interface", field)
		}
		if iface.Role == "wan" && policy.Gateway == "" {
			return fmt.Errorf("%s.gateway is required for an Ethernet WAN policy", field)
		}
		if policy.Gateway != "" {
			gateway, err := netip.ParseAddr(policy.Gateway)
			if err != nil || gateway.IsUnspecified() || gateway.IsMulticast() || gateway.Is4() != source.Addr().Is4() {
				return fmt.Errorf("%s.gateway must be a unicast address in the policy address family", field)
			}
		}
		if policy.Table < 10000 || policy.Table > 19999 || tables[policy.Table] {
			return fmt.Errorf("%s.table must be unique and in the reserved range 10000..19999", field)
		}
		if policy.Priority < 10000 || policy.Priority > 29999 || priorities[policy.Priority] {
			return fmt.Errorf("%s.priority must be unique and in the reserved range 10000..29999", field)
		}
		tables[policy.Table], priorities[policy.Priority] = true, true
	}
	if !c.Enabled && len(c.Policies) != 0 {
		return errors.New("policies must be empty when routing is disabled")
	}
	return nil
}

type QoSConfig struct {
	Enabled    bool           `json:"enabled"`
	Interfaces []QoSInterface `json:"interfaces,omitempty"`
}

type QoSInterface struct {
	InterfaceID string     `json:"interface_id"`
	TotalKbit   uint32     `json:"total_kbit"`
	Classes     []QoSClass `json:"classes"`
}

type QoSClass struct {
	ID       string `json:"id"`
	DSCP     uint8  `json:"dscp"`
	RateKbit uint32 `json:"rate_kbit"`
	CeilKbit uint32 `json:"ceil_kbit"`
	Priority uint8  `json:"priority"`
}

func (c QoSConfig) Validate(interfaces []Interface) error {
	if len(c.Interfaces) > 64 {
		return errors.New("interfaces may contain at most 64 entries")
	}
	byID := make(map[string]Interface, len(interfaces))
	for _, iface := range interfaces {
		byID[iface.ID] = iface
	}
	seenInterfaces := map[string]bool{}
	for i, iface := range c.Interfaces {
		field := fmt.Sprintf("interfaces[%d]", i)
		managed, ok := byID[iface.InterfaceID]
		if !ok || seenInterfaces[iface.InterfaceID] {
			return fmt.Errorf("%s.interface_id is unknown or duplicated", field)
		}
		seenInterfaces[iface.InterfaceID] = true
		if iface.TotalKbit < 8 || iface.TotalKbit > 10_000_000 {
			return fmt.Errorf("%s.total_kbit must be 8..10000000", field)
		}
		if len(iface.Classes) > 63 {
			return fmt.Errorf("%s.classes may contain at most 63 entries", field)
		}
		if managed.Role == "vpn" && iface.TotalKbit == 0 {
			return fmt.Errorf("%s requires a measurable egress rate", field)
		}
		ids, dscps := map[string]bool{}, map[uint8]bool{}
		var guaranteed uint64
		for j, class := range iface.Classes {
			classField := fmt.Sprintf("%s.classes[%d]", field, j)
			if !validID(class.ID) || ids[class.ID] {
				return fmt.Errorf("%s.id is invalid or duplicated", classField)
			}
			if class.DSCP > 63 || dscps[class.DSCP] {
				return fmt.Errorf("%s.dscp must be unique and in 0..63", classField)
			}
			if class.RateKbit < 1 || class.CeilKbit < class.RateKbit || class.CeilKbit > iface.TotalKbit || class.Priority > 7 {
				return fmt.Errorf("%s requires 1 <= rate <= ceil <= total_kbit and priority 0..7", classField)
			}
			ids[class.ID], dscps[class.DSCP] = true, true
			guaranteed += uint64(class.RateKbit)
		}
		if guaranteed+1 > uint64(iface.TotalKbit) {
			return fmt.Errorf("%s class guaranteed rates exceed total_kbit", field)
		}
	}
	if !c.Enabled && len(c.Interfaces) != 0 {
		return errors.New("interfaces must be empty when QoS is disabled")
	}
	return nil
}

type ipRuleRow struct {
	Priority uint32          `json:"priority"`
	Source   string          `json:"src"`
	Dest     string          `json:"dst"`
	Table    json.RawMessage `json:"table"`
}

type ipRouteRow struct {
	Type    string `json:"type"`
	Dev     string `json:"dev"`
	Gateway string `json:"gateway"`
}

func policyFamily(policy RoutePolicy) string {
	prefix, _ := netip.ParsePrefix(policy.SourceCIDR)
	if prefix.Addr().Is6() {
		return "-6"
	}
	return "-4"
}

func policyRuleArgs(policy RoutePolicy) []string {
	args := []string{"rule", "add", "priority", strconv.FormatUint(uint64(policy.Priority), 10), "from", policy.SourceCIDR}
	if policy.DestinationCIDR != "" {
		args = append(args, "to", policy.DestinationCIDR)
	}
	return append(args, "table", strconv.FormatUint(uint64(policy.Table), 10))
}

func policyRuleDeleteArgs(policy RoutePolicy) []string {
	args := []string{"rule", "del", "priority", strconv.FormatUint(uint64(policy.Priority), 10), "from", policy.SourceCIDR}
	if policy.DestinationCIDR != "" {
		args = append(args, "to", policy.DestinationCIDR)
	}
	return append(args, "table", strconv.FormatUint(uint64(policy.Table), 10))
}

func policyRouteArgs(policy RoutePolicy, action string, iface Interface) []string {
	args := []string{"route", action, "default"}
	if policy.Gateway != "" {
		args = append(args, "via", policy.Gateway)
	}
	args = append(args, "dev", iface.Name, "table", strconv.FormatUint(uint64(policy.Table), 10))
	return args
}

func readIPRules(ctx context.Context, runner Runner, family string) ([]ipRuleRow, error) {
	result, err := runner.Run(ctx, "ip", family, "-j", "rule", "show")
	if err != nil {
		return nil, err
	}
	var rows []ipRuleRow
	if err := json.Unmarshal(result.Stdout, &rows); err != nil {
		return nil, fmt.Errorf("parse %s routing policy rules: %w", family, err)
	}
	return rows, nil
}

func readIPRoutes(ctx context.Context, runner Runner, policy RoutePolicy) ([]ipRouteRow, error) {
	result, err := runner.Run(ctx, "ip", policyFamily(policy), "-j", "route", "show", "table", strconv.FormatUint(uint64(policy.Table), 10))
	if err != nil {
		return nil, err
	}
	var rows []ipRouteRow
	if err := json.Unmarshal(result.Stdout, &rows); err != nil {
		return nil, fmt.Errorf("parse route table %d: %w", policy.Table, err)
	}
	return rows, nil
}

func tableNumber(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var number uint32
	if json.Unmarshal(raw, &number) == nil {
		return strconv.FormatUint(uint64(number), 10)
	}
	var name string
	_ = json.Unmarshal(raw, &name)
	return name
}

func policyRulePresent(rows []ipRuleRow, policy RoutePolicy) bool {
	wantDest := policy.DestinationCIDR
	if wantDest == "" {
		wantDest = "all"
	}
	for _, row := range rows {
		gotSource := row.Source
		if gotSource == "" {
			gotSource = "all"
		}
		gotDest := row.Dest
		if gotDest == "" {
			gotDest = "all"
		}
		if row.Priority == policy.Priority && gotSource == policy.SourceCIDR && gotDest == wantDest && tableNumber(row.Table) == strconv.FormatUint(uint64(policy.Table), 10) {
			return true
		}
	}
	return false
}

func validateRoutingHost(ctx context.Context, runner Runner, current, desired Config) error {
	if !current.Routing.Enabled && !desired.Routing.Enabled {
		return nil
	}
	if !runner.Available("ip") {
		return errors.New("iproute2 is required for policy routing")
	}
	currentByPriority := make(map[uint32]RoutePolicy, len(current.Routing.Policies))
	currentByTable := make(map[uint32]RoutePolicy, len(current.Routing.Policies))
	for _, policy := range current.Routing.Policies {
		currentByPriority[policy.Priority] = policy
		currentByTable[policy.Table] = policy
	}
	for _, policy := range desired.Routing.Policies {
		rows, err := readIPRules(ctx, runner, policyFamily(policy))
		if err != nil {
			return fmt.Errorf("inspect policy rules for %s: %w", policy.ID, err)
		}
		for _, row := range rows {
			if row.Priority != policy.Priority || policyRulePresent([]ipRuleRow{row}, policy) {
				continue
			}
			if previous, owned := currentByPriority[policy.Priority]; !owned || !policyRulePresent([]ipRuleRow{row}, previous) {
				return fmt.Errorf("policy %q priority %d conflicts with an unmanaged routing rule", policy.ID, policy.Priority)
			}
		}
		routes, err := readIPRoutes(ctx, runner, policy)
		if err != nil {
			return fmt.Errorf("inspect policy route table %d: %w", policy.Table, err)
		}
		if len(routes) != 0 {
			if _, owned := currentByTable[policy.Table]; !owned {
				return fmt.Errorf("policy %q route table %d is not empty and is not owned by GameBond", policy.ID, policy.Table)
			}
		}
	}
	return nil
}

func applyRoutingTransition(ctx context.Context, runner Runner, from, to Config) error {
	toByID := make(map[string]RoutePolicy, len(to.Routing.Policies))
	interfaces := make(map[string]Interface, len(to.Interfaces))
	for _, iface := range to.Interfaces {
		interfaces[iface.ID] = iface
	}
	for _, policy := range to.Routing.Policies {
		toByID[policy.ID] = policy
	}
	removed := make([]RoutePolicy, 0)
	for _, old := range from.Routing.Policies {
		if next, ok := toByID[old.ID]; ok && next == old {
			continue
		}
		rows, err := readIPRules(ctx, runner, policyFamily(old))
		if err != nil {
			return err
		}
		if policyRulePresent(rows, old) {
			args := append([]string{policyFamily(old)}, policyRuleDeleteArgs(old)...)
			if _, err := runner.Run(ctx, "ip", args...); err != nil {
				return fmt.Errorf("remove policy rule %s: %w", old.ID, err)
			}
		}
		removed = append(removed, old)
	}
	for _, policy := range to.Routing.Policies {
		iface, ok := interfaces[policy.EgressInterfaceID]
		if !ok {
			return fmt.Errorf("policy %s egress interface is missing", policy.ID)
		}
		args := append([]string{policyFamily(policy)}, policyRouteArgs(policy, "replace", iface)...)
		if _, err := runner.Run(ctx, "ip", args...); err != nil {
			return fmt.Errorf("install policy route %s: %w", policy.ID, err)
		}
		rows, err := readIPRules(ctx, runner, policyFamily(policy))
		if err != nil {
			return err
		}
		if !policyRulePresent(rows, policy) {
			args := append([]string{policyFamily(policy)}, policyRuleArgs(policy)...)
			if _, err := runner.Run(ctx, "ip", args...); err != nil {
				return fmt.Errorf("install policy rule %s: %w", policy.ID, err)
			}
		}
	}
	for _, old := range removed {
		if _, reused := to.Routing.PoliciesForTable(old.Table); reused {
			continue
		}
		iface, ok := from.InterfacesByID(old.EgressInterfaceID)
		if !ok {
			return fmt.Errorf("previous policy %s egress interface is missing", old.ID)
		}
		args := append([]string{policyFamily(old)}, policyRouteArgs(old, "del", iface)...)
		if _, err := runner.Run(ctx, "ip", args...); err != nil && !strings.Contains(strings.ToLower(err.Error()), "no such process") {
			return fmt.Errorf("remove policy route %s: %w", old.ID, err)
		}
	}
	families := map[string]bool{}
	for _, policy := range append(append([]RoutePolicy(nil), from.Routing.Policies...), to.Routing.Policies...) {
		families[policyFamily(policy)] = true
	}
	for family := range families {
		if _, err := runner.Run(ctx, "ip", family, "route", "flush", "cache"); err != nil {
			return fmt.Errorf("flush %s route cache: %w", family, err)
		}
	}
	return nil
}

func (c RoutingConfig) PoliciesForTable(table uint32) (RoutePolicy, bool) {
	for _, policy := range c.Policies {
		if policy.Table == table {
			return policy, true
		}
	}
	return RoutePolicy{}, false
}

func (c Config) InterfacesByID(id string) (Interface, bool) {
	for _, iface := range c.Interfaces {
		if iface.ID == id {
			return iface, true
		}
	}
	return Interface{}, false
}

func verifyRouting(ctx context.Context, runner Runner, cfg Config) error {
	for _, policy := range cfg.Routing.Policies {
		rows, err := readIPRules(ctx, runner, policyFamily(policy))
		if err != nil {
			return err
		}
		if !policyRulePresent(rows, policy) {
			return fmt.Errorf("policy rule %s is not active", policy.ID)
		}
		routes, err := readIPRoutes(ctx, runner, policy)
		if err != nil {
			return err
		}
		iface, ok := cfg.InterfacesByID(policy.EgressInterfaceID)
		if !ok {
			return fmt.Errorf("policy %s interface disappeared", policy.ID)
		}
		active := false
		for _, route := range routes {
			if (route.Type == "" || route.Type == "unicast") && route.Dev == iface.Name && route.Gateway == policy.Gateway {
				active = true
			}
		}
		if !active {
			return fmt.Errorf("policy route %s is not active on %s", policy.ID, iface.Name)
		}
	}
	return nil
}

func snapshotRouting(ctx context.Context, runner Runner, cfg Config) RoutingSnapshot {
	snapshot := RoutingSnapshot{Enabled: cfg.Routing.Enabled, Policies: []RoutePolicyStatus{}}
	if !cfg.Routing.Enabled {
		return snapshot
	}
	for _, policy := range cfg.Routing.Policies {
		state := RoutePolicyStatus{ID: policy.ID}
		rules, err := readIPRules(ctx, runner, policyFamily(policy))
		if err != nil {
			state.Error = err.Error()
			snapshot.Policies = append(snapshot.Policies, state)
			continue
		}
		state.Rule = policyRulePresent(rules, policy)
		routes, err := readIPRoutes(ctx, runner, policy)
		if err != nil {
			state.Error = err.Error()
			snapshot.Policies = append(snapshot.Policies, state)
			continue
		}
		iface, ok := cfg.InterfacesByID(policy.EgressInterfaceID)
		if !ok {
			state.Error = "configured egress interface is missing"
		} else {
			for _, route := range routes {
				if (route.Type == "" || route.Type == "unicast") && route.Dev == iface.Name && route.Gateway == policy.Gateway {
					state.Route = true
				}
			}
		}
		state.Active = state.Rule && state.Route
		snapshot.Policies = append(snapshot.Policies, state)
	}
	return snapshot
}
