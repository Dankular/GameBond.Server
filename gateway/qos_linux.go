//go:build linux

package gateway

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
)

const gameBondQoSHandle = "7e:"

type tcQdiscRow struct {
	Kind   string `json:"kind"`
	Handle string `json:"handle"`
	Root   bool   `json:"root"`
}

type QoSClassStatus struct {
	ID      string `json:"id,omitempty"`
	ClassID string `json:"class_id"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type QoSInterfaceStatus struct {
	InterfaceID string           `json:"interface_id"`
	Active      bool             `json:"active"`
	Classes     []QoSClassStatus `json:"classes"`
	Error       string           `json:"error,omitempty"`
}

type QoSSnapshot struct {
	Enabled    bool                 `json:"enabled"`
	Interfaces []QoSInterfaceStatus `json:"interfaces"`
}

func rootQdiscs(ctx context.Context, runner Runner, name string) ([]tcQdiscRow, error) {
	result, err := runner.Run(ctx, "tc", "-j", "qdisc", "show", "dev", name)
	if err != nil {
		return nil, err
	}
	var rows []tcQdiscRow
	if err := json.Unmarshal(result.Stdout, &rows); err != nil {
		return nil, fmt.Errorf("parse qdisc state for %s: %w", name, err)
	}
	return rows, nil
}

func validateQoSQdisc(rows []tcQdiscRow, managed bool) error {
	for _, qdisc := range rows {
		if !qdisc.Root {
			continue
		}
		if qdisc.Kind == "noqueue" || (managed && qdisc.Kind == "htb" && qdisc.Handle == gameBondQoSHandle) {
			return nil
		}
		return fmt.Errorf("root qdisc %s (%s) is unmanaged; refusing to replace it", qdisc.Kind, qdisc.Handle)
	}
	return errors.New("cannot identify interface root qdisc")
}

func validateQoSHost(ctx context.Context, runner Runner, current, desired Config) error {
	if !current.QoS.Enabled && !desired.QoS.Enabled {
		return nil
	}
	if !runner.Available("tc") {
		return errors.New("iproute2 tc is required for QoS")
	}
	managed := map[string]bool{}
	for _, item := range current.QoS.Interfaces {
		managed[item.InterfaceID] = true
	}
	interfaces := make(map[string]Interface, len(desired.Interfaces))
	for _, iface := range desired.Interfaces {
		interfaces[iface.ID] = iface
	}
	for _, item := range desired.QoS.Interfaces {
		iface, ok := interfaces[item.InterfaceID]
		if !ok {
			return fmt.Errorf("QoS interface %s is not configured", item.InterfaceID)
		}
		rows, err := rootQdiscs(ctx, runner, iface.Name)
		if err != nil {
			return err
		}
		if err := validateQoSQdisc(rows, managed[item.InterfaceID]); err != nil {
			return fmt.Errorf("QoS interface %s: %w", item.InterfaceID, err)
		}
	}
	newNames := map[string]Interface{}
	oldNames := map[string]Interface{}
	newQoS := qosConfigByInterface(desired.QoS)
	for _, iface := range desired.Interfaces {
		newNames[iface.ID] = iface
	}
	for _, iface := range current.Interfaces {
		oldNames[iface.ID] = iface
	}
	for _, old := range current.QoS.Interfaces {
		oldIface, ok := oldNames[old.InterfaceID]
		if !ok {
			return fmt.Errorf("previous QoS interface %s is missing from stored config", old.InterfaceID)
		}
		if _, retained := newQoS[old.InterfaceID]; retained && newNames[old.InterfaceID].Name == oldIface.Name {
			continue
		}
		rows, err := rootQdiscs(ctx, runner, oldIface.Name)
		if err != nil {
			return err
		}
		if err := validateQoSQdisc(rows, true); err != nil {
			return fmt.Errorf("previous QoS interface %s: %w", old.InterfaceID, err)
		}
	}
	return nil
}

func qosCommands(config QoSInterface, iface Interface) [][]string {
	classes := append([]QoSClass(nil), config.Classes...)
	sort.Slice(classes, func(i, j int) bool { return classes[i].ID < classes[j].ID })
	commands := [][]string{{"qdisc", "replace", "dev", iface.Name, "root", "handle", gameBondQoSHandle, "htb", "default", "4095", "r2q", "10"}}
	commands = append(commands, []string{"class", "replace", "dev", iface.Name, "parent", gameBondQoSHandle, "classid", "7e:1", "htb", "rate", strconv.FormatUint(uint64(config.TotalKbit), 10) + "kbit", "ceil", strconv.FormatUint(uint64(config.TotalKbit), 10) + "kbit"})
	commands = append(commands, []string{"class", "replace", "dev", iface.Name, "parent", "7e:1", "classid", "7e:fff", "htb", "rate", "1kbit", "ceil", strconv.FormatUint(uint64(config.TotalKbit), 10) + "kbit", "prio", "7"})
	for i, class := range classes {
		minor := i + 2
		classID := "7e:" + strconv.Itoa(minor)
		rate := strconv.FormatUint(uint64(class.RateKbit), 10) + "kbit"
		ceil := strconv.FormatUint(uint64(class.CeilKbit), 10) + "kbit"
		commands = append(commands, []string{"class", "replace", "dev", iface.Name, "parent", "7e:1", "classid", classID, "htb", "rate", rate, "ceil", ceil, "prio", strconv.Itoa(int(class.Priority))})
		value := "0x" + hex.EncodeToString([]byte{class.DSCP << 2}) + "/0xfc"
		for _, protocol := range []string{"ip", "ipv6"} {
			commands = append(commands, []string{"filter", "replace", "dev", iface.Name, "protocol", protocol, "parent", gameBondQoSHandle, "prio", strconv.Itoa(minor), "flower", "ip_tos", value, "classid", classID})
		}
	}
	return commands
}

func qosConfigByInterface(config QoSConfig) map[string]QoSInterface {
	out := make(map[string]QoSInterface, len(config.Interfaces))
	for _, iface := range config.Interfaces {
		out[iface.InterfaceID] = iface
	}
	return out
}

func applyQoSTransition(ctx context.Context, runner Runner, from, to Config) error {
	oldQoS, newQoS := qosConfigByInterface(from.QoS), qosConfigByInterface(to.QoS)
	oldNames, newNames := map[string]Interface{}, map[string]Interface{}
	for _, iface := range from.Interfaces {
		oldNames[iface.ID] = iface
	}
	for _, iface := range to.Interfaces {
		newNames[iface.ID] = iface
	}
	for id := range oldQoS {
		oldIface, ok := oldNames[id]
		if !ok {
			continue
		}
		if _, retained := newQoS[id]; retained && newNames[id].Name == oldIface.Name {
			continue
		}
		rows, err := rootQdiscs(ctx, runner, oldIface.Name)
		if err != nil {
			return err
		}
		for _, qdisc := range rows {
			if qdisc.Root && qdisc.Kind == "htb" && qdisc.Handle == gameBondQoSHandle {
				if _, err := runner.Run(ctx, "tc", "qdisc", "del", "dev", oldIface.Name, "root"); err != nil {
					return fmt.Errorf("remove GameBond QoS from %s: %w", id, err)
				}
			}
		}
	}
	for id, config := range newQoS {
		iface, ok := newNames[id]
		if !ok {
			return fmt.Errorf("QoS interface %s is missing", id)
		}
		for _, args := range qosCommands(config, iface) {
			if _, err := runner.Run(ctx, "tc", args...); err != nil {
				return fmt.Errorf("configure QoS on %s: %w", id, err)
			}
		}
	}
	return nil
}

func verifyQoS(ctx context.Context, runner Runner, cfg Config) error {
	names := make(map[string]Interface, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		names[iface.ID] = iface
	}
	for _, wanted := range cfg.QoS.Interfaces {
		iface := names[wanted.InterfaceID]
		rows, err := rootQdiscs(ctx, runner, iface.Name)
		if err != nil {
			return err
		}
		active := false
		for _, qdisc := range rows {
			active = active || (qdisc.Root && qdisc.Kind == "htb" && qdisc.Handle == gameBondQoSHandle)
		}
		if !active {
			return fmt.Errorf("QoS qdisc is not active on %s", iface.Name)
		}
		result, err := runner.Run(ctx, "tc", "-j", "class", "show", "dev", iface.Name)
		if err != nil {
			return err
		}
		var classRows []struct {
			ClassID string `json:"classid"`
		}
		if err := json.Unmarshal(result.Stdout, &classRows); err != nil {
			return fmt.Errorf("parse effective QoS classes on %s: %w", iface.Name, err)
		}
		present := map[string]bool{}
		for _, row := range classRows {
			present[row.ClassID] = true
		}
		if !present["7e:1"] || !present["7e:fff"] {
			return fmt.Errorf("QoS root/default classes are missing on %s", iface.Name)
		}
		classes := append([]QoSClass(nil), wanted.Classes...)
		sort.Slice(classes, func(i, j int) bool { return classes[i].ID < classes[j].ID })
		for i := range classes {
			if !present["7e:"+strconv.Itoa(i+2)] {
				return fmt.Errorf("QoS class %s is missing on %s", classes[i].ID, iface.Name)
			}
		}
		filterResult, err := runner.Run(ctx, "tc", "-j", "filter", "show", "dev", iface.Name, "parent", gameBondQoSHandle)
		if err != nil {
			return err
		}
		var filters []json.RawMessage
		if err := json.Unmarshal(filterResult.Stdout, &filters); err != nil {
			return fmt.Errorf("parse effective QoS filters on %s: %w", iface.Name, err)
		}
		if len(filters) < len(wanted.Classes)*2 {
			return fmt.Errorf("QoS DSCP filters are missing on %s", iface.Name)
		}
	}
	return nil
}

func snapshotQoS(ctx context.Context, runner Runner, cfg Config) QoSSnapshot {
	snapshot := QoSSnapshot{Enabled: cfg.QoS.Enabled, Interfaces: []QoSInterfaceStatus{}}
	names := make(map[string]Interface, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		names[iface.ID] = iface
	}
	for _, wanted := range cfg.QoS.Interfaces {
		state := QoSInterfaceStatus{InterfaceID: wanted.InterfaceID, Classes: []QoSClassStatus{}}
		iface, ok := names[wanted.InterfaceID]
		if !ok {
			state.Error = "configured interface is missing"
			snapshot.Interfaces = append(snapshot.Interfaces, state)
			continue
		}
		rows, err := rootQdiscs(ctx, runner, iface.Name)
		if err != nil {
			state.Error = err.Error()
			snapshot.Interfaces = append(snapshot.Interfaces, state)
			continue
		}
		for _, qdisc := range rows {
			state.Active = state.Active || (qdisc.Root && qdisc.Kind == "htb" && qdisc.Handle == gameBondQoSHandle)
		}
		if !state.Active {
			state.Error = "GameBond HTB qdisc is not active"
			snapshot.Interfaces = append(snapshot.Interfaces, state)
			continue
		}
		result, err := runner.Run(ctx, "tc", "-s", "-j", "class", "show", "dev", iface.Name)
		if err != nil {
			state.Error = err.Error()
			snapshot.Interfaces = append(snapshot.Interfaces, state)
			continue
		}
		var classRows []struct {
			ClassID string `json:"classid"`
			Stats   struct {
				Bytes   uint64 `json:"bytes"`
				Packets uint64 `json:"packets"`
			} `json:"stats"`
		}
		if err := json.Unmarshal(result.Stdout, &classRows); err != nil {
			state.Error = fmt.Sprintf("parse QoS counters: %v", err)
		} else {
			configured := append([]QoSClass(nil), wanted.Classes...)
			sort.Slice(configured, func(i, j int) bool { return configured[i].ID < configured[j].ID })
			classNames := map[string]string{"7e:1": "root", "7e:fff": "default"}
			for i, class := range configured {
				classNames["7e:"+strconv.Itoa(i+2)] = class.ID
			}
			for _, row := range classRows {
				state.Classes = append(state.Classes, QoSClassStatus{ID: classNames[row.ClassID], ClassID: row.ClassID, Bytes: row.Stats.Bytes, Packets: row.Stats.Packets})
			}
		}
		snapshot.Interfaces = append(snapshot.Interfaces, state)
	}
	return snapshot
}
