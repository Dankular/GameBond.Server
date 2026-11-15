package adminportal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/Dankular/GameBond.Server/lab"
)

func (p *Portal) labDir() string {
	return p.labDirForTeam("default")
}

func (p *Portal) labDirForTeam(team string) string {
	if team == "" {
		team = "default"
	}
	if p.o.LabDirectory != "" {
		return filepath.Join(p.o.LabDirectory, "teams", team, "topologies")
	}
	return filepath.Join(filepath.Dir(p.o.ConfigPath), "labs", "teams", team, "topologies")
}

func (p *Portal) listLabTopologies(team string) ([]lab.Topology, error) {
	directory := p.labDirForTeam(team)
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return []lab.Topology{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]lab.Topology, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		topology, err := lab.DecodeTopology(data)
		if err != nil {
			return nil, fmt.Errorf("stored topology %s is invalid: %w", entry.Name(), err)
		}
		out = append(out, topology)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (p *Portal) saveLabTopology(team string, data []byte) error {
	topology, err := lab.DecodeTopology(data)
	if err != nil {
		return err
	}
	canonical, err := json.MarshalIndent(topology, "", "  ")
	if err != nil {
		return err
	}
	dir := p.labDirForTeam(team)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".topology-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(canonical); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filepath.Join(dir, topology.ID+".json"))
}
