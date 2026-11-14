package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

type rollbackTestApplier struct{ applied []Config }
type rollbackTestChange struct {
	owner   *rollbackTestApplier
	desired Config
}

func (a *rollbackTestApplier) Prepare(_ context.Context, _, desired Config) (PreparedChange, error) {
	return rollbackTestChange{owner: a, desired: desired}, nil
}
func (c rollbackTestChange) Apply(context.Context) error {
	c.owner.applied = append(c.owner.applied, c.desired)
	return nil
}
func (rollbackTestChange) Verify(context.Context) error   { return nil }
func (rollbackTestChange) Rollback(context.Context) error { return nil }

func TestManagerCanRollbackToPreviousSuccessfulConfig(t *testing.T) {
	initial := Config{Version: 1, SocketPath: "/run/gamebond/control.sock", Telemetry: Telemetry{OutageRetentionDays: 1, OutageMaxBytes: 4096}}
	applier := &rollbackTestApplier{}
	manager, err := NewManager(t.TempDir()+"/config.json", initial, applier)
	if err != nil {
		t.Fatal(err)
	}
	updated := initial
	updated.SocketGroup = "gamebond-admin"
	if err := manager.Apply(context.Background(), updated); err != nil {
		t.Fatal(err)
	}
	if err := manager.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := manager.Current(); got.SocketGroup != initial.SocketGroup {
		t.Fatalf("rollback config = %#v, want prior config %#v", got, initial)
	}
	if len(applier.applied) != 2 || applier.applied[0].SocketGroup != updated.SocketGroup || applier.applied[1].SocketGroup != initial.SocketGroup {
		t.Fatalf("applied sequence = %#v", applier.applied)
	}
}

func TestManagerRollbackWithoutSuccessfulPredecessorFails(t *testing.T) {
	initial := Config{Version: 1, SocketPath: "/run/gamebond/control.sock", Telemetry: Telemetry{OutageRetentionDays: 1, OutageMaxBytes: 4096}}
	manager, err := NewManager(t.TempDir()+"/config.json", initial, &rollbackTestApplier{})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Rollback(context.Background()); err == nil {
		t.Fatal("rollback without previous applied config succeeded")
	}
}

func TestPreparedSummaryContainsOnlyHumanReadableProviderActions(t *testing.T) {
	change := &linuxPreparedChange{changes: []bridgeLimitChange{{iface: "br0"}}, natScript: "nft add rule secret-material"}
	got := change.Summary()
	if len(got) != 2 || got[0] != "reconcile 1 bridge FDB learning limit(s)" || got[1] != "reconcile GameBond NAT rules" {
		t.Fatalf("plan summary = %#v", got)
	}
	for _, operation := range got {
		if operation == "nft add rule secret-material" {
			t.Fatal("plan exposed a raw provider command")
		}
	}
}

func TestGatewayAPIPlanAndRollbackEndpoints(t *testing.T) {
	initial := Config{Version: 1, SocketPath: "/run/gamebond/control.sock", Telemetry: Telemetry{OutageRetentionDays: 1, OutageMaxBytes: 4096}, Layer2: &layer2.Config{
		Version:    1,
		Interfaces: []layer2.Interface{{ID: "access", Name: "enp2s0"}},
		Bridges:    []layer2.Bridge{{ID: "main", Name: "br-main", VLANFiltering: true, Ports: []layer2.BridgePort{{Interface: "access", UntaggedNetwork: "media"}}}},
		Networks:   []layer2.Network{{ID: "media", Bridge: "main", VLAN: 10, MTU: 1500}},
		AVProfiles: []layer2.AVProfileSelection{{Profile: "dante", Network: "media"}},
	}}
	applier := &rollbackTestApplier{}
	manager, err := NewManager(t.TempDir()+"/config.json", initial, applier)
	if err != nil {
		t.Fatal(err)
	}
	updated := initial
	updated.SocketGroup = "gamebond-admin"
	if err := manager.Apply(context.Background(), updated); err != nil {
		t.Fatal(err)
	}
	runtime, err := NewRuntime(context.Background(), manager.Current(), unavailableRunner{}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	api := (&APIServer{Manager: manager, Runtime: runtime, Runner: unavailableRunner{}}).handler()
	profilesResponse := httptest.NewRecorder()
	api.ServeHTTP(profilesResponse, httptest.NewRequest(http.MethodGet, "/v1/layer2/profiles", nil))
	if profilesResponse.Code != http.StatusOK {
		t.Fatalf("profile catalogue status=%d body=%s", profilesResponse.Code, profilesResponse.Body.String())
	}
	var profileResponse struct {
		Catalog []struct {
			ID string `json:"id"`
		} `json:"catalog"`
		Selected []struct {
			Network     string `json:"network"`
			Enforcement string `json:"enforcement"`
			Profile     struct {
				ID string `json:"id"`
			} `json:"profile"`
		} `json:"selected"`
	}
	if err := json.Unmarshal(profilesResponse.Body.Bytes(), &profileResponse); err != nil || len(profileResponse.Catalog) != 8 || len(profileResponse.Selected) != 1 || profileResponse.Selected[0].Network != "media" || profileResponse.Selected[0].Profile.ID != "dante" || profileResponse.Selected[0].Enforcement != "advisory" {
		t.Fatalf("profile catalogue response = %#v, err=%v", profileResponse, err)
	}
	planRequest := httptest.NewRequest(http.MethodPost, "/v1/config/plan", strings.NewReader(`{"version":1,"socket_path":"/run/gamebond/control.sock","socket_group":"gamebond-admin","telemetry":{"outage_retention_days":1,"outage_max_bytes":4096}}`))
	planRequest.Header.Set("Content-Type", "application/json")
	planResponse := httptest.NewRecorder()
	api.ServeHTTP(planResponse, planRequest)
	if planResponse.Code != http.StatusOK {
		t.Fatalf("plan status=%d body=%s", planResponse.Code, planResponse.Body.String())
	}
	var plan struct {
		Valid      bool     `json:"valid"`
		Operations []string `json:"operations"`
	}
	if err := json.Unmarshal(planResponse.Body.Bytes(), &plan); err != nil || !plan.Valid {
		t.Fatalf("invalid plan response: %#v, err=%v", plan, err)
	}
	rollbackResponse := httptest.NewRecorder()
	api.ServeHTTP(rollbackResponse, httptest.NewRequest(http.MethodPost, "/v1/config/rollback", nil))
	if rollbackResponse.Code != http.StatusOK || manager.Current().SocketGroup != initial.SocketGroup {
		t.Fatalf("rollback status=%d config=%#v body=%s", rollbackResponse.Code, manager.Current(), rollbackResponse.Body.String())
	}
}

type unavailableRunner struct{}

func (unavailableRunner) Run(context.Context, string, ...string) (CommandResult, error) {
	return CommandResult{}, nil
}
func (unavailableRunner) Available(string) bool { return false }
