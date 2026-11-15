//go:build linux

package gateway

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Dankular/GameBond.Server/edge"
	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

const maxPortAuthEventBytes = 4096

type portAuthEventRequest struct {
	Interface string `json:"interface"`
	Event     string `json:"event"`
	MAC       string `json:"mac"`
}

// handlePortAuthEvent is available only on the permission-protected gateway
// Unix API. It validates hostapd's interface against managed policy and, when
// configured, proxies authorization to the segment broker using its separate
// root-protected admin credential.
func (s *APIServer) handlePortAuthEvent(w http.ResponseWriter, r *http.Request) {
	if ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); ct != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, errors.New("content type must be application/json"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPortAuthEventBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request portAuthEventRequest
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, errors.New("trailing event request data"))
		return
	}
	cfg := s.Manager.Current()
	if cfg.Layer2 == nil {
		writeError(w, http.StatusConflict, errors.New("Layer 2 policy is not configured"))
		return
	}
	policy, ok := portAuthPolicyByName(*cfg.Layer2, request.Interface)
	if !ok {
		writeError(w, http.StatusForbidden, errors.New("interface is not configured for wired 802.1X"))
		return
	}
	if policy.SegmentID != "" {
		if _, err := net.InterfaceByName(policy.EAPOLTapName); err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("configured EAPOL TAP %q is not visible in the gateway API network namespace; edge and hostapd must share that namespace", policy.EAPOLTapName))
			return
		}
	}
	mac, err := net.ParseMAC(request.MAC)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac == nil {
		writeError(w, http.StatusBadRequest, errors.New("station MAC must be a unicast six-byte address"))
		return
	}
	authorized, known := portAuthEventAuthorization(request.Event)
	if !known {
		writeJSON(w, http.StatusOK, map[string]any{"ignored": true})
		return
	}
	var brokerErr error
	var token []byte
	if policy.SegmentID != "" {
		token, err = loadPortAuthAdminToken(policy.SegmentAdminTokenFile)
		if err == nil {
			var station [6]byte
			copy(station[:], mac)
			brokerErr = edge.SetRemoteSegmentMACAuthorization(r.Context(), policy.SegmentSocketPath, policy.SegmentID, policy.SegmentIdentity, policy.EAPOLTapName, token, station, authorized)
		} else {
			brokerErr = err
		}
	}
	// Revoke the Linux bridge entry even if the broker is unavailable. For an
	// accept, install locally only after the broker accepted the MAC; on local
	// failure revoke the broker again so neither side remains partially open.
	if authorized && brokerErr != nil {
		_ = HandlePortAuthEvent(r.Context(), s.Runner, *cfg.Layer2, request.Interface, "CTRL-EVENT-EAP-FAILURE", request.MAC)
	}
	if authorized && brokerErr == nil || !authorized {
		if err := HandlePortAuthEvent(r.Context(), s.Runner, *cfg.Layer2, request.Interface, request.Event, request.MAC); err != nil {
			if authorized && policy.SegmentID != "" && brokerErr == nil {
				var station [6]byte
				copy(station[:], mac)
				_ = edge.SetRemoteSegmentMACAuthorization(context.Background(), policy.SegmentSocketPath, policy.SegmentID, policy.SegmentIdentity, policy.EAPOLTapName, token, station, false)
			}
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
	}
	if brokerErr != nil {
		writeError(w, http.StatusServiceUnavailable, brokerErr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authorized": authorized})
}

func portAuthEventAuthorization(event string) (bool, bool) {
	switch event {
	case "CTRL-EVENT-EAP-SUCCESS", "CTRL-EVENT-EAP-SUCCESS2":
		return true, true
	case "CTRL-EVENT-EAP-FAILURE", "AP-STA-DISCONNECTED", "CTRL-EVENT-EAP-STARTED":
		return false, true
	default:
		return false, false
	}
}

func portAuthPolicyByName(cfg layer2.Config, interfaceName string) (layer2.PortAuth, bool) {
	for _, policy := range cfg.PortAuth {
		iface, ok := findLayer2Interface(cfg, policy.Interface)
		if ok && iface.Name == interfaceName {
			return policy, true
		}
	}
	return layer2.PortAuth{}, false
}

func loadPortAuthAdminToken(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("segment admin token path is missing or not absolute")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open segment admin token file: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 256 {
		return nil, errors.New("segment admin token file must be a regular owner-only file no larger than 256 bytes")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil, errors.New("segment admin token file must be owned by root")
	}
	value, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil || len(value) > 256 {
		return nil, errors.New("segment admin token file exceeds size limit")
	}
	token, err := hex.DecodeString(strings.TrimSpace(string(value)))
	if err != nil || len(token) < 32 || len(token) > 128 {
		return nil, errors.New("segment admin token must be 64..256 hexadecimal characters")
	}
	return token, nil
}

// SendPortAuthEventViaAPI forwards one hostapd event through the existing
// gateway management Unix socket. File permissions on that socket authenticate
// the local event helper; no RADIUS credential or member token enters HTTP.
func SendPortAuthEventViaAPI(ctx context.Context, socketPath, interfaceName, event, mac string) error {
	if ctx == nil || !filepath.IsAbs(socketPath) || len(socketPath) >= 104 || interfaceName == "" || len(interfaceName) > 15 || strings.ContainsAny(interfaceName, "\x00\r\n") || len(event) > 128 || len(mac) > 32 {
		return errors.New("invalid gateway 802.1X event request")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socketPath)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	body, _ := json.Marshal(portAuthEventRequest{Interface: interfaceName, Event: event, MAC: mac})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://gateway/v1/layer2/port-auth/events", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send 802.1X event to gateway API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("gateway API rejected 802.1X event (%s): %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}
