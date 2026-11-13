//go:build linux

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	radiusUnit      = "gamebond-freeradius.service"
	radiusConfigDir = "/etc/gamebond/raddb"
	radiusSecretDir = "/etc/gamebond/radius-secrets"
	radiusCertDir   = "/etc/gamebond/radius-certs"
)

type RADIUSSnapshot struct {
	Enabled       bool   `json:"enabled"`
	Active        bool   `json:"active"`
	RadSecEnabled bool   `json:"radsec_enabled"`
	Error         string `json:"error,omitempty"`
}

func renderRADIUSConfigs(cfg RADIUSConfig, configDir string) (map[string][]byte, error) {
	if !cfg.Enabled {
		return map[string][]byte{}, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	secretValues := make(map[string]string, len(cfg.Clients))
	for _, client := range cfg.Clients {
		value, err := readRadiusCredential(filepath.Join(radiusSecretDir, client.ID), 16, 128)
		if err != nil {
			return nil, fmt.Errorf("RADIUS client %s secret: %w", client.ID, err)
		}
		secretValues[client.ID] = value
	}
	userValues := make(map[string]string, len(cfg.Users))
	for _, account := range cfg.Users {
		value, err := readRadiusCredential(filepath.Join(radiusSecretDir, "users", account.ID), 8, 128)
		if err != nil {
			return nil, fmt.Errorf("RADIUS user %s password: %w", account.ID, err)
		}
		userValues[account.ID] = value
	}
	var clients, users strings.Builder
	clients.WriteString("# GameBond managed FreeRADIUS clients v1\n")
	for _, client := range cfg.Clients {
		fmt.Fprintf(&clients, "client gb_%s {\n ipaddr = %s\n secret = \"%s\"\n proto = udp\n}\n", client.ID, client.Network, secretValues[client.ID])
		if cfg.RadSec.Enabled {
			fmt.Fprintf(&clients, "client gb_%s_tls {\n ipaddr = %s\n secret = \"%s\"\n proto = tls\n}\n", client.ID, client.Network, secretValues[client.ID])
		}
	}
	users.WriteString("# GameBond managed FreeRADIUS users v1\n")
	for _, account := range cfg.Users {
		fmt.Fprintf(&users, "%s Cleartext-Password := \"%s\"\n", account.Username, userValues[account.ID])
	}
	var config strings.Builder
	fmt.Fprintf(&config, `# GameBond managed FreeRADIUS server v1
prefix = /usr
exec_prefix = ${prefix}
sysconfdir = /etc
localstatedir = /var
sbindir = ${exec_prefix}/sbin
logdir = /var/log/gamebond-radius
raddbdir = %s
radacctdir = ${logdir}/radacct
name = radiusd
confdir = ${raddbdir}
modconfdir = ${confdir}/mods-config
certdir = ${confdir}
cadir = ${confdir}
run_dir = /run/gamebond-radius
db_dir = /var/lib/gamebond-radius
pidfile = ${run_dir}/radiusd.pid
correct_escapes = yes
proxy_requests = no

security {
 user = freerad
 group = freerad
 allow_core_dumps = no
}

$INCLUDE ${confdir}/dictionary
$INCLUDE ${confdir}/clients.conf

modules {
 files {
  filename = ${confdir}/users
 }
 pap {
  normalise = yes
 }
 detail {
  filename = ${radacctdir}/detail-%%Y%%m%%d
  permissions = 0600
 }
}

server default {
 listen {
  type = auth
  ipaddr = %s
  port = %d
 }
 listen {
  type = acct
  ipaddr = %s
  port = %d
 }
 authorize {
  files
  pap
 }
 authenticate {
  Auth-Type PAP {
   pap
  }
 }
 accounting {
  detail
 }
}
`, configDir, cfg.ListenAddress, cfg.AuthPort, cfg.ListenAddress, cfg.AccountingPort)
	if cfg.RadSec.Enabled {
		keyPath := filepath.Join(radiusCertDir, cfg.RadSec.PrivateKeyFile)
		certPath := filepath.Join(radiusCertDir, cfg.RadSec.CertificateFile)
		key, err := readRadiusCertificate(keyPath, true)
		if err != nil {
			return nil, fmt.Errorf("RadSec private key: %w", err)
		}
		cert, err := readRadiusCertificate(certPath, false)
		if err != nil {
			return nil, fmt.Errorf("RadSec certificate: %w", err)
		}
		var ca []byte
		if cfg.RadSec.CAFile != "" {
			ca, err = readRadiusCertificate(filepath.Join(radiusCertDir, cfg.RadSec.CAFile), false)
			if err != nil {
				return nil, fmt.Errorf("RadSec client CA: %w", err)
			}
		}
		caLine := ""
		if cfg.RadSec.RequireClientCertificate {
			caLine = "   ca_file = ${confdir}/radsec-ca.crt\n"
		}
		fmt.Fprintf(&config, `
server radsec {
 listen {
  type = auth+acct
  ipaddr = %s
  port = %d
  proto = tcp
  tls {
   private_key_file = ${confdir}/radsec.key
   certificate_file = ${confdir}/radsec.crt
%s
   require_client_cert = %s
  }
 }
 authorize {
  files
  pap
 }
 authenticate {
  Auth-Type PAP {
   pap
  }
 }
 accounting {
  detail
 }
}
`, cfg.RadSec.ListenAddress, cfg.RadSec.Port, caLine, strconv.FormatBool(cfg.RadSec.RequireClientCertificate))
		return map[string][]byte{"radiusd.conf": []byte(config.String()), "clients.conf": []byte(clients.String()), "users": []byte(users.String()), "radsec.key": key, "radsec.crt": cert, "radsec-ca.crt": ca}, nil
	}
	return map[string][]byte{"radiusd.conf": []byte(config.String()), "clients.conf": []byte(clients.String()), "users": []byte(users.String())}, nil
}

func readRadiusCredential(path string, min, max int) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("credential file must be a regular root-only file with mode 0600 or stricter")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return "", errors.New("credential file must be owned by root")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSuffix(string(data), "\n")
	if len(value) < min || len(value) > max {
		return "", fmt.Errorf("credential length must be %d..%d bytes", min, max)
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!@%_+=,:./-", r)) {
			return "", errors.New("credential must use printable ASCII letters, digits, and safe punctuation")
		}
	}
	return value, nil
}

func readRadiusCertificate(path string, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("certificate material must be a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil, errors.New("certificate material must be owned by root")
	}
	if private && (info.Mode().Perm()&0040 == 0 || info.Mode().Perm()&0007 != 0) {
		return nil, errors.New("private key must be group-readable by freerad and inaccessible to other users")
	}
	return os.ReadFile(path)
}

func validateRADIUSHost(ctx context.Context, runner Runner, cfg RADIUSConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if !runner.Available("freeradius") || !runner.Available("systemctl") {
		return errors.New("integrated RADIUS requires FreeRADIUS 3 and systemctl")
	}
	if _, err := user.Lookup("freerad"); err != nil {
		return errors.New("integrated RADIUS requires the freerad service account")
	}
	group, err := user.LookupGroup("freerad")
	if err != nil {
		return errors.New("integrated RADIUS requires the freerad service group")
	}
	loaded, err := runner.Run(ctx, "systemctl", "show", "--property=LoadState", "--value", radiusUnit)
	if err != nil {
		return fmt.Errorf("inspect GameBond RADIUS service: %w", err)
	}
	if strings.TrimSpace(string(loaded.Stdout)) != "loaded" {
		return errors.New("gamebond-freeradius.service is not installed; install the GameBond FreeRADIUS unit and reload systemd")
	}
	tempDir, err := os.MkdirTemp("/run/gamebond", ".radius-check-")
	if err != nil {
		return fmt.Errorf("create FreeRADIUS check directory: %w", err)
	}
	defer os.RemoveAll(tempDir)
	configs, err := renderRADIUSConfigs(cfg, tempDir)
	if err != nil {
		return err
	}
	if err := writeRadiusCheckFiles(tempDir, configs, group.Gid); err != nil {
		return err
	}
	if _, err := runner.Run(ctx, "freeradius", "-C", "-d", tempDir); err != nil {
		// FreeRADIUS diagnostics can echo client and user credential values from
		// generated files; keep the API and transaction log free of that output.
		return errors.New("generated FreeRADIUS configuration failed validation")
	}
	return nil
}

func writeRadiusCheckFiles(dir string, files map[string][]byte, groupID string) error {
	gid, err := strconv.Atoi(groupID)
	if err != nil {
		return err
	}
	if _, err := os.Stat("/usr/share/freeradius/dictionary"); err != nil {
		return errors.New("FreeRADIUS dictionary is missing from /usr/share/freeradius")
	}
	if err := os.Symlink("/usr/share/freeradius/dictionary", filepath.Join(dir, "dictionary")); err != nil {
		return err
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			return err
		}
		if err := os.Chown(path, 0, gid); err != nil {
			return err
		}
	}
	return nil
}

func ensureRadiusDictionary(dir string) error {
	path := filepath.Join(dir, "dictionary")
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return errors.New("refusing to replace a non-symlink FreeRADIUS dictionary")
		}
		target, err := os.Readlink(path)
		if err != nil {
			return err
		}
		if target != "/usr/share/freeradius/dictionary" {
			return errors.New("refusing to replace an unmanaged FreeRADIUS dictionary link")
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if _, err := os.Stat("/usr/share/freeradius/dictionary"); err != nil {
		return errors.New("FreeRADIUS dictionary is missing from /usr/share/freeradius")
	}
	return os.Symlink("/usr/share/freeradius/dictionary", path)
}

func writeRADIUSConfigs(cfg RADIUSConfig) error {
	if !cfg.Enabled {
		return removeOwnedRadiusConfig()
	}
	configs, err := renderRADIUSConfigs(cfg, radiusConfigDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(radiusConfigDir, 0750); err != nil {
		return err
	}
	if err := os.MkdirAll("/var/log/gamebond-radius/radacct", 0750); err != nil {
		return err
	}
	if err := os.MkdirAll("/var/lib/gamebond-radius", 0750); err != nil {
		return err
	}
	group, err := user.LookupGroup("freerad")
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return err
	}
	if err := os.Chown(radiusConfigDir, 0, gid); err != nil {
		return err
	}
	if err := ensureRadiusDictionary(radiusConfigDir); err != nil {
		return err
	}
	for _, dir := range []string{"/var/run/gamebond-radius", "/var/log/gamebond-radius", "/var/log/gamebond-radius/radacct", "/var/lib/gamebond-radius"} {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return err
		}
		if err := os.Chown(dir, 0, gid); err != nil {
			return err
		}
	}
	for name, data := range configs {
		if strings.HasSuffix(name, ".crt") || name == "radsec.key" {
			continue
		}
		path := filepath.Join(radiusConfigDir, name)
		if err := writeOwnedRadiusFile(path, data, gid); err != nil {
			return err
		}
	}
	if cfg.RadSec.Enabled {
		for _, pair := range []struct {
			name   string
			source string
		}{{"radsec.key", cfg.RadSec.PrivateKeyFile}, {"radsec.crt", cfg.RadSec.CertificateFile}, {"radsec-ca.crt", cfg.RadSec.CAFile}} {
			if pair.source == "" {
				continue
			}
			data, err := readRadiusCertificate(filepath.Join(radiusCertDir, pair.source), pair.name == "radsec.key")
			if err != nil {
				return err
			}
			if err := writeOwnedRadiusMaterial(filepath.Join(radiusConfigDir, pair.name), data, gid); err != nil {
				return err
			}
		}
	} else {
		if err := removeOwnedRadiusMaterials(); err != nil {
			return err
		}
	}
	return nil
}

func writeOwnedRadiusFile(path string, data []byte, gid int) error {
	prior, err := os.ReadFile(path)
	if err == nil && !strings.HasPrefix(string(prior), "# GameBond managed FreeRADIUS ") {
		return fmt.Errorf("refusing to replace unmanaged RADIUS file %s", path)
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".radius-*.tmp")
	if err != nil {
		return err
	}
	temp := f.Name()
	if err = f.Chmod(0640); err == nil {
		err = f.Chown(0, gid)
	}
	if err == nil {
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
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

func writeOwnedRadiusMaterial(path string, data []byte, gid int) error {
	markerPath := path + ".gamebond-owner"
	marker, markerErr := os.ReadFile(markerPath)
	prior, priorErr := os.Lstat(path)
	if priorErr == nil && !prior.Mode().IsRegular() {
		return fmt.Errorf("refusing to replace non-regular RADIUS material %s", path)
	}
	if priorErr == nil && (markerErr != nil || string(marker) != "GameBond managed RadSec material v1\n") {
		return fmt.Errorf("refusing to replace unmanaged RADIUS material %s", path)
	}
	if priorErr != nil && !errors.Is(priorErr, fs.ErrNotExist) {
		return priorErr
	}
	if markerErr != nil && !errors.Is(markerErr, fs.ErrNotExist) {
		return markerErr
	}
	if err := writeAtomicRadiusFile(markerPath, []byte("GameBond managed RadSec material v1\n"), 0600, 0); err != nil {
		return err
	}
	return writeAtomicRadiusFile(path, data, 0640, gid)
}

func writeAtomicRadiusFile(path string, data []byte, mode os.FileMode, gid int) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".radius-*.tmp")
	if err != nil {
		return err
	}
	temp := f.Name()
	if err = f.Chmod(mode); err == nil {
		err = f.Chown(0, gid)
	}
	if err == nil {
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
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

func removeOwnedRadiusMaterials() error {
	for _, name := range []string{"radsec.key", "radsec.crt", "radsec-ca.crt"} {
		path := filepath.Join(radiusConfigDir, name)
		if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		markerPath := path + ".gamebond-owner"
		marker, err := os.ReadFile(markerPath)
		if err != nil || string(marker) != "GameBond managed RadSec material v1\n" {
			return fmt.Errorf("refusing to remove unmanaged RADIUS material %s", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		if err := os.Remove(markerPath); err != nil {
			return err
		}
	}
	return nil
}

func removeOwnedRadiusConfig() error {
	if err := removeOwnedRadiusMaterials(); err != nil {
		return err
	}
	for _, name := range []string{"radiusd.conf", "clients.conf", "users"} {
		path := filepath.Join(radiusConfigDir, name)
		data, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !strings.HasPrefix(string(data), "# GameBond managed FreeRADIUS ") {
			return fmt.Errorf("refusing to remove unmanaged RADIUS file %s", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}

func applyRADIUSTransition(ctx context.Context, runner Runner, cfg RADIUSConfig) error {
	if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", radiusUnit); err == nil {
		if _, err := runner.Run(ctx, "systemctl", "stop", radiusUnit); err != nil {
			return fmt.Errorf("stop GameBond RADIUS: %w", err)
		}
	}
	if !cfg.Enabled {
		return removeOwnedRadiusConfig()
	}
	if err := writeRADIUSConfigs(cfg); err != nil {
		return err
	}
	if _, err := runner.Run(ctx, "systemctl", "start", radiusUnit); err != nil {
		return fmt.Errorf("start GameBond RADIUS: %w", err)
	}
	return nil
}

func snapshotRADIUS(ctx context.Context, runner Runner, cfg RADIUSConfig) RADIUSSnapshot {
	out := RADIUSSnapshot{Enabled: cfg.Enabled, RadSecEnabled: cfg.RadSec.Enabled}
	if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", radiusUnit); err != nil {
		if cfg.Enabled {
			out.Error = err.Error()
		}
		return out
	}
	out.Active = true
	return out
}

func verifyRADIUS(ctx context.Context, runner Runner, cfg RADIUSConfig) error {
	status := snapshotRADIUS(ctx, runner, cfg)
	if cfg.Enabled && (!status.Active || status.Error != "") {
		return fmt.Errorf("GameBond RADIUS service verification failed: %s", status.Error)
	}
	if !cfg.Enabled && status.Active {
		return errors.New("GameBond RADIUS remained active after disable")
	}
	return nil
}
