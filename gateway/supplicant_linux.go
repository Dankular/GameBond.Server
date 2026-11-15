//go:build linux

package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/Dankular/GameBond.Server/gateway/layer2"
)

const (
	wiredSupplicantUnit   = "gamebond-wpa_supplicant@"
	wiredSupplicantDir    = "/etc/gamebond/8021x/supplicants"
	wiredSupplicantMarker = "# GameBond managed wired 802.1X supplicant "
)

func renderWiredSupplicantFiles(cfg layer2.Config) (map[string][]byte, error) {
	files := make(map[string][]byte, len(cfg.WiredSupplicants))
	for _, policy := range cfg.WiredSupplicants {
		password, keyPassword := "", ""
		var err error
		if policy.PasswordFile != "" {
			password, err = readRadiusCredential(policy.PasswordFile, 16, 128)
			if err != nil {
				return nil, fmt.Errorf("wired supplicant %s credential: %w", policy.Interface, err)
			}
		}
		if policy.PrivateKeyPasswordFile != "" {
			keyPassword, err = readRadiusCredential(policy.PrivateKeyPasswordFile, 1, 128)
			if err != nil {
				return nil, fmt.Errorf("wired supplicant %s private-key credential: %w", policy.Interface, err)
			}
		}
		config, err := layer2.RenderWiredSupplicantConfig(cfg, policy.Interface, password, keyPassword)
		if err != nil {
			return nil, err
		}
		files[filepath.Join(wiredSupplicantDir, policy.Interface+".conf")] = config
	}
	return files, nil
}

func validateWiredSupplicantHost(ctx context.Context, runner Runner, cfg layer2.Config) error {
	if len(cfg.WiredSupplicants) == 0 {
		return nil
	}
	for _, tool := range []string{"wpa_supplicant", "wpa_cli", "systemctl"} {
		if !runner.Available(tool) {
			return fmt.Errorf("wired 802.1X supplicant requires %s", tool)
		}
	}
	result, err := runner.Run(ctx, "systemctl", "show", "--property=LoadState", "--value", "gamebond-wpa_supplicant@.service")
	if err != nil {
		return fmt.Errorf("inspect GameBond wired supplicant unit: %w", err)
	}
	if strings.TrimSpace(string(result.Stdout)) != "loaded" {
		return errors.New("gamebond-wpa_supplicant@.service is not installed; install the GameBond wired supplicant unit and reload systemd")
	}
	for _, policy := range cfg.WiredSupplicants {
		for _, path := range []string{policy.CAFile, policy.ClientCertFile} {
			if path == "" {
				continue
			}
			if err := validateSupplicantFile(path, false); err != nil {
				return fmt.Errorf("wired supplicant %s certificate: %w", policy.Interface, err)
			}
		}
		if policy.PrivateKeyFile != "" {
			if err := validateSupplicantFile(policy.PrivateKeyFile, true); err != nil {
				return fmt.Errorf("wired supplicant %s private key: %w", policy.Interface, err)
			}
		}
	}
	_, err = renderWiredSupplicantFiles(cfg)
	return err
}

func validateSupplicantFile(path string, private bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("must be a regular file")
	}
	if private {
		fileStat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || fileStat.Uid != 0 || info.Mode().Perm()&0077 != 0 {
			return errors.New("must be root-owned with mode 0600 or stricter")
		}
	}
	return nil
}

func writeWiredSupplicantFiles(files map[string][]byte) error {
	if err := os.MkdirAll(wiredSupplicantDir, 0700); err != nil {
		return err
	}
	dirInfo, err := os.Lstat(wiredSupplicantDir)
	if err != nil {
		return err
	}
	dirStat, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !dirInfo.IsDir() || !ok || dirStat.Uid != 0 || dirInfo.Mode().Perm()&0077 != 0 {
		return errors.New("wired supplicant config directory must be root-owned with mode 0700 or stricter")
	}
	for path, data := range files {
		if !strings.HasPrefix(string(data), wiredSupplicantMarker) {
			return fmt.Errorf("refusing to write unmarked wired supplicant file %s", path)
		}
		if info, err := os.Lstat(path); err == nil {
			fileStat, ownerOK := info.Sys().(*syscall.Stat_t)
			if !info.Mode().IsRegular() || !ownerOK || fileStat.Uid != 0 || info.Mode().Perm()&0077 != 0 {
				return fmt.Errorf("refusing to replace unsafe wired supplicant file %s", path)
			}
			prior, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if !strings.HasPrefix(string(prior), wiredSupplicantMarker) {
				return fmt.Errorf("refusing to replace unmanaged wired supplicant file %s", path)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		tempFile, err := os.CreateTemp(wiredSupplicantDir, ".supplicant-*.tmp")
		if err != nil {
			return err
		}
		temp := tempFile.Name()
		if err = tempFile.Chmod(0600); err == nil {
			_, err = tempFile.Write(data)
		}
		if err == nil {
			err = tempFile.Sync()
		}
		closeErr := tempFile.Close()
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
	}
	keep := map[string]bool{}
	for path := range files {
		keep[filepath.Base(path)] = true
	}
	entries, err := os.ReadDir(wiredSupplicantDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") || keep[entry.Name()] {
			continue
		}
		path := filepath.Join(wiredSupplicantDir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		fileStat, ownerOK := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || !ownerOK || fileStat.Uid != 0 || info.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("refusing to inspect unsafe wired supplicant file %s", path)
		}
		prior, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(string(prior), wiredSupplicantMarker) {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	}
	return nil
}

func reconcileWiredSupplicantServices(ctx context.Context, runner Runner, previous, desired layer2.Config) error {
	previousIDs, desiredIDs := map[string]bool{}, map[string]bool{}
	for _, policy := range previous.WiredSupplicants {
		previousIDs[policy.Interface] = true
	}
	for _, policy := range desired.WiredSupplicants {
		desiredIDs[policy.Interface] = true
	}
	ids := make([]string, 0, len(previousIDs)+len(desiredIDs))
	for id := range previousIDs {
		ids = append(ids, id)
	}
	for id := range desiredIDs {
		if !previousIDs[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		action := "stop"
		if desiredIDs[id] {
			action = "restart"
		}
		if _, err := runner.Run(ctx, "systemctl", action, wiredSupplicantUnit+id+".service"); err != nil {
			return fmt.Errorf("%s wired supplicant for %s: %w", action, id, err)
		}
	}
	return nil
}

func pauseWiredSupplicantServices(ctx context.Context, runner Runner, cfg layer2.Config) error {
	for _, policy := range cfg.WiredSupplicants {
		if _, err := runner.Run(ctx, "systemctl", "stop", wiredSupplicantUnit+policy.Interface+".service"); err != nil {
			return fmt.Errorf("stop wired supplicant for %s: %w", policy.Interface, err)
		}
	}
	return nil
}

func verifyWiredSupplicantServices(ctx context.Context, runner Runner, cfg layer2.Config) error {
	for _, policy := range cfg.WiredSupplicants {
		if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", wiredSupplicantUnit+policy.Interface+".service"); err != nil {
			return fmt.Errorf("wired supplicant service for %s is not active: %w", policy.Interface, err)
		}
	}
	return nil
}
