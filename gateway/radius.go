package gateway

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// RADIUSConfig configures a host-local FreeRADIUS instance without embedding credentials.
type RADIUSConfig struct {
	Enabled        bool           `json:"enabled"`
	ListenAddress  string         `json:"listen_address"`
	AuthPort       uint16         `json:"auth_port"`
	AccountingPort uint16         `json:"accounting_port"`
	Clients        []RADIUSClient `json:"clients"`
	Users          []RADIUSUser   `json:"users"`
	RadSec         RadSecConfig   `json:"radsec"`
}

type RADIUSClient struct {
	ID      string `json:"id"`
	Network string `json:"network"`
}
type RADIUSUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}
type RadSecConfig struct {
	Enabled                  bool   `json:"enabled"`
	ListenAddress            string `json:"listen_address"`
	Port                     uint16 `json:"port"`
	CertificateFile          string `json:"certificate_file"`
	PrivateKeyFile           string `json:"private_key_file"`
	CAFile                   string `json:"ca_file,omitempty"`
	RequireClientCertificate bool   `json:"require_client_certificate"`
}

func (c RADIUSConfig) Validate() error {
	if !c.Enabled {
		if c.RadSec.Enabled {
			return errors.New("radsec requires radius.enabled")
		}
		return nil
	}
	if addr, err := netip.ParseAddr(c.ListenAddress); err != nil || addr.IsUnspecified() && c.ListenAddress != "0.0.0.0" && c.ListenAddress != "::" || addr.String() != c.ListenAddress {
		return errors.New("listen_address must be a canonical IPv4 or IPv6 address")
	}
	if c.AuthPort == 0 || c.AccountingPort == 0 || c.AuthPort == c.AccountingPort {
		return errors.New("auth_port and accounting_port must be nonzero and distinct")
	}
	if len(c.Clients) == 0 || len(c.Clients) > 512 {
		return errors.New("clients must contain 1..512 RADIUS clients")
	}
	if len(c.Users) == 0 || len(c.Users) > 10000 {
		return errors.New("users must contain 1..10000 local RADIUS users")
	}
	ids := map[string]bool{}
	var networks []netip.Prefix
	for i, client := range c.Clients {
		p, err := netip.ParsePrefix(client.Network)
		if !validID(client.ID) || ids[client.ID] || err != nil || p.Masked().String() != client.Network || p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
			return fmt.Errorf("clients[%d] has an invalid or duplicated id/network", i)
		}
		for _, prior := range networks {
			if prior.Contains(p.Addr()) || p.Contains(prior.Addr()) {
				return fmt.Errorf("clients[%d] network overlaps another RADIUS client", i)
			}
		}
		ids[client.ID] = true
		networks = append(networks, p)
	}
	userIDs, usernames := map[string]bool{}, map[string]bool{}
	for i, user := range c.Users {
		if !validID(user.ID) || userIDs[user.ID] || len(user.Username) < 1 || len(user.Username) > 64 || strings.TrimSpace(user.Username) != user.Username || usernames[user.Username] {
			return fmt.Errorf("users[%d] has an invalid or duplicated id/username", i)
		}
		for _, r := range user.Username {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._@-", r)) {
				return fmt.Errorf("users[%d].username contains unsupported characters", i)
			}
		}
		userIDs[user.ID], usernames[user.Username] = true, true
	}
	if c.RadSec.Enabled {
		r := c.RadSec
		if addr, err := netip.ParseAddr(r.ListenAddress); err != nil || addr.IsUnspecified() && r.ListenAddress != "0.0.0.0" && r.ListenAddress != "::" || addr.String() != r.ListenAddress {
			return errors.New("radsec.listen_address must be a canonical IPv4 or IPv6 address")
		}
		if r.Port == 0 {
			return errors.New("radsec.port must be nonzero")
		}
		if !validSecretFilename(r.CertificateFile) || !validSecretFilename(r.PrivateKeyFile) || r.RequireClientCertificate && !validSecretFilename(r.CAFile) {
			return errors.New("radsec certificate, key, and required CA must be filenames in /etc/gamebond/radius-certs")
		}
	}
	return nil
}

func validSecretFilename(value string) bool {
	if len(value) < 1 || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
			return false
		}
	}
	return true
}
