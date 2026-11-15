package layer2

import (
	"errors"
	"fmt"
	"strings"
)

// RenderWiredSupplicantConfig builds one wired 802.1X client profile. The
// caller reads credentials from root-owned files and passes them only for this
// render operation; returned bytes are intended for mode-0600 storage.
func RenderWiredSupplicantConfig(cfg Config, interfaceID, password, privateKeyPassword string) ([]byte, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	var policy *WiredSupplicant
	for i := range cfg.WiredSupplicants {
		if cfg.WiredSupplicants[i].Interface == interfaceID {
			policy = &cfg.WiredSupplicants[i]
			break
		}
	}
	if policy == nil {
		return nil, fmt.Errorf("interface %q is not configured as a wired supplicant", interfaceID)
	}
	if policy.EAPMethod == "TLS" {
		if password != "" || (policy.PrivateKeyPasswordFile != "" && !validSupplicantCredential(privateKeyPassword, 1)) || (policy.PrivateKeyPasswordFile == "" && privateKeyPassword != "") {
			return nil, errors.New("invalid EAP-TLS private-key password")
		}
	} else if !validSupplicantCredential(password, 16) {
		return nil, errors.New("wired supplicant password must contain 16..128 safe ASCII characters")
	}
	iface, ok := findInterface(cfg.Interfaces, interfaceID)
	if !ok {
		return nil, fmt.Errorf("interface %q is not configured", interfaceID)
	}
	var output strings.Builder
	fmt.Fprintf(&output, "# GameBond managed wired 802.1X supplicant %s v1\n", interfaceID)
	fmt.Fprintf(&output, "ctrl_interface=DIR=/run/gamebond-wpa_supplicant/%s GROUP=0\n", interfaceID)
	fmt.Fprintf(&output, "interface=%s\n", iface.Name)
	output.WriteString("ap_scan=0\nfast_reauth=1\n")
	output.WriteString("network={\n")
	fmt.Fprintf(&output, "\tkey_mgmt=IEEE8021X\n\teap=%s\n", policy.EAPMethod)
	fmt.Fprintf(&output, "\tidentity=%q\n", policy.Identity)
	if policy.AnonymousIdentity != "" {
		fmt.Fprintf(&output, "\tanonymous_identity=%q\n", policy.AnonymousIdentity)
	}
	fmt.Fprintf(&output, "\tca_cert=%q\n", policy.CAFile)
	switch policy.EAPMethod {
	case "TLS":
		fmt.Fprintf(&output, "\tclient_cert=%q\n\tprivate_key=%q\n", policy.ClientCertFile, policy.PrivateKeyFile)
		if privateKeyPassword != "" {
			fmt.Fprintf(&output, "\tprivate_key_passwd=%q\n", privateKeyPassword)
		}
	case "PEAP", "TTLS":
		fmt.Fprintf(&output, "\tpassword=%q\n\tphase2=%q\n", password, policy.Phase2)
	}
	output.WriteString("}\n")
	return []byte(output.String()), nil
}

func validSupplicantCredential(value string, minimum int) bool {
	if len(value) < minimum || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!@%_+=,:./-", r)) {
			return false
		}
	}
	return true
}
