package adminportal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// WriteSelfSigned is cert.write_self_signed: an ECDSA P-256 certificate with
// the given hosts as SANs (IP literals as IP SANs), CN gamebond-admin, valid
// for days. The key file is created exclusively with mode 0600.
func WriteSelfSigned(directory string, hosts []string, days int) (map[string]any, error) {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		hosts = []string{"localhost"}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, err
	}
	name := pkix.Name{CommonName: "gamebond-admin"}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{SerialNumber: serial.Add(serial, big.NewInt(1)), Subject: name, Issuer: name,
		NotBefore: now, NotAfter: now.Add(time.Duration(days) * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPath, keyPath := filepath.Join(directory, "admin.crt"), filepath.Join(directory, "admin.key")
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	return map[string]any{"cert": certPath, "key": keyPath, "self_signed": true, "days": days}, nil
}
