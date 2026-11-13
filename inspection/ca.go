// Package inspection provides opt-in TLS interception for traffic routed through the server.
package inspection

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	certName = "inspection-ca.pem"
	keyName  = "inspection-ca-key.pem"
)

// CA holds the trusted root and creates short-lived leaf certificates.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	mu   sync.Mutex
}

// LoadOrCreate loads an existing CA or atomically creates one with private permissions.
func LoadOrCreate(dir string) (*CA, error) {
	if dir == "" {
		return nil, errors.New("inspection: CA directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("inspection: create CA directory: %w", err)
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("inspection: CA path must be a real directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("inspection: secure CA directory: %w", err)
	}
	certPath, keyPath := filepath.Join(dir, certName), filepath.Join(dir, keyName)
	_, certErr := os.Lstat(certPath)
	_, keyErr := os.Lstat(keyPath)
	if certErr == nil || keyErr == nil {
		if certErr != nil || keyErr != nil {
			return nil, errors.New("inspection: CA certificate and key must both exist")
		}
		certInfo, err := os.Lstat(certPath)
		if err != nil || certInfo.Mode()&os.ModeSymlink != 0 || !certInfo.Mode().IsRegular() {
			return nil, errors.New("inspection: CA certificate must be a regular file")
		}
		keyInfo, err := os.Lstat(keyPath)
		if err != nil || keyInfo.Mode()&os.ModeSymlink != 0 || !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("inspection: CA private key must be a regular file with mode 0600 or stricter")
		}
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return nil, err
		}
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		certBlock, _ := pem.Decode(certPEM)
		keyBlock, _ := pem.Decode(keyPEM)
		if certBlock == nil || keyBlock == nil || certBlock.Type != "CERTIFICATE" || keyBlock.Type != "EC PRIVATE KEY" {
			return nil, errors.New("inspection: CA files contain invalid PEM")
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || cert.CheckSignatureFrom(cert) != nil || time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
			return nil, errors.New("inspection: certificate is not a valid CA")
		}
		key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, errors.New("inspection: invalid CA private key")
		}
		certKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || !certKey.Equal(&key.PublicKey) {
			return nil, errors.New("inspection: CA key does not match certificate")
		}
		return &CA{cert: cert, key: key}, nil
	}
	if !errors.Is(certErr, os.ErrNotExist) || !errors.Is(keyErr, os.ErrNotExist) {
		return nil, errors.New("inspection: cannot inspect CA files")
	}
	return createCA(dir, certPath, keyPath)
}

func createCA(dir, certPath, keyPath string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "GameBond Inspection CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certTemp, keyTemp := certPath+".new", keyPath+".new"
	if err = os.WriteFile(keyTemp, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err = os.WriteFile(certTemp, certPEM, 0o644); err != nil {
		_ = os.Remove(keyTemp)
		return nil, err
	}
	if err = os.Link(keyTemp, keyPath); err != nil {
		_ = os.Remove(keyTemp)
		_ = os.Remove(certTemp)
		return nil, fmt.Errorf("inspection: install CA key: %w", err)
	}
	_ = os.Remove(keyTemp)
	if err = os.Link(certTemp, certPath); err != nil {
		_ = os.Remove(certTemp)
		return nil, fmt.Errorf("inspection: install CA certificate: %w", err)
	}
	_ = os.Remove(certTemp)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key}, nil
}

func (c *CA) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func (c *CA) Leaf(host string) (tlsCertPEM, keyPEM []byte, err error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/:@ ") {
		return nil, nil, errors.New("inspection: invalid TLS server name")
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil, nil, errors.New("inspection: IP-address TLS inspection is unsupported")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return nil, nil, errors.New("inspection: invalid TLS server name")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return nil, nil, errors.New("inspection: invalid TLS server name")
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}
