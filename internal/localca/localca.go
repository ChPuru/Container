// Package localca mints the certificates that make hull's <name>.localhost
// routing work over HTTPS, without a public CA and without ever touching a
// trust store behind the user's back.
//
// One P-256 ECDSA root is generated per data directory and kept there
// (hull-ca.pem plus hull-ca-key.pem, both 0600). Leaf certificates are minted
// on demand from that root, cached per name set, and are short-lived (90 days)
// so a leaked leaf ages out quickly even though the root is good for ten years.
//
// The root is *never* installed into a system or browser trust store by hull.
// Silently writing to a trust store is the single most invasive thing a
// developer tool can do, and it is exactly how mkcert-style helpers have turned
// into a supply-chain problem. [CA.InstallHint] returns the exact command for
// the user to run themselves, once, if they want a green padlock; until they do,
// HTTPS still works and the browser shows its usual untrusted-root warning.
//
// Typical use:
//
//	ca, err := localca.EnsureCA(filepath.Join(dataRoot, "ca"))
//	if err != nil { return err }
//	srv := &http.Server{Handler: h, TLSConfig: ca.TLSConfig()}
//	fmt.Fprintln(os.Stderr, ca.InstallHint()) // print once, do not act on it
package localca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// File names and permissions of the on-disk root. Both files live directly in
// the directory handed to [EnsureCA].
const (
	// CertFileName is the PEM-encoded root certificate.
	CertFileName = "hull-ca.pem"
	// KeyFileName is the PEM-encoded PKCS#8 root private key.
	KeyFileName = "hull-ca-key.pem"
	// FileMode is the mode both files are created with. The key is a signing
	// oracle for every hull hostname on this machine, so it is owner-only.
	FileMode os.FileMode = 0o600
	// DirMode is the mode the CA directory is created with.
	DirMode os.FileMode = 0o700
)

// Validity windows.
const (
	// CAValidity is how long a freshly generated root is good for.
	CAValidity = 10 * 365 * 24 * time.Hour
	// LeafValidity is how long a minted leaf is good for.
	LeafValidity = 90 * 24 * time.Hour
	// leafRenewBefore is how close to expiry a cached leaf may drift before
	// it is re-minted instead of reused.
	leafRenewBefore = 24 * time.Hour
	// clockSkew backdates NotBefore so a host whose clock is slightly behind
	// the signing host still accepts the certificate.
	clockSkew = time.Hour
)

// maxCachedLeaves bounds the leaf cache. SNI names come off the wire, so an
// unbounded cache is a memory amplifier for anything that can reach :443. The
// cache is dropped wholesale when it grows past this; re-minting is cheap.
const maxCachedLeaves = 256

// Sentinel errors returned by this package.
var (
	// ErrIncompleteCA means exactly one of the two files exists, so hull can
	// neither load the root nor safely overwrite what is there.
	ErrIncompleteCA = errors.New("incomplete CA on disk")
	// ErrExpiredCA means the stored root has passed its NotAfter. hull never
	// deletes it for you; the remedy is in the error text.
	ErrExpiredCA = errors.New("stored CA has expired")
	// ErrKeyMismatch means the stored key does not belong to the stored
	// certificate.
	ErrKeyMismatch = errors.New("stored CA key does not match the certificate")
	// ErrBadName means a requested SAN is not a usable DNS name or IP.
	ErrBadName = errors.New("not a usable certificate name")
)

// CA is a loaded local root plus its leaf cache. It is safe for concurrent use.
type CA struct {
	dir      string
	certPath string
	keyPath  string

	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey

	mu     sync.Mutex
	leaves map[string]*tls.Certificate

	// now is swappable in tests; nil means time.Now.
	now func() time.Time
}

// EnsureCA loads the root stored in dir, generating one if the directory has
// none. The directory is created with mode 0700 if it does not exist.
//
// An existing root is reused as-is: hull does not rotate a root the user may
// already have trusted. If only one of the two files is present, or the key
// does not match the certificate, or the certificate has expired, EnsureCA
// fails rather than overwriting anything — the error says which file to remove
// to get a fresh root.
func EnsureCA(dir string) (*CA, error) {
	if dir == "" {
		return nil, errors.New("localca: ensure CA: empty directory")
	}
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return nil, fmt.Errorf("localca: create %s: %w", dir, err)
	}
	certPath := filepath.Join(dir, CertFileName)
	keyPath := filepath.Join(dir, KeyFileName)

	certExists, err := exists(certPath)
	if err != nil {
		return nil, err
	}
	keyExists, err := exists(keyPath)
	if err != nil {
		return nil, err
	}

	switch {
	case certExists && keyExists:
		return load(dir, certPath, keyPath)
	case certExists != keyExists:
		present, missing := certPath, keyPath
		if keyExists {
			present, missing = keyPath, certPath
		}
		return nil, fmt.Errorf("localca: %w: %s is present but %s is not; remove %s to generate a fresh root",
			ErrIncompleteCA, present, missing, present)
	default:
		return generate(dir, certPath, keyPath)
	}
}

// Dir returns the directory the root is stored in.
func (c *CA) Dir() string { return c.dir }

// CertPath returns the absolute-or-as-given path of the root certificate file,
// which is what [CA.InstallHint] tells the user to trust.
func (c *CA) CertPath() string { return c.certPath }

// KeyPath returns the path of the root private key file.
func (c *CA) KeyPath() string { return c.keyPath }

// Certificate returns the parsed root certificate. The caller must not mutate it.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// CertPEM returns a copy of the PEM encoding of the root certificate, which is
// what a client needs in order to trust leaves minted by this CA.
func (c *CA) CertPEM() []byte {
	out := make([]byte, len(c.certPEM))
	copy(out, c.certPEM)
	return out
}

// Pool returns a new x509 pool containing only this root. It is what tests and
// hull's own health probes use to verify a leaf without touching the system
// trust store.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

func (c *CA) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func load(dir, certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("localca: read %s: %w", certPath, err)
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("localca: parse %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("localca: read %s: %w", keyPath, err)
	}
	key, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("localca: parse %s: %w", keyPath, err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(key.Public()) {
		return nil, fmt.Errorf("localca: %w: %s and %s; remove both to generate a fresh root",
			ErrKeyMismatch, certPath, keyPath)
	}
	if time.Now().After(cert.NotAfter) {
		return nil, fmt.Errorf("localca: %w on %s (NotAfter %s); remove %s and %s to generate a fresh root",
			ErrExpiredCA, certPath, cert.NotAfter.Format(time.RFC3339), certPath, keyPath)
	}
	return &CA{
		dir:      dir,
		certPath: certPath,
		keyPath:  keyPath,
		cert:     cert,
		certPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		key:      key,
		leaves:   make(map[string]*tls.Certificate),
	}, nil
}

func generate(dir, certPath, keyPath string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("localca: generate root key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "hull local CA",
			Organization: []string{"hull"},
		},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(CAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("localca: sign root: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("localca: parse generated root: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("localca: marshal root key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Key first: a reader that sees the certificate must always be able to
	// find the key next to it.
	if err := writeFile(keyPath, keyPEM); err != nil {
		return nil, err
	}
	if err := writeFile(certPath, certPEM); err != nil {
		return nil, err
	}
	return &CA{
		dir:      dir,
		certPath: certPath,
		keyPath:  keyPath,
		cert:     cert,
		certPEM:  certPEM,
		key:      key,
		leaves:   make(map[string]*tls.Certificate),
	}, nil
}

// writeFile writes b to path via a temporary file in the same directory, so a
// crash never leaves a half-written key where a later run would load it.
func writeFile(path string, b []byte) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, FileMode)
	if err != nil {
		return fmt.Errorf("localca: create %s: %w", tmp, err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("localca: write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("localca: sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("localca: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("localca: rename %s: %w", path, err)
	}
	// Rename preserves the temp file's mode, but be explicit: an inherited
	// umask must never widen these two files.
	if err := os.Chmod(path, FileMode); err != nil {
		return fmt.Errorf("localca: chmod %s: %w", path, err)
	}
	return nil
}

func parseCertPEM(b []byte) (*x509.Certificate, error) {
	for rest := b; len(rest) > 0; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		return cert, nil
	}
	return nil, errors.New("no CERTIFICATE block found")
}

func parseKeyPEM(b []byte) (*ecdsa.PrivateKey, error) {
	for rest := b; len(rest) > 0; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse EC private key: %w", err)
			}
			return key, nil
		case "PRIVATE KEY":
			parsed, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
			}
			key, ok := parsed.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("private key is %T, want *ecdsa.PrivateKey", parsed)
			}
			return key, nil
		}
	}
	return nil, errors.New("no PRIVATE KEY block found")
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("localca: serial number: %w", err)
	}
	return serial, nil
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("localca: stat %s: %w", path, err)
	}
}
