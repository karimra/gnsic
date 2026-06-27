package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/karimra/gnsic/api"
	certzapi "github.com/karimra/gnsic/api/certz"
	"github.com/karimra/gnsic/config"
	"github.com/karimra/gnsic/server/certz/manager"
	srv "github.com/karimra/gnsic/server/certz/server"
	"github.com/karimra/gnsic/server/certz/store"
	certzpb "github.com/openconfig/gnsi/certz"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// startEmbeddedCertzServer embeds the certz server (the same way an external
// project would) and returns its dial address.
func startEmbeddedCertzServer(t *testing.T) string {
	t.Helper()
	st := store.NewMap(store.StoreConfig{})
	mgr := manager.NewManager(st)
	s := srv.NewServer(
		srv.Config{Address: "127.0.0.1:0"},
		mgr,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	lis, err := s.Listener()
	if err != nil {
		t.Fatalf("Listener: %v", err)
	}
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return lis.Addr().String()
}

func verifyClient(t *testing.T, addr string) certzpb.CertzClient {
	t.Helper()
	creds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return certzpb.NewCertzClient(conn)
}

func profileExists(t *testing.T, c certzpb.CertzClient, id string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.GetProfileList(ctx, &certzpb.GetProfileListRequest{})
	if err != nil {
		t.Fatalf("GetProfileList: %v", err)
	}
	for _, p := range resp.GetSslProfileIds() {
		if p == id {
			return true
		}
	}
	return false
}

// newRotateTestApp builds a minimal App and a target pointing at addr over TLS
// with verification disabled (the embedded server uses a self-signed cert).
func newRotateTestApp(t *testing.T, addr string) (*App, *api.Target) {
	t.Helper()
	logger := log.New()
	logger.SetOutput(io.Discard)
	a := &App{
		wg:     new(sync.WaitGroup),
		Config: config.New(),
		Logger: log.NewEntry(logger),
		pm:     new(sync.Mutex),
	}
	skip := true
	tc := &config.TargetConfig{
		Name:       addr,
		Address:    addr,
		SkipVerify: &skip,
		Timeout:    15 * time.Second,
	}
	return a, api.NewTargetFromConfig(tc)
}

// runRotate runs the top-level dispatcher synchronously and returns the result.
func runRotate(a *App, target *api.Target) *rotateResponse {
	ch := make(chan *rotateResponse, 1)
	a.wg.Add(1)
	a.certzRotateRequest(context.Background(), target, ch)
	return <-ch
}

func writeCAFiles(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "ca.pem")
	keyPath = filepath.Join(dir, "ca-key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func writeLeafFiles(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "leaf.pem")
	keyPath = filepath.Join(dir, "leaf-key.pem")
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

const rsa2048SHA256 = "CSRSUITE_X509_KEY_TYPE_RSA_2048_SIGNATURE_ALGORITHM_SHA_2_256"

// TestRotateCase2TargetCSR: target generates the CSR, the client signs it and
// uploads the certificate (no private key).
func TestRotateCase2TargetCSR(t *testing.T) {
	addr := startEmbeddedCertzServer(t)
	a, target := newRotateTestApp(t, addr)
	caCert, caKey := writeCAFiles(t)

	a.Config.CertzRotateSSLProfileID = "case2"
	a.Config.CertzRotateCommonName = "device.example.com"
	a.Config.CertzRotateCSRSuite = rsa2048SHA256
	a.Config.CertzRotateCACert = caCert
	a.Config.CertzRotateCAKey = caKey
	a.Config.CertzRotateCertificateValidity = 24 * time.Hour

	if rsp := runRotate(a, target); rsp.Err != nil {
		t.Fatalf("rotate case 2 failed: %v", rsp.Err)
	}
	if !profileExists(t, verifyClient(t, addr), "case2") {
		t.Fatal("expected 'case2' profile after rotation")
	}
}

// TestRotateCase1LocalCSR: client generates the key/CSR locally, signs it and
// uploads the certificate together with the private key. The embedded server
// always advertises CanGenerate=true, so the case-1 handler is exercised
// directly.
func TestRotateCase1LocalCSR(t *testing.T) {
	addr := startEmbeddedCertzServer(t)
	a, target := newRotateTestApp(t, addr)
	caCert, caKey := writeCAFiles(t)

	a.Config.CertzRotateSSLProfileID = "case1"
	a.Config.CertzRotateCommonName = "device1.example.com"
	a.Config.CertzRotateCSRSuite = rsa2048SHA256
	a.Config.CertzRotateCACert = caCert
	a.Config.CertzRotateCAKey = caKey
	a.Config.CertzRotateCertificateValidity = 24 * time.Hour

	ctx := context.Background()
	if err := target.CreateGrpcClient(ctx, a.createBaseDialOpts()...); err != nil {
		t.Fatalf("CreateGrpcClient: %v", err)
	}
	defer target.Close()

	ch := make(chan *rotateResponse, 1)
	a.certzRotateWithGenerateCertificateCannotGenerateCSR(ctx, target, ch)
	if rsp := <-ch; rsp.Err != nil {
		t.Fatalf("rotate case 1 failed: %v", rsp.Err)
	}
	if !profileExists(t, verifyClient(t, addr), "case1") {
		t.Fatal("expected 'case1' profile after rotation")
	}
}

// TestRotatePreGenerated: client uploads a pre-generated certificate + key from
// files.
func TestRotatePreGenerated(t *testing.T) {
	addr := startEmbeddedCertzServer(t)
	a, target := newRotateTestApp(t, addr)
	certPath, keyPath := writeLeafFiles(t)

	a.Config.CertzRotateSSLProfileID = "pregen"
	a.Config.CertzRotateEntityCertChainCertificateCFile = []string{certPath}
	a.Config.CertzRotateEntityCertChainCertificateKFile = []string{keyPath}

	if rsp := runRotate(a, target); rsp.Err != nil {
		t.Fatalf("rotate pre-generated failed: %v", rsp.Err)
	}
	if !profileExists(t, verifyClient(t, addr), "pregen") {
		t.Fatal("expected 'pregen' profile after rotation")
	}
}

// TestRotateCase3TrustBundle: client rotates only the trust bundle.
func TestRotateCase3TrustBundle(t *testing.T) {
	addr := startEmbeddedCertzServer(t)
	a, target := newRotateTestApp(t, addr)
	caCert, _ := writeCAFiles(t)

	a.Config.CertzRotateSSLProfileID = "case3"
	a.Config.CertzRotateEntityCertChainTrustBundleCFile = []string{caCert}
	a.Config.CertzRotateEntityCertChainTrustBundleVersion = []string{"v1"}

	if rsp := runRotate(a, target); rsp.Err != nil {
		t.Fatalf("rotate case 3 failed: %v", rsp.Err)
	}
	if !profileExists(t, verifyClient(t, addr), "case3") {
		t.Fatal("expected 'case3' profile after rotation")
	}
}

// TestRotateCase4CRL: client rotates only the CRL bundle.
func TestRotateCase4CRL(t *testing.T) {
	addr := startEmbeddedCertzServer(t)
	a, target := newRotateTestApp(t, addr)

	dir := t.TempDir()
	crlPath := filepath.Join(dir, "crl.pem")
	if err := os.WriteFile(crlPath, []byte("-----BEGIN X509 CRL-----\nMIIB\n-----END X509 CRL-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	a.Config.CertzRotateSSLProfileID = "case4"
	a.Config.CertzRotateEntityCertChainCRLCFile = []string{crlPath}
	a.Config.CertzRotateEntityCertChainCRLID = []string{"crl1"}
	a.Config.CertzRotateEntityCertChainCRLVersion = []string{"v1"}

	if rsp := runRotate(a, target); rsp.Err != nil {
		t.Fatalf("rotate case 4 failed: %v", rsp.Err)
	}
	if !profileExists(t, verifyClient(t, addr), "case4") {
		t.Fatal("expected 'case4' profile after rotation")
	}
}

// TestBuildExtraEntityOptsTypes verifies that the upload request builders emit
// the correct Entity oneof variants for the entity types the embedded server
// does not (yet) round-trip: PKCS#7 trust bundle, authentication policy and
// existing-entity copies, plus a CRL bundle.
func TestBuildExtraEntityOptsTypes(t *testing.T) {
	logger := log.New()
	logger.SetOutput(io.Discard)
	a := &App{Config: config.New(), Logger: log.NewEntry(logger)}

	dir := t.TempDir()
	pkcs7Path := filepath.Join(dir, "bundle.p7b")
	if err := os.WriteFile(pkcs7Path, []byte("pkcs7-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"@type":"type.googleapis.com/google.protobuf.Empty"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	crlPath := filepath.Join(dir, "crl.pem")
	if err := os.WriteFile(crlPath, []byte("crl-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	a.Config.CertzRotateEntityCertChainTrustBundlePKCS7File = []string{pkcs7Path}
	a.Config.CertzRotateEntityCertChainTrustBundlePKCS7Version = []string{"p1"}
	a.Config.CertzRotateEntityCertChainCRLCFile = []string{crlPath}
	a.Config.CertzRotateEntityCertChainCRLID = []string{"crl1"}
	a.Config.CertzRotateEntityAuthPolicy = policyPath
	a.Config.CertzRotateExistingProfileID = []string{"other"}
	a.Config.CertzRotateExistingType = []string{"trust-bundle"}

	opts, err := a.buildExtraEntityOpts(time.Now())
	if err != nil {
		t.Fatalf("buildExtraEntityOpts: %v", err)
	}
	req, err := certzapi.NewRotateCertificateRequest(
		certzapi.SSLProfileID("x"),
		certzapi.CertificatesRequest(opts...),
	)
	if err != nil {
		t.Fatalf("NewRotateCertificateRequest: %v", err)
	}
	entities := req.GetCertificates().GetEntities()

	var gotPKCS7, gotCRL, gotPolicy, gotExisting bool
	for _, e := range entities {
		switch ev := e.Entity.(type) {
		case *certzpb.Entity_TrustBundlePkcs7:
			gotPKCS7 = ev.TrustBundlePkcs7.GetPkcs7Block() == "pkcs7-bytes"
		case *certzpb.Entity_CertificateRevocationListBundle:
			crls := ev.CertificateRevocationListBundle.GetCertificateRevocationLists()
			gotCRL = len(crls) == 1 && crls[0].GetId() == "crl1"
		case *certzpb.Entity_AuthenticationPolicy:
			gotPolicy = ev.AuthenticationPolicy.GetSerialized() != nil
		case *certzpb.Entity_ExistingEntity:
			gotExisting = ev.ExistingEntity.GetSslProfileId() == "other" &&
				ev.ExistingEntity.GetEntityType() == certzpb.ExistingEntity_ENTITY_TYPE_TRUST_BUNDLE
		}
	}
	if !gotPKCS7 {
		t.Error("missing/incorrect PKCS#7 trust bundle entity")
	}
	if !gotCRL {
		t.Error("missing/incorrect CRL bundle entity")
	}
	if !gotPolicy {
		t.Error("missing/incorrect authentication policy entity")
	}
	if !gotExisting {
		t.Error("missing/incorrect existing entity")
	}
}
