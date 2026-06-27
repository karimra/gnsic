package server_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/karimra/gnsic/server/certz/manager"
	srv "github.com/karimra/gnsic/server/certz/server"
	"github.com/karimra/gnsic/server/certz/store"
	certzpb "github.com/openconfig/gnsi/certz"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// newTestServer spins up the certz server the same way an external project would
// embed it: build a store, wrap it in a manager, construct the server and serve
// it on a listener. Returns the dial address.
func newTestServer(t *testing.T) string {
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

func newClient(t *testing.T, addr string) certzpb.CertzClient {
	t.Helper()
	creds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return certzpb.NewCertzClient(conn)
}

func ctxWithTimeout(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func listProfiles(t *testing.T, c certzpb.CertzClient, ctx context.Context) map[string]bool {
	t.Helper()
	resp, err := c.GetProfileList(ctx, &certzpb.GetProfileListRequest{})
	if err != nil {
		t.Fatalf("GetProfileList: %v", err)
	}
	out := make(map[string]bool, len(resp.GetSslProfileIds()))
	for _, id := range resp.GetSslProfileIds() {
		out[id] = true
	}
	return out
}

func TestGetProfileListHasDefault(t *testing.T) {
	addr := newTestServer(t)
	c := newClient(t, addr)
	ctx := ctxWithTimeout(t)

	got := listProfiles(t, c, ctx)
	if !got["system_default_profile"] {
		t.Fatalf("expected default profile in list, got %v", got)
	}
}

func TestAddDeleteProfile(t *testing.T) {
	addr := newTestServer(t)
	c := newClient(t, addr)
	ctx := ctxWithTimeout(t)

	if _, err := c.AddProfile(ctx, &certzpb.AddProfileRequest{SslProfileId: "p1"}); err != nil {
		t.Fatalf("AddProfile: %v", err)
	}
	if !listProfiles(t, c, ctx)["p1"] {
		t.Fatal("expected p1 after AddProfile")
	}
	if _, err := c.DeleteProfile(ctx, &certzpb.DeleteProfileRequest{SslProfileId: "p1"}); err != nil {
		t.Fatalf("DeleteProfile: %v", err)
	}
	if listProfiles(t, c, ctx)["p1"] {
		t.Fatal("did not expect p1 after DeleteProfile")
	}

	// empty id must be rejected.
	if _, err := c.AddProfile(ctx, &certzpb.AddProfileRequest{}); err == nil {
		t.Fatal("expected error for empty ssl profile id")
	}
}

func TestCanGenerateCSR(t *testing.T) {
	addr := newTestServer(t)
	c := newClient(t, addr)
	ctx := ctxWithTimeout(t)

	resp, err := c.CanGenerateCSR(ctx, &certzpb.CanGenerateCSRRequest{
		Params: &certzpb.CSRParams{
			CsrSuite: certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_2048_SIGNATURE_ALGORITHM_SHA_2_256,
		},
	})
	if err != nil {
		t.Fatalf("CanGenerateCSR: %v", err)
	}
	if !resp.GetCanGenerate() {
		t.Fatal("expected CanGenerate=true for a supported suite")
	}

	if _, err := c.CanGenerateCSR(ctx, &certzpb.CanGenerateCSRRequest{
		Params: &certzpb.CSRParams{CsrSuite: certzpb.CSRSuite_CSRSUITE_CIPHER_UNSPECIFIED},
	}); err == nil {
		t.Fatal("expected error for unspecified csr suite")
	}
}

// TestRotateUploadCertificates exercises the flow where the client supplies both
// the certificate and the private key.
func TestRotateUploadCertificates(t *testing.T) {
	addr := newTestServer(t)
	c := newClient(t, addr)
	ctx := ctxWithTimeout(t)

	certPEM, keyPEM := makeLeaf(t)

	stream, err := c.Rotate(ctx)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	err = stream.Send(&certzpb.RotateCertificateRequest{
		SslProfileId: "uploaded",
		RotateRequest: &certzpb.RotateCertificateRequest_Certificates{
			Certificates: &certzpb.UploadRequest{
				Entities: []*certzpb.Entity{certChainEntity(certPEM, keyPEM)},
			},
		},
	})
	if err != nil {
		t.Fatalf("send certificates: %v", err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv upload response: %v", err)
	}
	if resp.GetCertificates() == nil {
		t.Fatalf("expected certificates upload response, got %T", resp.GetRotateResponse())
	}

	if err := stream.Send(&certzpb.RotateCertificateRequest{
		RotateRequest: &certzpb.RotateCertificateRequest_FinalizeRotation{
			FinalizeRotation: &certzpb.FinalizeRequest{},
		},
	}); err != nil {
		t.Fatalf("send finalize: %v", err)
	}
	_ = stream.CloseSend()
	if _, err := stream.Recv(); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("expected clean stream end, got: %v", err)
	}

	if !listProfiles(t, c, ctx)["uploaded"] {
		t.Fatal("expected 'uploaded' profile after rotation")
	}
}

// TestRotateGenerateCSR exercises the flow where the server generates the key and
// CSR, the client signs it, and uploads the resulting certificate.
func TestRotateGenerateCSR(t *testing.T) {
	addr := newTestServer(t)
	c := newClient(t, addr)
	ctx := ctxWithTimeout(t)

	caCert, caKey := newCA(t)

	stream, err := c.Rotate(ctx)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := stream.Send(&certzpb.RotateCertificateRequest{
		SslProfileId: "generated",
		RotateRequest: &certzpb.RotateCertificateRequest_GenerateCsr{
			GenerateCsr: &certzpb.GenerateCSRRequest{
				Params: &certzpb.CSRParams{
					CsrSuite:   certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_2048_SIGNATURE_ALGORITHM_SHA_2_256,
					CommonName: "device.example.com",
				},
			},
		},
	}); err != nil {
		t.Fatalf("send generate csr: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv csr: %v", err)
	}
	gen := resp.GetGeneratedCsr()
	if gen == nil || gen.GetCertificateSigningRequest() == nil {
		t.Fatalf("expected generated CSR, got %T", resp.GetRotateResponse())
	}
	csrPEM := gen.GetCertificateSigningRequest().GetCertificateSigningRequest()
	certPEM := signCSR(t, csrPEM, caCert, caKey)

	if err := stream.Send(&certzpb.RotateCertificateRequest{
		RotateRequest: &certzpb.RotateCertificateRequest_Certificates{
			Certificates: &certzpb.UploadRequest{
				Entities: []*certzpb.Entity{certChainEntity(certPEM, nil)},
			},
		},
	}); err != nil {
		t.Fatalf("send signed certificate: %v", err)
	}
	resp, err = stream.Recv()
	if err != nil {
		t.Fatalf("recv upload response: %v", err)
	}
	if resp.GetCertificates() == nil {
		t.Fatalf("expected certificates upload response, got %T", resp.GetRotateResponse())
	}

	if err := stream.Send(&certzpb.RotateCertificateRequest{
		RotateRequest: &certzpb.RotateCertificateRequest_FinalizeRotation{
			FinalizeRotation: &certzpb.FinalizeRequest{},
		},
	}); err != nil {
		t.Fatalf("send finalize: %v", err)
	}
	_ = stream.CloseSend()
	if _, err := stream.Recv(); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("expected clean stream end, got: %v", err)
	}

	if !listProfiles(t, c, ctx)["generated"] {
		t.Fatal("expected 'generated' profile after rotation")
	}
}

func certChainEntity(certPEM, keyPEM []byte) *certzpb.Entity {
	cert := &certzpb.Certificate{
		Type:            certzpb.CertificateType_CERTIFICATE_TYPE_X509,
		Encoding:        certzpb.CertificateEncoding_CERTIFICATE_ENCODING_PEM,
		CertificateType: &certzpb.Certificate_RawCertificate{RawCertificate: certPEM},
	}
	if keyPEM != nil {
		cert.PrivateKeyType = &certzpb.Certificate_RawPrivateKey{RawPrivateKey: keyPEM}
	}
	return &certzpb.Entity{
		Entity: &certzpb.Entity_CertificateChain{
			CertificateChain: &certzpb.CertificateChain{Certificate: cert},
		},
	}
}

func makeLeaf(t *testing.T) (certPEM, keyPEM []byte) {
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
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func newCA(t *testing.T) (*x509.Certificate, crypto.Signer) {
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
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return caCert, key
}

func signCSR(t *testing.T, csrPEM []byte, caCert *x509.Certificate, caKey crypto.Signer) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("csr signature: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               csr.Subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              csr.DNSNames,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
