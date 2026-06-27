package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/karimra/gnsic/server/certz/profile"
	"github.com/karimra/gnsic/server/certz/store"
	certzpb "github.com/openconfig/gnsi/certz"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// validateCSRSuite reports whether suite is a CSR suite the server supports.
func validateCSRSuite(suite certzpb.CSRSuite) error {
	switch suite {
	case certzpb.CSRSuite_CSRSUITE_CIPHER_UNSPECIFIED:
		return status.Errorf(codes.InvalidArgument, "csr suite is unspecified")
	case certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_2048_SIGNATURE_ALGORITHM_SHA_2_256,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_2048_SIGNATURE_ALGORITHM_SHA_2_384,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_2048_SIGNATURE_ALGORITHM_SHA_2_512,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_3072_SIGNATURE_ALGORITHM_SHA_2_256,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_3072_SIGNATURE_ALGORITHM_SHA_2_384,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_3072_SIGNATURE_ALGORITHM_SHA_2_512,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_4096_SIGNATURE_ALGORITHM_SHA_2_256,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_4096_SIGNATURE_ALGORITHM_SHA_2_384,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_4096_SIGNATURE_ALGORITHM_SHA_2_512,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_PRIME256V1_SIGNATURE_ALGORITHM_SHA_2_256,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_PRIME256V1_SIGNATURE_ALGORITHM_SHA_2_384,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_PRIME256V1_SIGNATURE_ALGORITHM_SHA_2_512,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_SECP384R1_SIGNATURE_ALGORITHM_SHA_2_256,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_SECP384R1_SIGNATURE_ALGORITHM_SHA_2_384,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_SECP384R1_SIGNATURE_ALGORITHM_SHA_2_512,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_SECP521R1_SIGNATURE_ALGORITHM_SHA_2_256,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_SECP521R1_SIGNATURE_ALGORITHM_SHA_2_384,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_ECDSA_SECP521R1_SIGNATURE_ALGORITHM_SHA_2_512,
		certzpb.CSRSuite_CSRSUITE_X509_KEY_TYPE_EDDSA_ED25519:
		return nil
	default:
		return status.Errorf(codes.InvalidArgument, "unknown csr suite: %s", suite)
	}
}

// stageProfile activates prof for the given profile id and returns the profile
// that was previously stored (nil if none) so it can be restored if the rotation
// is not finalized. Staging makes the new material available to new TLS
// handshakes while the in-flight Rotate stream keeps using the old certificate.
func (s *Server) stageProfile(id profile.ProfileID, prof *profile.CertzProfile) (*profile.CertzProfile, error) {
	prev, err := s.manager.GetProfile(id)
	if err != nil && err != store.ErrNotFound {
		return nil, status.Errorf(codes.Internal, "failed to read current profile: %v", err)
	}
	if err := s.manager.SetProfile(id, prof); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to stage profile: %v", err)
	}
	return prev, nil
}

// rollbackProfile restores the profile captured by stageProfile after a rotation
// fails before finalization. If no usable profile existed previously, the staged
// one is removed.
func (s *Server) rollbackProfile(id profile.ProfileID, prev *profile.CertzProfile) {
	if prev == nil || !prev.HasMaterial() {
		if err := s.manager.DeleteProfile(id); err != nil && err != store.ErrNotFound {
			s.logger.Warn("failed to roll back staged profile", "profile", id, "error", err)
		}
		return
	}
	if err := s.manager.SetProfile(id, prev); err != nil {
		s.logger.Warn("failed to roll back profile", "profile", id, "error", err)
	}
}

func (s *Server) ensureDefaultProfile() error {
	defaultProfile, err := s.manager.GetProfile(profile.DefaultProfileName)
	if err != nil && err != store.ErrNotFound {
		return err
	}
	if defaultProfile == nil || !defaultProfile.HasMaterial() {
		return s.generateSelfSignedCertificate(s.config.TLS.SelfSigned)
	}
	return nil
}

func (s *Server) profileSpec(id profile.ProfileID) *profile.ProfileSpec {
	spec := &profile.ProfileSpec{ID: id}
	if s.config.TLS.TLSOptions == nil {
		return spec
	}
	opts := s.config.TLS.TLSOptions
	spec.MinVersion = opts.MinVersion
	spec.MaxVersion = opts.MaxVersion
	spec.CipherSuites = opts.CipherSuites
	spec.ClientAuth = parseClientAuth(opts.ClientAuth)
	return spec
}

func parseClientAuth(s string) tls.ClientAuthType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "request":
		return tls.RequestClientCert
	case "requireany":
		return tls.RequireAnyClientCert
	case "require", "requireandverify":
		return tls.RequireAndVerifyClientCert
	default:
		return tls.NoClientCert
	}
}

func (s *Server) generateSelfSignedCertificate(cfg *SelfSignedConfig) error {
	s.logger.Info("building the default profile, generating self-signed certificate")
	// generate a self-signed certificate
	defaultCerts, err := selfSignedCerts(cfg)
	if err != nil {
		return err
	}
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(defaultCerts.PrivateKey)
	if err != nil {
		return err
	}
	// convert cert from der to pem
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: defaultCerts.Certificate[0],
	})
	// convert key from der to pem
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	defaultProfile := &profile.CertzProfile{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}
	defaultProfile.NotBefore = defaultCerts.Leaf.NotBefore
	defaultProfile.NotAfter = defaultCerts.Leaf.NotAfter
	defaultProfile.Serial = defaultCerts.Leaf.SerialNumber.String()
	err = s.manager.SetProfile(profile.DefaultProfileName, defaultProfile)
	if err != nil {
		return err
	}
	return nil
}

// parseAddress parses address into network and address
// unix://path/to/socket -> unix, path/to/socket
// tcp://127.0.0.1:8080 -> tcp, 127.0.0.1:8080
// 192.168.1.1:8080 -> tcp, 192.168.1.1:8080
func (s *Server) parseAddress(address string) (string, string, error) {
	// check if the address is in the form network://address
	network, addr, found := strings.Cut(address, "://")
	if found {
		return network, addr, nil
	}
	// default to TCP
	return "tcp", address, nil
}
