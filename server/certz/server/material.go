package server

import (
	"crypto/x509"

	"github.com/karimra/gnsic/server/certz/profile"
	certzpb "github.com/openconfig/gnsi/certz"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func applyCertificateChain(prof *profile.CertzProfile, chain *certzpb.CertificateChain, targetGeneratesCSR bool) error {
	cert := chain.GetCertificate()
	if cert == nil {
		return status.Errorf(codes.InvalidArgument, "certificate is required")
	}
	if targetGeneratesCSR && cert.PrivateKey != nil {
		return status.Errorf(codes.InvalidArgument, "private key must not be populated when the target generates the CSR")
	}

	var certMaterial []byte
	switch {
	case cert.GetCertificate() != nil:
		certMaterial = cert.GetCertificate()
	case cert.GetRawCertificate() != nil:
		certMaterial = cert.GetRawCertificate()
	default:
		if _, ok := cert.GetCertificateType().(*certzpb.Certificate_CertSource_); ok {
			return status.Errorf(codes.InvalidArgument, "unsupported certificate type: %T", cert.GetCertificateType())
		}
		return status.Errorf(codes.InvalidArgument, "certificate material is required")
	}

	crt, certPEM, err := profile.ParseCertificateMaterial(certMaterial)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to parse certificate: %v", err)
	}
	prof.CertPEM = certPEM
	setCertMetadata(prof, crt)

	if targetGeneratesCSR {
		return nil
	}

	var keyMaterial []byte
	switch {
	case cert.PrivateKey != nil:
		keyMaterial = cert.PrivateKey
	case cert.GetRawPrivateKey() != nil:
		keyMaterial = cert.GetRawPrivateKey()
	default:
		if _, ok := cert.GetPrivateKeyType().(*certzpb.Certificate_KeySource_); ok {
			return status.Errorf(codes.InvalidArgument, "unsupported private key type: %T", cert.GetPrivateKeyType())
		}
		return status.Errorf(codes.InvalidArgument, "private key must be populated when the client supplies the certificate")
	}
	keyPEM, err := profile.PrivateKeyPEM(keyMaterial)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to parse private key: %v", err)
	}
	prof.KeyPEM = keyPEM
	return nil
}

func applyTrustBundle(prof *profile.CertzProfile, chain *certzpb.CertificateChain) error {
	if chain == nil || chain.Certificate == nil {
		return nil
	}
	c := chain.Certificate
	var material []byte
	switch {
	case c.GetCertificate() != nil:
		material = c.GetCertificate()
	case c.GetRawCertificate() != nil:
		material = c.GetRawCertificate()
	default:
		if _, ok := c.GetCertificateType().(*certzpb.Certificate_CertSource_); ok {
			return status.Errorf(codes.InvalidArgument, "unsupported certificate type: %T", c.GetCertificateType())
		}
		return nil
	}
	caPEM, err := profile.CAPEM(material)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to parse trust bundle: %v", err)
	}
	prof.CAPEM = caPEM
	return nil
}

func setCertMetadata(prof *profile.CertzProfile, crt *x509.Certificate) {
	prof.NotBefore = crt.NotBefore
	prof.NotAfter = crt.NotAfter
	prof.Serial = crt.SerialNumber.String()
}

func (s *Server) applyRotateEntity(prof *profile.CertzProfile, entity *certzpb.Entity, targetGeneratesCSR bool) error {
	switch e := entity.Entity.(type) {
	case *certzpb.Entity_CertificateChain:
		s.logger.Debug("rotate entity", "type", "certificate_chain")
		return applyCertificateChain(prof, e.CertificateChain, targetGeneratesCSR)
	case *certzpb.Entity_TrustBundle:
		s.logger.Debug("rotate entity", "type", "trust_bundle")
		return applyTrustBundle(prof, e.TrustBundle)
	case *certzpb.Entity_CertificateRevocationListBundle:
		s.logger.Debug("rotate entity", "type", "crl_bundle")
		return nil
	default:
		return status.Errorf(codes.InvalidArgument, "unknown entity type: %T", e)
	}
}
