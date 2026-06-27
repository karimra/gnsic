package profile

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Copy returns a deep copy of p.
func Copy(p *CertzProfile) *CertzProfile {
	if p == nil {
		return nil
	}
	cp := *p
	cp.CertPEM = bytes.Clone(p.CertPEM)
	cp.KeyPEM = bytes.Clone(p.KeyPEM)
	cp.CAPEM = bytes.Clone(p.CAPEM)
	return &cp
}

// HasMaterial reports whether leaf certificate and private key are present.
func (p *CertzProfile) HasMaterial() bool {
	return p != nil && len(p.CertPEM) > 0 && len(p.KeyPEM) > 0
}

// CertificatePEM normalizes DER or PEM certificate bytes to PEM encoding.
func CertificatePEM(derOrPEM []byte) ([]byte, error) {
	if len(derOrPEM) == 0 {
		return nil, errors.New("empty certificate")
	}
	if block, _ := pem.Decode(derOrPEM); block != nil {
		return pem.EncodeToMemory(block), nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derOrPEM}), nil
}

// CAPEM normalizes DER or PEM trust-anchor bytes to PEM encoding.
func CAPEM(derOrPEM []byte) ([]byte, error) {
	return CertificatePEM(derOrPEM)
}

// PrivateKeyPEM normalizes DER or PEM private key bytes to PEM encoding.
func PrivateKeyPEM(derOrPEM []byte) ([]byte, error) {
	if len(derOrPEM) == 0 {
		return nil, errors.New("empty private key")
	}
	if block, _ := pem.Decode(derOrPEM); block != nil {
		return pem.EncodeToMemory(block), nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(derOrPEM); err == nil {
		b, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(derOrPEM); err == nil {
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), nil
	}
	return nil, errors.New("unrecognized private key format")
}

// ParseCertificateMaterial parses a certificate from DER or PEM and returns PEM for storage.
func ParseCertificateMaterial(derOrPEM []byte) (*x509.Certificate, []byte, error) {
	pemBytes, err := CertificatePEM(derOrPEM)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, nil, errors.New("failed to decode certificate PEM")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}
	return crt, pemBytes, nil
}
