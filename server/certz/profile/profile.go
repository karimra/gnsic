package profile

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"
)

const (
	DefaultProfileName ProfileID = "system_default_profile" // default profile name
)

type ProfileID string

type ProfileSpec struct {
	ID           ProfileID
	ServerName   string // for clients (SNI)
	MinVersion   uint16
	MaxVersion   uint16
	CipherSuites []uint16           // optional
	ClientAuth   tls.ClientAuthType // for servers
}

// raw bytes as stored/fetched, with parsed fields for convenience.
type CertzProfile struct {
	// leaf + intermediates (server or client cert)
	CertPEM []byte `json:"cert_pem,omitempty"`
	// private key
	KeyPEM []byte `json:"key_pem,omitempty"`
	// root(s) used to verify peers
	CAPEM []byte `json:"capem,omitempty"`
	// parsed
	Serial       string    `json:"serial,omitempty"`     // parsed from CertPEM
	NotBefore    time.Time `json:"not_before,omitempty"` // parsed from CertPEM
	NotAfter     time.Time `json:"not_after,omitempty"`  // parsed from CertPEM
	CertzVersion int64     `json:"version,omitempty"`    // certz version impl?
}

func (p *CertzProfile) Parse() (tls.Certificate, *x509.CertPool, error) {
	leaf, err := tls.X509KeyPair(p.CertPEM, p.KeyPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	roots := x509.NewCertPool()
	if len(p.CAPEM) != 0 {
		if ok := roots.AppendCertsFromPEM(p.CAPEM); !ok {
			return tls.Certificate{}, nil, errors.New("failed to append CA certificate")
		}
	}
	// set timestamps and serial number
	p.NotBefore = leaf.Leaf.NotBefore
	p.NotAfter = leaf.Leaf.NotAfter
	p.Serial = leaf.Leaf.SerialNumber.String()
	return leaf, roots, nil
}

func (p *CertzProfile) Validate(now time.Time) error {
	if p.NotBefore.IsZero() {
		return errors.New("certificate not before is not set")
	}
	if p.NotAfter.IsZero() {
		return errors.New("certificate not after is not set")
	}
	if p.Serial == "" {
		return errors.New("certificate serial is not set")
	}
	if p.IsExpired(now) {
		return errors.New("certificate is expired")
	}
	return nil
}

func (p *CertzProfile) IsExpired(now time.Time) bool {
	return p.NotAfter.Before(now)
}
