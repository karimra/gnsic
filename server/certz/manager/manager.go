package manager

import (
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/karimra/gnsic/server/certz/profile"
	"github.com/karimra/gnsic/server/certz/store"
)

type Manager struct {
	store store.Store
}

func NewManager(store store.Store) *Manager {
	return &Manager{
		store: store,
	}
}

func (m *Manager) ServerTLSConfig(profileID profile.ProfileID, spec *profile.ProfileSpec) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		GetConfigForClient: m.ServerGetConfigForClient(profileID, spec),
	}
	return tlsConfig, nil
}

func (m *Manager) ServerGetConfigForClient(profileID profile.ProfileID, spec *profile.ProfileSpec) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(helloInfo *tls.ClientHelloInfo) (*tls.Config, error) {
		czp, err := m.store.Get(profileID)
		if err != nil {
			return nil, err
		}
		if czp == nil {
			return nil, errors.New("profile not found: " + string(profileID))
		}
		leaf, err := tls.X509KeyPair(czp.CertPEM, czp.KeyPEM)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if len(czp.CAPEM) != 0 { // only append CA certificate if it is set
			if ok := roots.AppendCertsFromPEM(czp.CAPEM); !ok {
				return nil, errors.New("failed to append CA certificate")
			}
		}
		tlsConfig := &tls.Config{
			NextProtos:         []string{"h2"},
			Certificates:       []tls.Certificate{leaf},
			ServerName:         spec.ServerName,
			ClientAuth:         spec.ClientAuth,
			ClientCAs:          roots,
			InsecureSkipVerify: false,
			CipherSuites:       spec.CipherSuites,
			MinVersion:         spec.MinVersion,
			MaxVersion:         spec.MaxVersion,
		}
		return tlsConfig, nil
	}
}

func (m *Manager) ClientTLSConfig(profileID profile.ProfileID, spec *profile.ProfileSpec) (*tls.Config, error) {
	czp, err := m.store.Get(profileID)
	if err != nil {
		return nil, err
	}
	if czp == nil {
		return nil, errors.New("profile not found: " + string(profileID))
	}
	// RootCAs are captured at dial time; the client side of crypto/tls has no
	// per-handshake hook to refresh them, unlike the server's GetConfigForClient.
	roots := x509.NewCertPool()
	if len(czp.CAPEM) != 0 { // only append CA certificate if it is set
		if ok := roots.AppendCertsFromPEM(czp.CAPEM); !ok {
			return nil, errors.New("failed to append CA certificate")
		}
	}
	tlsConfig := &tls.Config{
		ServerName:           spec.ServerName,
		RootCAs:              roots,
		InsecureSkipVerify:   false,
		CipherSuites:         spec.CipherSuites,
		MinVersion:           spec.MinVersion,
		MaxVersion:           spec.MaxVersion,
		GetClientCertificate: m.ClientGetCertificate(profileID),
	}
	return tlsConfig, nil
}

// ClientGetCertificate returns a GetClientCertificate callback that fetches the
// latest client certificate/key for the given profile at handshake time. When a
// server requests a client certificate but the profile has none, it returns an
// empty certificate so the handshake can proceed without one.
func (m *Manager) ClientGetCertificate(profileID profile.ProfileID) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		czp, err := m.store.Get(profileID)
		if err != nil {
			return nil, err
		}
		if czp == nil {
			return nil, errors.New("profile not found: " + string(profileID))
		}
		if len(czp.CertPEM) == 0 || len(czp.KeyPEM) == 0 {
			return &tls.Certificate{}, nil
		}
		leaf, err := tls.X509KeyPair(czp.CertPEM, czp.KeyPEM)
		if err != nil {
			return nil, err
		}
		return &leaf, nil
	}
}
