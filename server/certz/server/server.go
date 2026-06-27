package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/karimra/gnsic/server/certz/certzcsr"
	"github.com/karimra/gnsic/server/certz/manager"
	"github.com/karimra/gnsic/server/certz/profile"
	certzpb "github.com/openconfig/gnsi/certz"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type Server struct {
	certzpb.UnimplementedCertzServer

	config  Config
	manager *manager.Manager
	logger  *slog.Logger

	mu         sync.Mutex
	grpcServer *grpc.Server
}

type Config struct {
	Address string
	TLS     TLS
}

type TLS struct {
	TLSProfile string
	TLSOptions *TLSOptions
	SelfSigned *SelfSignedConfig
}

type TLSOptions struct {
	MinVersion   uint16
	MaxVersion   uint16
	CipherSuites []uint16
	ClientAuth   string
}

type SelfSignedConfig struct {
	CN         string
	O          string
	OU         string
	ST         string
	L          string
	PostalCode string
	DNSNames   []string
}

func NewServer(config Config, manager *manager.Manager, logger *slog.Logger) *Server {
	setDefaults(&config)
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}
	return &Server{
		config:  config,
		manager: manager,
		logger:  logger,
	}
}

func setDefaults(c *Config) {
	if c.TLS.TLSProfile == "" {
		c.TLS.TLSProfile = string(profile.DefaultProfileName)
	}
	if c.TLS.TLSOptions == nil {
		c.TLS.TLSOptions = &TLSOptions{
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		}
	}
	if c.TLS.SelfSigned == nil {
		c.TLS.SelfSigned = &SelfSignedConfig{
			CN: "gnsic",
			O:  "gnsic",
			OU: "gnsic",
			ST: "gnsic",
		}
	}
}

// Start builds the TLS listener for the configured address and serves gRPC on
// it. It blocks until the server is stopped or the listener fails.
func (s *Server) Start() error {
	lis, err := s.Listener()
	if err != nil {
		return err
	}
	return s.Serve(lis)
}

// Listener ensures the default profile exists and returns a TLS listener bound
// to the configured address. It is exposed so the server can be embedded next to
// other services that need control over startup ordering (e.g. to learn the
// bound address before serving).
func (s *Server) Listener() (net.Listener, error) {
	if err := s.ensureDefaultProfile(); err != nil {
		return nil, err
	}
	profileID := profile.DefaultProfileName
	if s.config.TLS.TLSProfile != "" {
		profileID = profile.ProfileID(s.config.TLS.TLSProfile)
	}
	tlsConfig, err := s.manager.ServerTLSConfig(profileID, s.profileSpec(profileID))
	if err != nil {
		return nil, err
	}
	network, address, err := s.parseAddress(s.config.Address)
	if err != nil {
		return nil, err
	}
	return tls.Listen(network, address, tlsConfig)
}

// Serve registers the Certz service and serves gRPC on lis until Stop is called
// or the listener fails.
func (s *Server) Serve(lis net.Listener) error {
	grpcServer := grpc.NewServer()
	s.mu.Lock()
	s.grpcServer = grpcServer
	s.mu.Unlock()
	certzpb.RegisterCertzServer(grpcServer, s)
	return grpcServer.Serve(lis)
}

// Stop gracefully stops the gRPC server if it is running.
func (s *Server) Stop() {
	s.mu.Lock()
	gs := s.grpcServer
	s.mu.Unlock()
	if gs != nil {
		gs.GracefulStop()
	}
}

func (s *Server) AddProfile(ctx context.Context, req *certzpb.AddProfileRequest) (*certzpb.AddProfileResponse, error) {
	if req.SslProfileId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ssl profile id is required")
	}
	s.logger.Debug("AddProfile request", "request", req)
	err := s.manager.SetProfile(profile.ProfileID(req.SslProfileId), &profile.CertzProfile{})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to add profile: %v", err)
	}
	return &certzpb.AddProfileResponse{}, nil
}

func (s *Server) DeleteProfile(ctx context.Context, req *certzpb.DeleteProfileRequest) (*certzpb.DeleteProfileResponse, error) {
	if req.SslProfileId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ssl profile id is required")
	}
	s.logger.Debug("DeleteProfile request", "request", req)
	err := s.manager.DeleteProfile(profile.ProfileID(req.SslProfileId))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete profile: %v", err)
	}
	return &certzpb.DeleteProfileResponse{}, nil
}

func (s *Server) GetProfileList(ctx context.Context, req *certzpb.GetProfileListRequest) (*certzpb.GetProfileListResponse, error) {
	ids, err := s.manager.ListProfiles()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get profile list: %v", err)
	}
	return &certzpb.GetProfileListResponse{
		SslProfileIds: ids,
	}, nil
}

func (s *Server) CanGenerateCSR(ctx context.Context, req *certzpb.CanGenerateCSRRequest) (*certzpb.CanGenerateCSRResponse, error) {
	if req.Params == nil {
		return nil, status.Errorf(codes.InvalidArgument, "params are required")
	}
	s.logger.Debug("CanGenerateCSR request", "request", req)
	if err := validateCSRSuite(req.Params.CsrSuite); err != nil {
		return nil, err
	}
	return &certzpb.CanGenerateCSRResponse{
		CanGenerate: true,
	}, nil
}

func (s *Server) GetIntegrityManifest(ctx context.Context, req *certzpb.GetIntegrityManifestRequest) (*certzpb.GetIntegrityManifestResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetIntegrityManifest not implemented")
}

func (s *Server) Rotate(stream certzpb.Certz_RotateServer) error {
	ctx := stream.Context()
	pr, _ := peer.FromContext(ctx)
	s.logger.Info("received Rotate request from peer", "peer", pr.Addr.String())
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	profileID := profile.ProfileID(msg.SslProfileId)
	s.logger.Debug("received message", "message", msg)
	switch msg := msg.RotateRequest.(type) {
	case *certzpb.RotateCertificateRequest_GenerateCsr:
		return s.handleRotateGenerateCSR(stream, profileID, msg)
	case *certzpb.RotateCertificateRequest_Certificates:
		s.logger.Debug("received CertificatesRequest", "message", msg)
		return s.handleRotateCertificates(stream, profileID, msg)
	case *certzpb.RotateCertificateRequest_FinalizeRotation:
		s.logger.Debug("received FinalizeRotation", "message", msg)
		// Invalid case, should not happen
		return status.Errorf(codes.InvalidArgument, "unexpected message type: %T", msg)
	default:
		return status.Errorf(codes.InvalidArgument, "unknown message type: %T", msg)
	}
}

func (s *Server) generateCSR(req *certzpb.GenerateCSRRequest) (*certzpb.GenerateCSRResponse, crypto.PrivateKey, error) {
	if err := validateCSRSuite(req.Params.CsrSuite); err != nil {
		return nil, nil, err
	}

	subject := pkix.Name{CommonName: req.Params.CommonName}
	if req.Params.Country != "" {
		subject.Country = []string{req.Params.Country}
	}
	if req.Params.Organization != "" {
		subject.Organization = []string{req.Params.Organization}
	}
	if req.Params.OrganizationalUnit != "" {
		subject.OrganizationalUnit = []string{req.Params.OrganizationalUnit}
	}
	if req.Params.City != "" {
		subject.Locality = []string{req.Params.City}
	}
	if req.Params.State != "" {
		subject.Province = []string{req.Params.State}
	}
	csrInput := certzcsr.CSRInput{
		Subject:        subject,
		DNSNames:       []string{},
		IPAddresses:    []net.IP{},
		EmailAddresses: []string{},
		URIs:           []*url.URL{},
	}

	if req.Params.San != nil {
		csrInput.DNSNames = append(csrInput.DNSNames, req.Params.San.Dns...)
		for _, ipaddr := range req.Params.San.Ips {
			csrInput.IPAddresses = append(csrInput.IPAddresses, net.ParseIP(ipaddr))
		}
		csrInput.EmailAddresses = append(csrInput.EmailAddresses, req.Params.San.Emails...)
		for _, uri := range req.Params.San.Uris {
			u, err := url.Parse(uri)
			if err != nil {
				return nil, nil, status.Errorf(codes.Internal, "failed to parse URI: %v", err)
			}
			csrInput.URIs = append(csrInput.URIs, u)
		}
	}
	csrPEM, privKey, err := certzcsr.CreateCSRFromSuiteName(req.Params.CsrSuite.String(), csrInput)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "failed to create certificate request: %v", err)
	}
	s.logger.Debug("generated CSR PEM", "bytes", len(csrPEM))
	rsp := &certzpb.GenerateCSRResponse{
		CertificateSigningRequest: &certzpb.CertificateSigningRequest{
			Type:                      certzpb.CertificateType_CERTIFICATE_TYPE_X509,
			Encoding:                  certzpb.CertificateEncoding_CERTIFICATE_ENCODING_PEM,
			CertificateSigningRequest: csrPEM,
		},
	}
	s.logger.Debug("generated CSR", "response", rsp)
	return rsp, privKey, nil
}

func (s *Server) handleRotateGenerateCSR(stream certzpb.Certz_RotateServer, profileID profile.ProfileID, msg *certzpb.RotateCertificateRequest_GenerateCsr) error {
	s.logger.Debug("received GenerateCSRRequest", "message", msg)
	generateCSRResponse, privKey, err := s.generateCSR(msg.GenerateCsr)
	if err != nil {
		return err
	}
	err = stream.Send(&certzpb.RotateCertificateResponse{
		RotateResponse: &certzpb.RotateCertificateResponse_GeneratedCsr{
			GeneratedCsr: generateCSRResponse,
		},
	})
	if err != nil {
		return err
	}
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return err
	}
	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	msg2, err := stream.Recv()
	if err != nil {
		return err
	}
	s.logger.Debug("received certificates upload")

	prof := &profile.CertzProfile{
		KeyPEM: privPem,
	}
	switch msg2 := msg2.RotateRequest.(type) {
	case *certzpb.RotateCertificateRequest_Certificates:
		for _, entity := range msg2.Certificates.Entities {
			if err := s.applyRotateEntity(prof, entity, true); err != nil {
				return err
			}
		}
	default:
		return status.Errorf(codes.InvalidArgument, "unknown message type: %T", msg2)
	}
	// Stage the new material so the client can validate it over a fresh
	// connection before finalizing. The in-flight Rotate stream keeps using the
	// previous certificate because it is already established.
	prev, err := s.stageProfile(profileID, prof)
	if err != nil {
		return err
	}
	err = stream.Send(&certzpb.RotateCertificateResponse{
		RotateResponse: &certzpb.RotateCertificateResponse_Certificates{
			Certificates: &certzpb.UploadResponse{},
		},
	})
	if err != nil {
		s.rollbackProfile(profileID, prev)
		return err
	}
	msg3, err := stream.Recv()
	if err != nil {
		s.rollbackProfile(profileID, prev)
		return err
	}
	switch msg3 := msg3.RotateRequest.(type) {
	case *certzpb.RotateCertificateRequest_FinalizeRotation:
		s.logger.Debug("received finalize response", "message", msg3)
		// The staged profile is already active; finalization just confirms it.
	default:
		s.rollbackProfile(profileID, prev)
		return status.Errorf(codes.InvalidArgument, "unknown message type: %T", msg3)
	}
	return nil
}

func (s *Server) handleRotateCertificates(stream certzpb.Certz_RotateServer, profileID profile.ProfileID, msg *certzpb.RotateCertificateRequest_Certificates) error {
	if msg.Certificates == nil {
		return status.Errorf(codes.InvalidArgument, "certificates are required")
	}
	prof := &profile.CertzProfile{}
	for _, entity := range msg.Certificates.Entities {
		if err := s.applyRotateEntity(prof, entity, false); err != nil {
			return err
		}
	}
	// Stage the new material so the client can validate it over a fresh
	// connection before finalizing. The in-flight Rotate stream keeps using the
	// previous certificate because it is already established.
	prev, err := s.stageProfile(profileID, prof)
	if err != nil {
		return err
	}
	err = stream.Send(&certzpb.RotateCertificateResponse{
		RotateResponse: &certzpb.RotateCertificateResponse_Certificates{
			Certificates: &certzpb.UploadResponse{},
		},
	})
	if err != nil {
		s.rollbackProfile(profileID, prev)
		return err
	}
	msg3, err := stream.Recv()
	if err != nil {
		s.rollbackProfile(profileID, prev)
		return err
	}
	switch msg3 := msg3.RotateRequest.(type) {
	case *certzpb.RotateCertificateRequest_FinalizeRotation:
		s.logger.Debug("received finalize response", "message", msg3)
		// The staged profile is already active; finalization just confirms it.
	default:
		s.rollbackProfile(profileID, prev)
		return status.Errorf(codes.InvalidArgument, "unknown message type: %T", msg3)
	}
	return nil
}

func selfSignedCerts(cfg *SelfSignedConfig) (tls.Certificate, error) {
	if cfg == nil {
		cfg = &SelfSignedConfig{}
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	subject := pkix.Name{CommonName: cfg.CN}
	if cfg.O != "" {
		subject.Organization = []string{cfg.O}
	}
	if cfg.OU != "" {
		subject.OrganizationalUnit = []string{cfg.OU}
	}
	if cfg.ST != "" {
		subject.Province = []string{cfg.ST}
	}
	if cfg.L != "" {
		subject.Locality = []string{cfg.L}
	}
	if cfg.PostalCode != "" {
		subject.PostalCode = []string{cfg.PostalCode}
	}
	certTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		DNSNames:              cfg.DNSNames,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return tls.Certificate{}, err
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certBuff := new(bytes.Buffer)
	keyBuff := new(bytes.Buffer)
	if err := pem.Encode(certBuff, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return tls.Certificate{}, err
	}
	if err := pem.Encode(keyBuff, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certBuff.Bytes(), keyBuff.Bytes())
}
