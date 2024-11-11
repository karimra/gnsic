package api

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"time"

	"github.com/AlekSi/pointer"
	"github.com/karimra/gnsic/config"
	"github.com/openconfig/gnsi/authz"
	certz "github.com/openconfig/gnsi/certz"
	"github.com/openconfig/gnsi/credentialz"
	"github.com/openconfig/gnsi/pathz"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var DefaultTargetTimeout = 10 * time.Second

type TargetOption func(*Target) error

type Target struct {
	Config *config.TargetConfig
	client *grpc.ClientConn
}

func (t *Target) Close() error {
	if t.client == nil {
		return nil
	}
	return t.client.Close()
}

func NewTarget(opts ...TargetOption) (*Target, error) {
	t := &Target{
		Config: &config.TargetConfig{},
	}
	var err error
	for _, o := range opts {
		err = o(t)
		if err != nil {
			return nil, err
		}
	}
	if t.Config.Address == "" {
		return nil, errors.New("missing address")
	}
	if t.Config.Name == "" {
		t.Config.Name = strings.Split(t.Config.Address, ",")[0]
	}
	if t.Config.Timeout == 0 {
		t.Config.Timeout = DefaultTargetTimeout
	}
	if t.Config.Insecure == nil && t.Config.SkipVerify == nil {
		t.Config.Insecure = pointer.ToBool(false)
		t.Config.SkipVerify = pointer.ToBool(false)
	}
	if t.Config.SkipVerify == nil {
		t.Config.SkipVerify = pointer.ToBool(false)
	}
	if t.Config.Insecure == nil {
		t.Config.Insecure = pointer.ToBool(false)
	}
	return t, nil
}

func NewTargetFromConfig(tc *config.TargetConfig) *Target {
	return &Target{Config: tc}
}

func (t *Target) CreateGrpcClient(ctx context.Context, opts ...grpc.DialOption) error {
	tOpts := make([]grpc.DialOption, 0, len(opts)+1)
	tOpts = append(tOpts, opts...)

	nOpts, err := t.Config.DialOpts()
	if err != nil {
		return err
	}
	tOpts = append(tOpts, nOpts...)
	timeoutCtx, cancel := context.WithTimeout(ctx, t.Config.Timeout)
	defer cancel()
	t.client, err = grpc.DialContext(timeoutCtx, t.Config.Address, tOpts...)
	return err
}

func (t *Target) Conn() grpc.ClientConnInterface { return t.client }

func (t *Target) AppendMetadata(ctx context.Context) context.Context {
	kv := make([]string, 0, 4)
	if t.Config.Username != nil {
		kv = append(kv, "username", *t.Config.Username)
	}
	if t.Config.Password != nil {
		kv = append(kv, "password", *t.Config.Password)
	}

	return metadata.AppendToOutgoingContext(ctx, kv...)
}

func (t *Target) NewAuthzClient() authz.AuthzClient {
	return authz.NewAuthzClient(t.client)
}

func (t *Target) NewCertzClient() certz.CertzClient {
	return certz.NewCertzClient(t.client)
}

func (t *Target) NewCredentialzClient() credentialz.CredentialzClient {
	return credentialz.NewCredentialzClient(t.client)
}

func (t *Target) NewPathzClient() pathz.PathzClient {
	return pathz.NewPathzClient(t.client)
}

// Name sets the target name.
func Name(name string) TargetOption {
	return func(t *Target) error {
		t.Config.Name = name
		return nil
	}
}

// Address sets the target address.
// This Option can be set multiple times.
func Address(addr string) TargetOption {
	return func(t *Target) error {
		if t.Config.Address != "" {
			t.Config.Address = strings.Join([]string{t.Config.Address, addr}, ",")
			return nil
		}
		t.Config.Address = addr
		return nil
	}
}

// Username sets the target Username.
func Username(username string) TargetOption {
	return func(t *Target) error {
		t.Config.Username = pointer.ToString(username)
		return nil
	}
}

// Password sets the target Password.
func Password(password string) TargetOption {
	return func(t *Target) error {
		t.Config.Password = pointer.ToString(password)
		return nil
	}
}

// Timeout sets the gNSI client creation timeout.
func Timeout(timeout time.Duration) TargetOption {
	return func(t *Target) error {
		t.Config.Timeout = timeout
		return nil
	}
}

// Insecure sets the option to create a gNSI client with an
// insecure gRPC connection
func Insecure(i bool) TargetOption {
	return func(t *Target) error {
		t.Config.Insecure = pointer.ToBool(i)
		return nil
	}
}

// SkipVerify sets the option to create a gNSI client with a
// secure gRPC connection without verifying the target's certificates.
func SkipVerify(i bool) TargetOption {
	return func(t *Target) error {
		t.Config.SkipVerify = pointer.ToBool(i)
		return nil
	}
}

// TLSCA sets that path towards the TLS certificate authority file.
func TLSCA(tlsca string) TargetOption {
	return func(t *Target) error {
		t.Config.TLSCA = pointer.ToString(tlsca)
		return nil
	}
}

// TLSCert sets that path towards the TLS certificate file.
func TLSCert(cert string) TargetOption {
	return func(t *Target) error {
		t.Config.TLSCert = pointer.ToString(cert)
		return nil
	}
}

// TLSKey sets that path towards the TLS key file.
func TLSKey(key string) TargetOption {
	return func(t *Target) error {
		t.Config.TLSKey = pointer.ToString(key)
		return nil
	}
}

// TLSMinVersion sets the TLS minimum version used during the TLS handshake.
func TLSMinVersion(v string) TargetOption {
	return func(t *Target) error {
		t.Config.TLSMinVersion = v
		return nil
	}
}

// TLSMaxVersion sets the TLS maximum version used during the TLS handshake.
func TLSMaxVersion(v string) TargetOption {
	return func(t *Target) error {
		t.Config.TLSMaxVersion = v
		return nil
	}
}

// TLSVersion sets the desired TLS version used during the TLS handshake.
func TLSVersion(v string) TargetOption {
	return func(t *Target) error {
		t.Config.TLSVersion = v
		return nil
	}
}
func TLSConfig(tlsConfig *tls.Config) TargetOption {
	return func(t *Target) error {
		t.Config.SetTLSConfig(tlsConfig)
		return nil
	}
}

// Gzip, if set to true,
// adds gzip compression to the gRPC connection.
func Gzip(b bool) TargetOption {
	return func(t *Target) error {
		t.Config.Gzip = pointer.ToBool(b)
		return nil
	}
}
