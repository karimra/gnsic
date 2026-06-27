package app

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/karimra/gnsic/api"
	certzapi "github.com/karimra/gnsic/api/certz"
	"github.com/karimra/gnsic/server/certz/certzcsr"

	certz "github.com/openconfig/gnsi/certz"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

func (a *App) InitCertzRotateFlags(cmd *cobra.Command) {
	cmd.ResetFlags()
	//
	cmd.Flags().StringVar(&a.Config.CertzRotateCACert, "ca-cert", "cert.pem", "CA certificate used for signing")
	cmd.Flags().StringVar(&a.Config.CertzRotateCAKey, "ca-key", "key.pem", "CA key used for signing")
	cmd.Flags().DurationVar(&a.Config.CertzRotateCertificateValidity, "validity", 87600*time.Hour, "certificate validity")
	cmd.Flags().BoolVar(&a.Config.CertzRotateForceOverwrite, "force", false, "force overwrite certificate profile")
	//
	cmd.Flags().StringVar(&a.Config.CertzRotateEntityCertChainCertificateVersion, "version", "", "certificate version")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCreatedOn, "created-on", nil, "entity creation time")
	cmd.Flags().StringVar(&a.Config.CertzRotateSSLProfileID, "id", "", "certificate profile ID to be rotated")
	cmd.Flags().StringVar(&a.Config.CertzRotateCSRSuite, "csr-suite", "", "the CSR suite. Format: '<certificate type>_<key type>_<signature algorithm>'")
	cmd.Flags().StringVar(&a.Config.CertzRotateCommonName, "cn", "", "common name")
	cmd.Flags().StringVar(&a.Config.CertzRotateCountry, "country", "", "country name")
	cmd.Flags().StringVar(&a.Config.CertzRotateState, "state", "", "state name")
	cmd.Flags().StringVar(&a.Config.CertzRotateCity, "city", "", "city name")
	cmd.Flags().StringVar(&a.Config.CertzRotateOrg, "org", "", "organization name")
	cmd.Flags().StringVar(&a.Config.CertzRotateOrgUnit, "org-unit", "", "organizational unit name")
	cmd.Flags().StringVar(&a.Config.CertzRotateIPAddress, "ip-address", "", "IP address")
	cmd.Flags().StringVar(&a.Config.CertzRotateEmailID, "email-id", "", "email ID")
	//
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateSanDNS, "dns", nil, "SAN DNS name(s)")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateSanEmail, "san-email-id", nil, "SAN email ID(s)")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateSanIP, "san-ip-address", nil, "SAN IP(s)")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateSanURI, "san-uri", nil, "SAN URI(s)")
	//
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainCertificateType, "type", nil, "certificate type")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainCertificateEncoding, "encoding", nil, "certificate encoding")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainCertificateCFile, "cert-file", nil, "certificate file")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainCertificateKFile, "key-file", nil, "key file")
	//
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainTrustBundleVersion, "bundle-version", nil, "trust-bundle version")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainTrustBundleType, "bundle-type", nil, "trust bundle type")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainTrustBundleEncoding, "bundle-encoding", nil, "trust bundle encoding")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainTrustBundleCFile, "bundle-cert-file", nil, "trust bundle certificate file")
	// cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainTrustBundleKFile, "bundle-key-file", nil, "trust bundle key file")
	//
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainTrustBundlePKCS7File, "bundle-pkcs7-file", nil, "PKCS#7 trust bundle file")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainTrustBundlePKCS7Version, "bundle-pkcs7-version", nil, "PKCS#7 trust bundle version")
	//
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainCRLVersion, "crl-version", nil, "certificate revocation list version")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainCRLType, "crl-type", nil, "certificate revocation list type")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainCRLEncoding, "crl-encoding", nil, "certificate revocation list encoding")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainCRLCFile, "crl-cert-file", nil, "certificate revocation list file")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainCRLID, "crl-id", nil, "certificate revocation list ID")
	//
	cmd.Flags().StringVar(&a.Config.CertzRotateEntityAuthPolicy, "auth-policy", "", "authentication policy file (serialized google.protobuf.Any, JSON)")
	cmd.Flags().StringVar(&a.Config.CertzRotateEntityAuthPolicyVersion, "auth-policy-version", "", "authentication policy version")
	//
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateExistingProfileID, "existing-profile-id", nil, "source SSL profile ID to copy an existing entity from")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateExistingType, "existing-type", nil, "existing entity type: certificate-chain|trust-bundle|crl-bundle|auth-policy")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateExistingVersion, "existing-version", nil, "existing entity version")
	//
	cmd.LocalFlags().VisitAll(func(flag *pflag.Flag) {
		a.Config.FileConfig.BindPFlag(fmt.Sprintf("%s-%s", cmd.Name(), flag.Name), flag)
	})
}

type rotateResponse struct {
	TargetError
	rsp *certz.RotateCertificateResponse
}

func (r *rotateResponse) Target() string {
	return r.TargetName
}

func (r *rotateResponse) Response() any {
	return r.rsp
}

func (a *App) PreRunECertzRotate(cmd *cobra.Command, args []string) error {
	// the proto returns InvalidArgument if ssl_profile_id is empty.
	if a.Config.CertzRotateSSLProfileID == "" {
		return errors.New("missing SSL profile ID: set --id")
	}
	// uploading pre-generated certificate(s)
	if len(a.Config.CertzRotateEntityCertChainCertificateCFile) != 0 {
		if len(a.Config.CertzRotateEntityCertChainCertificateCFile) != len(a.Config.CertzRotateEntityCertChainCertificateKFile) {
			return fmt.Errorf("non-matching number of certificate(s) (--cert-file) and key(s) (--key-file)")
		}
	}
	// generating a certificate
	if a.Config.CertzRotateCommonName != "" {
		if a.Config.CertzRotateCACert == "" || a.Config.CertzRotateCAKey == "" {
			return fmt.Errorf("missing CA cert and/or key (--ca-cert/--ca-key) for signing generated certificates")
		}
		if a.Config.CertzRotateCSRSuite != "" {
			if _, ok := certz.CSRSuite_value[a.Config.CertzRotateCSRSuite]; !ok {
				return fmt.Errorf("invalid --csr-suite %q", a.Config.CertzRotateCSRSuite)
			}
		}
	}
	// optional parallel arrays must match their primary array when provided.
	if n := len(a.Config.CertzRotateEntityCertChainTrustBundleVersion); n != 0 && n != len(a.Config.CertzRotateEntityCertChainTrustBundleCFile) {
		return errors.New("--bundle-version count must match --bundle-cert-file count")
	}
	if n := len(a.Config.CertzRotateExistingProfileID); n != 0 && len(a.Config.CertzRotateExistingType) != n {
		return errors.New("--existing-type count must match --existing-profile-id count")
	}
	return nil
}

func (a *App) RunECertzRotate(cmd *cobra.Command, args []string) error {
	targets, err := a.GetTargets()
	if err != nil {
		return err
	}
	a.Logger.Debugf("targets: %v", targets)
	numTargets := len(targets)
	responseChan := make(chan *rotateResponse, numTargets)
	a.wg.Add(numTargets)
	for _, t := range targets {
		go a.certzRotateRequest(cmd.Context(), t, responseChan)
	}
	a.wg.Wait()
	close(responseChan)
	//
	errs := make([]error, 0, numTargets)
	// result := make([]TargetResponse, 0, numTargets)
	for rsp := range responseChan {
		if rsp.Err != nil {
			wErr := fmt.Errorf("%q Certz RotateCertificate failed: %v", rsp.TargetName, rsp.Err)
			a.Logger.Error(wErr)
			errs = append(errs, rsp.Err)
			continue
		}
		// result = append(result, rsp)
		a.printProtoMsg(rsp.TargetName, rsp.rsp)
	}
	// a.printCMDOutput(result, a.rotatePrintF)
	return a.handleErrs(errs)
}

func (a *App) certzRotateRequest(ctx context.Context, t *api.Target, rspCh chan<- *rotateResponse) {
	defer a.wg.Done()
	ctx = t.AppendMetadata(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	a.Logger.Debugf("%s: creating a gRPC client", t.Config.Name)
	err := t.CreateGrpcClient(ctx, a.createBaseDialOpts()...)
	if err != nil {
		rspCh <- a.rotateErr(t, err)
		return
	}
	defer t.Close()

	switch {
	// generating a certificate: case 1 (local CSR) or case 2 (target CSR),
	// decided by CanGenerateCSR.
	case a.Config.CertzRotateCommonName != "":
		a.certzRotateWithGenerateCertificate(ctx, t, rspCh)
	// uploading a pre-generated certificate (+ key) and optional intermediates.
	case len(a.Config.CertzRotateEntityCertChainCertificateCFile) != 0:
		a.certzRotateUploadPreGenerated(ctx, t, rspCh)
	// upload-only rotation: trust bundle / CRL / auth policy / existing entity
	// (cases 3, 4, 5).
	case a.hasUploadOnlyEntities():
		a.certzRotateUploadOnly(ctx, t, rspCh)
	default:
		rspCh <- a.rotateErr(t, errors.New("nothing to rotate: provide --cn, --cert-file, --bundle-cert-file, --bundle-pkcs7-file, --crl-cert-file, --auth-policy or --existing-profile-id"))
	}
}

// rotateErr wraps an error into a per-target rotate response.
func (a *App) rotateErr(t *api.Target, err error) *rotateResponse {
	return &rotateResponse{
		TargetError: TargetError{
			TargetName: t.Config.Address,
			Err:        err,
		},
	}
}

// hasUploadOnlyEntities reports whether any entity that can be rotated without a
// (re)generated certificate is requested.
func (a *App) hasUploadOnlyEntities() bool {
	return len(a.Config.CertzRotateEntityCertChainTrustBundleCFile) != 0 ||
		len(a.Config.CertzRotateEntityCertChainTrustBundlePKCS7File) != 0 ||
		len(a.Config.CertzRotateEntityCertChainCRLCFile) != 0 ||
		a.Config.CertzRotateEntityAuthPolicy != "" ||
		len(a.Config.CertzRotateExistingProfileID) != 0
}

// rotateUploadAndFinalize sends an UploadRequest carrying entityOpts, reads the
// UploadResponse, then commits with a FinalizeRequest. The target closes the
// stream (io.EOF) on a successful commit; an error after Finalize means the
// commit failed and the target rolled back. On success the UploadResponse is
// forwarded to rspCh. Note: the optional "test the new connection before
// finalizing" step described by the proto is intentionally not performed.
func (a *App) rotateUploadAndFinalize(t *api.Target, stream certz.Certz_RotateClient, entityOpts []api.GNSIOption, rspCh chan<- *rotateResponse) {
	uploadReq, err := certzapi.NewRotateCertificateRequest(
		certzapi.ForceOverwrite(a.Config.CertzRotateForceOverwrite),
		certzapi.SSLProfileID(a.Config.CertzRotateSSLProfileID),
		certzapi.CertificatesRequest(entityOpts...),
	)
	if err != nil {
		rspCh <- a.rotateErr(t, fmt.Errorf("failed creating upload request: %v", err))
		return
	}
	a.Logger.Infof("%s: sending upload request: %v", t.Config.Name, uploadReq)
	if err := stream.Send(uploadReq); err != nil {
		rspCh <- a.rotateErr(t, err)
		return
	}
	uploadResponse, err := stream.Recv()
	if err != nil {
		rspCh <- a.rotateErr(t, err)
		return
	}
	a.Logger.Infof("%s: upload response: %v", t.Config.Name, uploadResponse)

	// finalize / commit
	finalizeReq, err := certzapi.NewRotateCertificateRequest(
		certzapi.ForceOverwrite(a.Config.CertzRotateForceOverwrite),
		certzapi.SSLProfileID(a.Config.CertzRotateSSLProfileID),
		certzapi.FinalizeRotation(),
	)
	if err != nil {
		rspCh <- a.rotateErr(t, fmt.Errorf("failed creating finalize request: %v", err))
		return
	}
	a.Logger.Infof("%s: sending finalize request", t.Config.Name)
	if err := stream.Send(finalizeReq); err != nil {
		rspCh <- a.rotateErr(t, err)
		return
	}
	if err := stream.CloseSend(); err != nil {
		rspCh <- a.rotateErr(t, err)
		return
	}
	if _, err := stream.Recv(); err != nil && err != io.EOF {
		rspCh <- a.rotateErr(t, err)
		return
	}
	rspCh <- &rotateResponse{
		TargetError: TargetError{TargetName: t.Config.Address},
		rsp:         uploadResponse,
	}
}

// certzRotateUploadPreGenerated implements uploading a pre-generated certificate
// chain (certificate + private key, with optional intermediates) read from
// files, plus any extra entities. This is the upload-only variant of case 1.
func (a *App) certzRotateUploadPreGenerated(ctx context.Context, t *api.Target, rspCh chan<- *rotateResponse) {
	createdOn := time.Now()
	certEntity, err := a.buildPreGeneratedCertEntityOpt(createdOn)
	if err != nil {
		rspCh <- a.rotateErr(t, err)
		return
	}
	extra, err := a.buildExtraEntityOpts(createdOn)
	if err != nil {
		rspCh <- a.rotateErr(t, err)
		return
	}
	stream, err := t.NewCertzClient().Rotate(ctx)
	if err != nil {
		rspCh <- a.rotateErr(t, err)
		return
	}
	a.rotateUploadAndFinalize(t, stream, append([]api.GNSIOption{certEntity}, extra...), rspCh)
}

// certzRotateUploadOnly implements cases 3 (trust bundle), 4 (CRL) and 5
// (authentication policy), as well as existing-entity copies, by uploading only
// the requested entities.
func (a *App) certzRotateUploadOnly(ctx context.Context, t *api.Target, rspCh chan<- *rotateResponse) {
	createdOn := time.Now()
	entities, err := a.buildExtraEntityOpts(createdOn)
	if err != nil {
		rspCh <- a.rotateErr(t, err)
		return
	}
	if len(entities) == 0 {
		rspCh <- a.rotateErr(t, errors.New("no entities to upload"))
		return
	}
	stream, err := t.NewCertzClient().Rotate(ctx)
	if err != nil {
		rspCh <- a.rotateErr(t, err)
		return
	}
	a.rotateUploadAndFinalize(t, stream, entities, rspCh)
}

// helpers
func (a *App) certzRotateWithGenerateCertificate(ctx context.Context, t *api.Target, rspCh chan<- *rotateResponse) {
	// create CSR
	// run can generate CSR
	csrParamsOpts := make([]api.GNSIOption, 0, 1)
	if a.Config.CertzRotateCSRSuite != "" {
		if i, ok := certz.CSRSuite_value[a.Config.CertzRotateCSRSuite]; ok {
			csrParamsOpts = append(csrParamsOpts, certzapi.CSRSuite(i))
		}
		// TODO: warn ?
	}
	csrParamsOpts = append(csrParamsOpts,
		certzapi.CommonName(a.Config.CertzRotateCommonName),
		certzapi.Country(a.Config.CertzRotateCountry),
		certzapi.State(a.Config.CertzRotateState),
		certzapi.City(a.Config.CertzRotateCity),
		certzapi.Org(a.Config.CertzRotateOrg),
		certzapi.OrgUnit(a.Config.CertzRotateOrgUnit),
		certzapi.IPAddress(a.Config.CertzRotateIPAddress),
		certzapi.EmailID(a.Config.CertzRotateEmailID),
		certzapi.V3ExtensionSAN(
			certzapi.DNS(a.Config.CertzRotateSanDNS...),
			certzapi.Emails(a.Config.CertzRotateSanEmail...),
			certzapi.IPs(a.Config.CertzRotateSanIP...),
			certzapi.URIs(a.Config.CertzRotateSanURI...),
		),
	)

	canGenReq, err := certzapi.NewCanGenerateCSRRequest(certzapi.CSRParams(csrParamsOpts...))
	if err != nil {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}

	rsp, err := t.NewCertzClient().CanGenerateCSR(ctx, canGenReq)
	if err != nil {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}

	if !rsp.GetCanGenerate() { // case 1
		a.Logger.Infof("%s: cannot generate CSR", t.Config.Name)
		a.certzRotateWithGenerateCertificateCannotGenerateCSR(ctx, t, rspCh)
		return
	}
	// case 2
	a.Logger.Infof("%s: can generate CSR", t.Config.Name)
	a.certzRotateWithGenerateCertificateCanGenerateCSR(ctx, t, csrParamsOpts, rspCh)
}

func (a *App) certzRotateWithGenerateCertificateCanGenerateCSR(ctx context.Context, t *api.Target, csrParamsOpts []api.GNSIOption, rspCh chan<- *rotateResponse) {
	stream, err := t.NewCertzClient().Rotate(ctx)
	if err != nil {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	req, err := certzapi.NewRotateCertificateRequest(
		certzapi.ForceOverwrite(a.Config.CertzRotateForceOverwrite),
		certzapi.SSLProfileID(a.Config.CertzRotateSSLProfileID),
		certzapi.GenerateCSR(certzapi.CSRParams(csrParamsOpts...)),
	)
	if err != nil {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	a.Logger.Infof("%s: sending Generate CSR: %v", t.Config.Name, req)
	err = stream.Send(req)
	if err != nil {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	genCSRRsp, err := stream.Recv()
	if err != nil {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	a.Logger.Infof("%s: got CSR back: %v", t.Config.Name, genCSRRsp)
	createdOn := time.Now()

	csrBytes := genCSRRsp.GetGeneratedCsr().GetCertificateSigningRequest().GetCertificateSigningRequest()
	p, rest := pem.Decode(csrBytes)
	if p == nil || len(rest) > 0 {
		rspCh <- a.rotateErr(t, fmt.Errorf("%q failed to decode returned CSR", t.Config.Address))
		return
	}
	creq, err := x509.ParseCertificateRequest(p.Bytes)
	if err != nil {
		rspCh <- a.rotateErr(t, fmt.Errorf("failed parsing certificate request: %v", err))
		return
	}
	if s, err := CertificateRequestText(creq); err == nil {
		a.Logger.Infof("%s: returned CSR:\n%s", t.Config.Name, s)
	}

	certPEM, err := a.signCSRToCertPEM(creq)
	if err != nil {
		rspCh <- a.rotateErr(t, fmt.Errorf("%q %v", t.Config.Address, err))
		return
	}

	// certificate entity WITHOUT a private key: the target holds the key it
	// generated for the CSR.
	certEntity := certzapi.Entity(
		certzapi.Version(a.Config.CertzRotateEntityCertChainCertificateVersion),
		certzapi.CreatedOn(uint64(createdOn.Unix())),
		certzapi.CertificateChain(
			certzapi.Certificate(
				certzapi.CertificateType_X509(),
				certzapi.CertificateEncoding_PEM(),
				certzapi.CertificateBytes(certPEM),    // deprecated field, kept for compatibility
				certzapi.CertificateRawBytes(certPEM), // raw_certificate oneof
			),
		),
	)
	extra, err := a.buildExtraEntityOpts(createdOn)
	if err != nil {
		rspCh <- a.rotateErr(t, err)
		return
	}
	a.rotateUploadAndFinalize(t, stream, append([]api.GNSIOption{certEntity}, extra...), rspCh)
}

// certzRotateWithGenerateCertificateCannotGenerateCSR implements case 1: the
// client generates the key and CSR locally, signs it with the configured CA and
// uploads the signed certificate together with the private key.
func (a *App) certzRotateWithGenerateCertificateCannotGenerateCSR(ctx context.Context, t *api.Target, rspCh chan<- *rotateResponse) {
	createdOn := time.Now()
	keyPEM, creq, err := a.createLocalCSR(t)
	if err != nil {
		rspCh <- a.rotateErr(t, fmt.Errorf("failed creating local CSR: %v", err))
		return
	}
	if s, err := CertificateRequestText(creq); err == nil {
		a.Logger.Infof("%s: local CSR:\n%s", t.Config.Name, s)
	}
	certPEM, err := a.signCSRToCertPEM(creq)
	if err != nil {
		rspCh <- a.rotateErr(t, fmt.Errorf("%q %v", t.Config.Address, err))
		return
	}
	stream, err := t.NewCertzClient().Rotate(ctx)
	if err != nil {
		rspCh <- a.rotateErr(t, err)
		return
	}
	// certificate entity WITH the locally-generated private key.
	certEntity := certzapi.Entity(
		certzapi.Version(a.Config.CertzRotateEntityCertChainCertificateVersion),
		certzapi.CreatedOn(uint64(createdOn.Unix())),
		certzapi.CertificateChain(
			certzapi.Certificate(
				certzapi.CertificateType_X509(),
				certzapi.CertificateEncoding_PEM(),
				certzapi.CertificateBytes(certPEM),
				certzapi.CertificateRawBytes(certPEM),
				certzapi.PrivateKeyBytes(keyPEM),              // deprecated field, kept for compatibility
				certzapi.PrivateKeyType_RawPrivateKey(keyPEM), // raw_private_key oneof
			),
		),
	)
	extra, err := a.buildExtraEntityOpts(createdOn)
	if err != nil {
		rspCh <- a.rotateErr(t, err)
		return
	}
	a.rotateUploadAndFinalize(t, stream, append([]api.GNSIOption{certEntity}, extra...), rspCh)
}

// signCSRToCertPEM builds a certificate from a CSR and signs it with the CA
// configured via --ca-cert/--ca-key, returning the PEM-encoded certificate.
func (a *App) signCSRToCertPEM(creq *x509.CertificateRequest) ([]byte, error) {
	certificate, err := certificateFromCSR(creq, a.Config.CertzRotateCertificateValidity)
	if err != nil {
		return nil, fmt.Errorf("failed building certificate from CSR: %v", err)
	}
	caCert, err := tls.LoadX509KeyPair(a.Config.CertzRotateCACert, a.Config.CertzRotateCAKey)
	if err != nil {
		return nil, fmt.Errorf("failed loading CA cert/key: %v", err)
	}
	if len(caCert.Certificate) != 1 {
		return nil, errors.New("CA cert and key contains 0 or more than 1 certificate")
	}
	if c, err := x509.ParseCertificate(caCert.Certificate[0]); err == nil && c != nil {
		caCert.Leaf = c
	}
	signedCert, err := a.sign(certificate, &caCert)
	if err != nil {
		return nil, fmt.Errorf("failed signing certificate: %v", err)
	}
	return toPEM(signedCert)
}

// buildPreGeneratedCertEntityOpt reads a certificate chain (leaf first, then
// intermediates) and matching keys from files into a single CertificateChain
// entity. Files are linked via the CertificateChain `parent` field.
func (a *App) buildPreGeneratedCertEntityOpt(createdOn time.Time) (api.GNSIOption, error) {
	files := a.Config.CertzRotateEntityCertChainCertificateCFile
	keys := a.Config.CertzRotateEntityCertChainCertificateKFile
	if len(files) == 0 {
		return nil, errors.New("no certificate files provided")
	}
	// build from the root inward so each level nests the already-built parent.
	var chainOpts []api.GNSIOption
	for i := len(files) - 1; i >= 0; i-- {
		certBytes, err := os.ReadFile(files[i])
		if err != nil {
			return nil, fmt.Errorf("failed reading certificate %q: %v", files[i], err)
		}
		certOpts := []api.GNSIOption{
			certzapi.CertificateType_X509(),
			certzapi.CertificateEncoding_PEM(),
			certzapi.CertificateBytes(certBytes),
			certzapi.CertificateRawBytes(certBytes),
		}
		if i < len(keys) && keys[i] != "" {
			keyBytes, err := os.ReadFile(keys[i])
			if err != nil {
				return nil, fmt.Errorf("failed reading key %q: %v", keys[i], err)
			}
			certOpts = append(certOpts,
				certzapi.PrivateKeyBytes(keyBytes),
				certzapi.PrivateKeyType_RawPrivateKey(keyBytes),
			)
		}
		levelOpts := append([]api.GNSIOption{certzapi.Certificate(certOpts...)}, chainOpts...)
		chainOpts = []api.GNSIOption{certzapi.CertificateChain(levelOpts...)}
	}
	entityOpts := append([]api.GNSIOption{
		certzapi.Version(a.Config.CertzRotateEntityCertChainCertificateVersion),
		certzapi.CreatedOn(uint64(createdOn.Unix())),
	}, chainOpts...)
	return certzapi.Entity(entityOpts...), nil
}

// helpers
// TODO: implement proper key generation
// createLocalCSR generates a private key and CSR locally according to the
// configured CSR suite (defaulting to RSA-2048/SHA-256). It returns the
// PEM-encoded (PKCS#8) private key and the parsed CSR.
func (a *App) createLocalCSR(t *api.Target) ([]byte, *x509.CertificateRequest, error) {
	commonName := a.Config.CertzRotateCommonName
	if commonName == "" {
		commonName = t.Config.CommonName
	}
	ipAddr := a.Config.CertzRotateIPAddress
	if ipAddr == "" {
		ipAddr = t.Config.ResolvedIP
	}

	var subj pkix.Name
	if commonName != "" {
		subj.CommonName = commonName
	}
	if a.Config.CertzRotateCountry != "" {
		subj.Country = []string{a.Config.CertzRotateCountry}
	}
	if a.Config.CertzRotateState != "" {
		subj.Province = []string{a.Config.CertzRotateState}
	}
	if a.Config.CertzRotateCity != "" {
		subj.Locality = []string{a.Config.CertzRotateCity}
	}
	if a.Config.CertzRotateOrg != "" {
		subj.Organization = []string{a.Config.CertzRotateOrg}
	}
	if a.Config.CertzRotateOrgUnit != "" {
		subj.OrganizationalUnit = []string{a.Config.CertzRotateOrgUnit}
	}

	input := certzcsr.CSRInput{Subject: subj}
	if commonName != "" {
		input.DNSNames = append(input.DNSNames, commonName)
	}
	input.DNSNames = append(input.DNSNames, a.Config.CertzRotateSanDNS...)
	if ipAddr != "" {
		if ip := net.ParseIP(ipAddr); ip != nil {
			input.IPAddresses = append(input.IPAddresses, ip)
		}
	}
	for _, s := range a.Config.CertzRotateSanIP {
		if ip := net.ParseIP(s); ip != nil {
			input.IPAddresses = append(input.IPAddresses, ip)
		}
	}
	if a.Config.CertzRotateEmailID != "" {
		input.EmailAddresses = append(input.EmailAddresses, a.Config.CertzRotateEmailID)
	}
	input.EmailAddresses = append(input.EmailAddresses, a.Config.CertzRotateSanEmail...)
	for _, s := range a.Config.CertzRotateSanURI {
		u, err := url.Parse(s)
		if err != nil {
			return nil, nil, fmt.Errorf("failed parsing SAN URI %q: %v", s, err)
		}
		input.URIs = append(input.URIs, u)
	}

	suite := a.Config.CertzRotateCSRSuite
	if suite == "" {
		suite = certz.CSRSuite_CSRSUITE_X509_KEY_TYPE_RSA_2048_SIGNATURE_ALGORITHM_SHA_2_256.String()
	}
	csrPEM, privKey, err := certzcsr.CreateCSRFromSuiteName(suite, input)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating CSR: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed marshaling private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, nil, errors.New("failed to decode generated CSR")
	}
	creq, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parsing generated CSR: %v", err)
	}
	return keyPEM, creq, nil
}

// func (a *App) createRemoteCSRInstall(stream cert.CertificateManagement_InstallClient, t *api.Target) (*x509.CertificateRequest, error) {
// 	var commonName = a.Config.CertzRotateCommonName
// 	var ipAddr = a.Config.CertzRotateIPAddress
// 	if commonName == "" {
// 		commonName = t.Config.CommonName
// 	}
// 	if ipAddr == "" {
// 		ipAddr = t.Config.ResolvedIP
// 	}
// 	csrParamsOpts := []gcert.CertOption{
// 		gcert.CertificateType(a.Config.CertzRotateCertificateType),
// 		gcert.MinKeySize(a.Config.CertzRotateMinKeySize),
// 		gcert.KeyType(a.Config.CertzRotateKeyType),
// 		gcert.CommonName(commonName),
// 		gcert.Country(a.Config.CertzRotateCountry),
// 		gcert.State(a.Config.CertzRotateState),
// 		gcert.City(a.Config.CertzRotateCity),
// 		gcert.Org(a.Config.CertzRotateOrg),
// 		gcert.OrgUnit(a.Config.CertzRotateOrgUnit),
// 		gcert.IPAddress(ipAddr),
// 	}
// 	if a.Config.CertzRotateEmailID != "" {
// 		csrParamsOpts = append(csrParamsOpts, gcert.EmailID(a.Config.CertzRotateEmailID))
// 	}
// 	req, err := gcert.NewCertInstallGenerateCSRRequest(
// 		gcert.CertificateID(a.Config.CertzRotateCertificateID),
// 		gcert.CSRParams(csrParamsOpts...),
// 	)
// 	if err != nil {
// 		return nil, err
// 	}
// 	a.printMsg(t.Config.Name, req)

// 	err = stream.Send(req)
// 	if err != nil {
// 		return nil, fmt.Errorf("%q failed send Install RPC: GenCSR: %v", err, t.Config.Address)
// 	}
// 	resp, err := stream.Recv()
// 	if err != nil {
// 		return nil, fmt.Errorf("%q failed rcv Install RPC: GenCSR: %v", err, t.Config.Address)
// 	}
// 	if resp == nil {
// 		return nil, fmt.Errorf("%q returned a <nil> CSR response", t.Config.Address)
// 	}
// 	if !a.Config.CertzRotatePrintCSR {
// 		a.printMsg(t.Config.Name, resp)
// 	}
// 	if a.Config.CertzRotatePrintCSR {
// 		fmt.Printf("%q genCSR response:\n %s\n", t.Config.Address, prototext.Format(resp))
// 	}

// 	p, rest := pem.Decode(resp.GetGeneratedCsr().GetCsr().GetCsr())
// 	if p == nil || len(rest) > 0 {
// 		return nil, fmt.Errorf("%q failed to decode returned CSR", t.Config.Address)
// 	}
// 	creq, err := x509.ParseCertificateRequest(p.Bytes)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed parsing certificate request: %v", err)
// 	}
// 	return creq, nil
// }

var pattern = `CSRSUITE_([^_]+)_KEY_TYPE_([A-Z0-9]+)(?:_([0-9]+))?_SIGNATURE_ALGORITHM_([A-Z]+)_2_([0-9]+)|CSRSUITE_([^_]+)_KEY_TYPE_([A-Z0-9]+)$`
var csrRegex = regexp.MustCompile(pattern)

// returns the cert type, key type, key size, signature alg
func parseCertificateDetails(text string) (certificateType, keyType, keyLength, signatureAlgorithm, algorithmVersion string, err error) {
	matches := csrRegex.FindStringSubmatch(text)
	if matches == nil {
		return "", "", "", "", "", fmt.Errorf("no match found")
	}

	if matches[7] != "" { // Handles the EDDSA case without a signature algorithm
		certificateType = matches[6]
		keyType = matches[7]
		return certificateType, keyType, "", "", "", nil
	}

	certificateType = matches[1]
	keyType = matches[2]
	keyLength = matches[3]
	signatureAlgorithm = matches[4]
	algorithmVersion = "2_" + matches[5]
	return
}

func certificateFromCSR(csr *x509.CertificateRequest, certExpiration time.Duration) (*x509.Certificate, error) {
	sn, err := genSerialNumber()
	if err != nil {
		return nil, err
	}
	certificate := &x509.Certificate{
		SerialNumber:          sn,
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		NotAfter:              time.Now().Add(certExpiration),
		NotBefore:             time.Now().Add(-1 * time.Hour),
		Subject:               csr.Subject,
		Signature:             csr.Signature,
		Extensions:            csr.Extensions,
		Version:               csr.Version,
		ExtraExtensions:       csr.ExtraExtensions,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
	}
	certificate.SubjectKeyId, err = keyID(csr.PublicKey)
	return certificate, err
}

func genSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

func keyID(pub crypto.PublicKey) ([]byte, error) {
	pkBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}
	subjectKeyID := sha256.Sum256(pkBytes)
	return subjectKeyID[:], nil
}

func (a *App) sign(c *x509.Certificate, ca *tls.Certificate) (*x509.Certificate, error) {
	derCert, err := x509.CreateCertificate(rand.Reader, c, ca.Leaf, c.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derCert)
}

func toPEM(c *x509.Certificate) ([]byte, error) {
	b := new(bytes.Buffer)
	err := pem.Encode(b, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	})
	return b.Bytes(), err
}

// buildExtraEntityOpts builds upload Entity options for every non-certificate
// artifact requested via flags: X509 trust bundles, PKCS#7 trust bundles, CRL
// bundles, an authentication policy and existing-entity copies. These are shared
// across all rotation cases (they may be uploaded alongside a certificate or on
// their own for cases 3, 4 and 5).
func (a *App) buildExtraEntityOpts(createdOn time.Time) ([]api.GNSIOption, error) {
	ts := uint64(createdOn.Unix())
	opts := make([]api.GNSIOption, 0)

	// X509 trust bundle entities (one per file)
	for i := range a.Config.CertzRotateEntityCertChainTrustBundleCFile {
		b, err := os.ReadFile(a.Config.CertzRotateEntityCertChainTrustBundleCFile[i])
		if err != nil {
			return nil, fmt.Errorf("failed reading trust bundle: %v", err)
		}
		opts = append(opts, certzapi.Entity(
			certzapi.Version(sliceAt(a.Config.CertzRotateEntityCertChainTrustBundleVersion, i)),
			certzapi.CreatedOn(ts),
			certzapi.TrustBundle(
				certzapi.Certificate(
					certzapi.CertificateType_X509(),
					certzapi.CertificateEncoding_PEM(),
					certzapi.CertificateBytes(b),
					certzapi.CertificateRawBytes(b),
				),
			),
		))
	}

	// PKCS#7 trust bundle entities (one per file)
	for i := range a.Config.CertzRotateEntityCertChainTrustBundlePKCS7File {
		b, err := os.ReadFile(a.Config.CertzRotateEntityCertChainTrustBundlePKCS7File[i])
		if err != nil {
			return nil, fmt.Errorf("failed reading pkcs7 trust bundle: %v", err)
		}
		opts = append(opts, certzapi.Entity(
			certzapi.Version(sliceAt(a.Config.CertzRotateEntityCertChainTrustBundlePKCS7Version, i)),
			certzapi.CreatedOn(ts),
			certzapi.TrustBundlePKCS7(string(b)),
		))
	}

	// CRL bundle (a single entity holding all CRLs)
	if len(a.Config.CertzRotateEntityCertChainCRLCFile) != 0 {
		crlOpts := make([]api.GNSIOption, 0, len(a.Config.CertzRotateEntityCertChainCRLCFile))
		for i := range a.Config.CertzRotateEntityCertChainCRLCFile {
			b, err := os.ReadFile(a.Config.CertzRotateEntityCertChainCRLCFile[i])
			if err != nil {
				return nil, fmt.Errorf("failed reading CRL: %v", err)
			}
			crlOpts = append(crlOpts, certzapi.CRL(
				certzapi.CertificateType_X509(),
				certzapi.CertificateEncoding_PEM(),
				certzapi.CRLBytes(b),
				certzapi.CRLID(sliceAt(a.Config.CertzRotateEntityCertChainCRLID, i)),
			))
		}
		opts = append(opts, certzapi.Entity(
			certzapi.Version(sliceAt(a.Config.CertzRotateEntityCertChainCRLVersion, 0)),
			certzapi.CreatedOn(ts),
			certzapi.CRLBundle(crlOpts...),
		))
	}

	// authentication policy
	if a.Config.CertzRotateEntityAuthPolicy != "" {
		anyPolicy, err := a.readAuthPolicy(a.Config.CertzRotateEntityAuthPolicy)
		if err != nil {
			return nil, err
		}
		opts = append(opts, certzapi.Entity(
			certzapi.Version(a.Config.CertzRotateEntityAuthPolicyVersion),
			certzapi.CreatedOn(ts),
			certzapi.AuthenticationPolicy(anyPolicy),
		))
	}

	// existing-entity copies from other SSL profiles
	for i := range a.Config.CertzRotateExistingProfileID {
		et, err := parseExistingEntityType(sliceAt(a.Config.CertzRotateExistingType, i))
		if err != nil {
			return nil, err
		}
		opts = append(opts, certzapi.Entity(
			certzapi.Version(sliceAt(a.Config.CertzRotateExistingVersion, i)),
			certzapi.CreatedOn(ts),
			certzapi.ExistingEntity(a.Config.CertzRotateExistingProfileID[i], et),
		))
	}

	return opts, nil
}

// readAuthPolicy reads an authentication policy file. The file is expected to
// contain a JSON-encoded google.protobuf.Any; if it cannot be parsed as such,
// the raw bytes are wrapped into an Any value.
func (a *App) readAuthPolicy(path string) (*anypb.Any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading auth policy: %v", err)
	}
	any := &anypb.Any{}
	if err := protojson.Unmarshal(b, any); err != nil {
		a.Logger.Warnf("auth policy %q is not a JSON-encoded google.protobuf.Any (%v); wrapping raw bytes", path, err)
		return &anypb.Any{Value: b}, nil
	}
	return any, nil
}

// parseExistingEntityType maps a user-friendly entity type string to its proto
// enum value.
func parseExistingEntityType(s string) (certz.ExistingEntity_EntityType, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "certificate-chain", "certificate_chain", "cert-chain", "cert":
		return certz.ExistingEntity_ENTITY_TYPE_CERTIFICATE_CHAIN, nil
	case "trust-bundle", "trust_bundle", "bundle":
		return certz.ExistingEntity_ENTITY_TYPE_TRUST_BUNDLE, nil
	case "crl-bundle", "crl_bundle", "crl":
		return certz.ExistingEntity_ENTITY_TYPE_CERTIFICATE_REVOCATION_LIST_BUNDLE, nil
	case "auth-policy", "authentication-policy", "auth_policy", "policy":
		return certz.ExistingEntity_ENTITY_TYPE_AUTHENTICATION_POLICY, nil
	default:
		return certz.ExistingEntity_ENTITY_TYPE_UNSPECIFIED, fmt.Errorf("unknown existing entity type: %q (want certificate-chain|trust-bundle|crl-bundle|auth-policy)", s)
	}
}

// sliceAt returns s[i] or an empty string if i is out of range.
func sliceAt(s []string, i int) string {
	if i >= 0 && i < len(s) {
		return s[i]
	}
	return ""
}
