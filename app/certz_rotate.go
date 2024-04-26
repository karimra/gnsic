package app

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"regexp"
	"time"

	"github.com/karimra/gnsic/api"
	certzapi "github.com/karimra/gnsic/api/certz"

	certz "github.com/openconfig/gnsi/certz"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func (a *App) InitCertzRotateFlags(cmd *cobra.Command) {
	cmd.ResetFlags()
	//
	cmd.Flags().StringVar(&a.Config.CertzRotateCACert, "ca-cert", "cert.pem", "CA certificate used for signing")
	cmd.Flags().StringVar(&a.Config.CertzRotateCAKey, "ca-key", "key.pem", "CA key used for signing")
	cmd.Flags().DurationVar(&a.Config.CertzRotateCertificateValidity, "validity", 87600*time.Hour, "certificate validity")
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
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainCRLType, "crl-type", nil, "certificate revocation list type")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainCRLEncoding, "crl-encoding", nil, "certificate revocation list encoding")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainCRLCFile, "crl-cert-file", nil, "certificate revocation list file")
	cmd.Flags().StringArrayVar(&a.Config.CertzRotateEntityCertChainCRLID, "crl-id", nil, "certificate revocation list ID")
	//
	cmd.Flags().StringVar(&a.Config.CertzRotateEntityAuthPolicy, "auth-policy", "", "authentication policy file")
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
	// uploading pre generated certificate(s)
	if a.Config.CertzRotateEntityCertChainCertificateCFile != nil {
		if len(a.Config.CertzRotateEntityCertChainCertificateCFile) != len(a.Config.CertzRotateEntityCertChainCertificateKFile) {
			return fmt.Errorf("non-matching number of Certificate(s) and Key(s)")
		}
		return nil
	}
	// generating certificate
	if a.Config.CertzRotateCommonName != "" {
		if a.Config.CertzRotateCACert == "" || a.Config.CertzRotateCAKey == "" {
			return fmt.Errorf("missing CA cert and/or key for signing generated certificates")
		}
	}
	// validate trust bundles input
	if len(a.Config.CertzRotateEntityCertChainTrustBundleCFile) != 0 {
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
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	defer t.Close()

	// uploading a pre generated certificate (and potentially intermediate certs)
	if len(a.Config.CertzRotateEntityCertChainCertificateCFile) != 0 && a.Config.CertzRotateCommonName == "" {
	}

	// if common-name is specified, we are generating a certificate. (case1, case2)
	if a.Config.CertzRotateCommonName != "" {
		a.certzRotateWithGenerateCertificate(ctx, t, rspCh)
		return
	}
	// else if only a trust bundle is specified: case 3
	if a.Config.CertzRotateEntityCertChainTrustBundleCFile != nil {

	}

	// else if a CRL is specified: case 4

	// else if a policy is set: case 5

	// build CSRParams
	// run can generate CSR
	// if true, rely on router, send CSR, get cert, sign it and upload
	// if false, generate CSR, sign and upload

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

	//
	block, _ := pem.Decode(genCSRRsp.GetGeneratedCsr().GetCertificateSigningRequest().GetCertificateSigningRequest())
	if block == nil {
		a.Logger.Errorf("%s: failed to decode returned CSR", t.Config.Name)
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        fmt.Errorf("failed to decode returned CSR"),
			},
		}
		return
	}

	cs, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		a.Logger.Errorf("%s: failed to parse returned CSR: %v", t.Config.Name, err)
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        fmt.Errorf("failed to parse returned CSR: %v", err),
			},
		}
		return

	}
	s, err := CertificateRequestText(cs)
	if err != nil {
		a.Logger.Errorf("%s: failed to print returned CSR: %v", t.Config.Name, err)
	}
	a.Logger.Infof("%s: returned CSR:\n%s", t.Config.Name, s)
	//

	csrBytes := genCSRRsp.GetGeneratedCsr().GetCertificateSigningRequest().GetCertificateSigningRequest()
	p, rest := pem.Decode(csrBytes)
	if p == nil || len(rest) > 0 {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        fmt.Errorf("%q failed to decode returned CSR", t.Config.Address),
			},
		}
		return
	}
	creq, err := x509.ParseCertificateRequest(p.Bytes)
	if err != nil {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        fmt.Errorf("failed parsing certificate request: %v", err),
			},
		}
		return
	}

	// create certificate from CSR
	certificate, err := certificateFromCSR(creq, a.Config.CertzRotateCertificateValidity)
	if err != nil {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        fmt.Errorf("failed parsing certificate request: %v", err),
			},
		}
		return
	}

	// read CA cert & key
	caCert, err := tls.LoadX509KeyPair(a.Config.CertzRotateCACert, a.Config.CertzRotateCAKey)
	if err != nil {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        fmt.Errorf("failed parsing certificate request: %v", err),
			},
		}
		return
	}
	if len(caCert.Certificate) != 1 {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        errors.New("CA cert and key contains 0 or more than 1 certificate"),
			},
		}
		return
	}
	c, err := x509.ParseCertificate(caCert.Certificate[0])
	if c != nil && err == nil {
		caCert.Leaf = c
	}
	a.Logger.Infof("read local CA certs")

	// sign it
	signedCert, err := a.sign(certificate, &caCert)
	if err != nil {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        fmt.Errorf("%q failed signing certificate: %v", t.Config.Address, err),
			},
		}
		return
	}
	b, err := toPEM(signedCert)
	if err != nil {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        fmt.Errorf("%q failed converting certificate to PEM: %v", t.Config.Address, err),
			},
		}
		return
	}

	// upload it
	// upload optins
	uploadReqOpts := []api.GNSIOption{
		certzapi.ForceOverwrite(a.Config.CertzRotateForceOverwrite),
		certzapi.SSLProfileID(a.Config.CertzRotateSSLProfileID),
		// certzapi.CertificatesRequest(
		// 	certzapi.Entity(
		// 		certzapi.Version(a.Config.CertzRotateCertificateVersion),
		// 		certzapi.CreatedOn(uint64(createdOn.Unix())),
		// 		certzapi.CertificateChain(
		// 			certzapi.Certificate(
		// 				certzapi.CertificateType_X509(),
		// 				certzapi.CertificateEncoding_PEM(),
		// 				certzapi.CertificateBytes(b),
		// 				// NO private key in this case
		// 			),
		// 		),
		// 	),
		// ),
	}
	// build certificate entity
	entities := []api.GNSIOption{
		certzapi.Entity(
			certzapi.Version(a.Config.CertzRotateEntityCertChainCertificateVersion),
			certzapi.CreatedOn(uint64(createdOn.Unix())),
			certzapi.CertificateChain(
				certzapi.Certificate(
					certzapi.CertificateType_X509(),
					certzapi.CertificateEncoding_PEM(),
					certzapi.CertificateBytes(b),
					// NO private key in this case
				),
			),
		),
	}

	// add trust/crl if defined
	trustBundleEntity, err := a.buildUploadRequestTrustBundleOpts(createdOn)
	if err != nil {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        fmt.Errorf("%q failed reading trust bundle: %v", t.Config.Address, err),
			},
		}
		return
	}
	entities = append(entities, trustBundleEntity...)
	//
	uploadReqOpts = append(uploadReqOpts, certzapi.CertificatesRequest(entities...))
	//
	uploadReq, err := certzapi.NewRotateCertificateRequest(uploadReqOpts...)
	if err != nil {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        fmt.Errorf("failed creating upload certificate request: %v", err),
			},
		}
		return
	}
	a.Logger.Infof("%s: sending upload request: %v", t.Config.Name, uploadReq)
	err = stream.Send(uploadReq)
	if err != nil {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	// read upload response
	uploadResponse, err := stream.Recv()
	if err != nil {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	a.Logger.Infof("%s: upload Response %v", t.Config.Name, uploadResponse)
	// TODO: test it?

	// Finalize
	err = stream.Send(&certz.RotateCertificateRequest{
		ForceOverwrite: a.Config.CertzRotateForceOverwrite,
		SslProfileId:   a.Config.CertzRotateSSLProfileID,
		RotateRequest: &certz.RotateCertificateRequest_FinalizeRotation{
			FinalizeRotation: &certz.FinalizeRequest{},
		},
	})
	// TODO: check what error the device returns here
	if err != nil {
		rspCh <- &rotateResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
}

func (a *App) certzRotateWithGenerateCertificateCannotGenerateCSR(ctx context.Context, t *api.Target, rspCh chan<- *rotateResponse) error {
	return nil
}

// helpers
// TODO: implement proper key generation
func (a *App) createLocalCSR(t *api.Target) ([]byte, *x509.CertificateRequest, error) {
	var commonName = a.Config.CertzRotateCommonName
	var ipAddr = a.Config.CertzRotateIPAddress

	if commonName == "" {
		commonName = t.Config.CommonName
	}
	if ipAddr == "" {
		ipAddr = t.Config.ResolvedIP
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // TODO:
	if err != nil {
		return nil, nil, err
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
	if a.Config.CertzRotateEmailID != "" {
		subj.ExtraNames = append(subj.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidEmailAddress,
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(a.Config.CertzRotateEmailID),
			},
		})
	}

	var ipAddrs net.IP
	if ipAddr != "" {
		ipAddrs = net.ParseIP(ipAddr)
	}
	template := x509.CertificateRequest{
		Subject:            subj,
		EmailAddresses:     []string{a.Config.CertzRotateEmailID},
		SignatureAlgorithm: x509.SHA256WithRSA,
		IPAddresses:        make([]net.IP, 0),
		DNSNames:           []string{commonName},
	}

	if ipAddrs != nil {
		template.IPAddresses = append(template.IPAddresses, ipAddrs)
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Certificate Request: %v", err)
	}
	creq, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parsing certificate request: %v", err)
	}
	//TODO:
	return nil, creq, nil
	// return &cert.KeyPair{
	// 		PrivateKey: pem.EncodeToMemory(&pem.Block{
	// 			Type:  "RSA PRIVATE KEY",
	// 			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	// 		}),
	// 		PublicKey: csrBytes,
	// 	},
	// 	creq, err
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
		SignatureAlgorithm:    csr.SignatureAlgorithm,
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
	pk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to parse public key, not a rsa.PublicKey type")
	}
	pkBytes, err := asn1.Marshal(*pk)
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

func (a *App) buildUploadRequestTrustBundleOpts(createdOn time.Time) ([]api.GNSIOption, error) {
	opts := make([]api.GNSIOption, 0, len(a.Config.CertzRotateEntityCertChainTrustBundleCFile))
	for i := range a.Config.CertzRotateEntityCertChainTrustBundleCFile {
		b, err := os.ReadFile(a.Config.CertzRotateEntityCertChainTrustBundleCFile[i])
		if err != nil {
			return nil, err
		}

		opts = append(opts,
			certzapi.Entity(
				certzapi.Version(a.Config.CertzRotateEntityCertChainTrustBundleVersion[i]),
				certzapi.CreatedOn(uint64(createdOn.Unix())),
				certzapi.TrustBundle(
					certzapi.Certificate(
						certzapi.CertificateType_X509(),
						certzapi.CertificateEncoding_PEM(),
						certzapi.CertificateBytes(b),
					),
				),
			),
		)
	}

	return opts, nil
}
