package certz

import (
	"fmt"

	"github.com/karimra/gnsic/api"
	certzpb "github.com/openconfig/gnsi/certz"
	"google.golang.org/protobuf/proto"
)

func ForceOverwrite(b bool) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.RotateCertificateRequest:
			msg.ForceOverwrite = b
		default:
			return fmt.Errorf("option ForceOverwrite: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func SSLProfileID(id string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.RotateCertificateRequest:
			msg.SslProfileId = id
		case *certzpb.AddProfileRequest:
			msg.SslProfileId = id
		case *certzpb.DeleteProfileRequest:
			msg.SslProfileId = id
		case *certzpb.GetProfileListResponse:
			if msg.SslProfileIds == nil {
				msg.SslProfileIds = make([]string, 0, 1)
			}
			msg.SslProfileIds = append(msg.SslProfileIds, id)
		default:
			return fmt.Errorf("option SSLProfileID: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func CertificatesRequest(opts ...api.GNSIOption) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.RotateCertificateRequest:
			uploadReq := new(certzpb.UploadRequest)
			err := api.Apply(uploadReq, opts...)
			if err != nil {
				return err
			}
			msg.RotateRequest = &certzpb.RotateCertificateRequest_Certificates{
				Certificates: uploadReq,
			}
		default:
			return fmt.Errorf("option CertificatesRequest: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func GenerateCSR(opts ...api.GNSIOption) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.RotateCertificateRequest:
			genCSRR := new(certzpb.GenerateCSRRequest)
			err := api.Apply(genCSRR, opts...)
			if err != nil {
				return err
			}
			msg.RotateRequest = &certzpb.RotateCertificateRequest_GenerateCsr{
				GenerateCsr: genCSRR,
			}
		default:
			return fmt.Errorf("option GenerateCSR: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func FinalizeRotation(opts ...api.GNSIOption) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.RotateCertificateRequest:
			msg.RotateRequest = &certzpb.RotateCertificateRequest_FinalizeRotation{
				FinalizeRotation: &certzpb.FinalizeRequest{},
			}
		default:
			return fmt.Errorf("option FinalizeRotation: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func GeneratedCSR(opts ...api.GNSIOption) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.RotateCertificateResponse:
			generatedCSR := new(certzpb.GenerateCSRResponse)
			err := api.Apply(generatedCSR, opts...)
			if err != nil {
				return err
			}
			msg.RotateResponse = &certzpb.RotateCertificateResponse_GeneratedCsr{
				GeneratedCsr: generatedCSR,
			}
		default:
			return fmt.Errorf("option GeneratedCSR: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func CertificatesResponse() func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.RotateCertificateResponse:
			msg.RotateResponse = &certzpb.RotateCertificateResponse_Certificates{
				Certificates: &certzpb.UploadResponse{},
			}
		default:
			return fmt.Errorf("option CertificatesResponse: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func CSRParams(opts ...api.GNSIOption) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CanGenerateCSRRequest:
			csrParams := new(certzpb.CSRParams)
			err := api.Apply(csrParams, opts...)
			if err != nil {
				return err
			}
			msg.Params = csrParams
		case *certzpb.GenerateCSRRequest:
			csrParams := new(certzpb.CSRParams)
			err := api.Apply(csrParams, opts...)
			if err != nil {
				return err
			}
			msg.Params = csrParams
		default:
			return fmt.Errorf("option CSRParams: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func CanGenerate(b bool) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CanGenerateCSRResponse:
			msg.CanGenerate = b
		default:
			return fmt.Errorf("option CanGenerate: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func CertificateType_UNSPECIFIED() func(m proto.Message) error {
	return CertificateType(0)
}

func CertificateType_X509() func(m proto.Message) error {
	return CertificateType(1)
}

func CertificateType(i int32) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.Certificate:
			msg.Type = certzpb.CertificateType(i)
		case *certzpb.CertificateRevocationList:
			msg.Type = certzpb.CertificateType(i)
		case *certzpb.CertificateSigningRequest:
			msg.Type = certzpb.CertificateType(i)
		default:
			return fmt.Errorf("option CertificateType: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func CertificateEncoding_UNSPECIFIED() func(m proto.Message) error {
	return CertificateEncodingCustom(0)
}

func CertificateEncoding_PEM() func(m proto.Message) error {
	return CertificateEncodingCustom(1)
}

func CertificateEncoding_DER() func(m proto.Message) error {
	return CertificateEncodingCustom(2)
}

func CertificateEncoding_CRT() func(m proto.Message) error {
	return CertificateEncodingCustom(3)
}

func CertificateEncodingCustom(i int32) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.Certificate:
			msg.Encoding = certzpb.CertificateEncoding(i)
		case *certzpb.CertificateRevocationList:
			msg.Encoding = certzpb.CertificateEncoding(i)
		case *certzpb.CertificateSigningRequest:
			msg.Encoding = certzpb.CertificateEncoding(i)
		default:
			return fmt.Errorf("option CertificateEncoding: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func PrivateKeyType_RawPrivateKey(b []byte) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.Certificate:
			msg.PrivateKeyType = &certzpb.Certificate_RawPrivateKey{
				RawPrivateKey: b,
			}
		}
		return nil
	}
}

func PrivateKeyType_KeySourceCustom(i int32) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.Certificate:
			msg.PrivateKeyType = &certzpb.Certificate_KeySource_{
				KeySource: certzpb.Certificate_KeySource(i),
			}
		}
		return nil
	}
}

func PrivateKeyType_KeySourceUnspecified() func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.Certificate:
			msg.PrivateKeyType = &certzpb.Certificate_KeySource_{
				KeySource: certzpb.Certificate_KEY_SOURCE_UNSPECIFIED,
			}
		}
		return nil
	}
}

func PrivateKeyType_KeySourceIDEVID_TPM() func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.Certificate:
			msg.PrivateKeyType = &certzpb.Certificate_KeySource_{
				KeySource: certzpb.Certificate_KEY_SOURCE_IDEVID_TPM,
			}
		}
		return nil
	}
}

func PrivateKeyType_KeySourceGenerated() func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.Certificate:
			msg.PrivateKeyType = &certzpb.Certificate_KeySource_{
				KeySource: certzpb.Certificate_KEY_SOURCE_GENERATED,
			}
		}
		return nil
	}
}

func CertificateChain(opts ...api.GNSIOption) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CertificateChain:
			m := new(certzpb.CertificateChain)
			err := api.Apply(m, opts...)
			if err != nil {
				return err
			}
			msg.Parent = m
		case *certzpb.Entity:
			m := new(certzpb.CertificateChain)
			err := api.Apply(m, opts...)
			if err != nil {
				return err
			}
			msg.Entity = &certzpb.Entity_CertificateChain{
				CertificateChain: m,
			}
		default:
			return fmt.Errorf("option CertificateChain: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func TrustBundle(opts ...api.GNSIOption) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.Entity:
			m := new(certzpb.CertificateChain)
			err := api.Apply(m, opts...)
			if err != nil {
				return err
			}
			msg.Entity = &certzpb.Entity_TrustBundle{
				TrustBundle: m,
			}
		default:
			return fmt.Errorf("option TrustBundle: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func Certificate(opts ...api.GNSIOption) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CertificateChain:
			m := new(certzpb.Certificate)
			err := api.Apply(m, opts...)
			if err != nil {
				return err
			}
			msg.Certificate = m
		default:
			return fmt.Errorf("option Certificate: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func CertificateBytes(b []byte) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.Certificate:
			msg.Certificate = b
		default:
			return fmt.Errorf("option CertificateBytes: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func PrivateKeyBytes(b []byte) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.Certificate:
			msg.PrivateKey = b
		default:
			return fmt.Errorf("option PrivateKeyBytes: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func CRL(opts ...api.GNSIOption) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CertificateRevocationListBundle:
			m := new(certzpb.CertificateRevocationList)
			err := api.Apply(m, opts...)
			if err != nil {
				return err
			}
			if msg.CertificateRevocationLists == nil {
				msg.CertificateRevocationLists = make([]*certzpb.CertificateRevocationList, 0, 1)
			}
			msg.CertificateRevocationLists = append(msg.CertificateRevocationLists, m)
		default:
			return fmt.Errorf("option CRL: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func CRLBytes(b []byte) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CertificateRevocationList:
			msg.CertificateRevocationList = b
		default:
			return fmt.Errorf("option CRLBytes: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func CRLID(s string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CertificateRevocationList:
			msg.Id = s
		default:
			return fmt.Errorf("option CRLID: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func CRLBundle(opts ...api.GNSIOption) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.Entity:
			m := new(certzpb.CertificateRevocationListBundle)
			err := api.Apply(m, opts...)
			if err != nil {
				return err
			}
			msg.Entity = &certzpb.Entity_CertificateRevocationListBundle{
				CertificateRevocationListBundle: m,
			}
		default:
			return fmt.Errorf("option CRLBundle: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func Entity(opts ...api.GNSIOption) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.UploadRequest:
			m := new(certzpb.Entity)
			err := api.Apply(m, opts...)
			if err != nil {
				return err
			}
			if msg.Entities == nil {
				msg.Entities = make([]*certzpb.Entity, 0, 1)
			}
			msg.Entities = append(msg.Entities, m)
		default:
			return fmt.Errorf("option Entity: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func CreatedOn(ts uint64) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.Entity:
			msg.CreatedOn = ts
		default:
			return fmt.Errorf("option CreatedOn: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func Version(s string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.Entity:
			msg.Version = s
		default:
			return fmt.Errorf("option Version: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func CSRBytes(b []byte) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CertificateSigningRequest:
			msg.CertificateSigningRequest = b
		default:
			return fmt.Errorf("option CSRBytes: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func CSR(opts ...api.GNSIOption) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.GenerateCSRResponse:
			m := new(certzpb.CertificateSigningRequest)
			err := api.Apply(m, opts...)
			if err != nil {
				return err
			}
			msg.CertificateSigningRequest = m
		default:
			return fmt.Errorf("option CSR: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func CSRSuite_UNSPECIFIED() func(m proto.Message) error {
	return CSRSuite(0)
}

func CSRSuite_X509_RSA_2048_SHA2_256() func(m proto.Message) error {
	return CSRSuite(1)
}

func CSRSuite_X509_RSA_2048_SHA2_384() func(m proto.Message) error {
	return CSRSuite(2)
}

func CSRSuite_X509_RSA_2048_SHA2_512() func(m proto.Message) error {
	return CSRSuite(3)
}

func CSRSuite_X509_RSA_3072_SHA2_256() func(m proto.Message) error {
	return CSRSuite(4)
}

func CSRSuite_X509_RSA_3072_SHA2_384() func(m proto.Message) error {
	return CSRSuite(5)
}

func CSRSuite_X509_RSA_3072_SHA2_512() func(m proto.Message) error {
	return CSRSuite(6)
}

func CSRSuite_X509_RSA_4096_SHA2_256() func(m proto.Message) error {
	return CSRSuite(7)
}

func CSRSuite_X509_RSA_4096_SHA2_384() func(m proto.Message) error {
	return CSRSuite(8)
}

func CSRSuite_X509_RSA_4096_SHA2_512() func(m proto.Message) error {
	return CSRSuite(9)
}

func CSRSuite_X509_ECDSA_PRIME256V1_SHA2_256() func(m proto.Message) error {
	return CSRSuite(10)
}

func CSRSuite_X509_ECDSA_PRIME256V1_SHA2_384() func(m proto.Message) error {
	return CSRSuite(11)
}

func CSRSuite_X509_ECDSA_PRIME256V1_SHA2_512() func(m proto.Message) error {
	return CSRSuite(12)
}

func CSRSuite_X509_ECDSA_SECP384R1_SHA2_256() func(m proto.Message) error {
	return CSRSuite(13)
}

func CSRSuite_X509_ECDSA_SECP384R1_SHA2_384() func(m proto.Message) error {
	return CSRSuite(14)
}

func CSRSuite_X509_ECDSA_SECP384R1_SHA2_512() func(m proto.Message) error {
	return CSRSuite(15)
}

func CSRSuite_X509_ECDSA_SECP521R1_SHA2_256() func(m proto.Message) error {
	return CSRSuite(16)
}

func CSRSuite_X509_ECDSA_SECP521R1_SHA2_384() func(m proto.Message) error {
	return CSRSuite(17)
}

func CSRSuite_X509_ECDSA_SECP521R1_SHA2_512() func(m proto.Message) error {
	return CSRSuite(18)
}

func CSRSuite_X509_EDDSA_ED25519() func(m proto.Message) error {
	return CSRSuite(19)
}

func CSRSuite(i int32) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CSRParams:
			msg.CsrSuite = certzpb.CSRSuite(i)
		default:
			return fmt.Errorf("option CSRSuite: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func CommonName(name string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CSRParams:
			msg.CommonName = name
		default:
			return fmt.Errorf("option CommonName: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func Country(name string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CSRParams:
			msg.Country = name
		default:
			return fmt.Errorf("option Country: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func State(name string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CSRParams:
			msg.State = name
		default:
			return fmt.Errorf("option State: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func Org(name string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CSRParams:
			msg.Organization = name
		default:
			return fmt.Errorf("option Org: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func City(name string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CSRParams:
			msg.City = name
		default:
			return fmt.Errorf("option City: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func OrgUnit(name string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CSRParams:
			msg.OrganizationalUnit = name
		default:
			return fmt.Errorf("option OrgUnit: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func IPAddress(name string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CSRParams:
			msg.IpAddress = name
		default:
			return fmt.Errorf("option IPAddress: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func EmailID(name string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CSRParams:
			msg.EmailId = name
		default:
			return fmt.Errorf("option EmailID: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func V3ExtensionSAN(opts ...api.GNSIOption) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.CSRParams:
			m := new(certzpb.V3ExtensionSAN)
			err := api.Apply(m, opts...)
			if err != nil {
				return err
			}
			msg.San = m
		default:
			return fmt.Errorf("option V3ExtensionSAN: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func DNS(names ...string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.V3ExtensionSAN:
			if msg.Dns == nil {
				msg.Dns = make([]string, 0, len(names))
			}
			msg.Dns = append(msg.Dns, names...)
		default:
			return fmt.Errorf("option DNS: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func Emails(names ...string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.V3ExtensionSAN:
			if msg.Emails == nil {
				msg.Emails = make([]string, 0, len(names))
			}
			msg.Emails = append(msg.Emails, names...)
		default:
			return fmt.Errorf("option Emails: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func IPs(ips ...string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.V3ExtensionSAN:
			if msg.Ips == nil {
				msg.Ips = make([]string, 0, len(ips))
			}
			msg.Ips = append(msg.Ips, ips...)
		default:
			return fmt.Errorf("option IPs: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func URIs(uris ...string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *certzpb.V3ExtensionSAN:
			if msg.Uris == nil {
				msg.Uris = make([]string, 0, len(uris))
			}
			msg.Uris = append(msg.Uris, uris...)
		default:
			return fmt.Errorf("option URIs: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}
