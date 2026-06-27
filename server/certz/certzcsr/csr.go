package certzcsr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	// Example:
	// CSRSUITE_X509_KEY_TYPE_RSA_2048_SIGNATURE_ALGORITHM_SHA_2_256
	reRSA = regexp.MustCompile(`X509_KEY_TYPE_RSA_(\d+)_SIGNATURE_ALGORITHM_SHA_2_(\d+)`)

	// Example:
	// CSRSUITE_X509_KEY_TYPE_ECDSA_PRIME256V1_SIGNATURE_ALGORITHM_SHA_2_256
	// CSRSUITE_X509_KEY_TYPE_ECDSA_SECP384R1_SIGNATURE_ALGORITHM_SHA_2_512
	reECDSA = regexp.MustCompile(`X509_KEY_TYPE_ECDSA_(PRIME256V1|SECP384R1|SECP521R1)_SIGNATURE_ALGORITHM_SHA_2_(\d+)`)

	// Example:
	// CSRSUITE_X509_KEY_TYPE_EDDSA_ED25519
	reED25519 = regexp.MustCompile(`X509_KEY_TYPE_EDDSA_ED25519`)
)

type ParsedSuite struct {
	KeyType    string // "RSA" | "ECDSA" | "ED25519"
	RSABits    int
	ECDSACurve string // "P256" | "P384" | "P521"
	HashBits   int    // 256/384/512, or 0
}

func parseCSRSuiteName(s string) (ParsedSuite, error) {
	// allow inputs like "certzpb.CSRSuite_...." or just the tail
	if i := strings.LastIndex(s, "CSRSUITE_"); i >= 0 {
		s = s[i:]
	}
	s = strings.TrimSpace(s)

	if reED25519.MatchString(s) {
		return ParsedSuite{KeyType: "ED25519"}, nil
	}

	if m := reRSA.FindStringSubmatch(s); m != nil {
		bits, _ := strconv.Atoi(m[1])
		hash, _ := strconv.Atoi(m[2])
		if bits == 0 || (hash != 256 && hash != 384 && hash != 512) {
			return ParsedSuite{}, fmt.Errorf("invalid RSA suite: %q", s)
		}
		return ParsedSuite{KeyType: "RSA", RSABits: bits, HashBits: hash}, nil
	}

	if m := reECDSA.FindStringSubmatch(s); m != nil {
		curveToken := m[1]
		hash, _ := strconv.Atoi(m[2])
		if hash != 256 && hash != 384 && hash != 512 {
			return ParsedSuite{}, fmt.Errorf("invalid ECDSA hash in suite: %q", s)
		}
		curve := map[string]string{
			"PRIME256V1": "P256",
			"SECP384R1":  "P384",
			"SECP521R1":  "P521",
		}[curveToken]
		if curve == "" {
			return ParsedSuite{}, fmt.Errorf("unknown ECDSA curve %q in %q", curveToken, s)
		}
		return ParsedSuite{KeyType: "ECDSA", ECDSACurve: curve, HashBits: hash}, nil
	}

	return ParsedSuite{}, fmt.Errorf("unrecognized CSR suite string: %q", s)
}

func (p ParsedSuite) SignatureAlgorithm() (x509.SignatureAlgorithm, error) {
	switch p.KeyType {
	case "RSA":
		switch p.HashBits {
		case 256:
			return x509.SHA256WithRSA, nil
		case 384:
			return x509.SHA384WithRSA, nil
		case 512:
			return x509.SHA512WithRSA, nil
		default:
			return 0, fmt.Errorf("unsupported RSA hash: %d", p.HashBits)
		}
	case "ECDSA":
		switch p.HashBits {
		case 256:
			return x509.ECDSAWithSHA256, nil
		case 384:
			return x509.ECDSAWithSHA384, nil
		case 512:
			return x509.ECDSAWithSHA512, nil
		default:
			return 0, fmt.Errorf("unsupported ECDSA hash: %d", p.HashBits)
		}
	case "ED25519":
		// Go will infer this from the private key; return 0 to let x509 decide.
		return 0, nil
	default:
		return 0, fmt.Errorf("unknown key type: %q", p.KeyType)
	}
}

func (p ParsedSuite) GenerateKey() (crypto.PrivateKey, error) {
	switch p.KeyType {
	case "RSA":
		if p.RSABits != 2048 && p.RSABits != 3072 && p.RSABits != 4096 {
			return nil, fmt.Errorf("unsupported RSA bits: %d", p.RSABits)
		}
		return rsa.GenerateKey(rand.Reader, p.RSABits)

	case "ECDSA":
		var c elliptic.Curve
		switch p.ECDSACurve {
		case "P256":
			c = elliptic.P256()
		case "P384":
			c = elliptic.P384()
		case "P521":
			c = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve: %q", p.ECDSACurve)
		}
		return ecdsa.GenerateKey(c, rand.Reader)

	case "ED25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err

	default:
		return nil, fmt.Errorf("unknown key type: %q", p.KeyType)
	}
}

type CSRInput struct {
	Subject        pkix.Name
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
	URIs           []*url.URL
}

func CreateCSRFromSuiteName(suiteName string, in CSRInput) ([]byte, crypto.PrivateKey, error) {
	parsed, err := parseCSRSuiteName(suiteName)
	if err != nil {
		return nil, nil, err
	}

	key, err := parsed.GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	sigAlg, err := parsed.SignatureAlgorithm()
	if err != nil {
		return nil, nil, err
	}

	tpl := &x509.CertificateRequest{
		Subject:            in.Subject,
		DNSNames:           in.DNSNames,
		IPAddresses:        in.IPAddresses,
		EmailAddresses:     in.EmailAddresses,
		URIs:               in.URIs,
		SignatureAlgorithm: sigAlg, // 0 means "auto" (good for Ed25519)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create csr: %w", err)
	}
	// parse to PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	return csrPEM, key, nil
}
