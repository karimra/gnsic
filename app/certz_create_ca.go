package app

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func (a *App) InitCertzCreateCaFlags(cmd *cobra.Command) {
	cmd.ResetFlags()
	//
	cmd.Flags().StringVar(&a.Config.CertzCreateCaOrg, "org", "gNSIc", "organization name")
	cmd.Flags().StringVar(&a.Config.CertzCreateCaOrgUnit, "org-unit", "gNSIc Certs", "organizational Unit name")
	cmd.Flags().StringVar(&a.Config.CertzCreateCaCountry, "country", "OC", "country name")
	cmd.Flags().StringVar(&a.Config.CertzCreateCaState, "state", "", "state name")
	cmd.Flags().StringVar(&a.Config.CertzCreateCaLocality, "locality", "", "locality name")
	cmd.Flags().StringVar(&a.Config.CertzCreateCaStreetAddress, "street-address", "", "street-address")
	cmd.Flags().StringVar(&a.Config.CertzCreateCaPostalCode, "postal-code", "", "postal-code")
	cmd.Flags().DurationVar(&a.Config.CertzCreateCaValidity, "validity", 87600*time.Hour, "certificate validity")
	cmd.Flags().IntVar(&a.Config.CertzCreateCaKeySize, "key-size", 2048, "key size")
	cmd.Flags().StringVar(&a.Config.CertzCreateCaEmailID, "email", "", "email ID")
	cmd.Flags().StringVar(&a.Config.CertzCreateCaCommonName, "common-name", "", "common name")
	cmd.Flags().StringVar(&a.Config.CertzCreateCaKeyOut, "key-out", "key.pem", "private key output path")
	cmd.Flags().StringVar(&a.Config.CertzCreateCaCertOut, "cert-out", "cert.pem", "CA certificate output path")
	//
	cmd.LocalFlags().VisitAll(func(flag *pflag.Flag) {
		a.Config.FileConfig.BindPFlag(fmt.Sprintf("%s-%s", cmd.Name(), flag.Name), flag)
	})
}

func (a *App) RunECertzCreateCa(cmd *cobra.Command, args []string) error {
	serialNumber, err := genSerialNumber()
	if err != nil {
		return err
	}
	ca := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{a.Config.CertzCreateCaCountry},
			Organization:       []string{a.Config.CertzCreateCaOrg},
			OrganizationalUnit: []string{a.Config.CertzCreateCaOrgUnit},
			Province:           []string{a.Config.CertzCreateCaState},
			Locality:           []string{a.Config.CertzCreateCaLocality},
			StreetAddress:      []string{a.Config.CertzCreateCaStreetAddress},
			PostalCode:         []string{a.Config.CertzCreateCaPostalCode},
			CommonName:         a.Config.CertzCreateCaCommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(a.Config.CertzCreateCaValidity),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	if a.Config.CertzCreateCaEmailID != "" {
		ca.Subject.ExtraNames = append(ca.Subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidEmailAddress,
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(a.Config.CertzCreateCaEmailID),
			},
		})
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, a.Config.CertzCreateCaKeySize)
	if err != nil {
		return err
	}

	// DER encoding
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}
	if a.Config.Debug {
		// parse for printing
		nca, err := x509.ParseCertificate(caBytes)
		if err != nil {
			return err
		}
		s, err := CertificateText(nca, false)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", s)
	}
	//
	certOut, err := os.Create(a.Config.CertzCreateCaCertOut)
	if err != nil {
		return err
	}
	defer certOut.Close()
	err = pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return err
	}

	keyOut, err := os.OpenFile(a.Config.CertzCreateCaKeyOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	err = pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err != nil {
		return err
	}
	a.Logger.Infof("CA certificate written to %s", a.Config.CertzCreateCaCertOut)
	a.Logger.Infof("CA key written to %s", a.Config.CertzCreateCaKeyOut)
	return nil
}
