package config

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	configName = ".gnsic"
	envPrefix  = "GNSIC"
)

type Config struct {
	GlobalFlags `mapstructure:",squash"`
	LocalFlags  `mapstructure:",squash"`
	FileConfig  *viper.Viper `mapstructure:"-" json:"-" yaml:"-" `

	logger *log.Entry
}

func New() *Config {
	return &Config{
		GlobalFlags{},
		LocalFlags{},
		viper.NewWithOptions(viper.KeyDelimiter("/")),
		nil,
	}
}

func (c *Config) Load() error {
	c.FileConfig.SetEnvPrefix(envPrefix)
	c.FileConfig.SetEnvKeyReplacer(strings.NewReplacer("/", "_", "-", "_"))
	c.FileConfig.AutomaticEnv()
	if c.GlobalFlags.CfgFile != "" {
		c.FileConfig.SetConfigFile(c.GlobalFlags.CfgFile)
	} else {
		home, err := homedir.Dir()
		if err != nil {
			return err
		}
		c.FileConfig.AddConfigPath(".")
		c.FileConfig.AddConfigPath(home)
		c.FileConfig.AddConfigPath(xdg.ConfigHome)
		c.FileConfig.AddConfigPath(xdg.ConfigHome + "/gnsic")
		c.FileConfig.SetConfigName(configName)
	}

	err := c.FileConfig.ReadInConfig()
	if err != nil {
		return err
	}

	err = c.FileConfig.Unmarshal(c.FileConfig)
	if err != nil {
		return err
	}
	// c.mergeEnvVars()
	// return c.expandOSPathFlagValues()
	return nil
}

type GlobalFlags struct {
	CfgFile       string
	Address       []string      `mapstructure:"address,omitempty" json:"address,omitempty" yaml:"address,omitempty"`
	Username      string        `mapstructure:"username,omitempty" json:"username,omitempty" yaml:"username,omitempty"`
	Password      string        `mapstructure:"password,omitempty" json:"password,omitempty" yaml:"password,omitempty"`
	Port          string        `mapstructure:"port,omitempty" json:"port,omitempty" yaml:"port,omitempty"`
	Encoding      string        `mapstructure:"encoding,omitempty" json:"encoding,omitempty" yaml:"encoding,omitempty"`
	Insecure      bool          `mapstructure:"insecure,omitempty" json:"insecure,omitempty" yaml:"insecure,omitempty"`
	TLSCa         string        `mapstructure:"tls-ca,omitempty" json:"tls-ca,omitempty" yaml:"tls-ca,omitempty"`
	TLSCert       string        `mapstructure:"tls-cert,omitempty" json:"tls-cert,omitempty" yaml:"tls-cert,omitempty"`
	TLSKey        string        `mapstructure:"tls-key,omitempty" json:"tls-key,omitempty" yaml:"tls-key,omitempty"`
	TLSMinVersion string        `mapstructure:"tls-min-version,omitempty" json:"tls-min-version,omitempty" yaml:"tls-min-version,omitempty"`
	TLSMaxVersion string        `mapstructure:"tls-max-version,omitempty" json:"tls-max-version,omitempty" yaml:"tls-max-version,omitempty"`
	TLSVersion    string        `mapstructure:"tls-version,omitempty" json:"tls-version,omitempty" yaml:"tls-version,omitempty"`
	LogTLSSecret  bool          `mapstructure:"log-tls-secret,omitempty" json:"log-tls-secret,omitempty" yaml:"log-tls-secret,omitempty"`
	Timeout       time.Duration `mapstructure:"timeout,omitempty" json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Debug         bool          `mapstructure:"debug,omitempty" json:"debug,omitempty" yaml:"debug,omitempty"`
	SkipVerify    bool          `mapstructure:"skip-verify,omitempty" json:"skip-verify,omitempty" yaml:"skip-verify,omitempty"`
	ProxyFromEnv  bool          `mapstructure:"proxy-from-env,omitempty" json:"proxy-from-env,omitempty" yaml:"proxy-from-env,omitempty"`
	Format        string        `mapstructure:"format,omitempty" json:"format,omitempty" yaml:"format,omitempty"`
	LogFile       string        `mapstructure:"log-file,omitempty" json:"log-file,omitempty" yaml:"log-file,omitempty"`
	Log           bool          `mapstructure:"log,omitempty" json:"log,omitempty" yaml:"log,omitempty"`
	MaxMsgSize    int           `mapstructure:"max-msg-size,omitempty" json:"max-msg-size,omitempty" yaml:"max-msg-size,omitempty"`
	PrintRequest  bool          `mapstructure:"print-request,omitempty" json:"print-request,omitempty" yaml:"print-request,omitempty"`
	Retry         time.Duration `mapstructure:"retry,omitempty" json:"retry,omitempty" yaml:"retry,omitempty"`
	PrintProto    bool          `mapstructure:"print-proto,omitempty" json:"print-proto,omitempty" yaml:"print-proto,omitempty"`
	Gzip          bool          `mapstructure:"gzip,omitempty" json:"gzip,omitempty" yaml:"gzip,omitempty"`
}

type LocalFlags struct {
	// Authz
	// AuthzProbe
	AuthzProbeUser string
	AuthzProbeRPC  string
	// AuthzRotate
	AuthzRotateForceOverwrite bool
	AuthzRotateVersion        string
	AuthzRotateCreatedOn      string
	AuthzRotatePolicy         string
	AuthzRotateFinalizeAfter  time.Duration

	// Pathz
	// PathzProbe
	PathzProbeUser string
	PathzProbeRPC  string
	// PathzRotate
	PathzRotateForceOverwrite bool
	PathzRotateVersion        string
	PathzRotateCreatedOn      string
	PathzRotatePolicy         string
	PathzRotateFinalizeAfter  time.Duration

	// Certz
	// Certz Info
	CertzInfoCertificate string
	// Certz CreateCa
	CertzCreateCaOrg           string
	CertzCreateCaOrgUnit       string
	CertzCreateCaCountry       string
	CertzCreateCaState         string
	CertzCreateCaLocality      string
	CertzCreateCaStreetAddress string
	CertzCreateCaPostalCode    string
	CertzCreateCaValidity      time.Duration
	CertzCreateCaKeySize       int
	CertzCreateCaEmailID       string
	CertzCreateCaCommonName    string
	CertzCreateCaKeyOut        string
	CertzCreateCaCertOut       string

	// Certz Rotate
	CertzRotateCertificateValidity time.Duration
	CertzRotateCACert              string
	CertzRotateCAKey               string
	CertzRotateForceOverwrite      bool
	CertzRotateSSLProfileID        string
	// Certz Rotate GenCSR
	CertzRotateCSRSuite   string
	CertzRotateCommonName string
	CertzRotateCountry    string
	CertzRotateState      string
	CertzRotateCity       string
	CertzRotateOrg        string
	CertzRotateOrgUnit    string
	CertzRotateIPAddress  string
	CertzRotateEmailID    string
	CertzRotateSanDNS     []string
	CertzRotateSanEmail   []string
	CertzRotateSanIP      []string
	CertzRotateSanURI     []string
	// Certz Rotate Upload
	// Certz Rotate Upload Entities
	CertzRotateEntityCreatedOn []string
	// Certz Rotate Upload Entity Cert Chain
	CertzRotateEntityCertChainCertificateVersion  string
	CertzRotateEntityCertChainCertificateType     []string
	CertzRotateEntityCertChainCertificateEncoding []string
	CertzRotateEntityCertChainCertificateCFile    []string
	CertzRotateEntityCertChainCertificateKFile    []string
	// Certz Rotate Upload Entity Trust Bundle
	CertzRotateEntityCertChainTrustBundleVersion  []string
	CertzRotateEntityCertChainTrustBundleType     []string
	CertzRotateEntityCertChainTrustBundleEncoding []string
	CertzRotateEntityCertChainTrustBundleCFile    []string
	// Certz Rotate Upload Entity CRL
	CertzRotateEntityCertChainCRLVersion  []string
	CertzRotateEntityCertChainCRLType     []string
	CertzRotateEntityCertChainCRLEncoding []string
	CertzRotateEntityCertChainCRLCFile    []string
	CertzRotateEntityCertChainCRLID       []string
	// Certz Rotate Upload Entity AuthPolicy
	CertzRotateEntityAuthPolicy string

	// Certz Add Profile
	CertzAddProfileID string
	// Certz delete Profile
	CertzDeleteProfileID string
	// Certz CanGenerateCSR
	CertzCanGenCSRCSRSuite   string
	CertzCanGenCSRCommonName string
	CertzCanGenCSRCountry    string
	CertzCanGenCSRState      string
	CertzCanGenCSRCity       string
	CertzCanGenCSROrg        string
	CertzCanGenCSROrgUnit    string
	CertzCanGenCSRIPAddress  string
	CertzCanGenCSREmailID    string
	CertzCanGenCSRSanDNS     []string
	CertzCanGenCSRSanEmail   []string
	CertzCanGenCSRSanIP      []string
	CertzCanGenCSRSanURI     []string
	//Version
	UpgradeUsePkg bool
}

func (c *Config) SetLogger() {
	logger := log.StandardLogger()
	if c.Debug {
		logger.SetLevel(log.DebugLevel)
	}
	c.logger = log.NewEntry(logger)
}

func (c *Config) LogOutput() io.Writer {
	return c.logger.Logger.Out
}

func (c *Config) SetPersistentFlagsFromFile(cmd *cobra.Command) {
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		flagName := flagFullName(cmd, f.Name)
		c.logger.Debugf("cmd=%s, flagName=%s, changed=%v, isSetInFile=%v",
			cmd.Name(), flagName, f.Changed, c.FileConfig.IsSet(f.Name))
		if !f.Changed && c.FileConfig.IsSet(f.Name) {
			c.setFlagValue(cmd, f.Name, c.FileConfig.Get(flagName))
		}
	})
}

func (c *Config) SetLocalFlagsFromFile(cmd *cobra.Command) {
	cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		flagName := flagFullName(cmd, f.Name)
		c.logger.Debugf("cmd=%s, flagName=%s, changed=%v, isSetInFile=%v",
			cmd.Name(), flagName, f.Changed, c.FileConfig.IsSet(flagName))
		if !f.Changed && c.FileConfig.IsSet(flagName) {
			c.setFlagValue(cmd, f.Name, c.FileConfig.Get(flagName))
		}
	})
}

func (c *Config) setFlagValue(cmd *cobra.Command, fName string, val interface{}) {
	switch val := val.(type) {
	case []interface{}:
		c.logger.Debugf("cmd=%s, flagName=%s, valueType=%T, length=%d, value=%#v",
			cmd.Name(), fName, val, len(val), val)

		nVal := make([]string, 0, len(val))
		for _, v := range val {
			nVal = append(nVal, fmt.Sprintf("%v", v))
		}
		cmd.Flags().Set(fName, strings.Join(nVal, ","))
	default:
		c.logger.Debugf("cmd=%s, flagName=%s, valueType=%T, value=%#v",
			cmd.Name(), fName, val, val)
		cmd.Flags().Set(fName, fmt.Sprintf("%v", val))
	}
}

func flagFullName(cmd *cobra.Command, fName string) string {
	if cmd.Name() == "gnsic" {
		return fName
	}
	ls := []string{cmd.Name(), fName}
	for cmd.Parent() != nil && cmd.Parent().Name() != "gnsic" {
		ls = append([]string{cmd.Parent().Name()}, ls...)
		cmd = cmd.Parent()
	}
	return strings.Join(ls, "-")
}
