package app

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/karimra/gnsic/config"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

const (
	defaultGrpcPort = "57400"
)

type App struct {
	// Cfn     context.CancelFunc
	RootCmd *cobra.Command

	wg     *sync.WaitGroup
	Config *config.Config
	Logger *log.Entry
	// print mutex
	pm *sync.Mutex
}

type TargetResponse interface {
	Target() string
	Response() any
}

type targetResponse struct {
	Target   string      `json:"target,omitempty"`
	Response interface{} `json:"response,omitempty"`
}

func New() *App {
	logger := log.New()
	return &App{
		wg:     new(sync.WaitGroup),
		Config: config.New(),
		Logger: log.NewEntry(logger),
		pm:     new(sync.Mutex),
	}
}

func (a *App) InitGlobalFlags() {
	a.RootCmd.ResetFlags()

	a.RootCmd.PersistentFlags().StringVar(&a.Config.CfgFile, "config", "", "config file (default is $HOME/.gnsic.yaml)")
	a.RootCmd.PersistentFlags().StringSliceVarP(&a.Config.GlobalFlags.Address, "address", "a", []string{}, "comma separated gNSI targets addresses")
	a.RootCmd.PersistentFlags().StringVarP(&a.Config.GlobalFlags.Username, "username", "u", "", "username")
	a.RootCmd.PersistentFlags().StringVarP(&a.Config.GlobalFlags.Password, "password", "p", "", "password")
	a.RootCmd.PersistentFlags().StringVarP(&a.Config.GlobalFlags.Port, "port", "", defaultGrpcPort, "gRPC port")
	a.RootCmd.PersistentFlags().BoolVarP(&a.Config.GlobalFlags.Insecure, "insecure", "", false, "insecure connection")
	a.RootCmd.PersistentFlags().StringVarP(&a.Config.GlobalFlags.TLSCa, "tls-ca", "", "", "tls certificate authority")
	a.RootCmd.PersistentFlags().StringVarP(&a.Config.GlobalFlags.TLSCert, "tls-cert", "", "", "tls certificate")
	a.RootCmd.PersistentFlags().StringVarP(&a.Config.GlobalFlags.TLSKey, "tls-key", "", "", "tls key")
	a.RootCmd.PersistentFlags().DurationVarP(&a.Config.GlobalFlags.Timeout, "timeout", "", 10*time.Second, "grpc timeout, valid formats: 10s, 1m30s, 1h")
	a.RootCmd.PersistentFlags().BoolVarP(&a.Config.GlobalFlags.Debug, "debug", "d", false, "debug mode")
	a.RootCmd.PersistentFlags().BoolVarP(&a.Config.GlobalFlags.SkipVerify, "skip-verify", "", false, "skip verify tls connection")
	a.RootCmd.PersistentFlags().BoolVarP(&a.Config.GlobalFlags.ProxyFromEnv, "proxy-from-env", "", false, "use proxy from environment")
	a.RootCmd.PersistentFlags().StringVarP(&a.Config.GlobalFlags.Format, "format", "", "text", "output format, one of: text, json")
	a.RootCmd.PersistentFlags().BoolVarP(&a.Config.GlobalFlags.PrintProto, "print-proto", "", false, "print request(s)/responses(s) in prototext format")
	a.RootCmd.PersistentFlags().BoolVarP(&a.Config.GlobalFlags.Gzip, "gzip", "", false, "enable gzip compression on gRPC connections")

	a.RootCmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		a.Config.FileConfig.BindPFlag(flag.Name, flag)
	})
}

func (a *App) PreRun(cmd *cobra.Command, args []string) error {
	// init logger
	a.Config.SetLogger()
	if a.Config.Debug {
		a.Logger.Logger.SetLevel(log.DebugLevel)
		grpclog.SetLogger(a.Logger) //lint:ignore SA1019 .
	}
	a.Config.SetPersistentFlagsFromFile(a.RootCmd)
	return nil
}

type TargetError struct {
	TargetName string
	Err        error
}

func (a *App) createBaseDialOpts() []grpc.DialOption {
	opts := []grpc.DialOption{grpc.WithBlock()}
	if !a.Config.ProxyFromEnv {
		opts = append(opts, grpc.WithNoProxy())
	}
	if a.Config.Gzip {
		opts = append(opts, grpc.WithDefaultCallOptions(grpc.UseCompressor(gzip.Name)))
	}
	return opts
}

func (a *App) printProtoMsg(targetName string, m proto.Message) {
	if !a.Config.PrintProto {
		return
	}
	a.pm.Lock()
	defer a.pm.Unlock()
	fmt.Fprintf(os.Stdout, "%q:\n%s\n%s\n",
		targetName,
		m.ProtoReflect().Descriptor().FullName(),
		prototext.Format(m))
}

func (a *App) printCMDOutput(rs []TargetResponse, fn func([]TargetResponse) string) {
	switch a.Config.Format {
	default:
		fmt.Println(fn(rs))
	case "json":
		for _, r := range rs {
			tRsp := targetResponse{
				Target:   r.Target(),
				Response: r.Response(),
			}
			b, err := json.MarshalIndent(tRsp, "", "  ")
			if err != nil {
				a.Logger.Errorf("failed to marshal Target response from %q: %v", r.Target(), err)
				continue
			}
			fmt.Println(string(b))
		}
	}
}

func (a *App) handleErrs(errs []error) error {
	numErrors := len(errs)
	if numErrors > 0 {
		for _, e := range errs {
			a.Logger.Debug(e)
		}
		return fmt.Errorf("there was %d error(s)", numErrors)
	}
	return nil
}
