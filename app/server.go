package app

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/openconfig/gnsi/acctz"
	"github.com/openconfig/gnsi/authz"
	certz "github.com/openconfig/gnsi/certz"
	credz "github.com/openconfig/gnsi/credentialz"
	"github.com/openconfig/gnsi/pathz"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

func (a *App) InitServerFlags(cmd *cobra.Command) {
	cmd.ResetFlags()
	//
	// cmd.PersistentFlags().StringVar(&a.Config.CertCAKey, "ca-key", "", "CA key")
	//
	cmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		a.Config.FileConfig.BindPFlag(fmt.Sprintf("%s-%s", cmd.Name(), flag.Name), flag)
	})
}

func (a *App) RunEServer(cmd *cobra.Command, args []string) error {
	var l net.Listener
	var err error
	network := "tcp"
	for {
		l, err = net.Listen(network, a.Config.Address[0])
		if err != nil {
			a.Logger.Printf("failed to start gRPC server listener: %v", err)
			time.Sleep(time.Second)
			continue
		}
		break
	}
	srv := &gNSIServer{
		s: grpc.NewServer(),
		authzServer: &authzServer{
			logger: a.Logger.WithField("server", "authz"),
		},
		credzServer: &credzServer{
			logger: a.Logger.WithField("server", "credentialz"),
		},
		certzServer: &certzServer{
			logger: a.Logger.WithField("server", "certz"),
		},
		pathzServer: &pathzServer{
			logger: a.Logger.WithField("server", "pathz"),
		},
	}

	acctz.RegisterAcctzServer(srv.s, srv.acctzServer)
	certz.RegisterCertzServer(srv.s, srv.certzServer)
	authz.RegisterAuthzServer(srv.s, srv.authzServer)
	pathz.RegisterPathzServer(srv.s, srv.pathzServer)
	credz.RegisterCredentialzServer(srv.s, srv.credzServer)

	reflection.Register(srv.s)

	ctx, cancel := context.WithCancel(cmd.Context())
	go func() {
		err = srv.s.Serve(l)
		if err != nil {
			a.Logger.Printf("gRPC server shutdown: %v", err)
		}
		cancel()
	}()
	a.Logger.Info("gNSI Server started...")
	<-ctx.Done()
	return nil
}

type gNSIServer struct {
	s           *grpc.Server
	acctzServer *acctzServer
	authzServer *authzServer
	credzServer *credzServer
	certzServer *certzServer
	pathzServer *pathzServer
}

type acctzServer struct {
	acctz.UnimplementedAcctzServer
}

type authzServer struct {
	authz.UnimplementedAuthzServer
	logger *log.Entry
}

type credzServer struct {
	credz.UnimplementedCredentialzServer
	logger *log.Entry
}

type certzServer struct {
	certz.UnimplementedCertzServer
	logger *log.Entry
}

type pathzServer struct {
	pathz.UnimplementedPathzServer
	logger *log.Entry
}

// authz
func (s *authzServer) Get(context.Context, *authz.GetRequest) (*authz.GetResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Get not implemented")
}

func (s *authzServer) Probe(context.Context, *authz.ProbeRequest) (*authz.ProbeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Probe not implemented")
}

func (s *authzServer) Rotate(stream authz.Authz_RotateServer) error {
	pr, _ := peer.FromContext(stream.Context())
	s.logger.Infof("received Rotate request from peer %s", pr.Addr.String())
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	s.logger.Infof("peer %s sent %v", pr.Addr.String(), msg)
	err = stream.Send(&authz.RotateAuthzResponse{
		RotateResponse: &authz.RotateAuthzResponse_UploadResponse{
			UploadResponse: &authz.UploadResponse{},
		},
	})
	if err != nil {
		return err
	}
	s.logger.Infof("waiting for finalize")
	msg, err = stream.Recv()
	if err != nil {
		// TODO: rollback policy
		return err
	}
	s.logger.Infof("peer %s sent %v", pr.Addr.String(), msg)
	switch msg := msg.RotateRequest.(type) {
	case *authz.RotateAuthzRequest_FinalizeRotation:
		s.logger.Infof("peer %s sent %v", pr.Addr.String(), msg)
	default:
	}
	// TODO: apply authorization policy
	// <-stream.Context().Done()
	return nil
}

// // pathz
// func (s *pathzServer) Get(context.Context, *pathz.GetRequest) (*pathz.GetResponse, error) {
// 	return nil, nil
// }
// func (s *pathzServer) Probe(context.Context, *pathz.ProbeRequest) (*pathz.ProbeResponse, error) {
// 	return nil, nil
// }
// func (s *pathzServer) Rotate(pathz.Pathz_RotateServer) error { return nil }
