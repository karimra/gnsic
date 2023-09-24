package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/karimra/gnsic/api"
	authzapi "github.com/karimra/gnsic/api/authz"
	"github.com/olekukonko/tablewriter"
	"github.com/openconfig/gnsi/authz"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func (a *App) InitAuthzFlags(cmd *cobra.Command) {
	cmd.ResetFlags()
	//
	// cmd.PersistentFlags().StringVar(&a.Config.CertCAKey, "ca-key", "", "CA key")
	//
	cmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		a.Config.FileConfig.BindPFlag(fmt.Sprintf("%s-%s", cmd.Name(), flag.Name), flag)
	})
}

func (a *App) InitAuthzRotateFlags(cmd *cobra.Command) {
	cmd.ResetFlags()
	//
	cmd.Flags().BoolVar(&a.Config.AuthzRotateForceOverwrite, "force", false, "force overwrite policy")
	cmd.Flags().StringVar(&a.Config.AuthzRotateVersion, "version", "", "policy version")
	cmd.Flags().StringVar(&a.Config.AuthzRotateCreatedOn, "created-on", "", "policy creation time")
	cmd.Flags().StringVar(&a.Config.AuthzRotatePolicy, "policy", "", "policy definition as a JSON string")
	cmd.Flags().DurationVar(&a.Config.AuthzRotateFinalizeAfter, "finalize-after", time.Second, "wait timer before sending a finalize request")
	//
	cmd.LocalFlags().VisitAll(func(flag *pflag.Flag) {
		a.Config.FileConfig.BindPFlag(fmt.Sprintf("%s-%s", cmd.Name(), flag.Name), flag)
	})
}

// NOTES:
//
// How should the testing be done, using probe RPC ? then why not make it explicit ?
// How does the server know it should use the new Policy ?
//
// https://github.com/openconfig/gnsi/blob/main/authz/authz.proto#L98
// quote: "The response is based on the instance of policy specified in the request"
// --> there is no reference to a policy in ProbeRequest: https://github.com/openconfig/gnsi/blob/main/authz/authz.proto#L183
// \1

func (a *App) RunEAuthzRotate(cmd *cobra.Command, args []string) error {
	targets, err := a.GetTargets()
	if err != nil {
		return err
	}
	a.Logger.Infof("targets: %v", targets)
	numTargets := len(targets)
	responseChan := make(chan *TargetError, numTargets)
	a.wg.Add(numTargets)
	for _, t := range targets {
		go a.authzRotateRequest(cmd.Context(), t, responseChan)
	}
	a.wg.Wait()
	close(responseChan)
	//
	errs := make([]error, 0, numTargets)
	// result := make([]*TargetError, 0, numTargets)
	for rsp := range responseChan {
		if rsp.Err != nil {
			wErr := fmt.Errorf("%q Authz Probe failed: %v", rsp.TargetName, rsp.Err)
			a.Logger.Error(wErr)
			errs = append(errs, rsp.Err)
			continue
		}
		// result = append(result, rsp)
	}
	return a.handleErrs(errs)
}

func (a *App) authzRotateRequest(ctx context.Context, t *api.Target, rspCh chan<- *TargetError) {
	defer a.wg.Done()
	ctx = t.AppendMetadata(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	err := t.CreateGrpcClient(ctx, a.createBaseDialOpts()...)
	if err != nil {
		rspCh <- &TargetError{
			TargetName: t.Config.Address,
			Err:        err,
		}
		return
	}
	defer t.Close()

	rotateClient, err := t.NewAuthzClient().Rotate(ctx)
	if err != nil {
		rspCh <- &TargetError{
			TargetName: t.Config.Address,
			Err:        err,
		}
		return
	}

	req, err := authzapi.NewRotateAuthzRequest(
		authzapi.ForceOverwrite(a.Config.LocalFlags.AuthzRotateForceOverwrite),
		authzapi.Version(a.Config.LocalFlags.AuthzRotateVersion),
		authzapi.CreatedOn(uint64(time.Now().UnixNano())),
		authzapi.Policy(a.Config.LocalFlags.AuthzRotatePolicy),
	)
	if err != nil {
		rspCh <- &TargetError{
			TargetName: t.Config.Address,
			Err:        err,
		}
		return
	}
	a.printProtoMsg(t.Config.Name, req)

	err = rotateClient.Send(req)
	if err != nil {
		rspCh <- &TargetError{
			TargetName: t.Config.Address,
			Err:        err,
		}
		return
	}

	rsp, err := rotateClient.Recv()
	if err != nil {
		rspCh <- &TargetError{
			TargetName: t.Config.Address,
			Err:        err,
		}
		return
	}
	switch rsp := rsp.RotateResponse.(type) {
	case *authz.RotateAuthzResponse_UploadResponse:
		a.Logger.Infof("%q: got UploadResponse", t.Config.Name)
	default:
		rspCh <- &TargetError{
			TargetName: t.Config.Address,
			Err:        fmt.Errorf("unexpected message type %T: expecting RotateAuthzResponse_UploadResponse", rsp),
		}
	}
	<-time.After(a.Config.LocalFlags.AuthzRotateFinalizeAfter)

	req, err = authzapi.NewRotateAuthzRequest(authzapi.FinalizeRotation())
	if err != nil {
		rspCh <- &TargetError{
			TargetName: t.Config.Address,
			Err:        err,
		}
		return
	}
	a.Logger.Infof("%q: sending finalize request", t.Config.Name)
	err = rotateClient.Send(req)
	if err != nil && !errors.Is(err, io.EOF) {
		rspCh <- &TargetError{
			TargetName: t.Config.Address,
			Err:        fmt.Errorf("failed finalize request: %v", err),
		}
		return
	}
	a.Logger.Debugf("finalize send request got err %v", err)
	a.Logger.Infof("%q: closing stream", t.Config.Name)
	cancel()
}

// Authz Probe

func (a *App) InitAuthzProbeFlags(cmd *cobra.Command) {
	cmd.ResetFlags()
	//
	cmd.Flags().StringVar(&a.Config.AuthzProbeUser, "user", "", "The user name to be used to perform the evaluation.")
	cmd.Flags().StringVar(&a.Config.AuthzProbeRPC, "rpc", "",
		"The gRPC RPC name to be used to perform the evaluation. It has to be a fully qualified name, like: \"/gnsi.ssh.Ssh/MutateHostCredentials\"")
	//
	cmd.LocalFlags().VisitAll(func(flag *pflag.Flag) {
		a.Config.FileConfig.BindPFlag(fmt.Sprintf("%s-%s", cmd.Name(), flag.Name), flag)
	})
}

type authzProbeResponse struct {
	TargetError
	rsp *authz.ProbeResponse
}

func (r *authzProbeResponse) Target() string {
	return r.TargetName
}

func (r *authzProbeResponse) Response() any {
	return r.rsp
}

func (a *App) RunEAuthzProbe(cmd *cobra.Command, args []string) error {
	targets, err := a.GetTargets()
	if err != nil {
		return err
	}
	a.Logger.Infof("targets: %v", targets)
	numTargets := len(targets)
	responseChan := make(chan *authzProbeResponse, numTargets)
	a.wg.Add(numTargets)
	for _, t := range targets {
		go a.authzProbeRequest(cmd.Context(), t, responseChan)
	}
	a.wg.Wait()
	close(responseChan)
	//
	errs := make([]error, 0, numTargets)
	result := make([]TargetResponse, 0, numTargets)
	for rsp := range responseChan {
		if rsp.Err != nil {
			wErr := fmt.Errorf("%q Authz Probe failed: %v", rsp.TargetName, rsp.Err)
			a.Logger.Error(wErr)
			errs = append(errs, rsp.Err)
			continue
		}
		result = append(result, rsp)
		a.printProtoMsg(rsp.TargetName, rsp.rsp)
	}
	a.printCMDOutput(result, a.authzProbePrintFn)
	return a.handleErrs(errs)
}

func (a *App) authzProbeRequest(ctx context.Context, t *api.Target, rspCh chan<- *authzProbeResponse) {
	defer a.wg.Done()
	ctx = t.AppendMetadata(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	err := t.CreateGrpcClient(ctx, a.createBaseDialOpts()...)
	if err != nil {
		rspCh <- &authzProbeResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	defer t.Close()
	req, err := authzapi.NewProbeRequest(
		authzapi.User(a.Config.LocalFlags.AuthzProbeUser),
		authzapi.RPC(a.Config.LocalFlags.AuthzProbeRPC),
	)
	if err != nil {
		rspCh <- &authzProbeResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	a.printProtoMsg(t.Config.Name, req)
	rsp, err := t.NewAuthzClient().Probe(ctx, req)
	rspCh <- &authzProbeResponse{
		TargetError: TargetError{
			TargetName: t.Config.Address,
			Err:        err,
		},
		rsp: rsp,
	}
}

func (a *App) authzProbePrintFn(rsps []TargetResponse) string {
	tabData := make([][]string, 0, len(rsps))
	sort.Slice(rsps, func(i, j int) bool {
		return rsps[i].Target() < rsps[j].Target()
	})
	for _, rsp := range rsps {
		switch r := rsp.Response().(type) {
		case *authzProbeResponse:
			tabData = append(tabData, []string{
				rsp.Target(),
				r.rsp.GetAction().String(),
				r.rsp.GetVersion(),
			})
		default:
			a.Logger.Printf("%s: unexpected message type: %T", rsp.Target(), rsp.Response())
		}
	}
	sort.Slice(tabData, func(i, j int) bool {
		return tabData[i][0] < tabData[j][0]
	})
	b := new(bytes.Buffer)
	table := tablewriter.NewWriter(b)
	table.SetHeader([]string{"Target Name", "Action", "Version"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoFormatHeaders(false)
	table.SetAutoWrapText(false)
	table.AppendBulk(tabData)
	table.Render()
	return b.String()
}

// Authz Get

func (a *App) InitAuthzGetFlags(cmd *cobra.Command) {
	cmd.ResetFlags()
	//
	// cmd.Flags().StringVar(&a.Config.CertCanGenerateCSRKeyType, "key-type", "KT_RSA", "Key Type")
	// cmd.Flags().StringVar(&a.Config.CertCanGenerateCSRCertificateType, "cert-type", "CT_X509", "Certificate Type")
	// cmd.Flags().Uint32Var(&a.Config.CertCanGenerateCSRKeySize, "key-size", 2048, "Key Size")
	//
	cmd.LocalFlags().VisitAll(func(flag *pflag.Flag) {
		a.Config.FileConfig.BindPFlag(fmt.Sprintf("%s-%s", cmd.Name(), flag.Name), flag)
	})
}

type authzGetResponse struct {
	TargetError
	rsp *authz.GetResponse
}

func (r *authzGetResponse) Target() string {
	return r.TargetName
}

func (r *authzGetResponse) Response() any {
	return r.rsp
}

func (a *App) RunEAuthzGet(cmd *cobra.Command, args []string) error {
	targets, err := a.GetTargets()
	if err != nil {
		return err
	}
	a.Logger.Infof("targets: %v", targets)
	numTargets := len(targets)
	responseChan := make(chan *authzGetResponse, numTargets)
	a.wg.Add(numTargets)
	for _, t := range targets {
		go a.authzGetRequest(cmd.Context(), t, responseChan)
	}
	a.wg.Wait()
	close(responseChan)
	//
	errs := make([]error, 0, numTargets)
	result := make([]TargetResponse, 0, numTargets)
	for rsp := range responseChan {
		if rsp.Err != nil {
			wErr := fmt.Errorf("%q Authz Get failed: %v", rsp.TargetName, rsp.Err)
			a.Logger.Error(wErr)
			errs = append(errs, rsp.Err)
			continue
		}
		result = append(result, rsp)
		a.printProtoMsg(rsp.TargetName, rsp.rsp)
	}
	a.printCMDOutput(result, a.authzGetPrintFn)
	return a.handleErrs(errs)
}

func (a *App) authzGetRequest(ctx context.Context, t *api.Target, rspCh chan<- *authzGetResponse) {
	defer a.wg.Done()
	ctx = t.AppendMetadata(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	err := t.CreateGrpcClient(ctx, a.createBaseDialOpts()...)
	if err != nil {
		rspCh <- &authzGetResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	defer t.Close()

	req := &authz.GetRequest{}
	rsp, err := t.NewAuthzClient().Get(ctx, req)
	rspCh <- &authzGetResponse{
		TargetError: TargetError{
			TargetName: t.Config.Address,
			Err:        err,
		},
		rsp: rsp,
	}
}

func (a *App) authzGetPrintFn(rsps []TargetResponse) string {
	tabData := make([][]string, 0, len(rsps))
	sort.Slice(rsps, func(i, j int) bool {
		return rsps[i].Target() < rsps[j].Target()
	})
	for _, rsp := range rsps {
		switch r := rsp.Response().(type) {
		case *authzGetResponse:
			tabData = append(tabData, []string{
				rsp.Target(),
				r.rsp.GetVersion(),
				fmt.Sprintf("%d", r.rsp.GetCreatedOn()),
				r.rsp.GetPolicy(),
			})
		default:
			a.Logger.Printf("%s: unexpected message type: %T", rsp.Target(), rsp.Response())
		}
	}
	sort.Slice(tabData, func(i, j int) bool {
		return tabData[i][0] < tabData[j][0]
	})
	b := new(bytes.Buffer)
	table := tablewriter.NewWriter(b)
	table.SetHeader([]string{"Target Name", "Version", "CreatedOn", "Policy"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoFormatHeaders(false)
	table.SetAutoWrapText(false)
	table.AppendBulk(tabData)
	table.Render()
	return b.String()
}
