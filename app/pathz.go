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
	pathzapi "github.com/karimra/gnsic/api/pathz"
	"github.com/olekukonko/tablewriter"
	"github.com/openconfig/gnsi/pathz"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func (a *App) InitPathzFlags(cmd *cobra.Command) {
	cmd.ResetFlags()
	//
	//
	cmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
		a.Config.FileConfig.BindPFlag(fmt.Sprintf("%s-%s", cmd.Name(), flag.Name), flag)
	})
}

func (a *App) InitPathzRotateFlags(cmd *cobra.Command) {
	cmd.ResetFlags()
	//
	cmd.Flags().BoolVar(&a.Config.PathzRotateForceOverwrite, "force", false, "force overwrite policy")
	cmd.Flags().StringVar(&a.Config.PathzRotateVersion, "version", "", "policy version")
	cmd.Flags().StringVar(&a.Config.PathzRotateCreatedOn, "created-on", "", "policy creation time")
	cmd.Flags().StringVar(&a.Config.PathzRotatePolicy, "policy", "", "policy definition as a JSON string")
	cmd.Flags().DurationVar(&a.Config.PathzRotateFinalizeAfter, "finalize-after", time.Second, "wait timer before sending a finalize request")
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
// https://github.com/openconfig/gnsi/blob/main/pathz/pathz.proto#L98
// quote: "The response is based on the instance of policy specified in the request"
// --> there is no reference to a policy in ProbeRequest: https://github.com/openconfig/gnsi/blob/main/pathz/pathz.proto#L183
// \1

func (a *App) RunEPathzRotate(cmd *cobra.Command, args []string) error {
	targets, err := a.GetTargets()
	if err != nil {
		return err
	}
	a.Logger.Infof("targets: %v", targets)
	numTargets := len(targets)
	responseChan := make(chan *TargetError, numTargets)
	a.wg.Add(numTargets)
	for _, t := range targets {
		go a.pathzRotateRequest(cmd.Context(), t, responseChan)
	}
	a.wg.Wait()
	close(responseChan)
	//
	errs := make([]error, 0, numTargets)
	// result := make([]*TargetError, 0, numTargets)
	for rsp := range responseChan {
		if rsp.Err != nil {
			wErr := fmt.Errorf("%q Pathz Probe failed: %v", rsp.TargetName, rsp.Err)
			a.Logger.Error(wErr)
			errs = append(errs, rsp.Err)
			continue
		}
		// result = append(result, rsp)
	}
	return a.handleErrs(errs)
}

func (a *App) pathzRotateRequest(ctx context.Context, t *api.Target, rspCh chan<- *TargetError) {
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

	rotateClient, err := t.NewPathzClient().Rotate(ctx)
	if err != nil {
		rspCh <- &TargetError{
			TargetName: t.Config.Address,
			Err:        err,
		}
		return
	}

	req, err := pathzapi.NewRotateRequest(
		pathzapi.ForceOverwrite(a.Config.LocalFlags.PathzRotateForceOverwrite),
		pathzapi.Version(a.Config.LocalFlags.PathzRotateVersion),
		pathzapi.CreatedOn(uint64(time.Now().UnixNano())),
		// TODO: add policy
		// pathzapi.Policy(a.Config.LocalFlags.PathzRotatePolicy),
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

	_, err = rotateClient.Recv()
	if err != nil {
		rspCh <- &TargetError{
			TargetName: t.Config.Address,
			Err:        err,
		}
		return
	}
	// switch rsp := rsp.(type) {
	// case *pathz.RotatePathzResponse_UploadResponse:
	// 	a.Logger.Infof("%q: got UploadResponse", t.Config.Name)
	// default:
	// 	rspCh <- &TargetError{
	// 		TargetName: t.Config.Address,
	// 		Err:        fmt.Errorf("unexpected message type %T: expecting RotatePathzResponse_UploadResponse", rsp),
	// 	}
	// }
	<-time.After(a.Config.LocalFlags.PathzRotateFinalizeAfter)

	req, err = pathzapi.NewRotateRequest(pathzapi.FinalizeRotation())
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

// Pathz Probe

func (a *App) InitPathzProbeFlags(cmd *cobra.Command) {
	cmd.ResetFlags()
	//
	cmd.Flags().StringVar(&a.Config.PathzProbeUser, "user", "", "The user name to be used to perform the evaluation.")
	cmd.Flags().StringVar(&a.Config.PathzProbeRPC, "rpc", "",
		"The gRPC RPC name to be used to perform the evaluation. It has to be a fully qualified name, like: \"/gnsi.ssh.Ssh/MutateHostCredentials\"")
	//
	cmd.LocalFlags().VisitAll(func(flag *pflag.Flag) {
		a.Config.FileConfig.BindPFlag(fmt.Sprintf("%s-%s", cmd.Name(), flag.Name), flag)
	})
}

type pathzProbeResponse struct {
	TargetError
	rsp *pathz.ProbeResponse
}

func (r *pathzProbeResponse) Target() string {
	return r.TargetName
}

func (r *pathzProbeResponse) Response() any {
	return r.rsp
}

func (a *App) RunEPathzProbe(cmd *cobra.Command, args []string) error {
	targets, err := a.GetTargets()
	if err != nil {
		return err
	}
	a.Logger.Infof("targets: %v", targets)
	numTargets := len(targets)
	responseChan := make(chan *pathzProbeResponse, numTargets)
	a.wg.Add(numTargets)
	for _, t := range targets {
		go a.pathzProbeRequest(cmd.Context(), t, responseChan)
	}
	a.wg.Wait()
	close(responseChan)
	//
	errs := make([]error, 0, numTargets)
	result := make([]TargetResponse, 0, numTargets)
	for rsp := range responseChan {
		if rsp.Err != nil {
			wErr := fmt.Errorf("%q Pathz Probe failed: %v", rsp.TargetName, rsp.Err)
			a.Logger.Error(wErr)
			errs = append(errs, rsp.Err)
			continue
		}
		result = append(result, rsp)
		a.printProtoMsg(rsp.TargetName, rsp.rsp)
	}
	a.printCMDOutput(result, a.pathzProbePrintFn)
	return a.handleErrs(errs)
}

func (a *App) pathzProbeRequest(ctx context.Context, t *api.Target, rspCh chan<- *pathzProbeResponse) {
	defer a.wg.Done()
	ctx = t.AppendMetadata(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	err := t.CreateGrpcClient(ctx, a.createBaseDialOpts()...)
	if err != nil {
		rspCh <- &pathzProbeResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	defer t.Close()
	req, err := pathzapi.NewProbeRequest(
		pathzapi.User(a.Config.LocalFlags.PathzProbeUser),
		pathzapi.RPC(a.Config.LocalFlags.PathzProbeRPC),
	)
	if err != nil {
		rspCh <- &pathzProbeResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	a.printProtoMsg(t.Config.Name, req)
	rsp, err := t.NewPathzClient().Probe(ctx, req)
	rspCh <- &pathzProbeResponse{
		TargetError: TargetError{
			TargetName: t.Config.Address,
			Err:        err,
		},
		rsp: rsp,
	}
}

func (a *App) pathzProbePrintFn(rsps []TargetResponse) string {
	tabData := make([][]string, 0, len(rsps))
	sort.Slice(rsps, func(i, j int) bool {
		return rsps[i].Target() < rsps[j].Target()
	})
	for _, rsp := range rsps {
		switch r := rsp.Response().(type) {
		case *pathzProbeResponse:
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

// Pathz Get

func (a *App) InitPathzGetFlags(cmd *cobra.Command) {
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

type pathzGetResponse struct {
	TargetError
	rsp *pathz.GetResponse
}

func (r *pathzGetResponse) Target() string {
	return r.TargetName
}

func (r *pathzGetResponse) Response() any {
	return r.rsp
}

func (a *App) RunEPathzGet(cmd *cobra.Command, args []string) error {
	targets, err := a.GetTargets()
	if err != nil {
		return err
	}
	a.Logger.Infof("targets: %v", targets)
	numTargets := len(targets)
	responseChan := make(chan *pathzGetResponse, numTargets)
	a.wg.Add(numTargets)
	for _, t := range targets {
		go a.pathzGetRequest(cmd.Context(), t, responseChan)
	}
	a.wg.Wait()
	close(responseChan)
	//
	errs := make([]error, 0, numTargets)
	result := make([]TargetResponse, 0, numTargets)
	for rsp := range responseChan {
		if rsp.Err != nil {
			wErr := fmt.Errorf("%q Pathz Get failed: %v", rsp.TargetName, rsp.Err)
			a.Logger.Error(wErr)
			errs = append(errs, rsp.Err)
			continue
		}
		result = append(result, rsp)
		a.printProtoMsg(rsp.TargetName, rsp.rsp)
	}
	a.printCMDOutput(result, a.pathzGetPrintFn)
	return a.handleErrs(errs)
}

func (a *App) pathzGetRequest(ctx context.Context, t *api.Target, rspCh chan<- *pathzGetResponse) {
	defer a.wg.Done()
	ctx = t.AppendMetadata(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	err := t.CreateGrpcClient(ctx, a.createBaseDialOpts()...)
	if err != nil {
		rspCh <- &pathzGetResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	defer t.Close()

	req := &pathz.GetRequest{}
	rsp, err := t.NewPathzClient().Get(ctx, req)
	rspCh <- &pathzGetResponse{
		TargetError: TargetError{
			TargetName: t.Config.Address,
			Err:        err,
		},
		rsp: rsp,
	}
}

func (a *App) pathzGetPrintFn(rsps []TargetResponse) string {
	tabData := make([][]string, 0, len(rsps))
	sort.Slice(rsps, func(i, j int) bool {
		return rsps[i].Target() < rsps[j].Target()
	})
	for _, rsp := range rsps {
		switch r := rsp.Response().(type) {
		case *pathzGetResponse:
			tabData = append(tabData, []string{
				rsp.Target(),
				r.rsp.GetVersion(),
				fmt.Sprintf("%d", r.rsp.GetCreatedOn()),
				r.rsp.GetPolicy().String(),
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
