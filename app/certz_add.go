package app

import (
	"context"
	"fmt"

	"github.com/karimra/gnsic/api"
	certzapi "github.com/karimra/gnsic/api/certz"
	certz "github.com/openconfig/gnsi/certz"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func (a *App) InitCertzAddProfileFlags(cmd *cobra.Command) {
	cmd.ResetFlags()
	//
	cmd.Flags().StringVar(&a.Config.CertzAddProfileID, "id", "", "SSL profile ID to be added")
	//
	cmd.LocalFlags().VisitAll(func(flag *pflag.Flag) {
		a.Config.FileConfig.BindPFlag(fmt.Sprintf("%s-%s", cmd.Name(), flag.Name), flag)
	})
}

type addProfileResponse struct {
	TargetError
	rsp *certz.AddProfileResponse
}

func (r *addProfileResponse) Target() string {
	return r.TargetName
}

func (r *addProfileResponse) Response() any {
	return r.rsp
}

func (a *App) RunECertzAddProfile(cmd *cobra.Command, args []string) error {
	targets, err := a.GetTargets()
	if err != nil {
		return err
	}
	a.Logger.Debugf("targets: %v", targets)
	numTargets := len(targets)
	responseChan := make(chan *addProfileResponse, numTargets)
	a.wg.Add(numTargets)
	for _, t := range targets {
		go a.certzAddProfileRequest(cmd.Context(), t, responseChan)
	}
	a.wg.Wait()
	close(responseChan)
	//
	errs := make([]error, 0, numTargets)
	for rsp := range responseChan {
		if rsp.Err != nil {
			wErr := fmt.Errorf("%q Certz AddProfileRequest failed: %v", rsp.TargetName, rsp.Err)
			a.Logger.Error(wErr)
			errs = append(errs, rsp.Err)
			continue
		}
		a.printProtoMsg(rsp.TargetName, rsp.rsp)
		a.Logger.Infof("%s: added profile %q", rsp.TargetName, a.Config.CertzAddProfileID)
	}
	return a.handleErrs(errs)
}

func (a *App) certzAddProfileRequest(ctx context.Context, t *api.Target, rspCh chan<- *addProfileResponse) {
	defer a.wg.Done()
	ctx = t.AppendMetadata(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	err := t.CreateGrpcClient(ctx, a.createBaseDialOpts()...)
	if err != nil {
		rspCh <- &addProfileResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	defer t.Close()

	req, err := certzapi.NewAddProfileRequest(
		certzapi.SSLProfileID(a.Config.CertzAddProfileID),
	)
	if err != nil {
		rspCh <- &addProfileResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	rsp, err := t.NewCertzClient().AddProfile(ctx, req)
	rspCh <- &addProfileResponse{
		TargetError: TargetError{
			TargetName: t.Config.Address,
			Err:        err,
		},
		rsp: rsp,
	}
}
