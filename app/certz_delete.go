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

func (a *App) InitCertzDeleteProfileFlags(cmd *cobra.Command) {
	cmd.ResetFlags()
	//
	cmd.Flags().StringVar(&a.Config.CertzDeleteProfileID, "id", "", "SSL profile ID to be deleted")
	//
	cmd.LocalFlags().VisitAll(func(flag *pflag.Flag) {
		a.Config.FileConfig.BindPFlag(fmt.Sprintf("%s-%s", cmd.Name(), flag.Name), flag)
	})
}

type deleteProfileResponse struct {
	TargetError
	rsp *certz.DeleteProfileResponse
}

func (r *deleteProfileResponse) Target() string {
	return r.TargetName
}

func (r *deleteProfileResponse) Response() any {
	return r.rsp
}

func (a *App) RunECertzDeleteProfile(cmd *cobra.Command, args []string) error {
	targets, err := a.GetTargets()
	if err != nil {
		return err
	}
	a.Logger.Debugf("targets: %v", targets)
	numTargets := len(targets)
	responseChan := make(chan *deleteProfileResponse, numTargets)
	a.wg.Add(numTargets)
	for _, t := range targets {
		go a.certzDeleteProfileRequest(cmd.Context(), t, responseChan)
	}
	a.wg.Wait()
	close(responseChan)
	//
	errs := make([]error, 0, numTargets)
	for rsp := range responseChan {
		if rsp.Err != nil {
			wErr := fmt.Errorf("%q Certz DeleteProfileRequest failed: %v", rsp.TargetName, rsp.Err)
			a.Logger.Error(wErr)
			errs = append(errs, rsp.Err)
			continue
		}
		a.printProtoMsg(rsp.TargetName, rsp.rsp)
		a.Logger.Infof("%s: profile %q deleted", rsp.TargetName, a.Config.CertzDeleteProfileID)
	}
	return a.handleErrs(errs)
}

func (a *App) certzDeleteProfileRequest(ctx context.Context, t *api.Target, rspCh chan<- *deleteProfileResponse) {
	defer a.wg.Done()
	ctx = t.AppendMetadata(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	err := t.CreateGrpcClient(ctx, a.createBaseDialOpts()...)
	if err != nil {
		rspCh <- &deleteProfileResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	defer t.Close()

	req, err := certzapi.NewDeleteProfileRequest(
		certzapi.SSLProfileID(a.Config.CertzDeleteProfileID),
	)
	if err != nil {
		rspCh <- &deleteProfileResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	rsp, err := t.NewCertzClient().DeleteProfile(ctx, req)
	rspCh <- &deleteProfileResponse{
		TargetError: TargetError{
			TargetName: t.Config.Address,
			Err:        err,
		},
		rsp: rsp,
	}
}
