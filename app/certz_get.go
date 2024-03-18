package app

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/karimra/gnsic/api"
	certzapi "github.com/karimra/gnsic/api/certz"
	"github.com/olekukonko/tablewriter"
	certz "github.com/openconfig/gnsi/certz"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func (a *App) InitCertzGetProfileFlags(cmd *cobra.Command) {
	cmd.ResetFlags()
	//
	cmd.LocalFlags().VisitAll(func(flag *pflag.Flag) {
		a.Config.FileConfig.BindPFlag(fmt.Sprintf("%s-%s", cmd.Name(), flag.Name), flag)
	})
}

type getProfileResponse struct {
	TargetError
	rsp *certz.GetProfileListResponse
}

func (r *getProfileResponse) Target() string {
	return r.TargetName
}

func (r *getProfileResponse) Response() any {
	return r.rsp
}

func (a *App) RunECertzGetProfile(cmd *cobra.Command, args []string) error {
	targets, err := a.GetTargets()
	if err != nil {
		return err
	}
	a.Logger.Debugf("targets: %v", targets)
	numTargets := len(targets)
	responseChan := make(chan *getProfileResponse, numTargets)
	a.wg.Add(numTargets)
	for _, t := range targets {
		go a.certzGetProfileListRequest(cmd.Context(), t, responseChan)
	}
	a.wg.Wait()
	close(responseChan)
	//
	errs := make([]error, 0, numTargets)
	result := make([]TargetResponse, 0, numTargets)
	for rsp := range responseChan {
		if rsp.Err != nil {
			wErr := fmt.Errorf("%q Certz GetProfileListRequest failed: %v", rsp.TargetName, rsp.Err)
			a.Logger.Error(wErr)
			errs = append(errs, rsp.Err)
			continue
		}
		result = append(result, rsp)
		a.printProtoMsg(rsp.TargetName, rsp.rsp)
	}
	a.printCMDOutput(result, a.getProfileListPrintFn)
	return a.handleErrs(errs)
}

func (a *App) certzGetProfileListRequest(ctx context.Context, t *api.Target, rspCh chan<- *getProfileResponse) {
	defer a.wg.Done()
	ctx = t.AppendMetadata(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	err := t.CreateGrpcClient(ctx, a.createBaseDialOpts()...)
	if err != nil {
		rspCh <- &getProfileResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	defer t.Close()

	req, err := certzapi.NewGetProfileListRequest()
	if err != nil {
		rspCh <- &getProfileResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	rsp, err := t.NewCertzClient().GetProfileList(ctx, req)
	rspCh <- &getProfileResponse{
		TargetError: TargetError{
			TargetName: t.Config.Address,
			Err:        err,
		},
		rsp: rsp,
	}
}

func (a *App) getProfileListPrintFn(rsps []TargetResponse) string {
	tabData := make([][]string, 0, len(rsps))
	sort.Slice(rsps, func(i, j int) bool {
		return rsps[i].Target() < rsps[j].Target()
	})
	for _, rsp := range rsps {
		switch r := rsp.Response().(type) {
		case *certz.GetProfileListResponse:
			for _, sslProfID := range r.GetSslProfileIds() {
				tabData = append(tabData, []string{
					rsp.Target(),
					sslProfID,
				})
			}
		default:
			a.Logger.Printf("%s: unexpected message type: %T", rsp.Target(), rsp.Response())
		}
	}
	sort.Slice(tabData, func(i, j int) bool {
		return tabData[i][0] < tabData[j][0]
	})
	b := new(bytes.Buffer)
	table := tablewriter.NewWriter(b)
	table.SetHeader([]string{"Target Name", "SSL Profile ID(s)"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoFormatHeaders(false)
	table.SetAutoWrapText(false)
	table.SetAutoMergeCellsByColumnIndex([]int{0}) // merge vals of first column only
	table.AppendBulk(tabData)
	table.Render()
	return b.String()
}
