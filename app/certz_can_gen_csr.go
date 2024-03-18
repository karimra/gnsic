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

// Can generate CSR
func (a *App) InitCertzCanGenerateCSRFlags(cmd *cobra.Command) {
	cmd.ResetFlags()
	//
	cmd.Flags().StringVar(&a.Config.CertzCanGenCSRCSRSuite, "csr-suite", "", "the CSR suite. Format: '<certificate type>_<key type>_<signature algorithm>'")
	cmd.Flags().StringVar(&a.Config.CertzCanGenCSRCommonName, "cn", "", "common name")
	cmd.Flags().StringVar(&a.Config.CertzCanGenCSRCountry, "country", "", "country name")
	cmd.Flags().StringVar(&a.Config.CertzCanGenCSRState, "state", "", "state name")
	cmd.Flags().StringVar(&a.Config.CertzCanGenCSRCity, "city", "", "city name")
	cmd.Flags().StringVar(&a.Config.CertzCanGenCSROrg, "org", "", "organization name")
	cmd.Flags().StringVar(&a.Config.CertzCanGenCSROrgUnit, "org-unit", "", "organizational unit name")
	cmd.Flags().StringVar(&a.Config.CertzCanGenCSRIPAddress, "ip-address", "", "IP address")
	cmd.Flags().StringVar(&a.Config.CertzCanGenCSREmailID, "email-id", "", "email ID")
	// sans
	cmd.Flags().StringArrayVar(&a.Config.CertzCanGenCSRSanDNS, "dns", nil, "SAN DNS name(s)")
	cmd.Flags().StringArrayVar(&a.Config.CertzCanGenCSRSanEmail, "san-email-id", nil, "SAN Email ID(s)")
	cmd.Flags().StringArrayVar(&a.Config.CertzCanGenCSRSanIP, "san-ip-address", nil, "SAN IP address(es)")
	cmd.Flags().StringArrayVar(&a.Config.CertzCanGenCSRSanURI, "san-uri", nil, "SAN URI(s)")
	//
	cmd.LocalFlags().VisitAll(func(flag *pflag.Flag) {
		a.Config.FileConfig.BindPFlag(fmt.Sprintf("%s-%s", cmd.Name(), flag.Name), flag)
	})
}

type canGenCSRResponse struct {
	TargetError
	rsp *certz.CanGenerateCSRResponse
}

func (r *canGenCSRResponse) Target() string {
	return r.TargetName
}

func (r *canGenCSRResponse) Response() any {
	return r.rsp
}

func (a *App) RunECertzCanGenerateCSR(cmd *cobra.Command, args []string) error {
	// validate input
	if a.Config.CertzCanGenCSRCSRSuite != "" {
		if _, ok := certz.CSRSuite_value[a.Config.CertzCanGenCSRCSRSuite]; !ok {
			return fmt.Errorf("unknown CSR suite: %s", a.Config.CertzCanGenCSRCSRSuite)
		}
	}
	targets, err := a.GetTargets()
	if err != nil {
		return err
	}
	a.Logger.Debugf("targets: %v", targets)
	numTargets := len(targets)
	responseChan := make(chan *canGenCSRResponse, numTargets)
	a.wg.Add(numTargets)
	for _, t := range targets {
		go a.certzCanGenCSRRequest(cmd.Context(), t, responseChan)
	}
	a.wg.Wait()
	close(responseChan)
	//
	errs := make([]error, 0, numTargets)
	result := make([]TargetResponse, 0, numTargets)
	for rsp := range responseChan {
		if rsp.Err != nil {
			wErr := fmt.Errorf("%q Certz CanGenerateCSR failed: %v", rsp.TargetName, rsp.Err)
			a.Logger.Error(wErr)
			errs = append(errs, rsp.Err)
			continue
		}
		result = append(result, rsp)
		a.printProtoMsg(rsp.TargetName, rsp.rsp)
	}
	a.printCMDOutput(result, a.certzCanGenerateCSRPrintFn)
	return a.handleErrs(errs)
}

func (a *App) certzCanGenCSRRequest(ctx context.Context, t *api.Target, rspCh chan<- *canGenCSRResponse) {
	defer a.wg.Done()
	ctx = t.AppendMetadata(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	a.Logger.Debugf("%s: creating a gRPC client", t.Config.Name)
	err := t.CreateGrpcClient(ctx, a.createBaseDialOpts()...)
	if err != nil {
		rspCh <- &canGenCSRResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}
	defer t.Close()
	req, err := certzapi.NewCanGenerateCSRRequest(a.canGenCSRRequestOpts()...)
	if err != nil {
		rspCh <- &canGenCSRResponse{
			TargetError: TargetError{
				TargetName: t.Config.Address,
				Err:        err,
			},
		}
		return
	}

	a.Logger.Debugf("%s: sending CanGenerateCSR", t.Config.Name)
	rsp, err := t.NewCertzClient().CanGenerateCSR(ctx, req)
	rspCh <- &canGenCSRResponse{
		TargetError: TargetError{
			TargetName: t.Config.Address,
			Err:        err,
		},
		rsp: rsp,
	}
}

func (a *App) canGenCSRRequestOpts() []api.GNSIOption {
	// these are the options that will go into CSRParams
	opts := make([]api.GNSIOption, 0, 1)

	if a.Config.CertzCanGenCSRCSRSuite != "" {
		// should be already validated
		if i, ok := certz.CSRSuite_value[a.Config.CertzCanGenCSRCSRSuite]; ok {
			opts = append(opts, certzapi.CSRSuite(i))
		}
	}
	opts = append(opts,
		certzapi.CommonName(a.Config.CertzCanGenCSRCommonName),
		certzapi.Country(a.Config.CertzCanGenCSRCountry),
		certzapi.State(a.Config.CertzCanGenCSRState),
		certzapi.City(a.Config.CertzCanGenCSRCity),
		certzapi.Org(a.Config.CertzCanGenCSROrg),
		certzapi.OrgUnit(a.Config.CertzCanGenCSROrgUnit),
		certzapi.IPAddress(a.Config.CertzCanGenCSRIPAddress),
		certzapi.EmailID(a.Config.CertzCanGenCSREmailID),
		certzapi.V3ExtensionSAN(
			certzapi.DNS(a.Config.CertzCanGenCSRSanDNS...),
			certzapi.Emails(a.Config.CertzCanGenCSRSanEmail...),
			certzapi.IPs(a.Config.CertzCanGenCSRSanIP...),
			certzapi.URIs(a.Config.CertzCanGenCSRSanURI...),
		),
	)

	//
	return []api.GNSIOption{
		certzapi.CSRParams(opts...),
	}
}

func (a *App) certzCanGenerateCSRPrintFn(rsps []TargetResponse) string {
	tabData := make([][]string, 0, len(rsps))
	sort.Slice(rsps, func(i, j int) bool {
		return rsps[i].Target() < rsps[j].Target()
	})
	for _, rsp := range rsps {
		switch r := rsp.Response().(type) {
		case *certz.CanGenerateCSRResponse:
			tabData = append(tabData, []string{
				rsp.Target(),
				fmt.Sprintf("%t", r.GetCanGenerate()),
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
	table.SetHeader([]string{"Target Name", "Can Generate CSR"})
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoFormatHeaders(false)
	table.SetAutoWrapText(false)
	table.AppendBulk(tabData)
	table.Render()
	return b.String()
}
