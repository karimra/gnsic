package certz

import (
	"github.com/karimra/gnsic/api"
	certzpb "github.com/openconfig/gnsi/certz"
)

func NewRotateCertificateRequest(opts ...api.GNSIOption) (*certzpb.RotateCertificateRequest, error) {
	m := new(certzpb.RotateCertificateRequest)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func NewRotateCertificateResponse(opts ...api.GNSIOption) (*certzpb.RotateCertificateResponse, error) {
	m := new(certzpb.RotateCertificateResponse)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

//

func NewAddProfileRequest(opts ...api.GNSIOption) (*certzpb.AddProfileRequest, error) {
	m := new(certzpb.AddProfileRequest)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func NewAddProfileResponse(opts ...api.GNSIOption) (*certzpb.AddProfileResponse, error) {
	m := new(certzpb.AddProfileResponse)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

//

func NewDeleteProfileRequest(opts ...api.GNSIOption) (*certzpb.DeleteProfileRequest, error) {
	m := new(certzpb.DeleteProfileRequest)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func NewDeleteProfileResponse(opts ...api.GNSIOption) (*certzpb.DeleteProfileResponse, error) {
	m := new(certzpb.DeleteProfileResponse)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

//

func NewGetProfileListRequest(opts ...api.GNSIOption) (*certzpb.GetProfileListRequest, error) {
	m := new(certzpb.GetProfileListRequest)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func NewGetProfileListResponse(opts ...api.GNSIOption) (*certzpb.GetProfileListResponse, error) {
	m := new(certzpb.GetProfileListResponse)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

//

func NewCanGenerateCSRRequest(opts ...api.GNSIOption) (*certzpb.CanGenerateCSRRequest, error) {
	m := new(certzpb.CanGenerateCSRRequest)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func NewCanGenerateCSRResponse(opts ...api.GNSIOption) (*certzpb.CanGenerateCSRResponse, error) {
	m := new(certzpb.CanGenerateCSRResponse)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}
