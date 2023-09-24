package pathz

import (
	"github.com/karimra/gnsic/api"
	pathzpb "github.com/openconfig/gnsi/pathz"
)

func NewRotateRequest(opts ...api.GNSIOption) (*pathzpb.RotateRequest, error) {
	m := new(pathzpb.RotateRequest)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func NewRotateAuthzResponse(opts ...api.GNSIOption) (*pathzpb.RotateResponse, error) {
	m := new(pathzpb.RotateResponse)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func NewProbeRequest(opts ...api.GNSIOption) (*pathzpb.ProbeRequest, error) {
	m := new(pathzpb.ProbeRequest)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func NewProbeResponse(opts ...api.GNSIOption) (*pathzpb.ProbeResponse, error) {
	m := new(pathzpb.ProbeResponse)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func NewGetRequest(opts ...api.GNSIOption) (*pathzpb.GetRequest, error) {
	m := new(pathzpb.GetRequest)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func NewGetResponse(opts ...api.GNSIOption) (*pathzpb.GetResponse, error) {
	m := new(pathzpb.GetResponse)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}
