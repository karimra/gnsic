package authz

import (
	"github.com/karimra/gnsic/api"
	authzpb "github.com/openconfig/gnsi/authz"
)

func NewRotateAuthzRequest(opts ...api.GNSIOption) (*authzpb.RotateAuthzRequest, error) {
	m := new(authzpb.RotateAuthzRequest)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func NewRotateAuthzResponse(opts ...api.GNSIOption) (*authzpb.RotateAuthzResponse, error) {
	m := new(authzpb.RotateAuthzResponse)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func NewProbeRequest(opts ...api.GNSIOption) (*authzpb.ProbeRequest, error) {
	m := new(authzpb.ProbeRequest)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func NewProbeResponse(opts ...api.GNSIOption) (*authzpb.ProbeResponse, error) {
	m := new(authzpb.ProbeResponse)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func NewGetRequest(opts ...api.GNSIOption) (*authzpb.GetRequest, error) {
	m := new(authzpb.GetRequest)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func NewGetResponse(opts ...api.GNSIOption) (*authzpb.GetResponse, error) {
	m := new(authzpb.GetResponse)
	err := api.Apply(m, opts...)
	if err != nil {
		return nil, err
	}
	return m, nil
}
