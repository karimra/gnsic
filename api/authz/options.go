package authz

import (
	"fmt"

	"github.com/karimra/gnsic/api"
	authzpb "github.com/openconfig/gnsi/authz"
	"google.golang.org/protobuf/proto"
	// v3rbacpb "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
)

func ForceOverwrite(b bool) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *authzpb.RotateAuthzRequest:
			msg.ForceOverwrite = b
		default:
			return fmt.Errorf("option ForceOverwrite: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func Version(v string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *authzpb.RotateAuthzRequest:
			if msg.RotateRequest == nil {
				msg.RotateRequest = &authzpb.RotateAuthzRequest_UploadRequest{
					UploadRequest: &authzpb.UploadRequest{},
				}
			}
			msg.GetUploadRequest().Version = v
		case *authzpb.ProbeResponse:
			msg.Version = v
		case *authzpb.GetResponse:
			msg.Version = v
		default:
			return fmt.Errorf("option Version: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func CreatedOn(ts uint64) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *authzpb.RotateAuthzRequest:
			if msg.RotateRequest == nil {
				msg.RotateRequest = &authzpb.RotateAuthzRequest_UploadRequest{}
			}
			msg.GetUploadRequest().CreatedOn = ts
		case *authzpb.GetResponse:
			msg.CreatedOn = ts
		default:
			return fmt.Errorf("option CreatedOn: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func Policy(p string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *authzpb.RotateAuthzRequest:
			if msg.RotateRequest == nil {
				msg.RotateRequest = &authzpb.RotateAuthzRequest_UploadRequest{}
			}
			msg.GetUploadRequest().Policy = p
		case *authzpb.GetResponse:
			msg.Policy = p
		default:
			return fmt.Errorf("option Policy: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func FinalizeRotation() func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *authzpb.RotateAuthzRequest:
			msg.RotateRequest = &authzpb.RotateAuthzRequest_FinalizeRotation{}
		default:
			return fmt.Errorf("option FinalizeRotation: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func UploadResponse() func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *authzpb.RotateAuthzResponse:
			msg.RotateResponse = &authzpb.RotateAuthzResponse_UploadResponse{}
		default:
			return fmt.Errorf("option UploadResponse: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func User(u string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *authzpb.ProbeRequest:
			msg.User = u
		default:
			return fmt.Errorf("option User: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func RPC(rpc string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *authzpb.ProbeRequest:
			msg.Rpc = rpc
		default:
			return fmt.Errorf("option RPC: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

func Action(a int32) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *authzpb.ProbeResponse:
			msg.Action = authzpb.ProbeResponse_Action(a)
		default:
			return fmt.Errorf("option Action: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}
