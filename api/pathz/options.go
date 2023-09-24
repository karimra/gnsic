package pathz

import (
	"fmt"

	"github.com/karimra/gnsic/api"
	pathzpb "github.com/openconfig/gnsi/pathz"
	"google.golang.org/protobuf/proto"
)

func ForceOverwrite(b bool) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *pathzpb.RotateRequest:
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
		case *pathzpb.RotateRequest:
			if msg.RotateRequest == nil {
				msg.RotateRequest = &pathzpb.RotateRequest_UploadRequest{}
			}
			msg.GetUploadRequest().Version = v
		case *pathzpb.ProbeResponse:
			msg.Version = v
		case *pathzpb.GetResponse:
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
		case *pathzpb.RotateRequest:
			if msg.RotateRequest == nil {
				msg.RotateRequest = &pathzpb.RotateRequest_UploadRequest{}
			}
			msg.GetUploadRequest().CreatedOn = ts
		case *pathzpb.GetResponse:
			msg.CreatedOn = ts
		default:
			return fmt.Errorf("option CreatedOn: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

// TODO:
func Policy(opts ...api.GNSIOption) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}

		switch msg := msg.ProtoReflect().Interface().(type) {
		case *pathzpb.RotateRequest:
			if msg.RotateRequest == nil {
				msg.RotateRequest = &pathzpb.RotateRequest_UploadRequest{
					UploadRequest: &pathzpb.UploadRequest{},
				}
			}
			authPol := &pathzpb.AuthorizationPolicy{}
			err := api.Apply(authPol, opts...)
			if err != nil {
				return err
			}
			msg.GetUploadRequest().Policy = authPol
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
		case *pathzpb.RotateRequest:
			msg.RotateRequest = &pathzpb.RotateRequest_FinalizeRotation{}
		default:
			return fmt.Errorf("option FinalizeRotation: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}

// func UploadResponse() func(m proto.Message) error {
// 	return func(msg proto.Message) error {
// 		if msg == nil {
// 			return api.ErrInvalidMsgType
// 		}
// 		switch msg := msg.ProtoReflect().Interface().(type) {
// 		case *pathzpb.RotateResponse:
// 			// msg.RotatePathzResponse = &pathzpb.RotateResponse_UploadResponse{}
// 		default:
// 			return fmt.Errorf("option UploadResponse: %w: %T", api.ErrInvalidMsgType, msg)
// 		}
// 		return nil
// 	}
// }

func User(u string) func(m proto.Message) error {
	return func(msg proto.Message) error {
		if msg == nil {
			return api.ErrInvalidMsgType
		}
		switch msg := msg.ProtoReflect().Interface().(type) {
		case *pathzpb.ProbeRequest:
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
		case *pathzpb.ProbeRequest:
			// msg.Rpc = rpc
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
		case *pathzpb.ProbeResponse:
			msg.Action = pathzpb.Action(a)
		default:
			return fmt.Errorf("option Action: %w: %T", api.ErrInvalidMsgType, msg)
		}
		return nil
	}
}
