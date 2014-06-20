package tao

import (
	"net/rpc"

	"code.google.com/p/goprotobuf/proto"
)

// TaoClient implements the Tao and passes on calls to a parent Tao across an
// RPC channel.
type TaoClient struct {
	Parent *rpc.Client
	HostedProgramHash []byte
}

func (t *TaoClient) GetRandomBytes(bytes []byte) (err error) {
	r := &TaoRPCRequest {
		Rpc: new(TaoRPCOperation),
		Size: proto.Int32(int32(len(bytes))),
	}

	*r.Rpc = TaoRPCOperation_TAO_RPC_GET_RANDOM_BYTES
	s := new(TaoRPCResponse)
	err = t.Parent.Call("TaoServer.GetRandomBytes", r, s)
	if err != nil {
		return err
	}

	copy(bytes, s.Data)
	return nil
}
