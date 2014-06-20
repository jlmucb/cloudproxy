package tao

import (
	"errors"
)

type TaoServer struct {
	T Tao
}

func (ts *TaoServer) GetRandomBytes(r *TaoRPCRequest, s *TaoRPCResponse) error {
	if r.GetRpc() != TaoRPCOperation_TAO_RPC_GET_RANDOM_BYTES {
		return errors.New("wrong RPC type")
	}

	if r.GetSize() <= 0 {
		return errors.New("Invalid array size")
	}

	s.Data = make([]byte, r.GetSize())
	return ts.T.GetRandomBytes(s.GetData())
}
