package tao

import (
	"net/rpc"

	"code.google.com/p/goprotobuf/proto"
)

// TaoClient implements the Tao and passes on calls to a parent Tao across an
// RPC channel.
type TaoClient struct {
	Parent            *rpc.Client
	HostedProgramHash []byte
}

func (t *TaoClient) GetRandomBytes(bytes []byte) (err error) {
	r := &TaoRPCRequest{
		Rpc:  new(TaoRPCOperation),
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

func (t *TaoClient) Seal(data, policy []byte) ([]byte, error) {
  rpcData := make([]byte, len(data))
  copy(rpcData, data)
  r := &TaoRPCRequest{
    Rpc: new(TaoRPCOperation),
    Data: rpcData,
    Policy: proto.String(string(policy)),
  }

  *r.Rpc = TaoRPCOperation_TAO_RPC_SEAL
  s := new(TaoRPCResponse)
  err := t.Parent.Call("TaoServer.Seal", r, s)
  if err != nil {
    return nil, err
  }

  sealed := make([]byte, len(s.Data))
  copy(sealed, s.Data)
  return sealed, nil
}

func (t *TaoClient) Unseal(sealed []byte) ([]byte, []byte, error) {
  rpcSealed := make([]byte, len(sealed))
  copy(rpcSealed, sealed)
  r := &TaoRPCRequest{
    Rpc: new(TaoRPCOperation),
    Data: rpcSealed,
  }

  *r.Rpc = TaoRPCOperation_TAO_RPC_UNSEAL

  s := new(TaoRPCResponse)
  err := t.Parent.Call("TaoServer.Unseal", r, s)
  if err != nil {
    return nil, nil, err
  }

  unsealed := make([]byte, len(s.Data))
  copy(unsealed, s.Data)

  return unsealed, []byte(*s.Policy), nil
}

func (t *TaoClient) Attest(stmt *Statement) (*Attestation, error) {
  stData, err := proto.Marshal(stmt)
  if err != nil {
    return nil, err
  }

  r := &TaoRPCRequest{
    Rpc: new(TaoRPCOperation),
    Data: stData,
  }

  *r.Rpc = TaoRPCOperation_TAO_RPC_ATTEST

  s := new(TaoRPCResponse)
  err = t.Parent.Call("TaoServer.Attest", r, s)
  if err != nil {
    return nil, err
  }

  a := new(Attestation)
  err = proto.Unmarshal(s.Data, a)
  if err != nil {
    return nil, err
  }

  return a, nil
}
