package tao

import (
	"cloudproxy/util"
	"cloudproxy/util/protorpc"
	"code.google.com/p/goprotobuf/proto"
	"errors"
	"math"
	"net/rpc"
	"strings"
)

var op_rpc_name = map[string]string{
		"Tao.GetRandomBytes": "TAO_RPC_GET_RANDOM_BYTES",
		"Tao.Seal": "TAO_RPC_SEAL",
		"Tao.Unseal": "TAO_RPC_UNSEAL",
		"Tao.Attest": "TAO_RPC_ATTEST",
		"Tao.GetTaoName": "TAO_RPC_GET_TAO_NAME",
		"Tao.ExtendTaoName": "TAO_RPC_EXTEND_TAO_NAME",
		"Tao.GetSharedSecret": "TAO_RPC_GET_SHARED_SECRET",
}

var op_go_name = make(map[string]string)

func init() {
	for go_name, rpc_name := range op_rpc_name{
			op_go_name[rpc_name] = go_name
	}
}

// Convert string "Tao.FooBar" into integer TaoRPCOperation_TAO_RPC_FOO_BAR.
func goToRPC(m string) (TaoRPCOperation, error) {
	op := TaoRPCOperation(TaoRPCOperation_value[op_rpc_name[m]])
	if op == TaoRPCOperation(0) {
		return op, protorpc.ErrBadRequestType
	}
	return op, nil
}

// Convert integer TaoRPCOperation_TAO_RPC_FOO_BAR into string "Tao.FooBar".
func rpcToGo(op TaoRPCOperation) (string, error) {
	s := op_go_name[TaoRPCOperation_name[int32(op)]]
	if s == "" {
		return "", protorpc.ErrBadRequestType
	}
	return s, nil
}

type taoMux struct{}

func (taoMux) SetRequestHeader(req proto.Message, servicemethod string, seq uint64) error {
	m, ok := req.(*TaoRPCRequest)
	if !ok || m == nil {
		return protorpc.ErrBadRequestType
	}
	rpc, err := goToRPC(servicemethod)
	if err != nil {
		return err
	}
	m.Rpc = &rpc
	m.Seq = &seq
	return nil
}

func (taoMux) SetResponseHeader(req proto.Message, servicemethod string, seq uint64) error {
	m, ok := req.(*TaoRPCResponse)
	if !ok || m == nil {
		return protorpc.ErrBadResponseType
	}
	rpc, err := goToRPC(servicemethod)
	if err != nil {
		return err
	}
	m.Rpc = &rpc
	m.Seq = &seq
	return nil
}

func (taoMux) GetServiceMethod(number uint64) (string, error) {
	return rpcToGo(TaoRPCOperation(int32(number)))
}

// TaoRPC sends requests between this hosted program and the host Tao.
type TaoRPC struct {
	rpc *rpc.Client
}

func DeserializeTaoRPC(s string) (*TaoRPC, error) {
	if s == "" {
		return nil, errors.New("Missing host Tao spec. " +
			"Make sure $" + HostTaoEnvVar +" is set.")
	}
	r := strings.TrimPrefix(s, "tao::TaoRPC+")
	if r == s {
		return nil, errors.New("Unrecognized $" + HostTaoEnvVar + " string: " + s)
	}
	ms, err := util.DeserializeFDMessageStream(r)
	if err != nil {
		return nil, errors.New("Unrecognized $" + HostTaoEnvVar + " string: " + s +
			" (" + err.Error() + ")")
	}
	return &TaoRPC{protorpc.NewClient(ms, taoMux{})}, nil
}

type expectedResponse int

const (
	wantNothing = 0
	wantData expectedResponse = 1 << iota
	wantPolicy
)

var ErrMalformedResponse = errors.New("tao rpc: malformed response")

func (t *TaoRPC) call(method string, r *TaoRPCRequest, e expectedResponse) (data []byte, policy string, err error) {
  s := new(TaoRPCResponse)
  err = t.rpc.Call(method, r, s)
  if err != nil {
    return
  }
	if s.Error != nil {
		err = errors.New(*s.Error)
		return
	}
	if (s.Data != nil) != (e&wantData != 0) ||
			(s.Policy != nil) != (e&wantPolicy != 0) {
		err = ErrMalformedResponse
		return
	}
	if s.Data != nil {
		data = s.Data
	}
	if s.Policy != nil {
		policy = *s.Policy
	}
	return
}

func (t *TaoRPC) GetTaoName() (string, error) {
  r := &TaoRPCRequest{}
	data, _, err := t.call("Tao.GetTaoName", r, wantData)
	return string(data), err
}

func (t *TaoRPC) ExtendTaoName(subprin string) (error) {
	r := &TaoRPCRequest{Data: []byte(subprin)}
	_, _, err := t.call("Tao.ExtendTaoName", r, wantNothing)
	return err
}

func (t *TaoRPC) GetRandomBytes(n int) ([]byte, error) {
	if n > math.MaxUint32 {
		return nil, errors.New("Request for too many random bytes")
	}
	r := &TaoRPCRequest{Size: proto.Int32(int32(n))}
	bytes, _, err := t.call("Tao.GetRandomBytes", r, wantData)
	return bytes, err
}

func (t *TaoRPC) GetSharedSecret(n int, policy string) ([]byte, error) {
	if n > math.MaxUint32 {
		return nil, errors.New("Request for too many secret bytes")
	}
	r := &TaoRPCRequest{Size: proto.Int32(int32(n)), Policy: proto.String(policy)}
	bytes, _, err := t.call("Tao.GetSharedSecret", r, wantData)
	return bytes, err
}

func (t *TaoRPC) Attest(stmt *Statement) (*Attestation, error) {
	data, err := proto.Marshal(stmt)
	if _, ok := err.(*proto.RequiredNotSetError); err != nil && !ok {
		return nil, err
	}
	r := &TaoRPCRequest{Data: data}
	bytes, _, err := t.call("Tao.Attest", r, wantData)
	if err != nil {
		return nil, err
	}
	var a Attestation
	err = proto.Unmarshal(bytes, &a)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (t *TaoRPC) Seal(data []byte, policy string) (sealed []byte, err error) {
	r := &TaoRPCRequest{Data: data, Policy: proto.String(policy)}
	sealed, _, err = t.call("Tao.Seal", r, wantData)
	return
}

func (t *TaoRPC) Unseal(sealed []byte) (data []byte, policy string, err error) {
	r := &TaoRPCRequest{Data: sealed}
	data, policy, err = t.call("Tao.Unseal", r, wantData | wantPolicy)
	return
}
