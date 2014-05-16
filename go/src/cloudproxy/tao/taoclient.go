package tao

import (
	"net/rpc"
)

// TaoClient implements the Tao and passes on calls to a parent Tao across an
// RPC channel.
type TaoClient struct {
	Parent rpc.Client
	HostedProgramHash []byte
}

// func (t *TaoClient) Init() (err error) {
	// err = t.Parent.Call("Tao.Init")
	// return
// }

// func (t *TaoClient) Destroy() (err error) {
	// err = t.Parent.Call("Tao.Destroy")
	// return
// }

// func (t *TaoClient) GetRandomBytes(bytes []byte) (err error) {
	// err = t.Parent.Call("Tao.GetRandomBytes", bytes)
	// return
// }

// func (t *TaoClient) Seal(data []byte) (sealed []byte, err error) {
	// sealed, err = t.Parent.Call("Tao.Seal", t.HostedProgramHash, data)
	// return
// }
