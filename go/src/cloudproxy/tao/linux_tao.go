package tao

import (
	"net/rpc"
)

type LinuxTao struct {
	parent rpc.Client
}

func (tao *LinuxTao) Init() (err error) {
	return
}

func (tao *LinuxTao) Destroy() (err error) {
	return
}

// func (tao *LinuxTao) GetRandomBytes(bytes []byte) (err error) {

// }
