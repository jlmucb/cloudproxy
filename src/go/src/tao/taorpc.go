//  File: tao_rpc.go
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: RPC client stub for channel-based Tao implementations.
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tao

import (
	"code.google.com/p/goprotobuf/proto"
	"errors"
	"math"
	"strings"
)

// A class that sends Tao requests and responses over a channel between Tao
// hosts and Tao hosted programs.

type TaoRPC struct {
	mc *MessageChannel
	err string
}

func DeserializeTaoRPC(s string) *TaoRPC {
	r := strings.TrimPrefix(s, "tao::TaoRPC+")
	if r == s {
		return nil
	}
	mc := DeserializeMessageChannel(r)
	if mc == nil {
		return nil
	}
	return &TaoRPC{mc, ""}
}

func (rpc *TaoRPC) request(req *TaoRPCRequest, data *[]byte, policy *string) error {
	err := rpc.mc.SendMessage(req)
	if err != nil {
		rpc.err = err.Error()
		return err
	}
	resp := new(TaoRPCResponse)
	err = rpc.mc.ReceiveMessage(resp)
	if err != nil {
		rpc.err = err.Error()
		return err
	}
	if !resp.GetSuccess() {
		if resp.GetReason() != "" {
			rpc.err = *resp.Reason
		} else {
			rpc.err = "Unknown failure at Tao Host"
		}
		return errors.New(rpc.err)
	}
	if data != nil {
		if resp.Data == nil {
			rpc.err = "Malformed response (missing data)"
			return errors.New(rpc.err)
		}
		*data = resp.Data
	}
	if policy != nil {
		if resp.Policy == nil {
			rpc.err = "Malformed response (missing policy)"
			return errors.New(rpc.err)
		}
		*policy = *resp.Policy
	}
	return nil
}

func (rpc *TaoRPC) GetTaoName() (name string, err error) {
	req := new(TaoRPCRequest)
	op := TaoRPCOperation_TAO_RPC_GET_TAO_NAME
	req.Rpc = &op
	var data []byte
	err = rpc.request(req, &data, nil /* policy */)
	if err == nil {
		name = string(data)
	}
	return
}

func (rpc *TaoRPC) ExtendTaoName(subprin string) error {
	req := new(TaoRPCRequest)
	op := TaoRPCOperation_TAO_RPC_EXTEND_TAO_NAME
	req.Rpc = &op
	req.Data = []byte(subprin)
	return rpc.request(req, nil /* data */, nil /* policy */)
}

func (rpc *TaoRPC) GetRandomBytes(n int) (bytes []byte, err error) {
	req := new(TaoRPCRequest)
	op := TaoRPCOperation_TAO_RPC_GET_RANDOM_BYTES
	req.Rpc = &op
	if n > math.MaxUint32 {
		rpc.err = "Request for too many random bytes"
		return nil, errors.New(rpc.err)
	}
	size := int32(n)
	req.Size = &size
	err = rpc.request(req, &bytes, nil /* policy */)
	return
}

func (rpc *TaoRPC) GetSharedSecret(n int, policy string) (bytes []byte, err error) {
	req := new(TaoRPCRequest)
	op := TaoRPCOperation_TAO_RPC_GET_SHARED_SECRET
	req.Rpc = &op
	req.Policy = &policy
	if n > math.MaxUint32 {
		rpc.err = "Request for too many random bytes"
		return nil, errors.New(rpc.err)
	}
	size := int32(n)
	req.Size = &size
	err = rpc.request(req, &bytes, nil /* policy */)
	return
}

func (rpc *TaoRPC) Attest(stmt *Statement) (*Attestation, error) {
	data, err := proto.Marshal(stmt)
	if err != nil {
		_, ok := err.(*proto.RequiredNotSetError)
		if !ok {
			rpc.err = "Can't serialize statement"
			return nil, err
		}
	}
	req := new(TaoRPCRequest)
	op := TaoRPCOperation_TAO_RPC_ATTEST
	req.Rpc = &op
	req.Data = data
	var adata []byte
	err = rpc.request(req, &adata, nil /* policy */)
	if err != nil {
		return nil, err
	}
	var a Attestation
	err = proto.Unmarshal(adata, &a)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (rpc *TaoRPC) Seal(data []byte, policy string) (sealed []byte, err error) {
	req := new(TaoRPCRequest)
	op := TaoRPCOperation_TAO_RPC_SEAL
	req.Rpc = &op
	req.Data = data
	req.Policy = &policy
	err = rpc.request(req, &sealed, nil /* policy */)
	return
}

func (rpc *TaoRPC) Unseal(sealed []byte) (data []byte, policy string, err error) {
	req := new(TaoRPCRequest)
	op := TaoRPCOperation_TAO_RPC_UNSEAL
	req.Rpc = &op
	req.Data = sealed
	err = rpc.request(req, &data, &policy)
	return
}

func (rpc *TaoRPC) GetRecentErrorMessage() string {
	return rpc.err
}

func (rpc *TaoRPC) ResetRecentErrorMessage() string {
	err := rpc.err
	rpc.err = ""
	return err
}