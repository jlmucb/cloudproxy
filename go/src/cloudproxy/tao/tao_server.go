//  Copyright (c) 2014, Google Inc.  All rights reserved.
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
	"errors"

	"code.google.com/p/goprotobuf/proto"
)

// A TaoServer wraps a Tao and serves its methods across a net/rpc connection.
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

	var err error
	s.Data, err = ts.T.GetRandomBytes(int(r.GetSize()))
	if err != nil {
		return err
	}

	return nil
}

func (ts *TaoServer) Seal(r *TaoRPCRequest, s *TaoRPCResponse) error {
	if r.GetRpc() != TaoRPCOperation_TAO_RPC_SEAL {
		return errors.New("wrong RPC type")
	}

	sealed, err := ts.T.Seal(r.GetData(), r.GetPolicy())
	if err != nil {
		return err
	}

	s.Data = sealed
	return nil
}

func (ts *TaoServer) Unseal(r *TaoRPCRequest, s *TaoRPCResponse) error {
	if r.GetRpc() != TaoRPCOperation_TAO_RPC_UNSEAL {
		return errors.New("wrong RPC type")
	}

	data, policy, err := ts.T.Unseal(r.GetData())
	if err != nil {
		return err
	}

	s.Data = data
	s.Policy = proto.String(string(policy))
	return nil
}

func (ts *TaoServer) Attest(r *TaoRPCRequest, s *TaoRPCResponse) error {
	if r.GetRpc() != TaoRPCOperation_TAO_RPC_ATTEST {
		return errors.New("wrong RPC type")
	}

	stmt := new(Statement)
	err := proto.Unmarshal(r.GetData(), stmt)
	if err != nil {
		return err
	}

	a, err := ts.T.Attest(stmt)
	if err != nil {
		return err
	}

	s.Data, err = proto.Marshal(a)
	return nil
}
