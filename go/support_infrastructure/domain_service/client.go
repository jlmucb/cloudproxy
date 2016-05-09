// Copyright (c) 2016, Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package domain_service

import (
	"errors"
	"net"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util"
)

func RequestProgramCert(hostAtt *tao.Attestation, network string, addr string) (*tao.Attestation,
	error) {
	serAtt, err := proto.Marshal(hostAtt)
	if err != nil {
		return nil, err
	}
	reqType := DomainServiceRequest_DOMAIN_CERT_REQUEST
	request := &DomainServiceRequest{
		Type: &reqType,
		SerializedHostAttestation: serAtt}

	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	ms := util.NewMessageStream(conn)
	_, err = ms.WriteMessage(request)
	if err != nil {
		return nil, err
	}
	var response DomainServiceResponse
	err = ms.ReadMessage(&response)
	if err != nil {
		return nil, err
	}

	if errStr := response.GetErrorMessage(); errStr != "" {
		return nil, errors.New(errStr)
	}
	var a tao.Attestation
	err = proto.Unmarshal(response.GetSerializedDomainAttestation(), &a)
	if err != nil {
		return nil, err
	}
	return &a, nil
}
