// Copyright (c) 2016, Google, Inc. All rights reserved.
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

package tpm2_apps

import (
	"fmt"
	"log"
	"net"

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tpm2"
	"github.com/jlmucb/cloudproxy/go/util"
)

type QuoteServer struct {
	listener net.Listener
}

func NewQuoteServer(network, addr string) *QuoteServer {
	ln, err := net.Listen(network, addr)
	if err != nil {
		log.Fatalln("Quote server: could not listen at port:", err)
	}

	return &QuoteServer{ln}
}

func (s *QuoteServer) Close() {
	if s.listener != nil {
		s.listener.Close()
	}
}

// TODO: probably receive a kill channel to kill this function..
func (s *QuoteServer) HandleQuote(pass, path string, details tao.X509Details) error {
	// Generate/Load policy key
	policyKey, err := tao.NewOnDiskPBEKeys(tao.Signing, []byte(pass), path,
		tao.NewX509Name(&details))
	if err != nil {
		return fmt.Errorf("Error loading policy key: %s", err)
	}
	if policyKey.Cert == nil || policyKey.Cert.Raw == nil {
		log.Fatalln("Quote server: cert missing in policy key.")
	}
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return fmt.Errorf("Quote server: could not accept connection: %s", err)
		}
		ms := util.NewMessageStream(conn)
		var request tpm2.AttestCertRequest
		if err := ms.ReadMessage(&request); err != nil {
			log.Printf("Quote server: Couldn't read request from channel: %s\n", err)
			continue
		}
		response, err := tpm2.ProcessQuoteDomainRequest(request, policyKey.SigningKey.GetSigner(),
			policyKey.Cert.Raw)
		if err != nil {
			sendError(err, ms)
			continue
		}
		if _, err := ms.WriteMessage(response); err != nil {
			log.Printf("Quote server: Error sending response on the channel: %s\n ", err)
		}
	}
	return nil
}

func sendError(err error, ms *util.MessageStream) {
	errCode := int32(1)
	resp := &tpm2.AttestCertResponse{Error: &errCode}
	if _, err := ms.WriteMessage(resp); err != nil {
		log.Printf("Quote server: Error sending resp on the channel: %s\n ", err)
	}
}
