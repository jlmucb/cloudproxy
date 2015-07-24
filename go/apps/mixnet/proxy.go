// Copyright (c) 2015, Google Inc. All rights reserved.
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

package mixnet

import (
	"net"

	"github.com/jlmucb/cloudproxy/go/tao"
)

// ProxyContext stores the runtime environment for a mixnet proxy. A mixnet
// proxy connects to a mixnet router on behalf of a client's application.
type ProxyContext struct {
	domain *tao.Domain // Policy guard and public key.
}

// NewProxyContext loads a domain from a local configuration.
func NewProxyContext(path string) (p *ProxyContext, err error) {
	p = new(ProxyContext)

	// Load domain from a local configuration.
	if p.domain, err = tao.LoadDomain(path, nil); err != nil {
		return nil, err
	}

	return p, nil
}

// DialRouter connects anonymously to a remote Tao-delegated mixnet router.
func (p ProxyContext) DialRouter(network, addr string) (net.Conn, error) {
	c, err := tao.Dial(network, addr, p.domain.Guard, p.domain.Keys.VerifyingKey, nil)
	if err != nil {
		return nil, err
	}
	return &Conn{c}, nil
}
