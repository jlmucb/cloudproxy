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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"

	"github.com/jlmucb/cloudproxy/go/tao"
)

const (
	CellBytes = 1024 // Length of a cell
)

// x509 identity of a mixnet router.
var x509Identity pkix.Name = pkix.Name{
	Organization:       []string{"Google Inc."},
	OrganizationalUnit: []string{"Cloud Security"},
}

// RouterContext stores the runtime environment for a Tao-delegated router.
type RouterContext struct {
	Keys     *tao.Keys    // Signing keys of this hosted program.
	Domain   *tao.Domain  // Policy guard and public key.
	Listener net.Listener // Socket where server listens for clients.
}

// NewRouterContext generates new keys, loads a local domain configuration from
// `path`, and binds an anonymous listener socket to `addr` on network
// `network`. It is expected that this program will be called from a host
// implementing the Tao, as it requests a delegation from its parent.
func NewRouterContext(path, network, addr string) (hp *RouterContext, err error) {
	hp = new(RouterContext)

	// Generate keys and get attestation from parent.
	hp.Keys, err = tao.NewTemporaryTaoDelegatedKeys(tao.Signing|tao.Crypting, tao.Parent())
	if err != nil {
		return nil, err
	}

	// Create a certificate.
	hp.Keys.Cert, err = hp.Keys.SigningKey.CreateSelfSignedX509(&x509Identity)
	if err != nil {
		return nil, err
	}

	// Load domain from local configuration.
	hp.Domain, err = tao.LoadDomain(path, nil)
	if err != nil {
		return nil, err
	}

	// Encode TLS certificate.
	cert, err := tao.EncodeTLSCert(hp.Keys)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*cert},
		InsecureSkipVerify: true,
		ClientAuth:         tls.NoClientCert,
	}

	// Bind address to socket.
	hp.Listener, err = tao.ListenAnonymous(network, addr, tlsConfig,
		hp.Domain.Guard, hp.Domain.Keys.VerifyingKey, hp.Keys.Delegation)
	if err != nil {
		return nil, err
	}

	return hp, nil
}

// Close releases any resources held by the hosted program.
func (hp RouterContext) Close() {
	if hp.Listener != nil {
		hp.Listener.Close()
	}
}

// ProxyContext stores the runtime environment for a mixnet proxy.
type ProxyContext struct {
	domain *tao.Domain // Policy guard and public key.
	conn   net.Conn    // One-way authenticated TLS channel to Tao router.
}

// NewProxyContext loads a domain from a local configuration and connects
// anonymously to the remote Tao router.
func NewProxyContext(path, network, addr string) (c *ProxyContext, err error) {
	c = new(ProxyContext)

	// Load domain from a local configuration.
	if c.domain, err = tao.LoadDomain(path, nil); err != nil {
		return nil, err
	}

	// Connect anonymously to the remote Tao server.
	if c.conn, err = tao.Dial(network, addr, c.domain.Guard, c.domain.Keys.VerifyingKey, nil); err != nil {
		return nil, err
	}

	return
}

func (c ProxyContext) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// Send message divides a byte slice into fixed-length
// cells and sends them to the Tao router.
func (c ProxyContext) SendMessage(msg []byte) error {
	// TODO(cjpatton) for now, just send one cell. The sender should
	// send the total number of bytes in the message in the first cell.
	cell := make([]byte, CellBytes)
	copy(cell, msg)
	if _, err := c.conn.Write(cell); err != nil {
		return err
	}
	return nil
}
