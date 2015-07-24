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
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
)

var errBadDirective error = errors.New("received bad directive")

// RouterContext stores the runtime environment for a Tao-delegated router.
type RouterContext struct {
	keys          *tao.Keys    // Signing keys of this hosted program.
	domain        *tao.Domain  // Policy guard and public key.
	proxyListener net.Listener // Socket where server listens for proxies.

	// For the moment, buffer a single message and destination.
	msgBuffer     []byte
	dstAddrBuffer string
}

// NewRouterContext generates new keys, loads a local domain configuration from
// path and binds an anonymous listener socket to addr on network
// network. A delegation is requested from the Tao9 t which is  nominally
// the parent of this hosted program.
func NewRouterContext(path, network, addr string, x509Identity *pkix.Name, t tao.Tao) (hp *RouterContext, err error) {
	hp = new(RouterContext)

	// Generate keys and get attestation from parent.
	if hp.keys, err = tao.NewTemporaryTaoDelegatedKeys(tao.Signing|tao.Crypting, t); err != nil {
		return nil, err
	}

	// Create a certificate.
	if hp.keys.Cert, err = hp.keys.SigningKey.CreateSelfSignedX509(x509Identity); err != nil {
		return nil, err
	}

	// Load domain from local configuration.
	if hp.domain, err = tao.LoadDomain(path, nil); err != nil {
		return nil, err
	}

	// Encode TLS certificate.
	cert, err := tao.EncodeTLSCert(hp.keys)
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
	if hp.proxyListener, err = tao.ListenAnonymous(network, addr, tlsConfig,
		hp.domain.Guard, hp.domain.Keys.VerifyingKey, hp.keys.Delegation); err != nil {
		return nil, err
	}

	return hp, nil
}

// AcceptProxy Waits for connectons from proxies.
func (hp RouterContext) AcceptProxy() (net.Conn, error) {
	c, err := hp.proxyListener.Accept()
	if err != nil {
		return nil, err
	}
	return &Conn{c}, nil
}

// Close releases any resources held by the hosted program.
func (hp *RouterContext) Close() {
	if hp.proxyListener != nil {
		hp.proxyListener.Close()
	}
}

// HandleProxy reads a directive or a message from a proxy.
func (hp *RouterContext) HandleProxy(c net.Conn) error {
	var err error
	cell := make([]byte, CellBytes)
	if _, err = c.Read(cell); err != nil && err != io.EOF {
		return err
	}

	// The first byte signals either a message or a directive to the router.
	if cell[0] == msgCell {

		// The first eight bytes of the first cell encode the message length.
		// TODO(cjpatton) How to deal with endianness discrepancies?
		msgBytes := int(binary.BigEndian.Uint64(cell[1:9]))
		hp.msgBuffer = make([]byte, msgBytes)
		bytes := copy(hp.msgBuffer, unpadCell(cell[9:]))

		// While the connection is open and the message is incomplete, read
		// the next cell.
		for err != io.EOF && bytes < msgBytes {
			if _, err = c.Read(cell); err != nil && err != io.EOF {
				return err
			}
			bytes += copy(hp.msgBuffer[bytes:], unpadCell(cell))
		}

	} else if cell[0] == dirCell {
		var d Directive
		if err := proto.Unmarshal(unpadCell(cell)[1:], &d); err != nil {
			return err
		}

		if *d.Type == DirectiveType_CREATE_CIRCUIT {
			if len(d.Addrs) == 0 {
				return errBadDirective
			} else if len(d.Addrs) > 1 {
				return errors.New("multi-hop circuits not implemented")
			}

			hp.dstAddrBuffer = d.Addrs[0]
		}
	}
	return nil
}
