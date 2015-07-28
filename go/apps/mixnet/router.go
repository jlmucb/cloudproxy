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

// RouterContext stores the runtime environment for a Tao-delegated router.
type RouterContext struct {
	keys          *tao.Keys    // Signing keys of this hosted program.
	domain        *tao.Domain  // Policy guard and public key.
	proxyListener net.Listener // Socket where server listens for proxies.

	id uint64 // Next serial identifier that will be assigned to a connection.

	// Map a connection to its next hop destination.
	next map[uint64]net.Conn

	// For the moment, buffer a single message and destination.
	msgBuffer     []byte
	dstAddrBuffer string

	network string // Network protocol, e.g. "tcp"
}

// NewRouterContext generates new keys, loads a local domain configuration from
// path and binds an anonymous listener socket to addr on network
// network. A delegation is requested from the Tao t which is  nominally
// the parent of this hosted program.
func NewRouterContext(path, network, addr string, x509Identity *pkix.Name, t tao.Tao) (hp *RouterContext, err error) {
	hp = new(RouterContext)

	hp.network = network
	hp.next = make(map[uint64]net.Conn)

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
func (hp RouterContext) AcceptProxy() (*Conn, error) {
	c, err := hp.proxyListener.Accept()
	if err != nil {
		return nil, err
	}
	return &Conn{c, hp.nextID()}, nil
}

// Close releases any resources held by the hosted program.
func (hp *RouterContext) Close() {
	for _, c := range hp.next {
		c.Close()
	}
	if hp.proxyListener != nil {
		hp.proxyListener.Close()
	}
}

// HandleProxy reads a directive or a message from a proxy.
func (hp *RouterContext) HandleProxy(c *Conn) error {
	var err error
	cell := make([]byte, CellBytes)
	if _, err = c.Read(cell); err != nil && err != io.EOF {
		return err
	}

	if cell[0] == msgCell { // Handle a message.
		msgBytes, n := binary.Uvarint(cell[1:])
		if msgBytes > MaxMsgBytes {
			hp.SendFatal(c, errMsgLength)
			c.Close()
			return nil
		}

		hp.msgBuffer = make([]byte, msgBytes)
		bytes := copy(hp.msgBuffer, cell[1+n:])

		// While the connection is open and the message is incomplete, read
		// the next cell.
		for err != io.EOF && uint64(bytes) < msgBytes {
			if _, err = c.Read(cell); err != nil && err != io.EOF {
				return err
			}
			bytes += copy(hp.msgBuffer[bytes:], cell)
		}

		// For now, send the message straight away.
		if _, err = hp.next[c.id].Write(hp.msgBuffer); err != nil {
			return err
		}

	} else if cell[0] == dirCell { // Handle a directive.
		dirBytes, n := binary.Uvarint(cell[1:])
		var d Directive
		if err := proto.Unmarshal(cell[1+n:1+n+int(dirBytes)], &d); err != nil {
			return err
		}

		// Construct a circuit and establish a connection with the destination.
		// TODO(cjpatton) For now, only single-hop circuits are supported.
		if *d.Type == DirectiveType_CREATE_CIRCUIT {
			if len(d.Addrs) == 0 {
				return errBadDirective
			}
			if len(d.Addrs) > 1 {
				return errors.New("multi-hop circuits not implemented")
			}

			// For now, connect to destination straight away.
			if hp.next[c.id], err = net.Dial(hp.network, d.Addrs[0]); err != nil {
				return err
			}
		}

	} else { // Unknown cell type, return an error.
		hp.SendError(c, errBadCellType)
	}

	return nil
}

// SendError sends an error message to a client.
func (hp *RouterContext) SendError(c net.Conn, err error) (int, error) {
	var d Directive
	d.Type = DirectiveType_ERROR.Enum()
	d.Error = proto.String(err.Error())
	return SendDirective(c, &d)
}

// SendFatal sends an error message and signals the client that the connection
// was severed on the server side.
func (hp *RouterContext) SendFatal(c net.Conn, err error) (int, error) {
	var d Directive
	d.Type = DirectiveType_FATAL.Enum()
	d.Error = proto.String(err.Error())
	return SendDirective(c, &d)
}

// Get the next Id to assign and increment counter.
// TODO(cjpatton) This will need mutual exclusion when AcceptRouter() is
// implemented.
func (hp *RouterContext) nextID() (id uint64) {
	id = hp.id
	hp.id++
	return id
}
