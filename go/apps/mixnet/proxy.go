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
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
)

// ProxyContext stores the runtime environment for a mixnet proxy. A mixnet
// proxy connects to a mixnet router on behalf of a client's application.
type ProxyContext struct {
	domain *tao.Domain // Policy guard and public key.
	id     uint64      // Next serial identifier that will assigned to a new connection.
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
func (p *ProxyContext) DialRouter(network, addr string) (*Conn, error) {
	c, err := tao.Dial(network, addr, p.domain.Guard, p.domain.Keys.VerifyingKey, nil)
	if err != nil {
		return nil, err
	}
	return &Conn{c, p.nextID()}, nil
}

// CreateCircuit directs the router to construct a circuit to a particular
// destination over the mixnet.
func (p *ProxyContext) CreateCircuit(c net.Conn, circuitAddrs []string) (int, error) {
	var d Directive
	d.Type = DirectiveType_CREATE_CIRCUIT.Enum()
	d.Addrs = circuitAddrs
	return SendDirective(c, &d)
}

// SendMessage directs the router to relay a message over the already constructed
// circuit. A message is signaled to the reecevier by the first byte of the first
// cell. The next 8 bytes encode the total number of bytes in the message.
func (p *ProxyContext) SendMessage(c net.Conn, msg []byte) (int, error) {
	msgBytes := len(msg)
	cell := make([]byte, CellBytes)
	cell[0] = msgCell
	n := binary.PutUvarint(cell[1:], uint64(msgBytes))

	bytes := copy(cell[1+n:], msg)
	if _, err := c.Write(cell); err != nil {
		return 0, err
	}

	for bytes < msgBytes {
		zeroCell(cell)
		bytes += copy(cell, msg[bytes:])
		if _, err := c.Write(cell); err != nil {
			return bytes, err
		}
	}

	return bytes, nil
}

// ReceiveMessage waits for a reply or error message from the router.
func (p *ProxyContext) ReceiveMessage(c net.Conn, msg []byte) (int, error) {
	var err error
	cell := make([]byte, CellBytes)
	if _, err = c.Read(cell); err != nil && err != io.EOF {
		return 0, err
	}

	if cell[0] == msgCell { // Read a message.
		// TODO(cjpatton)

	} else if cell[0] == dirCell { // Handle a directive.
		dirBytes, n := binary.Uvarint(cell[1:])
		var d Directive
		if err := proto.Unmarshal(cell[1+n:1+n+int(dirBytes)], &d); err != nil {
			return 0, err
		}

		switch *d.Type {
		case DirectiveType_ERROR:
			return 0, errors.New("router error: " + (*d.Error))
		case DirectiveType_FATAL:
			return 0, errors.New("router error: " + (*d.Error) + " (connection closed)")
		default:
			return 0, errBadDirective
		}
	}

	return 0, errBadCellType
}

func (p *ProxyContext) nextID() (id uint64) {
	id = p.id
	p.id++
	return id
}
