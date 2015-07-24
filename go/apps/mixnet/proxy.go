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
	"net"

	"github.com/golang/protobuf/proto"
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
func (p *ProxyContext) DialRouter(network, addr string) (net.Conn, error) {
	c, err := tao.Dial(network, addr, p.domain.Guard, p.domain.Keys.VerifyingKey, nil)
	if err != nil {
		return nil, err
	}
	return &Conn{c}, nil
}

// CreateCircuit directs the router to construct a circuit to a particular
// destination over the mixnet.
func (p *ProxyContext) CreateCircuit(c net.Conn, circuitAddrs []string) (n int, err error) {
	var d Directive
	d.Type = DirectiveType_CREATE_CIRCUIT.Enum()
	d.Addrs = circuitAddrs
	return p.SendDirective(c, &d)
}

// Serialize and pad a directive to the length of a cell and send it to the
// router. A directive is signaled to the receiver by the first byte of the
// cell. The next 8 bytes encodse the length of of the serialized protocol
// buffer. If the buffer doesn't fit in a cell, then throw an error.
func (p *ProxyContext) SendDirective(c net.Conn, d *Directive) (n int, err error) {
	db, err := proto.Marshal(d)
	if err != nil {
		return 0, err
	}
	dirBytes := len(db)

	// Throw an error if encoded Directive doesn't fit into a cell.
	if dirBytes+9 > CellBytes {
		return 0, errCellLength
	}

	cell := make([]byte, CellBytes)
	cell[0] = dirCell
	// TODO(cjpatton) How to deal with endianness discrepancies?
	binary.BigEndian.PutUint64(cell[1:9], uint64(dirBytes))
	copy(cell[9:], db)

	return c.Write(cell)
}

// SendMessage directs the router to relay a message over the already constructed
// circuit. A message is signaled to the reecevier by the first byte of the first
// cell. The next 8 bytes encode the total number of bytes in the message.
func (p *ProxyContext) SendMessage(c net.Conn, msg []byte) (n int, err error) {
	msgBytes := len(msg)
	cell := make([]byte, CellBytes)
	cell[0] = msgCell

	// TODO(cjpatton) How to deal with endianness discrepancies?
	binary.BigEndian.PutUint64(cell[1:9], uint64(msgBytes))

	bytes := copy(cell[9:], msg)
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
