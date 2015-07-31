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
func (p *ProxyContext) CreateCircuit(c *Conn, circuitAddrs ...string) error {
	d := &Directive{
		Type:  DirectiveType_CREATE.Enum(),
		Addrs: circuitAddrs,
	}

	// Send CREATE directive to router.
	if _, err := p.SendDirective(c, d); err != nil {
		return err
	}

	// Wait for CREATED directive from router.
	if _, err := p.ReceiveDirective(c, d); err != nil {
		return err
	} else if *d.Type != DirectiveType_CREATED {
		return errors.New("could not create circuit")
	}
	return nil
}

// SendMessage divides a message into cells and sends each cell over the network
// connection. A message is signaled to the receiver by the first byte of the
// first cell. The next few bytes encode the total number of bytes in the
// message.
func (p *ProxyContext) SendMessage(c *Conn, msg []byte) error {
	msgBytes := len(msg)
	cell := make([]byte, CellBytes)
	cell[0] = msgCell
	n := binary.PutUvarint(cell[1:], uint64(msgBytes))

	bytes := copy(cell[1+n:], msg)
	if _, err := c.Write(cell); err != nil {
		return err
	}

	for bytes < msgBytes {
		zeroCell(cell)
		cell[0] = msgCell
		bytes += copy(cell[1:], msg[bytes:])
		if _, err := c.Write(cell); err != nil {
			return err
		}
	}
	return nil
}

// ReceiveMessage reads message cells from the router and assembles them into
// a messsage.
func (p *ProxyContext) ReceiveMessage(c *Conn) ([]byte, error) {
	var err error

	// Receive cells from router.
	cell := make([]byte, CellBytes)
	if _, err = c.Read(cell); err != nil && err != io.EOF {
		return nil, err
	}

	if cell[0] == dirCell {
		var d Directive
		if err = unmarshalDirective(cell, &d); err != nil {
			return nil, err
		}
		if *d.Type == DirectiveType_ERROR {
			return nil, errors.New("router error: " + (*d.Error))
		}
		return nil, errCellType
	} else if cell[0] != msgCell {
		return nil, errCellType
	}

	msgBytes, n := binary.Uvarint(cell[1:])
	if msgBytes > MaxMsgBytes {
		return nil, errMsgLength
	}

	msg := make([]byte, msgBytes)
	bytes := copy(msg, cell[1+n:])

	for err != io.EOF && uint64(bytes) < msgBytes {
		if _, err = c.Read(cell); err != nil && err != io.EOF {
			return nil, err
		}
		if cell[0] != msgCell {
			return nil, errCellType
		}
		bytes += copy(msg[bytes:], cell[1:])
	}

	return msg, nil
}

// SendDirective serializes and pads a directive to the length of a cell and
// sends it to the peer. A directive is signaled to the receiver by the first
// byte of the cell. The next few bytes encode the length of of the serialized
// protocol buffer. If the buffer doesn't fit in a cell, then throw an error.
func (p *ProxyContext) SendDirective(c *Conn, d *Directive) (int, error) {
	cell, err := marshalDirective(d)
	if err != nil {
		return 0, err
	}
	return c.Write(cell)
}

// ReceiveDirective awaits a reply from the peer and returns the directive
// received, e.g. in response to RouterContext.HandleProxy(). If the directive
// type is ERROR, return an error.
func (p *ProxyContext) ReceiveDirective(c *Conn, d *Directive) (int, error) {
	cell := make([]byte, CellBytes)
	bytes, err := c.Read(cell)
	if err != nil && err != io.EOF {
		return 0, err
	}

	err = unmarshalDirective(cell, d)
	if err != nil {
		return 0, err
	}

	if *d.Type == DirectiveType_ERROR {
		return bytes, errors.New("router error: " + (*d.Error))
	}
	return bytes, nil
}

// Return the next serial identifier.
func (p *ProxyContext) nextID() (id uint64) {
	id = p.id
	p.id++
	return id
}
