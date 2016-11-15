// Copyright (c) 2016, Google Inc. All rights reserved.
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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/box"

	"github.com/jlmucb/cloudproxy/go/tao"
)

// A circuit carries cells
type Circuit struct {
	conn  *Conn
	id    uint64
	cells chan []byte
	errs  chan error
	next  *Circuit
	prev  *Circuit

	key        *[32]byte
	publicKey  *[32]byte
	privateKey *[32]byte
}

func NewCircuit(conn *Conn, id uint64) *Circuit {
	pub, priv, _ := box.GenerateKey(rand.Reader)
	return &Circuit{
		conn:       conn,
		id:         id,
		cells:      make(chan []byte, 2),
		errs:       make(chan error, 2),
		publicKey:  pub,
		privateKey: priv,
	}
}

func (c *Circuit) Write(msg []byte) (int, error) {
	// No need to multiplex writes
	return c.conn.Write(msg)
}

func (c *Circuit) BufferCell(cell []byte, err error) {
	c.cells <- cell
	c.errs <- err
}

func (c *Circuit) Read(msg []byte) (int, error) {
	cell, ok1 := <-c.cells
	err, ok2 := <-c.errs
	if !ok1 || !ok2 {
		return 0, io.EOF
	} else if err != nil {
		return 0, err
	}
	n := copy(msg, cell)
	return n, nil
}

func (c *Circuit) Close() error {
	close(c.cells)
	return nil
}

// SendMessage divides a message into cells and sends each cell over the network
// connection. A message is signaled to the receiver by the first byte of the
// first cell. The next few bytes encode the total number of bytes in the
// message.
func (c *Circuit) SendMessage(msg []byte) error {
	msgBytes := len(msg)
	cell := make([]byte, CellBytes)

	binary.LittleEndian.PutUint64(cell[ID:], c.id)
	cell[TYPE] = msgCell
	binary.LittleEndian.PutUint64(cell[BODY:], uint64(msgBytes))

	bytes := copy(cell[BODY+LEN_SIZE:], msg)
	if _, err := c.Write(cell); err != nil {
		return err
	}

	for bytes < msgBytes {
		tao.ZeroBytes(cell)
		binary.LittleEndian.PutUint64(cell[ID:], c.id)
		cell[TYPE] = msgCell
		bytes += copy(cell[BODY:], msg[bytes:])
		if _, err := c.Write(cell); err != nil {
			return err
		}
	}
	return nil
}

// SendDirective serializes and pads a directive to the length of a cell and
// sends it to the peer. A directive is signaled to the receiver by the first
// byte of the cell. The next few bytes encode the length of of the serialized
// protocol buffer. If the buffer doesn't fit in a cell, then throw an error.
func (c *Circuit) SendDirective(d *Directive) (int, error) {
	cell, err := marshalDirective(c.id, d)
	if err != nil {
		return 0, err
	}
	return c.Write(cell)
}

// ReceiveMessage reads message cells from the router and assembles them into
// a messsage.
func (c *Circuit) ReceiveMessage() ([]byte, error) {
	// Receive cells from router.
	cell := make([]byte, CellBytes)
	n, err := c.Read(cell)
	if err != nil {
		return nil, err
	}

	if cell[TYPE] == dirCell {
		var d Directive
		if err = unmarshalDirective(cell, &d); err != nil {
			return nil, err
		}
		if *d.Type == DirectiveType_ERROR {
			return nil, errors.New("router error: " + (*d.Error))
		}
		return nil, errCellType
	} else if cell[TYPE] != msgCell {
		return nil, errCellType
	}

	msgBytes := binary.LittleEndian.Uint64(cell[BODY:])
	if msgBytes > MaxMsgBytes {
		return nil, errMsgLength
	}

	msg := make([]byte, msgBytes)
	bytes := copy(msg, cell[BODY+LEN_SIZE:n])

	for uint64(bytes) < msgBytes {
		tao.ZeroBytes(cell)
		n, err = c.Read(cell)
		if err != nil {
			return nil, err
		}
		if err != nil {
			return nil, err
		} else if cell[TYPE] != msgCell {
			return nil, errCellType
		}
		bytes += copy(msg[bytes:], cell[BODY:n])
	}

	return msg, nil
}

// ReceiveDirective awaits a reply from the peer and returns the directive
// received, e.g. in response to RouterContext.HandleProxy(). If the directive
// type is ERROR, return an error.
func (c *Circuit) ReceiveDirective(d *Directive) error {
	cell := make([]byte, CellBytes)
	_, err := c.Read(cell)
	if err != nil {
		return err
	}

	err = unmarshalDirective(cell, d)
	if err != nil {
		return err
	}

	if *d.Type == DirectiveType_ERROR {
		return errors.New("router error: " + (*d.Error))
	}
	return nil
}
