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
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
)

const (

	// CellBytes specifies the length of a cell.
	CellBytes = 1 << 10

	// MaxMsgBytes specifies the maximum length of a message.
	MaxMsgBytes = 1 << 16
)

const (
	msgCell = iota
	dirCell
)

const (
	ID   = 0
	TYPE = 8
	BODY = 9
)

var errCellLength = errors.New("incorrect cell length")
var errCellType = errors.New("incorrect cell type")
var errBadCellType = errors.New("unrecognized cell type")
var errBadDirective = errors.New("received bad directive")
var errMsgLength = errors.New("message too long")

var dirCreated = &Directive{Type: DirectiveType_CREATED.Enum()}
var dirDestroy = &Directive{Type: DirectiveType_DESTROY.Enum()}

// Conn implements the net.Conn interface. The read and write operations are
// overloaded to check that only cells are sent between entities in the mixnet
// protocol.
type Conn struct {
	net.Conn
	timeout  time.Duration // timeout on read/write.
	circuits map[uint64]Circuit
}

// A cell read from the network connection
type Cell struct {
	cell []byte
	err  error
}

// A circuit carries cells
type Circuit struct {
	cells chan Cell
}

// Read a cell from the channel. If len(msg) != CellBytes, return an error.
func (c *Conn) Read(msg []byte) (n int, err error) {
	c.Conn.SetDeadline(time.Now().Add(c.timeout))
	n, err = c.Conn.Read(msg)
	if err != nil {
		return n, err
	}
	if n != CellBytes {
		return n, errCellLength
	}
	return n, nil
}

// Write a cell to the channel. If the len(cell) != CellBytes, return an error.
func (c *Conn) Write(msg []byte) (n int, err error) {
	c.Conn.SetDeadline(time.Now().Add(c.timeout))
	if len(msg) != CellBytes {
		return 0, errCellLength
	}
	n, err = c.Conn.Write(msg)
	if err != nil {
		return n, err
	}
	return n, nil
}

// GetID returns the connection's serial ID.
func getID(cell []byte) uint64 {
	id, _ := binary.Uvarint(cell[ID:])
	return id
}

// SendMessage divides a message into cells and sends each cell over the network
// connection. A message is signaled to the receiver by the first byte of the
// first cell. The next few bytes encode the total number of bytes in the
// message.
func (c *Conn) SendMessage(id uint64, msg []byte) error {
	msgBytes := len(msg)
	cell := make([]byte, CellBytes)

	binary.PutUvarint(cell[ID:], id)
	cell[TYPE] = msgCell
	m := binary.PutUvarint(cell[BODY:], uint64(msgBytes))

	bytes := copy(cell[BODY+m:], msg)
	if _, err := c.Write(cell); err != nil {
		return err
	}

	for bytes < msgBytes {
		tao.ZeroBytes(cell)
		binary.PutUvarint(cell[ID:], id)
		cell[TYPE] = msgCell
		bytes += copy(cell[BODY:], msg[bytes:])
		if _, err := c.Write(cell); err != nil {
			return err
		}
	}
	return nil
}

// ReceiveMessage reads message cells from the router and assembles them into
// a messsage.
func (c *Conn) ReceiveMessage(id uint64) ([]byte, error) {
	// Receive cells from router.
	read := <-c.circuits[id].cells
	cell := read.cell
	err := read.err
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

	msgBytes, n := binary.Uvarint(cell[BODY:])
	if msgBytes > MaxMsgBytes {
		return nil, errMsgLength
	}

	msg := make([]byte, msgBytes)
	bytes := copy(msg, cell[BODY+n:])

	for err != io.EOF && uint64(bytes) < msgBytes {
		read = <-c.circuits[id].cells
		cell = read.cell
		err = read.err
		if err != nil && err != io.EOF {
			return nil, err
		} else if cell[TYPE] != msgCell {
			return nil, errCellType
		}
		bytes += copy(msg[bytes:], cell[BODY:])
	}

	return msg, nil
}

// SendDirective serializes and pads a directive to the length of a cell and
// sends it to the peer. A directive is signaled to the receiver by the first
// byte of the cell. The next few bytes encode the length of of the serialized
// protocol buffer. If the buffer doesn't fit in a cell, then throw an error.
func (c *Conn) SendDirective(id uint64, d *Directive) (int, error) {
	cell, err := marshalDirective(id, d)
	if err != nil {
		return 0, err
	}
	return c.Write(cell)
}

// ReceiveDirective awaits a reply from the peer and returns the directive
// received, e.g. in response to RouterContext.HandleProxy(). If the directive
// type is ERROR, return an error.
func (c *Conn) ReceiveDirective(id uint64, d *Directive) error {
	read := <-c.circuits[id].cells
	cell := read.cell
	err := read.err

	if err != nil && err != io.EOF {
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

// Transform a directive into a cell, encoding its length and padding it to the
// length of a cell.
func marshalDirective(id uint64, d *Directive) ([]byte, error) {
	db, err := proto.Marshal(d)
	if err != nil {
		return nil, err
	}
	dirBytes := len(db)

	cell := make([]byte, CellBytes)
	binary.PutUvarint(cell[ID:], id)

	cell[TYPE] = dirCell
	n := binary.PutUvarint(cell[BODY:], uint64(dirBytes))

	// Throw an error if encoded Directive doesn't fit into a cell.
	if dirBytes+n+1 > CellBytes {
		return nil, errCellLength
	}
	copy(cell[BODY+n:], db)

	return cell, nil
}

// Parse a directive from a cell.
func unmarshalDirective(cell []byte, d *Directive) error {
	if cell[TYPE] != dirCell {
		return errCellType
	}

	dirBytes, n := binary.Uvarint(cell[BODY:])
	if err := proto.Unmarshal(cell[BODY+n:BODY+n+int(dirBytes)], d); err != nil {
		return err
	}

	return nil
}
