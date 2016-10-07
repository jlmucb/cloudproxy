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
	"net"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
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
	ID_SIZE  = 8
	LEN_SIZE = 8
)

const (
	ID   = 0
	TYPE = ID + ID_SIZE
	BODY = 9
)

var errCellLength = errors.New("incorrect cell length")
var errCellType = errors.New("incorrect cell type")
var errBadCellType = errors.New("unrecognized cell type")
var errBadDirective = errors.New("received bad directive")
var errMsgLength = errors.New("message too long")

var dirCreated = &Directive{Type: DirectiveType_CREATED.Enum()}
var dirDestroy = &Directive{Type: DirectiveType_DESTROY.Enum()}
var dirDestroyed = &Directive{Type: DirectiveType_DESTROYED.Enum()}

// Conn implements the net.Conn interface. The read and write operations are
// overloaded to check that only cells are sent between entities in the mixnet
// protocol.
type Conn struct {
	net.Conn
	id        uint32
	timeout   time.Duration // timeout on read/write.
	circuits  map[uint64]*Circuit
	cLock     *sync.RWMutex
	withProxy bool
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

func (c *Conn) GetCircuit(id uint64) *Circuit {
	c.cLock.RLock()
	circuit := c.circuits[id]
	c.cLock.RUnlock()
	return circuit
}

func (c *Conn) AddCircuit(circuit *Circuit) {
	c.cLock.Lock()
	c.circuits[circuit.id] = circuit
	c.cLock.Unlock()
}

func (c *Conn) DeleteCircuit(circuit *Circuit) bool {
	c.cLock.Lock()
	close(circuit.cells)
	delete(c.circuits, circuit.id)
	empty := len(c.circuits) == 0
	c.cLock.Unlock()
	return empty
}

// Transform a directive into a cell, encoding its length and padding it to the
// length of a cell.
func marshalDirective(id uint64, d *Directive) ([]byte, error) {
	db, err := proto.Marshal(d)
	if err != nil {
		return nil, err
	}
	dirBytes := uint64(len(db))

	cell := make([]byte, CellBytes)
	binary.LittleEndian.PutUint64(cell[ID:], id)

	cell[TYPE] = dirCell
	binary.LittleEndian.PutUint64(cell[BODY:], dirBytes)

	// Throw an error if encoded Directive doesn't fit into a cell.
	if dirBytes+LEN_SIZE+1 > CellBytes {
		return nil, errCellLength
	}
	copy(cell[BODY+LEN_SIZE:], db)

	return cell, nil
}

// Parse a directive from a cell.
func unmarshalDirective(cell []byte, d *Directive) error {
	if cell[TYPE] != dirCell {
		return errCellType
	}

	dirBytes := binary.LittleEndian.Uint64(cell[BODY:])
	if err := proto.Unmarshal(cell[BODY+LEN_SIZE:BODY+LEN_SIZE+int(dirBytes)], d); err != nil {
		return err
	}

	return nil
}
