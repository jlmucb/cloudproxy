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
	conn    *Conn
	id      uint64
	cells   chan []byte
	errs    chan error
	next    *Circuit
	entry   bool
	exit    bool
	forward bool

	peerKey    *[32]byte
	publicKey  *[32]byte
	privateKey *[32]byte
	sharedKey  *[32]byte
}

// A circuit now encrypts for the exit circuit. The key is assumed to be available
// through "peerKey", and publicKey and privateKey are the keys are local keys
// used to perform diffiehellman with peerKey. The keys are optional.
func NewCircuit(conn *Conn, id uint64, entry, exit, forward bool) *Circuit {
	return &Circuit{
		conn:    conn,
		id:      id,
		cells:   make(chan []byte, 2),
		errs:    make(chan error, 2),
		entry:   entry,
		exit:    exit,
		forward: forward,
	}
}

func (c *Circuit) SetKeys(peerKey, publicKey, privateKey *[32]byte) {
	var sharedKey [32]byte
	box.Precompute(&sharedKey, peerKey, privateKey)
	c.peerKey = peerKey
	c.publicKey = publicKey
	c.privateKey = privateKey
	c.sharedKey = &sharedKey
}

func (c *Circuit) Encrypt(msg []byte) []byte {
	var nonce [24]byte
	rand.Read(nonce[:])
	boxed := box.SealAfterPrecomputation(nil, msg, &nonce, c.sharedKey)
	boxed = append(nonce[:], boxed...)
	return boxed
}

func (c *Circuit) Decrypt(boxed []byte) ([]byte, bool) {
	var nonce [24]byte
	copy(nonce[:], boxed[:24])
	return box.OpenAfterPrecomputation(nil, boxed[24:], &nonce, c.sharedKey)
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

func breakMessages(msg []byte, res chan []byte) {
	body := make([]byte, BODY_SIZE)
	binary.LittleEndian.PutUint64(body, uint64(len(msg)))
	bytes := copy(body[LEN_SIZE:], msg)
	res <- body
	for bytes < len(msg) {
		body := make([]byte, BODY_SIZE)
		bytes += copy(body, msg[bytes:])
		res <- body
	}
	close(res)
}

// SendMessage divides a message into cells and sends each cell over the network
// connection. A message is signaled to the receiver by the first byte of the
// first cell. The next few bytes encode the total number of bytes in the
// message.
func (c *Circuit) SendMessage(msg []byte) error {
	cell := make([]byte, CellBytes)
	binary.LittleEndian.PutUint64(cell[ID:], c.id)
	cell[TYPE] = msgCell

	bodies := make(chan []byte)

	go breakMessages(msg, bodies)
	for {
		body, ok := <-bodies
		if !ok {
			break
		}
		boxed := c.Encrypt(body)
		copy(cell[BODY:], boxed)
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

	boxed := cell[BODY:n]
	if len(boxed) > 0 {
		body, ok := c.Decrypt(boxed)
		if !ok {
			return nil, errors.New("Misauthenticated ciphertext")
		}

		msgBytes := binary.LittleEndian.Uint64(body)
		if msgBytes > MaxMsgBytes {
			return nil, errMsgLength
		}

		msg := make([]byte, msgBytes)
		bytes := copy(msg, body[LEN_SIZE:])

		for uint64(bytes) < msgBytes {
			tao.ZeroBytes(cell)
			n, err = c.Read(cell)
			if err != nil {
				return nil, err
			} else if cell[TYPE] != msgCell {
				return nil, errCellType
			}
			boxed := cell[BODY:n]
			body, ok := c.Decrypt(boxed)
			if !ok {
				return nil, errors.New("Misauthenticated ciphertext")
			}
			bytes += copy(msg[bytes:], body)
		}
		return msg, nil
	} else {
		return nil, nil
	}
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
