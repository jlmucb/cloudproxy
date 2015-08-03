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
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
)

// RouterContext stores the runtime environment for a Tao-delegated router.
type RouterContext struct {
	keys          *tao.Keys    // Signing keys of this hosted program.
	domain        *tao.Domain  // Policy guard and public key.
	proxyListener net.Listener // Socket where server listens for proxies.

	id uint64 // Next serial identifier that will be assigned to a connection.

	// Data structures for queueing and batching messages from sender to
	// recipient and recipient to sender respectively.
	sendQueue  *Queue
	replyQueue *Queue

	// The queues and error handlers are instantiated as go routines; these
	// channels are for tearing them down.
	killQueue             chan bool
	killQueueErrorHandler chan bool

	network string        // Network protocol, e.g. "tcp"
	timeout time.Duration // Timeout on read/write/dial.
}

// NewRouterContext generates new keys, loads a local domain configuration from
// path and binds an anonymous listener socket to addr on network
// network. A delegation is requested from the Tao t which is  nominally
// the parent of this hosted program.
func NewRouterContext(path, network, addr string, batchSize int, timeout time.Duration,
	x509Identity *pkix.Name, t tao.Tao) (hp *RouterContext, err error) {

	hp = new(RouterContext)
	hp.network = network
	hp.timeout = timeout

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

	// Instantiate the queues.
	hp.sendQueue = NewQueue(network, batchSize, timeout)
	hp.replyQueue = NewQueue(network, batchSize, timeout)
	hp.killQueue = make(chan bool)
	hp.killQueueErrorHandler = make(chan bool)
	go hp.sendQueue.DoQueue(hp.killQueue)
	go hp.replyQueue.DoQueue(hp.killQueue)
	go hp.sendQueue.DoQueueErrorHandler(hp.replyQueue, hp.killQueueErrorHandler)
	go hp.replyQueue.DoQueueErrorHandlerLog("reply queue", hp.killQueueErrorHandler)

	return hp, nil
}

// AcceptProxy Waits for connectons from proxies.
func (hp *RouterContext) AcceptProxy() (*Conn, error) {
	c, err := hp.proxyListener.Accept()
	if err != nil {
		return nil, err
	}
	return &Conn{c, hp.nextID()}, nil
}

// Close releases any resources held by the hosted program.
func (hp *RouterContext) Close() {
	hp.killQueue <- true
	hp.killQueue <- true
	hp.killQueueErrorHandler <- true
	hp.killQueueErrorHandler <- true
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

	hp.replyQueue.SetConn(c.id, c)
	hp.replyQueue.SetAddr(c.id, c.RemoteAddr().String())

	if cell[0] == msgCell {
		// If this router is an exit point, then read cells until the whole
		// message is assembled and add it to sendQueue. If this router is
		// a relay (not implemented), then just add the cell to the
		// sendQueue.
		msgBytes, n := binary.Uvarint(cell[1:])
		if msgBytes > MaxMsgBytes {
			if err = hp.SendError(c, errMsgLength); err != nil {
				return err
			}
			return nil
		}

		msg := make([]byte, msgBytes)
		bytes := copy(msg, cell[1+n:])

		// While the connection is open and the message is incomplete, read
		// the next cell.
		for err != io.EOF && uint64(bytes) < msgBytes {
			if _, err = c.Read(cell); err != nil && err != io.EOF {
				return err
			} else if cell[0] != msgCell {
				return errCellType
			}
			bytes += copy(msg[bytes:], cell[1:])
		}

		// Wait for a message from the destination, divide it into cells,
		// and add the cells to replyQueue.
		reply := make(chan []byte)
		hp.sendQueue.EnqueueMsgReply(c.id, msg, reply)

		msg = <-reply
		if msg != nil {
			zeroCell(cell)
			msgBytes := len(msg)

			cell[0] = msgCell
			n := binary.PutUvarint(cell[1:], uint64(msgBytes))
			bytes := copy(cell[1+n:], msg)
			hp.replyQueue.EnqueueMsg(c.id, cell)

			for bytes < msgBytes {
				zeroCell(cell)
				cell[0] = msgCell
				bytes += copy(cell[1:], msg[bytes:])
				hp.replyQueue.EnqueueMsg(c.id, cell)
			}
		}

	} else if cell[0] == dirCell { // Handle a directive.
		dirBytes, n := binary.Uvarint(cell[1:])
		var d Directive
		if err := proto.Unmarshal(cell[1+n:1+n+int(dirBytes)], &d); err != nil {
			return err
		}

		if *d.Type == DirectiveType_CREATE {
			// Add next hop for this circuit to sendQueue and send a CREATED
			// directive to sender to inform the sender. TODO(cjpatton) For
			// now, only single hop circuits are supported.
			if len(d.Addrs) == 0 {
				if err = hp.SendError(c, errBadDirective); err != nil {
					return err
				}
				return nil
			}
			if len(d.Addrs) > 1 {
				if err = hp.SendError(c, errors.New("multi-hop circuits not implemented")); err != nil {
					return err
				}
				return nil
			}

			hp.sendQueue.SetAddr(c.id, d.Addrs[0])
			cell, err = marshalDirective(dirCreated)
			if err != nil {
				return err
			}
			hp.replyQueue.EnqueueMsg(c.id, cell)

		} else if *d.Type == DirectiveType_DESTROY {
			// TODO(cjpatton) when multi-hop circuits are implemented, send
			// a DESTROY directive to the next hop and wait for DESTROYED in
			// response. For now, just close the connection to the circuit.
			hp.sendQueue.Close(c.id)
			hp.replyQueue.Close(c.id)
			return io.EOF
		}

	} else { // Unknown cell type, return an error.
		if err = hp.SendError(c, errBadCellType); err != nil {
			return err
		}
	}

	return nil
}

// SendError sends an error message to a client.
func (hp *RouterContext) SendError(c *Conn, err error) error {
	var d Directive
	d.Type = DirectiveType_ERROR.Enum()
	d.Error = proto.String(err.Error())
	cell, err := marshalDirective(&d)
	if err != nil {
		return err
	}
	hp.replyQueue.EnqueueMsg(c.id, cell)
	return nil
}

// Get the next Id to assign and increment counter.
// TODO(cjpatton) AcceptRouter() will wait for connections from other mixnet
// routers when multi-hop circuits are implemented. This will need mutual
// exclusion when that happens.
func (hp *RouterContext) nextID() (id uint64) {
	id = hp.id
	hp.id++
	return id
}
