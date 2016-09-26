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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
)

// RouterContext stores the runtime environment for a Tao-delegated router.
type RouterContext struct {
	keys           *tao.Keys    // Signing keys of this hosted program.
	domain         *tao.Domain  // Policy guard and public key.
	proxyListener  net.Listener // Socket where server listens for proxies.
	routerListener net.Listener // Socket where server listens for proxies.

	// Data structures for queueing and batching messages from sender to
	// recipient and recipient to sender respectively.
	sendQueue  *Queue
	replyQueue *Queue

	// Connections to next hop routers
	conns struct {
		sync.RWMutex
		m map[string]*Conn
	}
	circuits struct {
		sync.RWMutex
		m map[uint64]*Conn
	}
	nextIds struct {
		sync.RWMutex
		m map[uint64]uint64
	}
	// If this server is an entry or exit for this circuit
	entry struct {
		sync.RWMutex
		m map[uint64]bool
	}
	exit struct {
		sync.RWMutex
		m map[uint64]bool
	}

	// The queues and error handlers are instantiated as go routines; these
	// channels are for tearing them down.
	killQueue             chan bool
	killQueueErrorHandler chan bool

	network string        // Network protocol, e.g. "tcp"
	timeout time.Duration // Timeout on read/write/dial.

	errs chan error
}

// NewRouterContext generates new keys, loads a local domain configuration from
// path and binds an anonymous listener socket to addr using network protocol.
// It also creates a regular listener socket for other routers to connect to.
// A delegation is requested from the Tao t which is  nominally
// the parent of this hosted program.
func NewRouterContext(path, network, addr1, addr2 string, batchSize int, timeout time.Duration,
	x509Identity *pkix.Name, t tao.Tao) (hp *RouterContext, err error) {

	hp = new(RouterContext)
	hp.network = network
	hp.timeout = timeout

	hp.conns = struct {
		sync.RWMutex
		m map[string]*Conn
	}{m: make(map[string]*Conn)}
	hp.circuits = struct {
		sync.RWMutex
		m map[uint64]*Conn
	}{m: make(map[uint64]*Conn)}
	hp.nextIds = struct {
		sync.RWMutex
		m map[uint64]uint64
	}{m: make(map[uint64]uint64)}
	hp.entry = struct {
		sync.RWMutex
		m map[uint64]bool
	}{m: make(map[uint64]bool)}
	hp.exit = struct {
		sync.RWMutex
		m map[uint64]bool
	}{m: make(map[uint64]bool)}

	hp.errs = make(chan error)

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

	tlsConfigProxy := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*cert},
		InsecureSkipVerify: true,
	}

	tlsConfigRouter := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*cert},
		InsecureSkipVerify: true,
	}

	// Bind address to socket.
	if hp.proxyListener, err = tao.ListenAnonymous(network, addr1, tlsConfigProxy,
		hp.domain.Guard, hp.domain.Keys.VerifyingKey, hp.keys.Delegation); err != nil {
		return nil, err
	}

	// Different listener, since mixes should be authenticated
	if hp.routerListener, err = tao.Listen(network, addr2, tlsConfigRouter,
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
	conn := &Conn{c, hp.timeout, make(map[uint64]Circuit)}
	go hp.handleConn(conn, true)
	return conn, nil
}

// AcceptRouter Waits for connectons from other routers.
func (hp *RouterContext) AcceptRouter() (*Conn, error) {
	c, err := hp.routerListener.Accept()
	if err != nil {
		return nil, err
	}
	conn := &Conn{c, hp.timeout, make(map[uint64]Circuit)}
	go hp.handleConn(conn, false)
	return conn, nil
}

// DialRouter connects to a remote Tao-delegated mixnet router.
func (hp *RouterContext) DialRouter(network, addr string) (*Conn, error) {
	c, err := tao.Dial(network, addr, hp.domain.Guard, hp.domain.Keys.VerifyingKey, hp.keys)
	if err != nil {
		return nil, err
	}
	conn := &Conn{c, hp.timeout, make(map[uint64]Circuit)}
	hp.conns.Lock()
	hp.conns.m[addr] = conn
	hp.conns.Unlock()

	return conn, nil
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
	if hp.routerListener != nil {
		hp.routerListener.Close()
	}
	hp.conns.RLock()
	for _, conn := range hp.conns.m {
		for _, circuit := range conn.circuits {
			close(circuit.cells)
		}
		conn.Close()
	}
	hp.conns.RUnlock()
}

// Return a random circuit ID
// TODO(kwonalbert): probably won't happen, but should check for duplicates
func (p *RouterContext) newID() (uint64, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	id, _ := binary.Uvarint(b)
	return id, nil
}

// Handle errors internal to the router
// When instantiating a real router (not for testing),
// one start this function as well to handle the errors
func (hp *RouterContext) HandleErr() {
	for {
		err := <-hp.errs
		if err != nil {
			// TODO(kwonalbert) Handle errors properly
		}
	}
}

// handleConn reads a directive or a message from a proxy.
// Handling directives is done here, but actually receiving the messages
// is done in handleCircuit
func (hp *RouterContext) handleConn(c *Conn, withProxy bool) {
	for {
		var err error
		cell := make([]byte, CellBytes)
		if _, err = c.Read(cell); err != nil {
			hp.errs <- err
			if err == io.EOF {
				hp.errs <- err
				return
			}
		}

		id := getID(cell)

		hp.replyQueue.SetConn(id, c)
		hp.replyQueue.SetAddr(id, c.RemoteAddr().String())

		if cell[TYPE] == msgCell {
			c.circuits[id].cells <- Cell{cell, err}
		} else if cell[TYPE] == dirCell { // Handle a directive.
			var d Directive
			if err = unmarshalDirective(cell, &d); err != nil {
				hp.errs <- err
				return
			}
			if *d.Type == DirectiveType_ERROR {
				hp.errs <- errors.New("router error: " + (*d.Error))
				return
			}

			if *d.Type == DirectiveType_CREATE {
				// Add next hop for this circuit to sendQueue and send a CREATED
				// directive to sender to inform the sender.
				if len(d.Addrs) == 0 {
					if err = hp.SendError(id, errBadDirective); err != nil {
						hp.errs <- err
					}
					return
				}

				c.circuits[id] = Circuit{make(chan Cell)}
				go hp.handleCircuit(c.circuits[id])

				newId, err := hp.newID()
				hp.nextIds.Lock()
				hp.nextIds.m[id] = newId
				hp.nextIds.Unlock()

				hp.sendQueue.SetAddr(newId, d.Addrs[0])

				hp.entry.Lock()
				hp.entry.m[id] = withProxy
				hp.entry.Unlock()
				// Relay the CREATE message
				if len(d.Addrs) > 1 {
					if err != nil {
						hp.errs <- err
						return
					}
					var nextConn *Conn
					hp.conns.RLock()
					_, ok := hp.conns.m[d.Addrs[0]]
					hp.conns.RUnlock()
					if !ok {
						nextConn, err = hp.DialRouter(hp.network, d.Addrs[0])
						if err != nil {
							if e := hp.SendError(id, err); e != nil {
								hp.errs <- e
							}
							return
						}
					} else {
						hp.conns.Lock()
						nextConn = hp.conns.m[d.Addrs[0]]
						hp.conns.Unlock()
					}
					nextConn.circuits[newId] = Circuit{make(chan Cell)}
					hp.circuits.Lock()
					hp.circuits.m[newId] = nextConn
					hp.circuits.Unlock()
					hp.sendQueue.SetConn(newId, nextConn)

					dir := &Directive{
						Type:  DirectiveType_CREATE.Enum(),
						Addrs: d.Addrs[1:],
					}
					nextCell, err := marshalDirective(newId, dir)
					if err != nil {
						hp.errs <- err
						return
					}

					hp.sendQueue.EnqueueMsg(newId, id, nextCell)
					hp.exit.Lock()
					hp.exit.m[id] = false
					hp.exit.Unlock()
				} else {
					hp.exit.Lock()
					hp.exit.m[id] = true
					hp.exit.Unlock()
				}

				// Tell the previous hop (proxy or router) it's created
				cell, err = marshalDirective(id, dirCreated)
				if err != nil {
					hp.errs <- err
					return
				}
				hp.replyQueue.EnqueueMsg(id, 0, cell)
			} else if *d.Type == DirectiveType_DESTROY {
				// Close the connection if you are an exit for this circuit
				hp.nextIds.RLock()
				nextId := hp.nextIds.m[id]
				hp.nextIds.RUnlock()

				hp.circuits.RLock()
				noCircuits := hp.circuits.m[nextId] != nil &&
					len(hp.circuits.m[nextId].circuits) == 0
				hp.circuits.RUnlock()

				hp.exit.RLock()
				isExit := hp.exit.m[id]
				hp.exit.RUnlock()

				destroy := noCircuits || isExit
				hp.sendQueue.Close(nextId, nil, destroy)

				// Send back destroyed msg
				cell, err = marshalDirective(id, dirDestroyed)
				if err != nil {
					hp.errs <- err
					return
				}
				hp.replyQueue.Close(id, cell, len(c.circuits) == 0)

				// TODO(kwonalbert) Check that this circuit is
				// actually on this conn
				close(c.circuits[id].cells)
				delete(c.circuits, id)
				hp.entry.Lock()
				delete(hp.entry.m, id)
				hp.entry.Unlock()
				hp.exit.Lock()
				delete(hp.exit.m, id)
				hp.exit.Unlock()
				if len(c.circuits) == 0 {
					hp.conns.Lock()
					delete(hp.conns.m, c.RemoteAddr().String())
					hp.conns.Unlock()
					hp.circuits.Lock()
					delete(hp.circuits.m, id)
					hp.circuits.Unlock()
					hp.nextIds.Lock()
					delete(hp.nextIds.m, id)
					hp.nextIds.Unlock()
				}
			}
		} else { // Unknown cell type, return an error.
			if err = hp.SendError(id, errBadCellType); err != nil {
				hp.errs <- err
				return
			}
		}
		// (kwonalbert) This is done to make testing easier;
		// Easier to count cells by getting the number of errs
		hp.errs <- nil
	}
}

// Handles messages coming in on a circuit.
// The directives are handled in handleConn
func (hp *RouterContext) handleCircuit(circ Circuit) {
	for {
		read, ok := <-circ.cells
		if !ok {
			return
		}
		cell := read.cell
		err := read.err

		if err != nil {
			return
		}

		id := getID(cell)

		// If this router is an exit point, then read cells until the whole
		// message is assembled and add it to sendQueue. If this router is
		// a relay (not implemented), then just add the cell to the
		// sendQueue.
		msgBytes, n := binary.Uvarint(cell[BODY:])
		if msgBytes > MaxMsgBytes {
			if err = hp.SendError(id, errMsgLength); err != nil {
				// TODO(kwonalbert) handle this error
				return
			}
			return
		}

		msg := make([]byte, msgBytes)
		bytes := copy(msg, cell[BODY+n:])

		// While the connection is open and the message is incomplete, read
		// the next cell.
		for err != io.EOF && uint64(bytes) < msgBytes {
			read, ok = <-circ.cells
			if !ok {
				return
			}
			cell = read.cell
			err = read.err
			if err != nil {
				return
			} else if cell[TYPE] != msgCell {
				if err = hp.SendError(id, errCellType); err != nil {
					// TODO(kwonalbert) handle this error
					return
				}
			}
			bytes += copy(msg[bytes:], cell[BODY:])
		}

		// Wait for a message from the destination, divide it into cells,
		// and add the cells to replyQueue.
		reply := make(chan []byte)
		hp.nextIds.RLock()
		nextId := hp.nextIds.m[id]
		hp.nextIds.RUnlock()
		hp.sendQueue.EnqueueMsgReply(nextId, id, msg, reply)

		msg = <-reply
		if msg != nil {
			tao.ZeroBytes(cell)
			binary.PutUvarint(cell[ID:], id)
			msgBytes := len(msg)

			cell[TYPE] = msgCell
			n := binary.PutUvarint(cell[BODY:], uint64(msgBytes))
			bytes := copy(cell[BODY+n:], msg)
			hp.replyQueue.EnqueueMsg(id, 0, cell)

			for bytes < msgBytes {
				tao.ZeroBytes(cell)
				binary.PutUvarint(cell[ID:], id)
				cell[TYPE] = msgCell
				bytes += copy(cell[BODY:], msg[bytes:])
				hp.replyQueue.EnqueueMsg(id, 0, cell)
			}
		}
	}
}

// SendError sends an error message to a client.
func (hp *RouterContext) SendError(id uint64, err error) error {
	var d Directive
	d.Type = DirectiveType_ERROR.Enum()
	d.Error = proto.String(err.Error())
	cell, err := marshalDirective(id, &d)
	if err != nil {
		return err
	}
	hp.replyQueue.EnqueueMsg(id, 0, cell)
	return nil
}
