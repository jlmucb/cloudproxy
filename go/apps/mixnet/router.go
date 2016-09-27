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
	conns    map[string]*Conn
	circuits map[uint64]*Conn
	nextIds  map[uint64]uint64
	prevIds  map[uint64]uint64
	// If this server is an entry or exit for this circuit
	entry map[uint64]bool
	exit  map[uint64]bool

	mapLock *sync.RWMutex

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

	hp.conns = make(map[string]*Conn)
	hp.circuits = make(map[uint64]*Conn)
	hp.nextIds = make(map[uint64]uint64)
	hp.prevIds = make(map[uint64]uint64)
	hp.entry = make(map[uint64]bool)
	hp.exit = make(map[uint64]bool)

	hp.mapLock = new(sync.RWMutex)

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
	hp.conns[addr] = conn
	go hp.handleConn(conn, false)
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
	for _, conn := range hp.conns {
		for _, circuit := range conn.circuits {
			close(circuit.cells)
		}
		conn.Close()
	}
}

// Return a random circuit ID
// TODO(kwonalbert): probably won't happen, but should check for duplicates
func (p *RouterContext) newID() (uint64, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	id := binary.LittleEndian.Uint64(b)
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
// is done in handleMessages
func (hp *RouterContext) handleConn(c *Conn, withProxy bool) {
	for {
		var err error
		cell := make([]byte, CellBytes)
		if _, err = c.Read(cell); err != nil {
			if err == io.EOF {
				hp.errs <- nil
				break
			} else {
				hp.errs <- err
				break
			}
		}

		id := getID(cell)
		hp.replyQueue.SetConn(id, c)
		hp.replyQueue.SetAddr(id, c.RemoteAddr().String())

		hp.mapLock.RLock()
		prevId := hp.prevIds[id]
		nextId := hp.nextIds[id]
		isExit := hp.exit[id]
		hp.mapLock.RUnlock()

		if cell[TYPE] == msgCell {
			if !isExit {
				binary.LittleEndian.PutUint64(cell[ID:], nextId)
				hp.sendQueue.EnqueueMsg(nextId, id, cell)
			} else {
				c.circuits[id].cells <- Cell{cell, err}
			}
		} else if cell[TYPE] == dirCell { // Handle a directive.
			var d Directive
			if err = unmarshalDirective(cell, &d); err != nil {
				hp.errs <- err
				break
			}

			// relay the errors back to users
			if *d.Type == DirectiveType_ERROR {
				binary.LittleEndian.PutUint64(cell[ID:], prevId)
				hp.replyQueue.EnqueueMsg(prevId, 0, cell)
			} else if *d.Type == DirectiveType_CREATE {
				err := hp.handleCreate(d, c, withProxy, id)
				if err != nil {
					hp.errs <- err
					break
				}
			} else if *d.Type == DirectiveType_DESTROY {
				err := hp.handleDestroy(d, c, isExit, id, nextId)
				if err != nil {
					hp.errs <- err
					break
				}
			} else if *d.Type == DirectiveType_CREATED {
				// Simply relay created back
				cell, err = marshalDirective(prevId, dirCreated)
				if err != nil {
					hp.errs <- err
					break
				}
				hp.replyQueue.EnqueueMsg(prevId, 0, cell)
			} else if *d.Type == DirectiveType_DESTROYED {
				// Close the forward circuit if it's an exit or empty now
				hp.mapLock.RLock()
				// == 1 because we haven't removed the circuit yet
				empty := !isExit && len(hp.circuits[id].circuits) == 1
				hp.mapLock.RUnlock()
				hp.sendQueue.Close(id, nil, empty)

				// Relay back destroyed
				cell, err = marshalDirective(prevId, dirDestroyed)
				if err != nil {
					hp.errs <- err
					break
				}
				hp.delete(c, id)
				hp.replyQueue.Close(prevId, cell, len(c.circuits) == 0)
			}
		} else { // Unknown cell type, return an error.
			if err = hp.SendError(id, errBadCellType); err != nil {
				hp.errs <- err
				break
			}
		}
		// (kwonalbert) This is done to make testing easier;
		// Easier to count cells by getting the number of errs
		hp.errs <- nil
	}
}

func (hp *RouterContext) handleCreate(d Directive, c *Conn, entry bool, id uint64) error {
	hp.mapLock.Lock()
	newId, err := hp.newID()
	hp.nextIds[id] = newId
	hp.prevIds[newId] = id

	// Add next hop for this circuit to sendQueue and send a CREATED
	// directive to sender to inform the sender.
	if len(d.Addrs) == 0 {
		if err := hp.SendError(id, errBadDirective); err != nil {
			return err
		}
	}

	c.circuits[id] = Circuit{make(chan Cell)}
	go hp.handleMessages(c.circuits[id], id, newId)

	hp.entry[id] = entry

	hp.sendQueue.SetAddr(newId, d.Addrs[0])

	// Relay the CREATE message
	if len(d.Addrs) > 1 {
		hp.exit[id] = false
		if err != nil {
			hp.mapLock.Unlock()
			return err
		}
		var nextConn *Conn
		if _, ok := hp.conns[d.Addrs[0]]; !ok {
			nextConn, err = hp.DialRouter(hp.network, d.Addrs[0])
			if err != nil {
				hp.mapLock.Unlock()
				if e := hp.SendError(id, err); e != nil {
					return e
				}
			}
		} else {
			nextConn = hp.conns[d.Addrs[0]]
		}
		nextConn.circuits[newId] = Circuit{make(chan Cell)}
		hp.circuits[newId] = nextConn
		hp.sendQueue.SetConn(newId, nextConn)

		dir := &Directive{
			Type:  DirectiveType_CREATE.Enum(),
			Addrs: d.Addrs[1:],
		}
		nextCell, err := marshalDirective(newId, dir)
		if err != nil {
			hp.mapLock.Unlock()
			return err
		}
		hp.sendQueue.EnqueueMsg(newId, id, nextCell)
	} else {
		hp.exit[id] = true
		// Tell the previous hop (proxy or router) it's created
		cell, err := marshalDirective(id, dirCreated)
		if err != nil {
			hp.mapLock.Unlock()
			return err
		}
		hp.replyQueue.EnqueueMsg(id, 0, cell)
	}
	hp.mapLock.Unlock()
	return nil
}

func (hp *RouterContext) handleDestroy(d Directive, c *Conn, exit bool, id, nextId uint64) error {
	// Close the connection if you are an exit for this circuit
	if exit {
		// Send back destroyed msg
		cell, err := marshalDirective(id, dirDestroyed)
		if err != nil {
			return err
		}
		hp.delete(c, id)
		hp.replyQueue.Close(id, cell, len(c.circuits) == 0)
		hp.sendQueue.Close(nextId, nil, exit)
	} else {
		nextCell, err := marshalDirective(nextId, dirDestroy)
		if err != nil {
			return err
		}
		hp.sendQueue.EnqueueMsg(nextId, id, nextCell)
	}
	return nil
}

// Handles messages coming in on a circuit.
// The directives are handled in handleConn
func (hp *RouterContext) handleMessages(circ Circuit, id, nextId uint64) {
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

		msgBytes := binary.LittleEndian.Uint64(cell[BODY:])
		if msgBytes > MaxMsgBytes {
			if err = hp.SendError(id, errMsgLength); err != nil {
				hp.errs <- err
				return
			}
			return
		}

		msg := make([]byte, msgBytes)
		bytes := copy(msg, cell[BODY+LEN_SIZE:])

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
					hp.errs <- err
					return
				}
			}
			bytes += copy(msg[bytes:], cell[BODY:])
		}

		// Wait for a message from the destination, divide it into cells,
		// and add the cells to replyQueue.
		reply := make(chan []byte)
		hp.sendQueue.EnqueueMsgReply(nextId, id, msg, reply)

		msg = <-reply
		if msg != nil {
			tao.ZeroBytes(cell)
			binary.LittleEndian.PutUint64(cell[ID:], id)
			msgBytes := len(msg)

			cell[TYPE] = msgCell
			binary.LittleEndian.PutUint64(cell[BODY:], uint64(msgBytes))
			bytes := copy(cell[BODY+LEN_SIZE:], msg)
			hp.replyQueue.EnqueueMsg(id, 0, cell)

			for bytes < msgBytes {
				tao.ZeroBytes(cell)
				binary.LittleEndian.PutUint64(cell[ID:], id)
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

func (hp *RouterContext) delete(c *Conn, id uint64) {
	// TODO(kwonalbert) Check that this circuit is
	// actually on this conn
	hp.mapLock.Lock()
	close(c.circuits[id].cells)
	delete(c.circuits, id)
	delete(hp.entry, id)
	delete(hp.exit, id)
	if len(c.circuits) == 0 {
		delete(hp.conns, c.RemoteAddr().String())
		delete(hp.circuits, id)
		delete(hp.nextIds, id)
		delete(hp.prevIds, id)
	}
	hp.mapLock.Unlock()
}
