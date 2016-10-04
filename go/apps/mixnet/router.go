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
	keys     *tao.Keys    // Signing keys of this hosted program.
	domain   *tao.Domain  // Policy guard and public key.
	listener net.Listener // Socket where server listens for proxies/routers

	// Data structures for queueing and batching messages
	queue     *Queue
	proxyReq  *Queue
	proxyResp *Queue

	// Connections to next hop routers
	conns map[string]*Conn
	// Maps circuit id to next hop connections
	circuits map[uint64]*Conn
	// Mapping id to next hop circuit id or prev hop circuit id
	nextIds map[uint64]uint64
	prevIds map[uint64]uint64
	// If this server is an entry or exit for this circuit
	entry map[uint64]bool
	exit  map[uint64]bool

	directory []string

	mapLock *sync.RWMutex

	// The queues and error handlers are instantiated as go routines; these
	// channels are for tearing them down.
	killQueue             chan bool
	killQueueErrorHandler chan bool

	network string        // Network protocol, e.g. "tcp"
	timeout time.Duration // Timeout on read/write/dial.

	errs chan error
	done chan bool
}

// NewRouterContext generates new keys, loads a local domain configuration from
// path and binds an anonymous listener socket to addr using network protocol.
// It also creates a regular listener socket for other routers to connect to.
// A delegation is requested from the Tao t which is  nominally
// the parent of this hosted program.
func NewRouterContext(path, network, addr string, batchSize int, timeout time.Duration,
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
	hp.done = make(chan bool)

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
		ClientAuth:         tls.RequestClientCert,
	}

	if hp.listener, err = Listen(network, addr, tlsConfig,
		hp.domain.Guard, hp.domain.Keys.VerifyingKey, hp.keys.Delegation); err != nil {
		return nil, err
	}

	// Instantiate the queues.
	hp.queue = NewQueue(network, batchSize, timeout)
	hp.proxyReq = NewQueue(network, batchSize, timeout)
	hp.proxyResp = NewQueue(network, batchSize, timeout)
	hp.killQueue = make(chan bool)
	hp.killQueueErrorHandler = make(chan bool)
	go hp.queue.DoQueue(hp.killQueue)
	go hp.proxyReq.DoQueue(hp.killQueue)
	go hp.proxyResp.DoQueue(hp.killQueue)
	go hp.queue.DoQueueErrorHandler(hp.queue, hp.killQueueErrorHandler)
	go hp.proxyReq.DoQueueErrorHandler(hp.queue, hp.killQueueErrorHandler)
	go hp.proxyResp.DoQueueErrorHandler(hp.queue, hp.killQueueErrorHandler)

	return hp, nil
}

// AcceptRouter Waits for connectons from other routers.
func (hp *RouterContext) Accept() (*Conn, error) {
	c, err := hp.listener.Accept()
	if err != nil {
		return nil, err
	}
	id, err := hp.newConnID()
	if err != nil {
		return nil, err
	}
	conn := &Conn{c, id, hp.timeout, make(map[uint64]Circuit), new(sync.RWMutex), true}
	if len(c.(*tls.Conn).ConnectionState().PeerCertificates) > 0 {
		conn.withProxy = false
	}
	go hp.handleConn(conn)
	return conn, nil
}

// DialRouter connects to a remote Tao-delegated mixnet router.
func (hp *RouterContext) DialRouter(network, addr string) (*Conn, error) {
	c, err := tao.Dial(network, addr, hp.domain.Guard, hp.domain.Keys.VerifyingKey, hp.keys)
	if err != nil {
		return nil, err
	}
	id, err := hp.newConnID()
	if err != nil {
		return nil, err
	}
	conn := &Conn{c, id, hp.timeout, make(map[uint64]Circuit), new(sync.RWMutex), false}
	hp.conns[addr] = conn
	go hp.handleConn(conn)
	return conn, nil
}

// Register the current router to a directory server
func (hp *RouterContext) Register(dirAddr string) error {
	c, err := tao.Dial(hp.network, dirAddr, hp.domain.Guard, hp.domain.Keys.VerifyingKey, hp.keys)
	if err != nil {
		return err
	}
	err = RegisterRouter(c, []string{hp.listener.Addr().String()})
	if err != nil {
		return err
	}
	return c.Close()

}

// Read the directory from a directory server
func (hp *RouterContext) GetDirectory(dirAddr string) error {
	c, err := tao.Dial(hp.network, dirAddr, hp.domain.Guard, hp.domain.Keys.VerifyingKey, hp.keys)
	if err != nil {
		return err
	}
	directory, err := GetDirectory(c)
	if err != nil {
		return err
	}
	hp.directory = directory
	return c.Close()
}

// Close releases any resources held by the hosted program.
func (hp *RouterContext) Close() {
	hp.killQueue <- true
	hp.killQueue <- true
	hp.killQueue <- true
	hp.killQueueErrorHandler <- true
	hp.killQueueErrorHandler <- true
	hp.killQueueErrorHandler <- true
	if hp.listener != nil {
		hp.listener.Close()
	}
	for _, conn := range hp.conns {
		hp.done <- true
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

// Return a random connection ID
// TODO(kwonalbert): should check for duplicates
func (hp *RouterContext) newConnID() (uint32, error) {
	id := uint32(0)
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	id = binary.LittleEndian.Uint32(b)
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

// handleConn reads a directive or a message from a proxy. The directives
// are handled here, but actual messages are handled in handleMessages
func (hp *RouterContext) handleConn(c *Conn) {
	for {
		var err error
		cell := make([]byte, CellBytes)
		if _, err = c.Read(cell); err != nil {
			if err == io.EOF {
				break
			} else {
				select {
				case <-hp.done: // Indicate this is done
				case hp.errs <- err:
				}
				break
			}
		}

		id := getID(cell)
		hp.mapLock.RLock()
		prevId := hp.prevIds[id]
		nextId, forward := hp.nextIds[id]
		exit := hp.exit[id]
		nextConn := hp.circuits[nextId]
		prevConn := hp.circuits[prevId]
		sendQ, respQ := hp.queue, hp.queue
		sId, rId := nextId, prevId
		// if connecting to proxy, queue based on connection id, not circuit
		if c.withProxy {
			sendQ = hp.proxyReq
			respQ = hp.proxyResp
			sId = uint64(c.id)
			rId = uint64(c.id)
		}
		if hp.entry[prevId] {
			respQ = hp.proxyResp
			rId = uint64(prevConn.id)
		} else if exit {
			rId = id
		}
		hp.mapLock.RUnlock()

		if cell[TYPE] == msgCell {
			if !exit { // if it's not exit, just relay the cell
				if forward {
					binary.LittleEndian.PutUint64(cell[ID:], nextId)
					sendQ.EnqueueMsg(sId, cell, nextConn, c)
				} else {
					binary.LittleEndian.PutUint64(cell[ID:], prevId)
					respQ.EnqueueMsg(rId, cell, prevConn, c)
				}
			} else { // actually handle the message
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
				respQ.EnqueueMsg(rId, cell, prevConn, c)
			} else if *d.Type == DirectiveType_CREATE {
				err := hp.handleCreate(d, c, c.withProxy, id, sendQ, respQ, sId, rId)
				if err != nil {
					hp.errs <- err
					break
				}
			} else if *d.Type == DirectiveType_DESTROY {
				err := hp.handleDestroy(d, c, nextConn, exit, id, nextId,
					sendQ, respQ, sId, rId)
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
				respQ.EnqueueMsg(rId, cell, prevConn, c)
			} else if *d.Type == DirectiveType_DESTROYED {
				// Close the forward circuit if it's an exit or empty now
				hp.mapLock.RLock()
				// == 1 because we haven't removed the circuit yet
				empty := !exit && len(hp.circuits[id].circuits) == 1
				hp.mapLock.RUnlock()
				sendQ.Close(sId, nil, empty, c, prevConn)

				// Relay back destroyed
				cell, err = marshalDirective(prevId, dirDestroyed)
				if err != nil {
					hp.errs <- err
					break
				}
				empty = hp.delete(c, id, prevId)
				respQ.Close(rId, cell, empty, prevConn, nil)
			}
		} else { // Unknown cell type, return an error.
			if err = hp.SendError(respQ, rId, id, errBadCellType, c); err != nil {
				hp.errs <- err
				break
			}
		}
		// Sending nil err makes testing easier;
		// Easier to count cells by getting the number of errs
		hp.errs <- nil
		c.cLock.RLock()
		if len(c.circuits) == 0 { // empty connection
			break
		}
		c.cLock.RUnlock()
	}
}

func member(s string, set []string) bool {
	for _, member := range set {
		if member == s {
			return true
		}
	}
	return false
}

// handleCreated handles the create directive by either relaying it on
// (which opens a new connection), or sending back created directive
// if this is an exit.
func (hp *RouterContext) handleCreate(d Directive, c *Conn, entry bool, id uint64,
	sendQ, respQ *Queue, sId, rId uint64) error {
	hp.mapLock.Lock()
	newId, err := hp.newID()
	hp.nextIds[id] = newId
	hp.prevIds[newId] = id

	if entry {
		// Pick a fresh path of the same length
		// Random selection without replacement
		directory := make([]string, len(hp.directory))
		copy(directory, hp.directory)
		for _, router := range d.Addrs {
			for i, addr := range directory {
				if addr == router {
					directory[i] = directory[len(directory)-1]
					directory = directory[:len(directory)-1]
					break
				}
			}
		}
		for i := 1; i < len(d.Addrs)-1; i++ {
			if d.Addrs[i] != "" {
				continue
			}
			b := make([]byte, LEN_SIZE)
			if _, err := rand.Read(b); err != nil {
				return err
			}
			idx := int(binary.LittleEndian.Uint32(b)) % len(directory)
			d.Addrs[i] = directory[idx]
			directory[idx] = directory[len(directory)-1]
			directory = directory[:len(directory)-1]
		}
	}

	c.circuits[id] = Circuit{make(chan Cell)}

	hp.circuits[id] = c
	hp.entry[id] = entry

	// Add next hop for this circuit to queue and send a CREATED
	// directive to sender to inform the sender.
	relayIdx := -1
	for i, addr := range d.Addrs {
		if addr == hp.listener.Addr().String() {
			relayIdx = i
		}
	}
	if relayIdx != len(d.Addrs)-2 { // last element is the final dest, so check -2
		// Relay the CREATE message
		hp.exit[id] = false
		if err != nil {
			hp.mapLock.Unlock()
			return err
		}
		var nextConn *Conn
		if _, ok := hp.conns[d.Addrs[relayIdx+1]]; !ok {
			nextConn, err = hp.DialRouter(hp.network, d.Addrs[relayIdx+1])
			nextConn.cLock.Lock()
			if err != nil {
				hp.mapLock.Unlock()
				if e := hp.SendError(respQ, rId, id, err, c); e != nil {
					return e
				}
			}
		} else {
			nextConn = hp.conns[d.Addrs[relayIdx+1]]
			nextConn.cLock.Lock()
		}
		nextConn.circuits[newId] = Circuit{make(chan Cell)}
		nextConn.cLock.Unlock()
		hp.circuits[newId] = nextConn

		dir := &Directive{
			Type:  DirectiveType_CREATE.Enum(),
			Addrs: d.Addrs,
		}
		nextCell, err := marshalDirective(newId, dir)
		if err != nil {
			hp.mapLock.Unlock()
			return err
		}
		// middle node, then just queue to the generic queue, not one of the proxy queue
		if !entry {
			sId = newId
		}
		sendQ.EnqueueMsg(sId, nextCell, nextConn, c)
	} else {
		// Response id should be just id here not rId if it's not an entry
		if !entry {
			sId = newId
			rId = id
		}
		go hp.handleMessages(d.Addrs[len(d.Addrs)-1], c.circuits[id], id, newId, c, sendQ, respQ, sId, rId)
		hp.exit[id] = true
		// Tell the previous hop (proxy or router) it's created
		cell, err := marshalDirective(id, dirCreated)
		if err != nil {
			hp.mapLock.Unlock()
			return err
		}
		// TODO(kwonalbert) If an error occurs sending back destroyed, handle it here
		respQ.EnqueueMsg(id, cell, c, nil)
	}
	hp.mapLock.Unlock()
	return nil
}

// handleDestroy handles the destroy directive by either relaying it on,
// or sending back destroyed directive if this is an exit
func (hp *RouterContext) handleDestroy(d Directive, c, nextConn *Conn, exit bool, id, nextId uint64,
	sendQ, respQ *Queue, sId, rId uint64) error {
	// Close the connection if you are an exit for this circuit
	if exit {
		// Send back destroyed msg
		cell, err := marshalDirective(id, dirDestroyed)
		if err != nil {
			return err
		}
		if nextConn != nil {
			nextConn.Close()
		}
		empty := hp.delete(c, id, id) // there is not previous id for this, so delete id
		respQ.Close(rId, cell, empty, c, c)
	} else {
		nextCell, err := marshalDirective(nextId, dirDestroy)
		if err != nil {
			return err
		}
		sendQ.EnqueueMsg(sId, nextCell, nextConn, c)
	}
	return nil
}

// handleMessages reconstructs the full message at the exit node, and sends it
// out to the final destination. The directives are handled in handleConn.
func (hp *RouterContext) handleMessages(dest string, circ Circuit, id, nextId uint64, prevConn *Conn,
	sendQ, respQ *Queue, sId, rId uint64) {
	var conn net.Conn = nil
	for {
		read, ok := <-circ.cells
		if !ok {
			break
		}
		cell := read.cell
		err := read.err
		if err != nil {
			break
		}

		msgBytes := binary.LittleEndian.Uint64(cell[BODY:])
		if msgBytes > MaxMsgBytes {
			if err = hp.SendError(respQ, rId, id, errMsgLength, prevConn); err != nil {
				hp.errs <- err
				return
			}
			continue
		}

		msg := make([]byte, msgBytes)
		bytes := copy(msg, cell[BODY+LEN_SIZE:])

		// While the connection is open and the message is incomplete, read
		// the next cell.
		for uint64(bytes) < msgBytes {
			read, ok = <-circ.cells
			if !ok {
				break
			}
			cell = read.cell
			err = read.err
			if err == io.EOF {
				hp.errs <- errors.New("Connection closed before receiving all messages")
			} else if err != nil {
				hp.errs <- err
				return
			} else if cell[TYPE] != msgCell {
				if err = hp.SendError(respQ, rId, id, errCellType, prevConn); err != nil {
					hp.errs <- err
					break
				}
			}
			bytes += copy(msg[bytes:], cell[BODY:])
		}

		if conn == nil { // dial when you receive the first message to send
			conn, err = net.DialTimeout(hp.network, dest, hp.timeout)
			if err != nil {
				if err = hp.SendError(respQ, rId, id, err, prevConn); err != nil {
					hp.errs <- err
					break
				}
				break
			}
			hp.mapLock.Lock()
			hp.circuits[nextId] = &Conn{conn, 0, hp.timeout, nil, nil, false}
			hp.mapLock.Unlock()
			// Create handler for responses from the destination
			go func(conn net.Conn, prevConn *Conn, queue *Queue, queueId, id uint64) {
				for {
					resp := make([]byte, MaxMsgBytes+1)
					conn.SetDeadline(time.Now().Add(hp.timeout))
					n, e := conn.Read(resp)
					if e == io.EOF {
						return
					} else if e != nil {
						hp.SendError(queue, queueId, id, e, prevConn)
						return
					} else if n > MaxMsgBytes {
						hp.SendError(queue, queueId, id, errors.New("Response message too long"), prevConn)
						return
					}
					cell := make([]byte, CellBytes)
					binary.LittleEndian.PutUint64(cell[ID:], id)
					respBytes := len(resp[:n])

					cell[TYPE] = msgCell
					binary.LittleEndian.PutUint64(cell[BODY:], uint64(respBytes))
					bytes := copy(cell[BODY+LEN_SIZE:], resp)
					queue.EnqueueMsg(queueId, cell, prevConn, nil)

					for bytes < n {
						tao.ZeroBytes(cell)
						binary.LittleEndian.PutUint64(cell[ID:], id)
						cell[TYPE] = msgCell
						bytes += copy(cell[BODY:], resp[bytes:])
						queue.EnqueueMsg(queueId, cell, prevConn, nil)
					}

				}
			}(conn, prevConn, respQ, rId, id)
		}
		sendQ.EnqueueMsg(sId, msg, conn, prevConn)
	}
	if conn != nil {
		conn.Close()
	}
}

// SendError sends an error message to a client.
func (hp *RouterContext) SendError(queue *Queue, queueId, id uint64, err error, c *Conn) error {
	var d Directive
	d.Type = DirectiveType_ERROR.Enum()
	d.Error = proto.String(err.Error())
	cell, err := marshalDirective(id, &d)
	if err != nil {
		return err
	}
	queue.EnqueueMsg(queueId, cell, c, nil)
	return nil
}

func (hp *RouterContext) delete(c *Conn, id uint64, prevId uint64) bool {
	// TODO(kwonalbert) Check that this circuit is
	// actually on this conn
	hp.mapLock.Lock()
	c.cLock.Lock()

	close(c.circuits[id].cells)
	delete(c.circuits, id)
	empty := len(c.circuits) == 0

	delete(hp.circuits, id)
	delete(hp.nextIds, prevId)
	delete(hp.prevIds, id)
	delete(hp.entry, id)
	delete(hp.exit, id)
	if len(c.circuits) == 0 {
		delete(hp.conns, c.RemoteAddr().String())
	}
	c.cLock.Unlock()
	hp.mapLock.Unlock()
	return empty
}
