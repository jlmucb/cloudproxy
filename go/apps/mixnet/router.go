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
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
)

// RouterContext stores the runtime environment for a Tao-delegated router.
type RouterContext struct {
	keys       *tao.Keys    // Signing keys of this hosted program.
	domain     *tao.Domain  // Policy guard and public key.
	listener   net.Listener // Socket where server listens for proxies/routers
	publicKey  *[32]byte
	privateKey *[32]byte

	addr string

	// Data structures for queueing and batching messages
	queue     *Queue
	proxyReq  *Queue
	proxyResp *Queue

	// Connections to next hop routers
	conns map[string]*Conn
	// Maps circuit id to circuits
	circuits map[uint64]*Circuit
	// Used to check duplicate connection ids
	connIds struct {
		sync.Mutex
		m map[uint32]bool
	}

	// address of the directories
	directories []string
	// list of available servers and their keys for exit encryption
	directory  []string
	serverKeys [][]byte

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
func NewRouterContext(path, network, addr string, timeout time.Duration,
	directories []string, batchSize int,
	x509Identity *pkix.Name, t tao.Tao) (r *RouterContext, err error) {

	r = new(RouterContext)
	r.network = network
	r.timeout = timeout

	r.addr = addr
	port := addr
	if addr != "127.0.0.1:0" {
		port = ":" + strings.Split(addr, ":")[1]
	}

	r.conns = make(map[string]*Conn)
	r.circuits = make(map[uint64]*Circuit)
	r.connIds = struct {
		sync.Mutex
		m map[uint32]bool
	}{m: make(map[uint32]bool)}

	r.mapLock = new(sync.RWMutex)

	r.errs = make(chan error)
	r.done = make(chan bool)

	// Generate keys and get attestation from parent.
	if r.keys, err = tao.NewTemporaryTaoDelegatedKeys(tao.Signing|tao.Crypting, t); err != nil {
		return nil, err
	}

	// Create a certificate.
	if r.keys.Cert, err = r.keys.SigningKey.CreateSelfSignedX509(x509Identity); err != nil {
		return nil, err
	}

	// Load domain from local configuration.
	if r.domain, err = tao.LoadDomain(path, nil); err != nil {
		return nil, err
	}

	// Encode TLS certificate.
	cert, err := tao.EncodeTLSCert(r.keys)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*cert},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequestClientCert,
	}

	if r.listener, err = Listen(network, port, tlsConfig,
		r.domain.Guard, r.domain.Keys.VerifyingKey, r.keys.Delegation); err != nil {
		return nil, err
	}

	// NaCl keys
	r.publicKey, r.privateKey, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	r.directories = directories
	r.register()
	go r.updateDirectory()

	// Instantiate the queues.
	r.queue = NewQueue(network, t, batchSize, timeout)
	r.proxyReq = NewQueue(network, t, batchSize, timeout)
	r.proxyResp = NewQueue(network, t, batchSize, timeout)
	r.killQueue = make(chan bool)
	r.killQueueErrorHandler = make(chan bool)
	go r.queue.DoQueue(r.killQueue)
	go r.proxyReq.DoQueue(r.killQueue)
	go r.proxyResp.DoQueue(r.killQueue)
	go r.queue.DoQueueErrorHandler(r.queue, r.killQueueErrorHandler)
	go r.proxyReq.DoQueueErrorHandler(r.queue, r.killQueueErrorHandler)
	go r.proxyResp.DoQueueErrorHandler(r.queue, r.killQueueErrorHandler)

	return r, nil
}

func (r *RouterContext) register() {
	for _, dirAddr := range r.directories {
		err := r.Register(dirAddr)
		if err != nil {
			log.Println("Register err:", err)
		}
	}
}

func (r *RouterContext) directoryConsensus() {
	for _, dirAddr := range r.directories {
		directory, keys, err := r.GetDirectory(dirAddr)
		if err != nil {
			log.Println("GetDirectory err:", err)
		}
		//fmt.Println("Got directory")
		// TODO(kwonalbert): Check directory consensus
		r.directory = directory
		r.serverKeys = keys
	}
}

func (r *RouterContext) updateDirectory() {
	for {
		r.directoryConsensus()
		time.Sleep(DefaultUpdateFrequency)
	}
}

// AcceptRouter Waits for connectons from other routers.
func (r *RouterContext) Accept() (*Conn, error) {
	c, err := r.listener.Accept()
	if err != nil {
		return nil, err
	}
	id, err := r.newConnID()
	if err != nil {
		return nil, err
	}
	conn := &Conn{c, id, r.timeout, make(map[uint64]*Circuit), new(sync.RWMutex), true}
	if len(c.(*tls.Conn).ConnectionState().PeerCertificates) > 0 {
		conn.withProxy = false
	}
	go r.handleConn(conn)
	return conn, nil
}

// DialRouter connects to a remote Tao-delegated mixnet router.
func (r *RouterContext) DialRouter(network, addr string) (*Conn, error) {
	c, err := tao.Dial(network, addr, r.domain.Guard, r.domain.Keys.VerifyingKey, r.keys)
	if err != nil {
		return nil, err
	}
	id, err := r.newConnID()
	if err != nil {
		return nil, err
	}
	conn := &Conn{c, id, r.timeout, make(map[uint64]*Circuit), new(sync.RWMutex), false}
	r.conns[addr] = conn
	go r.handleConn(conn)
	return conn, nil
}

// Register the current router to a directory server
func (r *RouterContext) Register(dirAddr string) error {
	c, err := tao.Dial(r.network, dirAddr, r.domain.Guard, r.domain.Keys.VerifyingKey, r.keys)
	if err != nil {
		return err
	}
	err = RegisterRouter(c, []string{r.addr}, [][]byte{(*r.publicKey)[:]})
	if err != nil {
		return err
	}
	return c.Close()

}

// Read the directory from a directory server
func (r *RouterContext) GetDirectory(dirAddr string) ([]string, [][]byte, error) {
	c, err := tao.Dial(r.network, dirAddr, r.domain.Guard, r.domain.Keys.VerifyingKey, r.keys)
	if err != nil {
		return nil, nil, err
	}
	directory, keys, err := GetDirectory(c)
	if err != nil {
		return nil, nil, err
	}
	return directory, keys, c.Close()
}

// Close releases any resources held by the hosted program.
func (r *RouterContext) Close() {
	r.killQueue <- true
	r.killQueue <- true
	r.killQueue <- true
	r.killQueueErrorHandler <- true
	r.killQueueErrorHandler <- true
	r.killQueueErrorHandler <- true
	if r.listener != nil {
		r.listener.Close()
	}
	for _, conn := range r.conns {
		r.done <- true
		for _, circuit := range conn.circuits {
			circuit.Close()
		}
		conn.Close()
	}
}

// Return a random circuit ID
func (r *RouterContext) newID() (uint64, error) {
	id := uint64(0)
	ok := true
	// Reserve ids < 2^32 to connection ids
	for ok || id < (1<<32) {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return 0, err
		}
		id = binary.LittleEndian.Uint64(b)
		_, ok = r.circuits[id]
	}
	return id, nil
}

// Return a random connection ID
func (r *RouterContext) newConnID() (uint32, error) {
	r.connIds.Lock()
	var id uint32
	ok := true
	for ok {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return 0, err
		}
		id = binary.LittleEndian.Uint32(b)
		_, ok = r.connIds.m[id]
	}
	r.connIds.m[id] = true
	r.connIds.Unlock()
	return id, nil
}

// Handle errors internal to the router
// When instantiating a real router (not for testing),
// one start this function as well to handle the errors
func (r *RouterContext) HandleErr() {
	for {
		err := <-r.errs
		if err != nil {
			// TODO(kwonalbert) Handle errors properly
			glog.Error("Router err:", err)
		}
	}
}

// handleConn reads a directive or a message from a proxy. The directives
// are handled here, but actual messages are handled in handleMessages
func (r *RouterContext) handleConn(c *Conn) {
	for {
		var err error
		cell := make([]byte, CellBytes)
		if _, err = c.Read(cell); err != nil {
			if err == io.EOF {
				break
			} else {
				select {
				case <-r.done: // Indicate this is done
				case r.errs <- err:
				}
				break
			}
		}

		id := getID(cell)
		r.mapLock.RLock()
		sendQ, respQ := r.queue, r.queue
		circ, ok := r.circuits[id]
		var nextCirc *Circuit
		var sId, rId uint64
		if ok {
			nextCirc = circ.next
			sId = nextCirc.id
			if circ.entry {
				sendQ = r.proxyReq
				respQ = r.proxyResp
			}
			if nextCirc.entry {
				respQ = r.proxyResp
				rId = uint64(nextCirc.conn.id)
			} else {
				rId = nextCirc.id
			}
		}
		if c.withProxy {
			sId, rId = uint64(c.id), uint64(c.id)
		}
		r.mapLock.RUnlock()

		if cell[TYPE] == msgCell {
			if !circ.exit { // if it's not exit, just relay the cell
				binary.LittleEndian.PutUint64(cell[ID:], nextCirc.id)
				if !circ.forward {
					sendQ.EnqueueMsg(sId, cell, nextCirc.conn, c)
				} else {
					respQ.EnqueueMsg(rId, cell, nextCirc.conn, c)
				}
			} else { // actually handle the message
				c.GetCircuit(id).BufferCell(cell, err)
			}
		} else if cell[TYPE] == dirCell { // Handle a directive.
			var d Directive
			if err = unmarshalDirective(cell, &d); err != nil {
				r.errs <- err
				break
			}

			// relay the errors back to users
			if *d.Type == DirectiveType_ERROR {
				binary.LittleEndian.PutUint64(cell[ID:], nextCirc.id)
				respQ.EnqueueMsg(rId, cell, nextCirc.conn, c)
			} else if *d.Type == DirectiveType_CREATE {
				err := r.handleCreate(d, c, id, sendQ, respQ, sId, rId)
				if err != nil {
					r.errs <- err
					break
				}
			} else if *d.Type == DirectiveType_DESTROY {
				err := r.handleDestroy(d, c, circ, sendQ, respQ, sId, rId)
				if err != nil {
					r.errs <- err
					break
				}
			} else if *d.Type == DirectiveType_CREATED {
				// Simply relay created back
				cell, err = marshalDirective(nextCirc.id, dirCreated)
				if err != nil {
					r.errs <- err
					break
				}
				respQ.EnqueueMsg(rId, cell, nextCirc.conn, c)
			} else if *d.Type == DirectiveType_DESTROYED {
				cell, err = marshalDirective(nextCirc.id, dirDestroyed)
				if err != nil {
					r.errs <- err
					break
				}
				empty := r.delete(c, circ)
				// Close the forward circuit if it's an exit or empty now
				// Relay back destroyed
				sendQ.Close(sId, nil, empty, c, nextCirc.conn)
				respQ.Close(rId, cell, empty, nextCirc.conn, nil)
				if empty {
					break
				}
			}
		} else { // Unknown cell type, return an error.
			if err = r.SendError(respQ, rId, id, errBadCellType, c); err != nil {
				r.errs <- err
				break
			}
		}
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
func (r *RouterContext) handleCreate(d Directive, c *Conn, id uint64,
	sendQ, respQ *Queue, sId, rId uint64) error {
	if c.withProxy && len(r.directory) > 0 {
		// Get the most recent directory before forming a circuit
		r.directoryConsensus()
		// A fresh path of the same length if user has no preference
		// (Random selection without replacement)
		directory := make([]string, len(r.directory))
		copy(directory, r.directory)
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
				// TODO(kwonalbert) Currently, we allow the
				// clients to pick the path, if they want,
				// mostly for testing. But for better security,
				// we should not allows this for final version.
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

	r.mapLock.Lock()
	defer r.mapLock.Unlock()

	newId, err := r.newID()
	if err != nil {
		return err
	}
	circuit := NewCircuit(c, id, c.withProxy, false, false)
	newCirc := NewCircuit(nil, newId, false, false, true)
	circuit.next = newCirc
	newCirc.next = circuit

	c.AddCircuit(circuit)
	r.circuits[id] = circuit

	// Add next hop for this circuit to queue and send a CREATED
	// directive to sender to inform the sender.
	relayIdx := -1
	for i, addr := range d.Addrs {
		if addr == r.addr {
			relayIdx = i
		}
	}
	if relayIdx != len(d.Addrs)-2 { // last addr is the final dest, so check -2
		// Relay the CREATE message
		if err != nil {
			return err
		}
		var nextConn *Conn
		if _, ok := r.conns[d.Addrs[relayIdx+1]]; !ok {
			nextConn, err = r.DialRouter(r.network, d.Addrs[relayIdx+1])
			if err != nil {
				if e := r.SendError(respQ, rId, id, err, c); e != nil {
					return e
				}
			}
		} else {
			nextConn = r.conns[d.Addrs[relayIdx+1]]
		}
		newCirc.conn = nextConn
		nextConn.AddCircuit(newCirc)
		r.circuits[newId] = newCirc

		nextCell, err := marshalDirective(newId, &d)
		if err != nil {
			return err
		}
		// middle node, then just queue to the generic queue, not one of the proxy queue
		if !c.withProxy {
			sId = newId
		}
		sendQ.EnqueueMsg(sId, nextCell, nextConn, c)
	} else {
		// Response id should be just id here not rId if it's not an entry
		var key [32]byte
		copy(key[:], d.Key)
		circuit.exit = true
		circuit.SetKeys(&key, r.publicKey, r.privateKey)
		if !c.withProxy {
			sId = newId
			rId = id
		}

		dest, ok := circuit.Decrypt([]byte(d.Addrs[len(d.Addrs)-1]))
		if !ok {
			log.Fatal("Misauthenticated ciphertext")
		}
		go r.handleMessage(string(dest), circuit, sendQ, respQ, sId, rId)
		// Tell the previous hop (proxy or router) it's created
		cell, err := marshalDirective(id, dirCreated)
		if err != nil {
			return err
		}
		respQ.EnqueueMsg(rId, cell, c, nil)
	}
	return nil
}

// handleDestroy handles the destroy directive by either relaying it on,
// or sending back destroyed directive if this is an exit
func (r *RouterContext) handleDestroy(d Directive, c *Conn, circ *Circuit,
	sendQ, respQ *Queue, sId, rId uint64) error {
	// Close the connection if you are an exit for this circuit

	if !c.Member(circ.id) {
		return errors.New("Cannot destroy a circuit that does not belong to the connection")
	}

	if circ.exit {
		// Send back destroyed msg
		cell, err := marshalDirective(circ.id, dirDestroyed)
		if err != nil {
			return err
		}
		if circ.next.conn != nil {
			circ.next.conn.Close()
		}
		empty := r.delete(c, circ) // there is not previous id for this, so delete id
		respQ.Close(rId, cell, empty, circ.conn, circ.conn)
	} else {
		nextCell, err := marshalDirective(circ.next.id, dirDestroy)
		if err != nil {
			return err
		}
		sendQ.EnqueueMsg(sId, nextCell, circ.next.conn, circ.conn)
	}
	return nil
}

// handleMessages reconstructs the full message at the exit node, and sends it
// out to the final destination. The directives are handled in handleConn.
func (r *RouterContext) handleMessage(dest string, circ *Circuit,
	sendQ, respQ *Queue, sId, rId uint64) {
	var conn *Conn = nil
	var netConn net.Conn = nil
	for {
		msg, err := circ.ReceiveMessage()
		if err == io.EOF {
			break
		} else if err != nil {
			if err = r.SendError(respQ, rId, circ.id, err, circ.conn); err != nil {
				r.errs <- err
			}
			continue
		}

		if conn == nil { // dial when you receive the first message to send
			netConn, err = net.DialTimeout(r.network, dest, r.timeout)
			if err != nil {
				if err = r.SendError(respQ, rId, circ.id, err, circ.conn); err != nil {
					r.errs <- err
				}
				continue
			}
			r.mapLock.Lock()
			conn = &Conn{netConn, 0, r.timeout, make(map[uint64]*Circuit), new(sync.RWMutex), false}
			circ.next.conn = conn
			// Add the circuit to final dest to list of circuits
			conn.AddCircuit(circ.next)
			r.circuits[circ.next.id] = circ.next
			r.mapLock.Unlock()
			// Create handler for responses from the destination
			go r.handleResponse(netConn, circ, respQ, rId)
		}
		sendQ.EnqueueMsg(sId, msg, netConn, circ.conn)
	}
	if conn != nil {
		conn.Close()
		conn.DeleteCircuit(circ.next)
	}
}

// handleResponse receives a message from the final destination, breaks it down
// into cells, and sends it back to the user
func (r *RouterContext) handleResponse(conn net.Conn, respCirc *Circuit, queue *Queue, queueId uint64) {
	for {
		resp := make([]byte, MaxMsgBytes+1)
		conn.SetDeadline(time.Now().Add(r.timeout))
		n, e := conn.Read(resp)
		if e == io.EOF {
			// the connection closed
			return
		} else if e != nil {
			if strings.Contains(e.Error(), "closed network connection") {
				// TODO(kwonalbert) Currently, this is a hack to
				// avoid sending unnecesary error back to user,
				// since Read returns this error when the conn
				// closes while it's constructing response cells
				return
			} else {
				r.SendError(queue, queueId, respCirc.id, e, respCirc.conn)
				return
			}
		} else if n > MaxMsgBytes {
			r.SendError(queue, queueId, respCirc.id, errors.New("Response message too long"), respCirc.conn)
			return
		}

		cell := make([]byte, CellBytes)
		binary.LittleEndian.PutUint64(cell[ID:], respCirc.id)

		cell[TYPE] = msgCell

		bodies := make(chan []byte)
		go breakMessages(resp[:n], bodies)
		for {
			body, ok := <-bodies
			if !ok {
				break
			}
			boxed := respCirc.Encrypt(body)
			copy(cell[BODY:], boxed)
			queue.EnqueueMsg(queueId, cell, respCirc.conn, nil)
		}
	}
}

// SendError sends an error message to a client.
func (r *RouterContext) SendError(queue *Queue, queueId, id uint64, err error, c *Conn) error {
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

func (r *RouterContext) delete(c *Conn, circuit *Circuit) bool {
	r.mapLock.Lock()
	delete(r.circuits, circuit.id)
	delete(r.circuits, circuit.next.id)
	empty := c.DeleteCircuit(circuit)
	if empty {
		delete(r.conns, c.RemoteAddr().String())
	}
	r.mapLock.Unlock()
	return empty
}
