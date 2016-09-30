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
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/tao"
)

// ProxyContext stores the runtime environment for a mixnet proxy. A mixnet
// proxy connects to a mixnet router on behalf of a client's application.
type ProxyContext struct {
	domain   *tao.Domain  // Policy guard and public key.
	listener net.Listener // SOCKS5 server for listening to clients.

	// Mapping circuit id to a connection,
	// and mapping address to connection for multiplexing
	clients  map[uint64]net.Conn
	circuits map[uint64]*Conn
	// Because DeleteCircuit could be called at anytime,
	// we put a global lock around adding/deleting circuits
	// Should be okay for performance, since it doesn't happen often
	conns struct {
		sync.Mutex
		m map[string]*Conn
	}

	network string        // Network protocol, e.g. "tcp".
	timeout time.Duration // Timeout on read/write.
}

// NewProxyContext loads a domain from a local configuration.
func NewProxyContext(path, network, addr string, timeout time.Duration) (p *ProxyContext, err error) {
	p = new(ProxyContext)
	p.network = network
	p.timeout = timeout

	// Load domain from a local configuration.
	if p.domain, err = tao.LoadDomain(path, nil); err != nil {
		return nil, err
	}

	// Initialize a SOCKS server.
	if p.listener, err = SocksListen(network, addr); err != nil {
		return nil, err
	}

	p.clients = make(map[uint64]net.Conn)
	p.circuits = make(map[uint64]*Conn)
	p.conns = struct {
		sync.Mutex
		m map[string]*Conn
	}{m: make(map[string]*Conn)}

	return p, nil
}

// Close unbinds the proxy server socket.
func (p *ProxyContext) Close() {
	if p.listener != nil {
		p.listener.Close()
	}
}

// DialRouter connects anonymously to a remote Tao-delegated mixnet router.
func (p *ProxyContext) DialRouter(network, addr string) (*Conn, error) {
	c, err := tao.Dial(network, addr, p.domain.Guard, p.domain.Keys.VerifyingKey, nil)
	if err != nil {
		return nil, err
	}
	id, err := p.newConnID()
	if err != nil {
		return nil, err
	}
	conn := &Conn{c, id, p.timeout, make(map[uint64]Circuit), new(sync.RWMutex)}
	go p.multiplexConn(conn)
	return conn, nil
}

// Multiplexes reading from a connection
// (kwonalbert) No need to multiplex writes;
// each circuit should be able to write whenever
func (p *ProxyContext) multiplexConn(c *Conn) {
	for {
		cell := make([]byte, CellBytes)
		c.SetDeadline(time.Now().Add(p.timeout))
		_, err := c.Read(cell)
		if err == nil {
			id := getID(cell)
			c.circuits[id].cells <- Cell{cell, err}
		} else {
			// Relay other errors (mostly timeout) to all circuits in this connection
			p.conns.Lock()
			for _, circuit := range c.circuits {
				go func(circuit Circuit) {
					circuit.cells <- Cell{nil, err}
				}(circuit)
			}
			p.conns.Unlock()
			break
		}
		if len(c.circuits) == 0 { // no more circuits, close the conn
			c.Close()
			break
		}
	}
}

// CreateCircuit connects anonymously to a remote Tao-delegated mixnet router
// specified by addrs[0]. It directs the router to construct a circuit to a
// particular destination over the mixnet specified by addrs[len(addrs)-1].
func (p *ProxyContext) CreateCircuit(addrs []string) (uint64, error) {
	id, err := p.newID()
	if err != nil {
		return id, err
	}

	var c *Conn
	if _, ok := p.conns.m[addrs[0]]; !ok {
		c, err = p.DialRouter(p.network, addrs[0])
		if err != nil {
			return id, err
		}
		p.conns.m[addrs[0]] = c
	} else {
		c = p.conns.m[addrs[0]]
	}
	c.circuits[id] = Circuit{make(chan Cell)}
	p.circuits[id] = c

	d := &Directive{
		Type:  DirectiveType_CREATE.Enum(),
		Addrs: addrs[1:],
	}

	// Send CREATE directive to router.
	if _, err := c.SendDirective(id, d); err != nil {
		return id, err
	}

	// Wait for CREATED directive from router.
	if err := c.ReceiveDirective(id, d); err != nil {
		return id, err
	} else if *d.Type != DirectiveType_CREATED {
		return id, errors.New("could not create circuit")
	}

	return id, nil
}

// DestroyCircuit directs the router to close the connection to the destination
// and destroy the circuit then closes the connection.
func (p *ProxyContext) DestroyCircuit(id uint64) error {
	// Send DESTROY directive to router.
	c := p.circuits[id]
	if _, err := c.SendDirective(id, dirDestroy); err != nil {
		return err
	}
	// Wait for DESTROYED directive from router.
	var d Directive
	if err := c.ReceiveDirective(id, &d); err != nil {
		return err
	} else if *d.Type != DirectiveType_DESTROYED {
		return errors.New("could not destroy circuit")
	}

	delete(c.circuits, id)
	return nil
}

// Return a random circuit ID
// TODO(kwonalbert): probably won't happen, but should check for duplicates
func (p *ProxyContext) newID() (uint64, error) {
	id := uint64(0)
	for id < 1<<32 { // Reserving the first 2^32 ids for connection id
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return 0, err
		}
		id = binary.LittleEndian.Uint64(b)
	}
	return id, nil
}

// Return a random connection ID
// TODO(kwonalbert): should check for duplicates
func (p *ProxyContext) newConnID() (uint32, error) {
	id := uint32(0)
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	id = binary.LittleEndian.Uint32(b)
	return id, nil
}

// Accept waits for clients running the SOCKS5 protocol.
func (p *ProxyContext) Accept() (net.Conn, error) {
	return p.listener.Accept()
}

// ServeClient creates a circuit over the mixnet and relays messages to a
// destination (specified by addrs[len(addrs)-1]) on behalf of the client.
// Read a message from the client, send it over the mixnet, wait for a reply,
// and forward it the client. Once an EOF is encountered (or some other error
// occurs), destroy the circuit.
func (p *ProxyContext) ServeClient(c net.Conn, addrs ...string) error {
	circuit := make([]string, len(addrs))
	for i := range circuit {
		circuit[i] = addrs[i]
	}
	id, err := p.CreateCircuit(circuit)
	if err != nil {
		return err
	}
	p.clients[id] = c

	for {
		err = p.HandleClient(id)
		if err == io.EOF {
			glog.Info("proxy: encountered EOF while serving")
			break
		} else if err != nil {
			glog.Errorf("proxy: reading message from client: %s", err)
			break
		}
	}

	return p.DestroyCircuit(id)
}

// HandleClient relays a message read from client connection c to mixnet
// connection  d and relay reply.
func (p *ProxyContext) HandleClient(id uint64) error {
	c := p.clients[id]
	d := p.circuits[id]

	msg := make([]byte, MaxMsgBytes)
	bytes, err := c.Read(msg)
	if err != nil {
		return err
	}

	if err = d.SendMessage(id, msg[:bytes]); err != nil {
		return err
	}

	reply, err := d.ReceiveMessage(id)
	if err != nil {
		return err
	}

	c.SetDeadline(time.Now().Add(p.timeout))
	if _, err = c.Write(reply); err != nil {
		return err
	}

	return nil
}
