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
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"

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
	conns *struct {
		sync.Mutex
		m map[string]*Conn
	}
	// Used to check duplicates
	circuitIds *struct {
		sync.Mutex
		m map[uint64]bool
	}
	connIds *struct {
		sync.Mutex
		m map[uint32]bool
	}

	// address of the directories
	directories []string
	// list of available servers and their keys for exit encryption
	directory  []string
	serverKeys [][]byte

	network string        // Network protocol, e.g. "tcp".
	timeout time.Duration // Timeout on read/write.

	hopCount int
}

// NewProxyContext loads a domain from a local configuration.
func NewProxyContext(path, network, addr string, directories []string, hopCount int, timeout time.Duration) (*ProxyContext, error) {
	// Load domain from a local configuration.
	domain, err := tao.LoadDomain(path, nil)
	if err != nil {
		return nil, err
	}

	// Initialize a SOCKS server.
	listener, err := SocksListen(network, addr)
	if err != nil {
		return nil, err
	}

	clients := make(map[uint64]net.Conn)
	circuits := make(map[uint64]*Conn)
	conns := struct {
		sync.Mutex
		m map[string]*Conn
	}{m: make(map[string]*Conn)}
	circuitIds := struct {
		sync.Mutex
		m map[uint64]bool
	}{m: make(map[uint64]bool)}
	connIds := struct {
		sync.Mutex
		m map[uint32]bool
	}{m: make(map[uint32]bool)}

	p := &ProxyContext{
		domain:   domain,
		listener: listener,

		clients:    clients,
		circuits:   circuits,
		conns:      &conns,
		circuitIds: &circuitIds,
		connIds:    &connIds,

		directories: directories,

		network: network,
		timeout: timeout,

		hopCount: hopCount,
	}
	return p, nil
}

func (p *ProxyContext) directoryConsensus() {
	for _, dirAddr := range p.directories {
		directory, keys, err := p.GetDirectory(dirAddr)
		if err != nil {
			log.Println("GetDirectory err:", err)
		}
		// TODO(kwonalbert): Check directory consensus
		p.directory = directory
		p.serverKeys = keys
	}
}

// Read the directory from a directory server
// TODO(kwonalbert): This is more or less a duplicate of the router get dir..
// Combine them..
func (p *ProxyContext) GetDirectory(dirAddr string) ([]string, [][]byte, error) {
	c, err := tao.Dial(p.network, dirAddr, p.domain.Guard, p.domain.Keys.VerifyingKey, nil)
	if err != nil {
		return nil, nil, err
	}
	directory, keys, err := GetDirectory(c)
	if err != nil {
		return nil, nil, err
	}
	return directory, keys, c.Close()
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
	conn := &Conn{c, id, p.timeout, make(map[uint64]*Circuit), new(sync.RWMutex), false}
	go p.handleConn(conn)
	return conn, nil
}

// handleConn multiplexes one a connection read for multiple circuits
// There is no need to multiplex writes;
// each circuit should be able to write whenever.
func (p *ProxyContext) handleConn(c *Conn) {
	for {
		cell := make([]byte, CellBytes)
		c.SetDeadline(time.Now().Add(p.timeout))
		_, err := c.Read(cell)
		if err == nil {
			id := getID(cell)
			circuit := c.GetCircuit(id)
			circuit.BufferCell(cell, err)
		} else {
			// Relay other errors (mostly timeout) to all circuits in this connection
			for _, circuit := range c.circuits {
				go func(circuit *Circuit) {
					circuit.BufferCell(nil, err)
				}(circuit)
			}
			break
		}
	}
}

func (p *ProxyContext) pickCircuit(path []string) ([]string, *[32]byte, error) {
	// TODO(kwonalbert): there could be flags to show which servers
	// are "more" trustworthy
	exit := ""
	if len(path) == 0 {
		// only has the final dest, pick a random exit
		b := make([]byte, LEN_SIZE)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		exit = p.directory[int(binary.LittleEndian.Uint32(b))%len(p.directory)]
		path = append(path, exit)
	} else {
		// only has the final dest, pick a random exit
		exit = path[len(path)-1]
	}

	idx := -1
	for s, server := range p.directory {
		if server == exit {
			idx = s
		}
	}
	if idx == -1 {
		return nil, nil, errors.New("Exit key not found")
	}

	var key [32]byte
	copy(key[:], p.serverKeys[idx])

	if len(path) < p.hopCount {
		entry := ""
		exit := path[len(path)-1]
		ok := false
		for !ok {
			b := make([]byte, LEN_SIZE)
			if _, err := rand.Read(b); err != nil {
				return nil, nil, err
			}
			entry = p.directory[int(binary.LittleEndian.Uint32(b))%len(p.directory)]
			ok = entry != exit
		}
		newPath := make([]string, p.hopCount)
		newPath[0] = entry
		for i := 1; i < p.hopCount; i++ {
			newPath[i] = ""
		}
		path = append(newPath, path...)
	}
	return path, &key, nil
}

// CreateCircuit connects anonymously to a remote Tao-delegated mixnet router
// specified by path[0]. It directs the router to construct a circuit to dest.
// The user either provides just the exit, or the whole path
func (p *ProxyContext) CreateCircuit(path []string, dest string) (*Circuit, uint64, error) {
	p.directoryConsensus()

	path, exitKey, err := p.pickCircuit(path)
	if err != nil {
		return nil, 0, err
	}
	path = append(path, dest)

	id, err := p.newID()
	if err != nil {
		return nil, id, err
	}

	var c *Conn
	p.conns.Lock()
	if _, ok := p.conns.m[path[0]]; !ok {
		c, err = p.DialRouter(p.network, path[0])
		if err != nil {
			p.conns.Unlock()
			return nil, id, err
		}
		p.conns.m[path[0]] = c
	} else {
		c = p.conns.m[path[0]]
	}
	p.circuits[id] = c
	pub, priv, _ := box.GenerateKey(rand.Reader)
	circuit := NewCircuit(c, id, false, false, false)
	circuit.SetKeys(exitKey, pub, priv)
	c.AddCircuit(circuit)
	p.conns.Unlock()

	boxedDest := circuit.Encrypt([]byte(path[len(path)-1]))
	path[len(path)-1] = string(boxedDest)

	d := &Directive{
		Type:  DirectiveType_CREATE.Enum(),
		Addrs: path,
		Key:   pub[:],
	}

	// Send CREATE directive to router.
	if _, err := circuit.SendDirective(d); err != nil {
		return nil, id, err
	}

	// Wait for CREATED directive from router.
	if err := circuit.ReceiveDirective(d); err != nil {
		return nil, id, err
	} else if *d.Type != DirectiveType_CREATED {
		return nil, id, errors.New("could not create circuit")
	}

	return circuit, id, nil
}

// DestroyCircuit directs the router to close the connection to the destination
// and destroy the circuit then closes the connection.
func (p *ProxyContext) DestroyCircuit(id uint64) error {
	c := p.circuits[id]
	circuit := c.GetCircuit(id)

	// Send DESTROY directive to router.
	if _, err := circuit.SendDirective(dirDestroy); err != nil {
		return err
	}

	// Wait for DESTROYED directive from router.
	var d Directive
	if err := circuit.ReceiveDirective(&d); err != nil {
		return err
	} else if *d.Type != DirectiveType_DESTROYED {
		return errors.New("could not destroy circuit")
	}

	p.conns.Lock()
	empty := c.DeleteCircuit(circuit)
	delete(p.circuits, id)
	if empty { // no more circuits, close the conn
		c.Close()
		delete(p.conns.m, c.RemoteAddr().String())
	}
	p.conns.Unlock()
	return nil
}

// Return a random circuit ID
func (p *ProxyContext) newID() (uint64, error) {
	p.circuitIds.Lock()
	id := uint64(0)
	ok := true
	// Reserve ids < 2^32 to connection ids
	for ok || id < (1<<32) {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return 0, err
		}
		id = binary.LittleEndian.Uint64(b)
		_, ok = p.circuitIds.m[id]
	}
	p.circuitIds.m[id] = true
	p.circuitIds.Unlock()
	return id, nil
}

// Return a random connection ID
func (p *ProxyContext) newConnID() (uint32, error) {
	p.connIds.Lock()
	id := uint32(0)
	ok := true
	for ok {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return 0, err
		}
		id = binary.LittleEndian.Uint32(b)
		_, ok = p.connIds.m[id]
	}
	p.connIds.m[id] = true
	p.connIds.Unlock()
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
func (p *ProxyContext) ServeClient(c net.Conn, path []string, dest string) error {
	circuit, id, err := p.CreateCircuit(path, dest)
	if err != nil {
		return err
	}
	p.clients[id] = c

	proxyErrs := make(chan error)
	routerErrs := make(chan error)
	go func(id uint64) {
		c := p.clients[id]
		d := p.circuits[id]

		for {
			msg := make([]byte, MaxMsgBytes)
			bytes, err := c.Read(msg)
			if err != nil {
				proxyErrs <- err
				d.circuits[id].BufferCell(nil, io.EOF)
				return
			}

			if err = circuit.SendMessage(msg[:bytes]); err != nil {
				proxyErrs <- err
				return
			}

		}
	}(id)

	go func(id uint64) {
		c := p.clients[id]
		d := p.circuits[id]

		for {
			reply, err := circuit.ReceiveMessage()
			if err != nil {
				routerErrs <- err
				return
			}

			c.SetDeadline(time.Now().Add(p.timeout))
			if _, err = c.Write(reply); err != nil {
				proxyErrs <- err
				d.circuits[id].BufferCell(nil, io.EOF)
				return
			}
		}
	}(id)

	select {
	case err = <-proxyErrs:
		if err == io.EOF {
			glog.Info("proxy: encountered EOF with client")
			break
		} else if err != nil {
			glog.Error("proxy: encounter unexpected error with client", err)
			break
		}
	case err = <-routerErrs:
		if err == io.EOF {
			glog.Info("proxy: encountered EOF with router")
			break
		} else if err != nil {
			glog.Error("proxy: encounter unexpected error with router", err)
			break
		}
	}
	// Clear the errors
	select {
	case <-proxyErrs:
	case <-routerErrs:
	default:
	}

	return p.DestroyCircuit(id)
}

// HandleClient relays a message read from client connection c to mixnet
// connection  d and relay reply.
func (p *ProxyContext) HandleClient(id uint64) error {
	c := p.clients[id]
	d := p.circuits[id]
	circuit := d.GetCircuit(id)

	msg := make([]byte, MaxMsgBytes)
	bytes, err := c.Read(msg)
	if err != nil {
		return err
	}

	if err = circuit.SendMessage(msg[:bytes]); err != nil {
		return err
	}

	reply, err := circuit.ReceiveMessage()
	if err != nil {
		return err
	}

	c.SetDeadline(time.Now().Add(p.timeout))
	if _, err = c.Write(reply); err != nil {
		return err
	}

	return nil
}
