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
	"errors"
	"net"
	"strconv"
)

// Codes used in the RFC standard of SOCKS version 5.
const (
	SocksVersion            = 0x05
	SocksMethodNoAuth       = 0x00
	SocksNoAcceptableMethod = 0xff
	SocksCmdConnect         = 0x01
	SocksAtypIPv4           = 0x01
	SocksRepSuccess         = 0x00
	SocksRepFailure         = 0x01
	SocksRepUnsupported     = 0x07
)

// SocksConn implements the net.Conn interface and contains a destination
// network and address for the proxy.
type SocksConn struct {
	net.Conn
	network, dstAddr string // Destination network and address.
}

// DestinationAddr returns the destination address negotiated in the SOCKS
// protocol.
func (c *SocksConn) DestinationAddr() string {
	return c.dstAddr
}

// SocksListener implements the net.Listener interface as a SOCKS server. This
// program partially implements the server role in version 5 of the SOCKS
// protocol specified in RFC 1928. In particular, it only supports TCP clients
// with no authentication who request CONNECT to IPv4 addresses; neither BIND
// nor UDP ASSOCIATE are supported.
type SocksListener struct {
	net.Listener
	network string // Network protocol for proxying, e.g. "tcp".
}

// SocksListen binds an address to a socket and returns a
// SocksListener for serving SOCKS clients.
func SocksListen(network, addr string) (net.Listener, error) {
	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return &SocksListener{l, network}, nil
}

// Accept exposes the SOCKS5 protocol to connecting client. Return the
// connection and the requested destination address.
func (l *SocksListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// First, wait for greeting from client containing the SOCKS version and
	// requested methods.
	msg := make([]byte, MaxMsgBytes)
	reply := make([]byte, MaxMsgBytes)
	bytes, err := c.Read(msg)
	if err != nil {
		c.Close()
		return nil, err
	}

	// Parse client's greeting, making sure that it is the proper length.
	// Only the NO AUTHENTICATION REQUIRED method is allowed. Note that this
	// makes the server non-compliant since GSSAPI is not allowed.
	ok := false
	var ver, nmethods int
	if bytes > 2 {
		ver = int(msg[0])
		nmethods = int(msg[1])
		if bytes >= 2+nmethods {
			for _, method := range msg[2 : 2+nmethods] {
				if method == SocksMethodNoAuth {
					ok = true
					break
				}
			}
		}
	}

	// Second, reply with selected method.
	reply[0] = SocksVersion
	if ok {
		reply[1] = SocksMethodNoAuth
	} else {
		reply[1] = SocksNoAcceptableMethod
	}

	if _, err = c.Write(reply[:2]); err != nil {
		c.Close()
		return nil, err
	}

	// If NO ACCEPTABLE METHOD, the client closes the connection.
	if !ok {
		c.Close()
		return nil, errors.New("socks: client did not provide acceptable method")
	}

	// Third, wait for command from client.
	bytes, err = c.Read(msg)
	if err != nil {
		c.Close()
		return nil, err
	}

	// Test that client's command is long enough. It must be at least 6 bytes long
	// to accomadate the version, command, reserved byte, address type, and
	// destination port.
	if bytes < 6 {
		reply[0] = SocksVersion
		reply[1] = SocksRepFailure
		for i := 2; i < 6; i++ {
			reply[i] = 0x00
		}
		defer c.Close()
		if _, err = c.Write(reply[:6]); err != nil {
			return nil, err
		}
		return nil, errors.New("socks: client sent a malformed command")
	}

	ver = int(msg[0])
	cmd := msg[1]
	// msg[2] is a reserved byte in the protocol.
	atyp := msg[3]

	// Only CONNECT to IPv4 addresses is allowed. Since traffic will be proxied
	// over the mixnet, don't connect to the intended host just yet. Reply to
	// the client.
	copy(reply, msg[:bytes])
	if ver == SocksVersion && cmd == SocksCmdConnect /* CONNECT */ && atyp == SocksAtypIPv4 /* IPv4 */ {
		reply[1] = SocksRepSuccess
	} else {
		reply[1] = SocksRepUnsupported
	}
	if _, err = c.Write(reply[:bytes]); err != nil {
		c.Close()
		return nil, err
	}

	// dstAddr specifies the destination of the client. At this point the
	// proxy is ready to construct a circuit and relay a message on behalf of
	// the client.
	port := strconv.Itoa((int(msg[bytes-2]) << 8) + int(msg[bytes-1]))
	dstAddr := strconv.Itoa(int(msg[4])) + "." +
		strconv.Itoa(int(msg[5])) + "." +
		strconv.Itoa(int(msg[6])) + "." +
		strconv.Itoa(int(msg[7])) + ":" + port

	return &SocksConn{c, l.network, dstAddr}, nil
}
