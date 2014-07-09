//  File: rpc_channel.go
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Conn implementation.
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
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

package tao

import (
	"code.google.com/p/goprotobuf/proto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)

const overhead = 40

type Conn struct {
	selfName string
	peerName string
	mc *MessageChannel
}

func Dial(network, addr string,
					cert tls.Certificate, unused_delegation string)  (*Conn, error) {
	tls_conn, err := tls.Dial(network, addr, &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	conn := &Conn{"", "", NewMessageChannel(tls_conn)}
	err = conn.handshake()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

type Listener struct {
	sock net.Listener
}

func (l *Listener) Accept() (net.Conn, error) {
	tls_conn, err := l.sock.Accept()
	if err != nil {
		return nil, err
	}
	conn = &Conn{"", "", NewMessageChannel(tls_conn)}
	err = conn.handshake()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func Listen(network, addr string,
	cert tls.Certificate, unused_delegation string) (net.Listener, error) {
	tls_sock, err := tls.Listen(network, addr, &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	})
	return &Sock{tls_sock}, nil
}

// Close closes a connection. It is safe to call this multiple times.
func (c *Conn) Close() error {
	return c.mc.Close()
}

// IsClosed checks if a channel is closed.
func (c *Conn) IsClosed() bool {
	return c.mc.IsClosed()
}

// MaxMessageSize gets the maximum message reception size.
func (c *Conn) MaxMessageSize() uint {
	return c.mc.MaxMessageSize() - overhead
}

// SetMaxMessageSize sets the maximum message reception size.
func (c *Conn) SetMaxMessageSize(size uint) {
	c.mc.SetMaxMessageSize(size + overhead)
}

func (c *Conn) sendFrame(tag CloudChannelFrameTag, data string) error {
	frame := new(CloudChannelFrame)
	frame.Tag = &tag
	frame.Data = data
	return c.mc.SendMessage(frame)
}

func (c *Conn) receiveFrame(tag CloudChannelFrameTag) (string, error) {
	frame := new(CloudChannelFrame)
	err := c.mc.RecieveMessage(frame)
	if err != nil {
		return "", err
	}
	switch frame.Tag {
	case CloudChannelFrameTag_CLOUD_CHANNEL_FRAME_ABORT:
		c.Close()
		return "", io.EOF
	case CloudChannelFrameTag_CLOUD_CHANNEL_FRAME_SHUTDOWN:
		c.sendFrame(CloudChannelFrameTag_CLOUD_CHANNEL_FRAME_SHUTDOWN_RESPONSE, "")
		c.Close()
		return "", io.EOF
	case tag:
		return frame.Data, nil
	default:
		return "", errors.New("Unexpected frame tag")
	}
}

func validateDelegation(delegation, cert string) (string, error) {
	// fixme: temporary hack - delegation holds just the name
	return delegation, nil
}

func getDelegation(certPem []byte) (delegation Attestation, err error) {
	// todo: serialize in keyczar json format, then base64w
	key_name, err := GetPrincipalName(certPem)
	if err != nil {
		return
	}
	var stmt Statement
	stmt.Delegate = key_name
	delegation, err = tao.Host().Attest(stmt)
	if err != nil {
		fmt.Printf("Can't get delegation for my key")
		return
	}
	return
}


func makeDelegation() string {
	// fixme: temporaryhack - delegation just holds my tao name
	host := tao.Host()
	if host == nil {
		return "anonymous"
	}
	name, err := host.GetTaoName()
	if err != nil {
		return "unknown"
	}
	return name
}

func (c *Conn) handshake() error {
	selfDelgation, err := makeDelegation()
	if err != nil {
		return err
	}
	c.selfName, err = validateDelegation(selfDelegation, selfCert)
	if err != nil {
		return err
	}
	err = sendFrame(CloudChannelFrameTag_CLOUD_CHANNEL_FRAME_HANDSHAKE,
		selfDelegation)
	if err != nil {
		return err
	}
	peerDelegation, err :=
		receiveFrame(CloudChannelFrameTag_CLOUD_CHANNEL_FRAME_HANDSHAKE)
	if err != nil {
		return err
	}
	if eof {
		return errors.New("Lost connection during handshake")
	}
	c.peerName, err = validateDelegation(peerPelegation, peerCert)
	if err != nil {
		return err
	}
	return nil
}

// SendData sends raw data to the channel.
// Failure will close the channel.
func (c *Conn) SendData(bytes []byte) error {
	return c.sendFrame(CloudChannelFrameTag_CLOUD_CHANNEL_FRAME_WRAPPED_BUFFER,
		string(bytes))
}

// ReceiveData receive raw data from the channel.
// No maximum message size applies, the caller is expected to supply a
// reasonable size buffer, which will be filled entirely.
// Failure or eof will close the channel.
func (c *Conn) ReceiveData(bytes []byte) error {
	s, err := receiveFrame(CloudChannelFrameTag_CLOUD_CHANNEL_FRAME_WRAPPED_BUFFER)
	if err != nil {
		return err
	}
	if len(bytes) != len(s) {
		return errors.New("Received incorrect buffer size")
	}
	copy(bytes, s)
	return nil
}

// SendString sends a raw string to the channel.
// Failure will close the channel.
func (cc *Conn) SendString(s string) error {
	return c.sendFrame(CloudChannelFrameTag_CLOUD_CHANNEL_FRAME_WRAPPED_STRING, s)
}

// ReceiveString receive a string over the channel.
// Failure or eof will close the channel.
func (c *Conn) ReceiveString() (string, error) {
	return receiveFrame(CloudChannelFrameTag_CLOUD_CHANNEL_FRAME_WRAPPED_STRING)
}

// SendMessage sends a Message to the channel.
// Failure will close the channel.
func (c *Conn) SendMessage(m proto.Message) error {
	bytes, err := proto.Marshal(m)
	if err != nil {
		c.mc.Close()
		return err
	}
	return c.sendFrame(CloudChannelFrameTag_CLOUD_CHANNEL_FRAME_WRAPPED_MESSAGE,
		string(bytes))
}

// ReceiveMessage receives a Message (of a particular type) over the
// channel. Failure or eof will close the channel.
func (c *Conn) ReceiveMessage(m proto.Message) error {
	s, err :=
		receiveFrame(CloudChannelFrameTag_CLOUD_CHANNEL_FRAME_WRAPPED_MESSAGE)
	if err != nil {
		return err
	}
	err = proto.Unmarshal([]byte(s), m)
	if err != nil {
		mc.Close()
		return err
	}
	return nil
}

func (c *Conn) Abort(msg string) error {
	err := sendFrame(CloudChannelFrameTag_CLOUD_CHANNEL_FRAME_ABORT, msg)
	Close()
	return err
}

func (c *Conn) Disconnect() error {
	err := sendFrame(CloudChannelFrameTag_CLOUD_CHANNEL_FRAME_SHUTDOWN, "")
	if err != nil {
		_, err :=
			receiveFrame(CloudChannelFrameTag_CLOUD_CHANNEL_FRAME_SHUTDOWN_RESPONSE)
	}
	Close()
	return err
}
