// Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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

// Package protorpc implements a protobuf-based ClientCodec and ServerCodec for
// the rpc package. Clients can make concurrent or asynchronous requests, and
// these are handled in whatever order the servers chooses.
//
// All service methods take two protobuf message pointers: a request and a
// response. RPC service method strings, sequence numbers, and response errors
// are sent over the connection separately from the requests and responses.
//
// Wire format: A request or response is encoded on the wire as a 32-bit length
// (in network byte order), followed by a marshalled protobuf for the header,
// followed by another 32-bit length, then a marshaled protobuf for the body.
// Separate length fields are used for framing because the protobuf encoding does
// not preserve message boundaries. Except for I/O errors, protobufs are encoded
// in pairs: first the header, then the request or response body.
package protorpc

import (
	"errors"
	"io"
	"net/rpc"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/util"
)

// clientCodec is a net/rpc client codec for protobuf messages
type clientCodec struct {
	m       *util.MessageStream
	sending sync.Mutex
}

// NewClientCodec returns a new rpc.ClientCodec using protobuf messages on conn.
func NewClientCodec(conn io.ReadWriteCloser) rpc.ClientCodec {
	m, ok := conn.(*util.MessageStream)
	if !ok {
		// The given conn lacks framing, so add some.
		m = util.NewMessageStream(conn)
	}
	return &clientCodec{m, sync.Mutex{}}
}

// NewClient returns a new rpc.Client to handle requests to the set of services
// at the other end of the connection.
func NewClient(conn io.ReadWriteCloser) *rpc.Client {
	return rpc.NewClientWithCodec(NewClientCodec(conn))
}

// Error types for the protorpc package.
var (
	ErrBadRequestType  = errors.New("protorpc: bad request type")
	ErrMissingRequest  = errors.New("protorpc: missing request")
	ErrBadResponseType = errors.New("protorpc: bad response type")
	ErrMissingResponse = errors.New("protorpc: missing response")
)

// WriteRequest encodes and sends a net/rpc request header r with body x.
func (c *clientCodec) WriteRequest(r *rpc.Request, x interface{}) error {
	body, ok := x.(proto.Message)
	if !ok || body == nil {
		// TODO(kwalsh) Not clear if this is legal, but I think not.
		// Don't send anything.
		return util.Logged(ErrBadRequestType)
	}
	var hdr ProtoRPCRequestHeader
	hdr.Op = proto.String(r.ServiceMethod)
	hdr.Seq = proto.Uint64(r.Seq)
	c.sending.Lock()
	_, err := c.m.WriteMessage(&hdr) // writes htonl(length), marshal(hdr)
	if err == nil {
		_, err = c.m.WriteMessage(body) // writes htonl(length), marshal(body)
	}
	c.sending.Unlock()
	return util.Logged(err)
}

// ReadResponseHeader receives and decodes a net/rpc response header r.
func (c *clientCodec) ReadResponseHeader(r *rpc.Response) error {
	var err error
	var hdr ProtoRPCResponseHeader
	if err = c.m.ReadMessage(&hdr); err != nil {
		return util.Logged(err)
	}
	r.Seq = *hdr.Seq
	r.ServiceMethod = *hdr.Op
	if hdr.Error != nil {
		r.Error = *hdr.Error
	}
	return nil
}

// ReadResponseBody receives and decodes a net/rpc response body x.
func (c *clientCodec) ReadResponseBody(x interface{}) error {
	if x == nil {
		// rpc.Client is telling us to read and discard the response, perhaps
		// because response header contains an error (in which case the server would
		// have encoded a blank message body).
		_, err := c.m.ReadString()
		return util.Logged(err)
	}
	body, ok := x.(proto.Message)
	if !ok || body == nil {
		// TODO(kwalsh) Not clear if this is legal, but I think not.
		// Read and discard the response body.
		c.m.ReadString()
		return util.Logged(ErrBadResponseType)
	}
	return util.Logged(c.m.ReadMessage(body))
}

// Close closes the channel used by the client codec.
func (c *clientCodec) Close() error {
	return c.m.Close()
}

// serverCodec is a net/rpc server codec for protobuf messages
type serverCodec struct {
	m       *util.MessageStream
	sending sync.Mutex
}

// NewServerCodec returns a new rpc.ServerCodec using protobuf messages on conn.
func NewServerCodec(conn io.ReadWriteCloser) rpc.ServerCodec {
	m, ok := conn.(*util.MessageStream)
	if !ok {
		// The given conn lacks framing, so add some.
		m = util.NewMessageStream(conn)
	}
	return &serverCodec{m, sync.Mutex{}}
}

// ReadRequestHeader receives and decodes a net/rpc request header r.
func (c *serverCodec) ReadRequestHeader(r *rpc.Request) error {
	// This is almost identical to ReadResponseHeader(), above.
	var err error
	var hdr ProtoRPCRequestHeader
	if err = c.m.ReadMessage(&hdr); err != nil {
		// Don't log an error here, since this is where normal EOF
		// happens over net/rpc channels, e.g., if a client finishes and
		// disconnects.
		return err
	}
	r.Seq = *hdr.Seq
	r.ServiceMethod = *hdr.Op
	return nil
}

// ReadRequestBody receives and decodes a net/rpc request body x.
func (c *serverCodec) ReadRequestBody(x interface{}) error {
	// This is almost identical to ReadResponseBody(), above.
	if x == nil {
		// rpc.Server is telling us to read and discard the request, perhaps because
		// response header was read successfully but contained an unexpected service
		// method string. The client would have encoded an actual message body.
		_, err := c.m.ReadString()
		return util.Logged(err)
	}
	body, ok := x.(proto.Message)
	if !ok || body == nil {
		// TODO(kwalsh) Not clear if this is legal, but I think not.
		// Read and discard the request body.
		c.m.ReadString()
		return util.Logged(ErrBadRequestType)
	}
	return util.Logged(c.m.ReadMessage(body))
}

// WriteResponse encodes and sends a net/rpc response header r with body x.
func (c *serverCodec) WriteResponse(r *rpc.Response, x interface{}) error {
	// This is similar to WriteRequest(), above.
	var encodeErr error
	var hdr ProtoRPCResponseHeader
	hdr.Op = proto.String(r.ServiceMethod)
	hdr.Seq = proto.Uint64(r.Seq)
	var body proto.Message
	var ok bool
	if r.Error != "" {
		// Error responses have empty body. In this case, x can be an empty struct
		// from net/rpc.Server, and net/rpc.Client will discard the body in any
		// case, so leave body == nil.
		hdr.Error = proto.String(r.Error)
	} else if body, ok = x.(proto.Message); !ok || body == nil {
		// If x isn't a protobuf, or is a nil protobuf, turn reply into an error and
		// leave body == nil.
		encodeErr = ErrBadResponseType
		msg := encodeErr.Error()
		hdr.Error = &msg
	}

	c.sending.Lock()
	_, err := c.m.WriteMessage(&hdr) // writes htonl(length), marshal(hdr)
	if err == nil {
		_, err = c.m.WriteMessage(body) // writes htonl(length), marshal(body)
	}
	c.sending.Unlock()
	if encodeErr != nil {
		err = encodeErr
	}
	return util.Logged(err)
}

// Close closes the channel used by the server codec.
func (c *serverCodec) Close() error {
	return c.m.Close()
}
