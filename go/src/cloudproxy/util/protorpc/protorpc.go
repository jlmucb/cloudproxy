// File: protorpc.go
// Author: Kevin Walsh <kwalsh@holycross.edu>
// Description: Support for RPC over protobufs.
//
// Copyright (c) 2013, Google Inc.  All rights reserved.
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

/*
	Package protorpc implements a protobuf-based ClientCodec and ServerCodec for the
	rpc package. Clients can make concurrent or asynchronous requests, and these
	are handled in whatever order the servers choses.

	All service methods take two protobuf message pointers: a request and a
	response. RPC service method strings and sequence numbers are not sent over
	the connection separately from the requests and responses. Instead, the
	request and response protobuf messages must carry this information. To this
	end, both types of protobuf messages must begin with two fields: a method
	number and a sequence number. The method number must have tag 1 and can be any
	of the protobuf types that encode as a positive varint (uint32, enum, etc.).
	The sequence number must have tag 2 and be of type uint64. For example, the
	request (or response) protobuf definition might look like:

	  enum MyOperation { MULTIPLY = 1; DIVIDE = 2; }
	  message MyRequest {
			required MyOperation op = 1;
			required uint64 seq = 2;
			... // additional fields here...
		}
	
	Wire format: A request or response is encoded on the wire as a 32-bit length
	(encoded in network byte order), followed by a marshalled protobuf message.
	The separate length field is used for framing because the protobuf encoding
	does not preserve message boundaries.
*/
package protorpc

import (
	"errors"
	"io"
	"net/rpc"
	"sync"

	"code.google.com/p/goprotobuf/proto"

	"cloudproxy/util"
)

type ProtoClientMux interface {
	// Set the service method string and sequence number for a request.
	SetRequestHeader(req proto.Message, servicemethod string, seq uint64) error

	// Get the service method string for a given method number
	GetServiceMethod(number uint64) (string, error)
}

type clientCodec struct {
	m *util.MessageStream
	mux ProtoClientMux
	sending sync.Mutex
	resp []byte
}

// NewClientCodec returns a new rpc.ClientCodec using protobuf messages on conn,
// where mux is used to match request messages with the appropriate service and
// method.
func NewClientCodec(conn io.ReadWriteCloser, mux ProtoClientMux) rpc.ClientCodec {
	if m, ok := conn.(*util.MessageStream); ok {
		return &clientCodec{m, mux, sync.Mutex{}, nil}
	} else {
		return &clientCodec{util.NewMessageStream(conn), mux, sync.Mutex{}, nil}
	}
}

// NewClient returns a new rpc.Client to handle requests to the set of services
// at the other end of the connection. 
func NewClient(conn io.ReadWriteCloser, mux ProtoClientMux) *rpc.Client {
	return rpc.NewClientWithCodec(NewClientCodec(conn, mux))
}

var ErrBadRequestType = errors.New("protorpc: bad request type")
var ErrMissingRequest = errors.New("protorpc: missing request")
var ErrBadResponseType = errors.New("protorpc: bad response type")
var ErrMissingResponse = errors.New("protorpc: missing response")

func (c *clientCodec) WriteRequest(r *rpc.Request, x interface{}) error {
	y, ok := x.(proto.Message)
	if !ok || y == nil {
		return ErrBadRequestType
	}
	c.mux.SetRequestHeader(y, r.ServiceMethod, r.Seq)
	c.sending.Lock()
	_, err := c.m.WriteMessage(y) // writes htonl(length), marshal(y)
	c.sending.Unlock()
	return err
}

func (c *clientCodec) ReadResponseHeader(r *rpc.Response) error {
	// We can't just c.m.ReadMessage(x) because we don't yet know the type of
	// response message x. Instead, read the still-encoded message as a string,
	// then decode it (partially) using the ProtoRPCHeader protobuf message type.
	// Note: It is tempting to instead simply decode the first few fields directly
	// using proto.DecodeVarint() and friends, but that would rely on the ordering
	// of encoded fields which is not strictly guaranteed.
	s, err := c.m.ReadString() // reads htonl(length), string
	if err != nil {
		return err
	}
	resp := []byte(s)
	var hdr ProtoRPCHeader
	err = proto.Unmarshal(resp, &hdr)
	if err != nil {
		return err
	}
	r.Seq = *hdr.Seq
	r.ServiceMethod, err = c.mux.GetServiceMethod(*hdr.Op)
	if err != nil {
		return err
	}
	c.resp = resp
	return nil
}

func (c *clientCodec) ReadResponseBody(x interface{}) error {
	resp := c.resp
	c.resp = nil
	if x == nil {
		return nil
	}
	if resp == nil {
		return ErrMissingResponse
	}
	// Decode the response bytes again, this time using the correct response
	// message type.
	y, ok := x.(proto.Message)
	if !ok || y == nil {
		return ErrBadResponseType
	}
	return proto.Unmarshal(resp, y)
}

func (c *clientCodec) Close() error {
	return c.m.Close()
}

type ProtoServerMux interface {
	// Set the service method string and sequence number for a response.
	SetResponseHeader(req proto.Message, servicemethod string, seq uint64) error

	// Get the service method string for a given method number
	GetServiceMethod(number uint64) (string, error)
}

type serverCodec struct {
	m *util.MessageStream
	mux ProtoServerMux
	sending sync.Mutex
	req []byte
}

// NewServerCodec returns a new rpc.ServerCodec using protobuf messages on conn,
// where mux is used to match request messages with the appropriate service and
// method.
func NewServerCodec(conn io.ReadWriteCloser, mux ProtoServerMux) rpc.ServerCodec {
	return &serverCodec{util.NewMessageStream(conn), mux, sync.Mutex{}, nil}
}

func (c *serverCodec) ReadRequestHeader(r *rpc.Request) error {
	// This is almost identical to ReadResponseHeader(), above.
	s, err := c.m.ReadString() // reads htonl(length), string
	if err != nil {
		return err
	}
	req := []byte(s)
	var hdr ProtoRPCHeader
	err = proto.Unmarshal(req, &hdr)
	if err != nil {
		return err
	}
	r.Seq = *hdr.Seq
	r.ServiceMethod, err = c.mux.GetServiceMethod(*hdr.Op)
	if err != nil {
		return err
	}
	c.req = req
	return nil
}

func (c *serverCodec) ReadRequestBody(x interface{}) error {
	// This is almost identical to ReadResponseBody(), above.
	req := c.req
	c.req = nil
	if x == nil {
		return nil
	}
	if req == nil {
		return ErrMissingRequest
	}
	// Decode the request bytes again, this time using the correct request
	// message type.
	y, ok := x.(proto.Message)
	if !ok || y == nil {
		return ErrBadRequestType
	}
	return proto.Unmarshal(req, y)
}

func (c *serverCodec) WriteResponse(r *rpc.Response, x interface{}) error {
	y, ok := x.(proto.Message)
	if !ok || y == nil {
		return ErrBadResponseType
	}
	c.mux.SetResponseHeader(y, r.ServiceMethod, r.Seq)
	c.sending.Lock()
	_, err := c.m.WriteMessage(y) // writes htonl(length), marshal(req)
	c.sending.Unlock()
	return err
}

func (c *serverCodec) Close() error {
	return c.m.Close()
}

