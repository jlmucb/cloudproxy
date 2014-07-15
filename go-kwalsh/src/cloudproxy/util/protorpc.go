package util

import (
	"code.google.com/p/goprotobuf/proto"
	"fmt"
	"io"
	"os"
	"sync"
)

type outstandingRequest struct {
	uint64 seq
	string method
}

type clientCodec struct {
	m MessageReadWriteCloser

	mutex   sync.Mutex

	// Tao RPC does not send sequence numbers (requests are always handled in
	// order) or method names (which are instead embeded within arg messages).
	// Client side keeps a queue of sequence numbers and method names for
	// outstanding calls so it can fill out the responses.

	// Queue of outstanding requests. New requests go at qtail. When qcount > 0,
	// the oldest outstanding request is at qhead.
	qnodes []outstandingRequest
	qhead, qtail, qcount int

	proto.Message *reply
}

// NewClientCodec returns a new rpc.ClientCodec using protobuf messages on conn.
func NewClientCodec(conn MessageReadWriteCloser) rpc.ClientCodec {
	return &clientCodec{
		m: conn,
		qnodes: make([]outstandingRequest, 1),
	}
}

const BadRequestType = errors.New("Bad request type")

func (c *clientCodec) WriteRequest(r *rpc.Request, param interface{}) error {
	req, ok = param.(proto.Message)
	if !ok {
		return BadRequestType
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	err := c.m.WriteMessage(req)
	if err != nil {
		return err
	}
	if c.qcount > 0 && c.qhead == c.qtail {
		nodes := make([]outstandingRequest, 2*len(c.qnodes))
		copy(nodes, c.qnodes[c.qhead:])
		copy(nodes[len(c.qnodes)-c.qhead:], c.qnodes[:c.qhead])
		c.qhead = 0
		c.qtail = len(q.nodes)
		c.qnodes = nodes
	}
	c.qnodes[c.qtail].seq = r.Seq
	c.qnodes[c.qtail].method = r.ServiceMethod
	c.qtail = (c.qtail + 1) % len(c.qnodes)
	c.qcount++
}

func (c *clientCodec) ReadResponseHeader(r *rpc.Response) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.qcount == 0 {
		return err
	}
	node := q.nodes[q.head]
	q.head = (q.head + 1) % len(q.nodes)
	q.count--
	return node
}

func (c *clientCodec) ReadResponseBody(x interface{}) error {
	if x == nil {
		return nil
	}
	return json.Unmarshal(*c.resp.Result, x)
}

func (c *clientCodec) Close() error {
	return c.c.Close()
}

// NewClient returns a new rpc.Client to handle requests to the
// set of services at the other end of the connection.
func NewClient(conn io.ReadWriteCloser) *rpc.Client {
	return rpc.NewClientWithCodec(NewClientCodec(conn))
}

// Dial connects to a JSON-RPC server at the specified network address.
func Dial(network, address string) (*rpc.Client, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return NewClient(conn), err
}
