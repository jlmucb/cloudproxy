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
	"container/list"
	"errors"
	"io"
	"math/rand"
	"net"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
)

// The Queueable object is passed through a channel and mutates the state of
// the Queue in some manner; for example, it can set the destination
// adddress or connection of a sender, add a message or request for reply
// to the queue, or destroy any resources associated with the connection.
type Queueable struct {
	id      uint64 // circuit id
	prevId  uint64 // prev hop circuit id
	addr    string
	msg     []byte
	conn    net.Conn
	reply   chan []byte
	remove  bool
	destroy bool
}

type sendQueueError struct {
	id uint64 // circuit id
	error
}

// The Queue structure maps a serial identifier corresponding to a sender
// (in the router context) to a destination. It also maintains a message buffer
// for each sender. Once there messages ready on enough buffers, a batch of
// messages are transmitted simultaneously.
type Queue struct {
	batchSize int // Number of messages to transmit in a round.
	ct        int // Current number of buffers with messages ready.

	network string        // Network protocol, e.g. "tcp".
	timeout time.Duration // Timeout on dial/read/write.

	nextAddr   map[uint64]string     // Address of destination.
	nextConn   map[uint64]net.Conn   // Connection to destination.
	sendBuffer map[uint64]*list.List // Message buffer of sender.
	errIds     map[uint64]uint64

	queue     chan *Queueable     // Channel for queueing messages/directives.
	err       chan sendQueueError // Channel for handling errors.
	destroyed chan uint64         // Channel for waiting for circuit destruction, which happens asynchronously.
}

// NewQueue creates a new Queue structure.
func NewQueue(network string, batchSize int, timeout time.Duration) (sq *Queue) {
	sq = new(Queue)
	sq.batchSize = batchSize
	sq.network = network
	sq.timeout = timeout

	sq.nextAddr = make(map[uint64]string)
	sq.nextConn = make(map[uint64]net.Conn)
	sq.sendBuffer = make(map[uint64]*list.List)
	sq.errIds = make(map[uint64]uint64)

	sq.queue = make(chan *Queueable)
	sq.err = make(chan sendQueueError)
	sq.destroyed = make(chan uint64)
	return sq
}

// Enqueue inserts a queueable object into the queue. Note that this is
// generally unsafe to use concurrently because it doesn't make a copy of the
// data.
func (sq *Queue) Enqueue(q *Queueable) {
	sq.queue <- q
}

// EnqueueMsg copies a byte slice into a queueable object and adds it to
// the queue.
func (sq *Queue) EnqueueMsg(id, prevId uint64, msg []byte) {
	q := new(Queueable)
	q.id = id
	q.prevId = prevId
	q.msg = make([]byte, len(msg))
	copy(q.msg, msg)
	sq.queue <- q
}

// EnqueueReply creates a queuable object with a reply channel and adds it to
// the queue.
func (sq *Queue) EnqueueReply(id, prevId uint64, reply chan []byte) {
	q := new(Queueable)
	q.id = id
	q.prevId = prevId
	q.reply = reply
	sq.queue <- q
}

// EnqueueMsgReply creates a queueable object with a message and a reply channel
// and adds it to the queue.
func (sq *Queue) EnqueueMsgReply(id, prevId uint64, msg []byte, reply chan []byte) {
	q := new(Queueable)
	q.id = id
	q.prevId = prevId
	q.msg = make([]byte, len(msg))
	q.reply = reply
	copy(q.msg, msg)
	sq.queue <- q
}

// SetAddr copies an address into a queuable object and adds it to the queue.
// This sets the next-hop address for the id.
func (sq *Queue) SetAddr(id uint64, addr string) {
	q := new(Queueable)
	q.id = id
	q.addr = addr
	sq.queue <- q
}

// SetConn creates a queueable object with a net.Conn interface and adds it to
// the queue. This allows us to reuse an already created channel for replying.
func (sq *Queue) SetConn(id uint64, c net.Conn) {
	q := new(Queueable)
	q.id = id
	q.conn = c
	sq.queue <- q
}

// Close creates a queueable object that sends the last msg,
// closes the connection and deletes all associated resources.
func (sq *Queue) Close(id uint64, msg []byte, destroy bool) {
	q := new(Queueable)
	q.id = id
	if msg != nil {
		q.msg = make([]byte, len(msg))
		copy(q.msg, msg)
	}
	q.remove = true
	q.destroy = destroy
	sq.queue <- q
}

func (sq *Queue) delete(q *Queueable) {
	// Close the connection and delete all resources. Any subsequent
	// messages or reply requests will cause an error.
	if c, def := sq.nextConn[q.id]; def {
		if q.destroy {
			_, err := c.Read([]byte{0})
			if err == io.EOF {
				c.Close()
			}
		}
		delete(sq.nextConn, q.id)
	}
	if _, def := sq.nextAddr[q.id]; def {
		delete(sq.nextAddr, q.id)
	}
	if _, def := sq.sendBuffer[q.id]; def {
		delete(sq.sendBuffer, q.id)
	}
}

// DoQueue adds messages to a queue and transmits messages in batches. It also
// provides an interface for receiving messages from a server. Typically a
// message is a cell, but when the calling router is an exit point, the message
// length is arbitrary. A batch is transmitted when there are messages on
// batchSize distinct sender channels.
func (sq *Queue) DoQueue(kill <-chan bool) {
	for {
		select {
		case <-kill:
			for _, c := range sq.nextConn {
				c.Close()
			}
			return

		case q := <-sq.queue:
			// Set the next-hop address. We don't allow the destination address
			// or connection to be overwritten in order to avoid accumulating
			// stale connections on routers.
			if _, def := sq.nextAddr[q.id]; !def && q.addr != "" {
				sq.nextAddr[q.id] = q.addr
			}

			// Set the next-hop connection. This is useful for routing replies
			// from the destination over already created circuits back to the
			// source.
			if _, def := sq.nextConn[q.id]; !def && q.conn != nil {
				sq.nextConn[q.id] = q.conn
			}

			if q.msg != nil || q.reply != nil {
				// Add message or message request (reply) to the queue.
				if _, def := sq.nextAddr[q.id]; !def {
					sq.err <- sendQueueError{q.prevId,
						errors.New("request to send/receive message without a destination")}
					continue
				}

				// Create a send buffer for the sender ID if it doesn't exist.
				if _, def := sq.sendBuffer[q.id]; !def {
					sq.sendBuffer[q.id] = list.New()
				}
				buf := sq.sendBuffer[q.id]

				// The buffer was empty but now has a message ready; increment
				// the counter.
				if buf.Len() == 0 {
					sq.ct++
				}

				// Add message to send buffer.
				buf.PushBack(q)
			} else if q.remove {
				sq.delete(q)
			}

			// Transmit batches of messages.
			for sq.ct >= sq.batchSize {
				sq.dequeue()
			}
		}
	}
}

// DoQueueErrorHandler handles errors produced by DoQueue by enqueing onto
// queue a directive containing the error message.
func (sq *Queue) DoQueueErrorHandler(queue *Queue, kill <-chan bool) {
	for {
		select {
		case <-kill:
			return
		case err := <-sq.err:
			var d Directive
			d.Type = DirectiveType_ERROR.Enum()
			d.Error = proto.String(err.Error())
			cell, e := marshalDirective(err.id, &d)
			if e != nil {
				glog.Errorf("queue: %s\n", e)
				return
			}
			queue.EnqueueMsg(err.id, 0, cell)
		}
	}
}

// DoQueueErrorHandlerLog logs errors that occur on this queue.
func (sq *Queue) DoQueueErrorHandlerLog(name string, kill <-chan bool) {
	for {
		select {
		case <-kill:
			return
		case err := <-sq.err:
			glog.Errorf("%s, client no. %d: %s\n", name, err.id, err)
		}
	}
}

// dequeue sends one message from each send buffer for each serial ID in a
// random order. This is called by DoQueue and is not safe to call directly
// elsewhere.
func (sq *Queue) dequeue() {

	// Shuffle the serial IDs.
	order := rand.Perm(int(sq.ct)) // TODO(cjpatton) Use tao.GetRandomBytes().
	ids := make([]uint64, sq.ct)
	i := 0
	for id, buf := range sq.sendBuffer {
		if buf.Len() > 0 {
			ids[order[i]] = id
			i++
		}
	}

	// Issue a sendWorker thread for each message to be sent.
	ch := make(chan senderResult)
	for _, id := range ids[:sq.batchSize] {
		addr := sq.nextAddr[id]
		q := sq.sendBuffer[id].Front().Value.(*Queueable)
		c, def := sq.nextConn[id]
		go senderWorker(sq.network, addr, q, c, def, ch, sq.err, sq.timeout)
	}

	// Wait for workers to finish.
	for _ = range ids[:sq.batchSize] {
		res := <-ch
		if res.c != nil {
			// Save the connection.
			sq.nextConn[res.id] = res.c
		}

		// If this was close with a message, then remove q here
		q := sq.sendBuffer[res.id].Front().Value.(*Queueable)
		if q.remove {
			sq.delete(q)
		}

		// Pop the message from the buffer and decrement the counter
		// if the buffer is empty.
		// resource might be removed (circuit destroyed); check first
		if buf, ok := sq.sendBuffer[res.id]; ok {
			buf.Remove(buf.Front())
			if buf.Len() == 0 {
				sq.ct--
			}
		} else {
			sq.ct--
		}
	}
}

type senderResult struct {
	c  net.Conn
	id uint64
}

func senderWorker(network, addr string, q *Queueable, c net.Conn, def bool,
	res chan<- senderResult, err chan<- sendQueueError, timeout time.Duration) {
	var e error

	// Wait to connect until the queue is dequeued in order to prevent
	// an observer from correlating an incoming cell with the handshake
	// with the destination server.
	if !def {
		c, e = net.DialTimeout(network, addr, timeout)
		if e != nil {
			err <- sendQueueError{q.prevId, e}
			res <- senderResult{c, q.id}
			if q.reply != nil {
				q.reply <- nil
			}
			return
		}
	}

	c.SetDeadline(time.Now().Add(timeout))
	if q.msg != nil { // Send the message.
		if _, e := c.Write(q.msg); e != nil {
			err <- sendQueueError{q.prevId, e}
			res <- senderResult{c, q.id}
			if q.reply != nil {
				q.reply <- nil
			}
			return
		}
	}

	c.SetDeadline(time.Now().Add(timeout))
	if q.reply != nil { // Receive a message.
		msg := make([]byte, MaxMsgBytes)
		bytes, e := c.Read(msg)
		if e != nil {
			err <- sendQueueError{q.prevId, e}
			res <- senderResult{c, q.id}
			q.reply <- nil
			return
		}
		// Pass message to channel.
		q.reply <- msg[:bytes]
	}

	res <- senderResult{c, q.id}
}
