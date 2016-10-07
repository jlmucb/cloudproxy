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
	"crypto/rand"
	"encoding/binary"
	"io"
	"log"
	"net"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
)

// The Queueable object is passed through a channel and mutates the state of
// the Queue in some manner; for example, it can set the destination
// adddress or connection of a sender, add a message or request for reply
// to the queue, or destroy any resources associated with the connection.
type Queueable struct {
	id       uint64 // circuit id
	msg      []byte
	conn     net.Conn
	prevConn net.Conn
	remove   bool
	destroy  bool
}

type sendQueueError struct {
	id   uint64
	conn net.Conn // where to send the error to
	error
}

// The Queue structure maps a circuit identifier corresponding to a sender
// (in the router context) to a destination. It also maintains a message buffer
// for each sender. Once messages are ready on enough buffers, a batch of
// messages are transmitted simultaneously.
type Queue struct {
	batchSize int // Number of messages to transmit in a round.
	ct        int // Current number of buffers with messages ready.
	// Tao to get the random bytes
	// Might be okay to just use crypto/rand..
	t tao.Tao

	network string        // Network protocol, e.g. "tcp".
	timeout time.Duration // Timeout on dial/read/write.

	sendBuffer map[uint64]*list.List // Message buffer of sender.

	queue chan *Queueable     // Channel for queueing messages/directives.
	err   chan sendQueueError // Channel for handling errors.
}

// NewQueue creates a new Queue structure.
func NewQueue(network string, t tao.Tao, batchSize int, timeout time.Duration) (sq *Queue) {
	sq = new(Queue)
	sq.batchSize = batchSize
	sq.network = network
	sq.t = t
	sq.timeout = timeout

	sq.sendBuffer = make(map[uint64]*list.List)

	sq.queue = make(chan *Queueable)
	sq.err = make(chan sendQueueError)
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
func (sq *Queue) EnqueueMsg(id uint64, msg []byte, conn, prevConn net.Conn) {
	q := new(Queueable)
	q.id = id
	q.msg = make([]byte, len(msg))
	copy(q.msg, msg)
	q.conn = conn
	q.prevConn = prevConn
	sq.queue <- q
}

// Close creates a queueable object that sends the last msg in the circuit,
// closes the connection and deletes all associated resources.
func (sq *Queue) Close(id uint64, msg []byte, destroy bool, conn, prevConn net.Conn) {
	q := new(Queueable)
	q.id = id
	if msg != nil {
		q.msg = make([]byte, len(msg))
		copy(q.msg, msg)
	}
	q.remove = true
	q.destroy = destroy
	q.conn = conn
	q.prevConn = prevConn
	sq.queue <- q
}

func (sq *Queue) delete(q *Queueable) {
	// Close the connection and delete all resources. Any subsequent
	// messages or reply requests will cause an error.
	if q.destroy {
		// Wait for the client to kill the connection or timeout
		if q.msg == nil {
			q.conn.Close()
		} else {
			_, err := q.conn.Read([]byte{0})
			if err != nil {
				e, ok := err.(net.Error)
				if err == io.EOF || (ok && e.Timeout()) {
					// If it times out, and the connection
					// is supposed to be closed,
					// ignore it..
					q.conn.Close()
				}
			}
		}
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
			return

		case q := <-sq.queue:
			if q.msg != nil {
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
			if err.conn == nil {
				var d Directive
				d.Type = DirectiveType_ERROR.Enum()
				d.Error = proto.String(err.Error())
				cell, e := marshalDirective(err.id, &d)
				if e != nil {
					glog.Errorf("queue: %s\n", e)
					return
				}
				queue.EnqueueMsg(err.id, cell, err.conn, nil)
			} else {
				glog.Errorf("client no. %d: %s\n", err.id, err)
			}
		}
	}
}

// dequeue sends one message from each send buffer for each serial ID in a
// random order. This is called by DoQueue and is not safe to call directly
// elsewhere.
func (sq *Queue) dequeue() {

	// Shuffle the serial IDs.
	pi := make([]int, sq.ct)
	for i := 0; i < sq.ct; i++ { // Initialize a trivial permutation
		pi[i] = i
	}

	for i := sq.ct - 1; i > 0; i-- { // Shuffle by random swaps
		var b []byte
		var err error = nil
		if sq.t != nil {
			b, err = sq.t.GetRandomBytes(8)
		}
		if err != nil || sq.t == nil {
			glog.Error("Could not read random bytes from Tao")
			b = make([]byte, 8)
			if _, err := rand.Read(b); err != nil {
				// if we can't even get crypto/rand, fatal error
				log.Fatal(err)
			}
		}
		j := int(binary.LittleEndian.Uint64(b) % uint64(i+1))
		if j != i {
			tmp := pi[j]
			pi[j] = pi[i]
			pi[i] = tmp
		}
	}

	ids := make([]uint64, sq.ct)
	i := 0
	for id, buf := range sq.sendBuffer {
		if buf.Len() > 0 {
			ids[pi[i]] = id
			i++
		}
	}

	// Issue a sendWorker thread for each message to be sent.
	ch := make(chan senderResult)
	for _, id := range ids[:sq.batchSize] {
		q := sq.sendBuffer[id].Front().Value.(*Queueable)
		go senderWorker(sq.network, q, ch, sq.err, sq.timeout)
	}

	// Wait for workers to finish.
	for _ = range ids[:sq.batchSize] {
		res := <-ch

		// If this was close with a message, then remove q here
		q := sq.sendBuffer[res.id].Front().Value.(*Queueable)
		if q.remove {
			sq.delete(q)
		}

		// Pop the message from the buffer and decrement the counter
		// if the buffer is empty.
		// Resource might be removed (circuit destroyed); check first
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

func senderWorker(network string, q *Queueable,
	res chan<- senderResult, err chan<- sendQueueError, timeout time.Duration) {
	// Wait to connect until the queue is dequeued in order to prevent
	// an observer from correlating an incoming cell with the handshake
	// with the destination server.

	q.conn.SetDeadline(time.Now().Add(timeout))
	if q.msg != nil { // Send the message.
		if q.msg[TYPE] == 1 {
			var d Directive
			unmarshalDirective(q.msg, &d)
		}
		if _, e := q.conn.Write(q.msg); e != nil {
			err <- sendQueueError{q.id, q.prevConn, e}
			res <- senderResult{q.conn, q.id}
			return
		}
	}

	res <- senderResult{q.conn, q.id}
}
