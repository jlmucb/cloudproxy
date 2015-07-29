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
	"math/rand"
	"net"

	"github.com/golang/glog"
)

type sendQueueError struct {
	id uint64 // Serial identifier of sender to which error pertains.
	error
}

// The SendQueue structure maps a serial identifier corresponding to a sender
// (in the router context) to a destination. It also maintains a message buffer
// for each sender. Once there messages ready on enough buffers, a batch of
// messages are transmitted simultaneously.
type SendQueue struct {
	batchSize int // Number of messages to transmit in a roud.
	ct        int // Current number of buffers with messages ready.

	network string // Network protocol, e.g. "tcp".

	nextAddr   map[uint64]string     // Address of destination.
	nextConn   map[uint64]net.Conn   // Connection to destination.
	sendBuffer map[uint64]*list.List // Message buffer of sender.

	queue chan Queueable      // Channel for queueing messages/directives.
	err   chan sendQueueError // Channel for handling errors.
}

// NewSendQueue creates a new SendQueue structure.
func NewSendQueue(network string, batchSize int) (sq *SendQueue) {
	sq = new(SendQueue)
	sq.batchSize = batchSize
	sq.network = network

	sq.nextAddr = make(map[uint64]string)
	sq.nextConn = make(map[uint64]net.Conn)
	sq.sendBuffer = make(map[uint64]*list.List)

	sq.queue = make(chan Queueable)
	sq.err = make(chan sendQueueError)
	return sq
}

// Enqueue adds a queueable object, such as a message or directive, to the
// send queue.
func (sq *SendQueue) Enqueue(q *Queueable) {
	sq.queue <- *q
}

// DoSendQueue adds messages to a queue and transmits messages in batches.
// Typically a message is a cell, but when the calling router is an exit point,
// the message length is arbitrary. A batch is transmitted when there are
// messages on batchSize distinct sender channels.
func (sq *SendQueue) DoSendQueue(kill <-chan bool) {
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
			if _, def := sq.nextAddr[*q.Id]; !def && q.Addr != nil {
				sq.nextAddr[*q.Id] = *q.Addr
			}

			if q.Dir != nil {
				sq.err <- sendQueueError{*q.Id,
					errors.New("directives not implemented")}

			} else if _, def := sq.nextAddr[*q.Id]; !def && q.Msg != nil {
				sq.err <- sendQueueError{*q.Id,
					errors.New("request to send message without a destination")}

			} else {

				// Create a send buffer for the sender ID if it doesn't exist.
				if _, def := sq.sendBuffer[*q.Id]; !def {
					sq.sendBuffer[*q.Id] = list.New()
				}
				buf := sq.sendBuffer[*q.Id]

				// The buffer was empty but now has a message ready; increment
				// the counter.
				if buf.Len() == 0 {
					sq.ct++
				}

				// Add message to send buffer.
				buf.PushBack(q.Msg)
			}

			// Transmit the message batch if it is full.
			if sq.ct == sq.batchSize {
				sq.dequeue()
			}
		}
	}
}

// DoSendQueueErrorHandler handles errors produced by DoSendQueue. When this
// is fully fleshed out, it will enqueue into the response queue a Directive
// containing an error message. For now, just print out the error.
func (sq *SendQueue) DoSendQueueErrorHandler(kill <-chan bool) {
	for {
		select {
		case <-kill:
			return
		case err := <-sq.err:
			glog.Errorf("send queue (%d): %s\n", err.id, err.Error())
		}
	}
}

// dequeue sends one message from each send buffer for each serial ID in a
// random order. This is called by DoSendQueue and is not safe to call directly
// elsewhere.
func (sq *SendQueue) dequeue() {

	// Shuffle the serial IDs.
	order := rand.Perm(int(sq.ct)) // TODO(cjpatton) Use tao.GetRandomBytes().
	ids := make([]uint64, sq.ct)
	i := 0
	for id := range sq.sendBuffer {
		ids[order[i]] = id
		i++
	}

	// Issue a sendWorker thread for each message to be sent.
	ch := make(chan senderResult)
	for _, id := range ids {
		addr := sq.nextAddr[id]
		msg := sq.sendBuffer[id].Front().Value.([]byte)
		c, def := sq.nextConn[id]
		go senderWorker(sq.network, addr, id, msg, c, def, ch, sq.err)
	}

	// Wait for workers to finish.
	for _ = range ids {
		res := <-ch
		if res.c != nil {
			// Save the connection.
			sq.nextConn[res.id] = res.c

			// Pop the message from the buffer and decrement the counter
			// if the buffer is empty.
			buf := sq.sendBuffer[res.id]
			buf.Remove(buf.Front())
			if buf.Len() == 0 {
				sq.ct--
			}
		}
	}
}

type senderResult struct {
	c  net.Conn
	id uint64
}

func senderWorker(network, addr string, id uint64, msg []byte, c net.Conn, def bool,
	res chan<- senderResult, err chan<- sendQueueError) {
	var e error

	// Wait to connect until the queue is dequeued in order to prevent
	// an observer from correlating an incoming cell with the handshake
	// with the destination server.
	if !def {
		c, e = net.Dial(network, addr) // TODO(cjpatton) timeout.
		if e != nil {
			err <- sendQueueError{id, e}
			res <- senderResult{nil, id}
			return
		}
	}

	// Send the message.
	if _, e := c.Write(msg); e != nil {
		err <- sendQueueError{id, e}
		res <- senderResult{nil, id}
		return
	}

	res <- senderResult{c, id}
}
