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
// limitations under the License0.

package mixnet

import (
	"fmt"
	"net"
	"testing"

	"github.com/golang/protobuf/proto"
)

// A dummy server that accepts ct connections and waits for a message
// from each client.
func runDummyServer(ct int, ch chan<- testResult) {
	l, err := net.Listen(network, dstAddr)
	if err != nil {
		ch <- testResult{err, []byte{}}
		return
	}
	defer l.Close()

	done := make(chan bool)
	for i := 0; i < ct; i++ {
		c, err := l.Accept()
		if err != nil {
			ch <- testResult{err, []byte{}}
			return
		}
		defer c.Close()

		go func() {
			buff := make([]byte, CellBytes*10)
			bytes, err := c.Read(buff)
			if err != nil {
				ch <- testResult{err, []byte{}}
				done <- true
				return
			}

			ch <- testResult{nil, buff[:bytes]}
			done <- true
		}()
	}

	for i := 0; i < ct; i++ {
		<-done
	}
}

// Enqueue a bunch of messages and then dequeue them.
func TestSendQueue(t *testing.T) {
	batchSize := 10
	sq := NewSendQueue(network, batchSize)
	kill := make(chan bool)
	done := make(chan bool)
	dstCh := make(chan testResult)

	go runDummyServer(batchSize, dstCh)

	go func() {
		sq.DoSendQueue(kill)
		done <- true
	}()

	go func() {
		sq.DoSendQueueErrorHandler(kill)
		done <- true
	}()

	// Enqueue some messages.
	for i := 0; i < batchSize; i++ {
		q := new(Queueable)
		q.Id = proto.Uint64(uint64(i))
		q.Addr = proto.String(dstAddr)
		q.Msg = []byte(
			fmt.Sprintf("I am anonymous, but my ID is %d.", i))
		sq.Enqueue(q)
	}

	// Read results from destination server.
	for i := 0; i < batchSize; i++ {
		res := <-dstCh
		if res.err != nil {
			t.Error(res.err)
		} else {
			t.Log(string(res.msg))
		}
	}

	kill <- true
	kill <- true

	<-done
	<-done
}
