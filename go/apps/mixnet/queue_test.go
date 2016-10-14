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
	"time"
)

// A dummy sever that reads a message from the connecting client.
func runDummyServerOne(ch chan<- testResult) {
	l, err := net.Listen(network, localAddr)
	if err != nil {
		ch <- testResult{err, nil}
		return
	}
	defer l.Close()

	c, err := l.Accept()
	if err != nil {
		ch <- testResult{err, nil}
		return
	}
	defer c.Close()

	buf := make([]byte, MaxMsgBytes)
	bytes, err := c.Read(buf)
	if err != nil {
		ch <- testResult{err, nil}
		return
	}

	if _, err = c.Write(buf[:bytes]); err != nil {
		ch <- testResult{err, nil}
		return
	}
	ch <- testResult{nil, buf[:bytes]}
}

// A dummy server that accepts clientCt connections and waits for msgCt messages
// from each client. The message is echoed.
func runDummyServer(clientCt, msgCt int, ch chan<- testResult, addr chan<- string) {
	l, err := net.Listen(network, localAddr)
	if err != nil {
		ch <- testResult{err, []byte{}}
		return
	}
	defer l.Close()
	addr <- l.Addr().String()

	done := make(chan bool)
	for i := 0; i < clientCt; i++ {
		c, err := l.Accept()
		if err != nil {
			ch <- testResult{err, []byte{}}
			return
		}

		go func(c net.Conn, clientNo int) {
			defer c.Close()
			buf := make([]byte, MaxMsgBytes+1)
			for j := 0; j < msgCt; j++ {
				bytes, err := c.Read(buf)
				if err != nil {
					ch <- testResult{err, nil}
				} else {
					_, err := c.Write(buf[:bytes])
					if err != nil {
						ch <- testResult{err, nil}
					} else {
						bufCopy := make([]byte, bytes)
						copy(bufCopy, buf[:bytes])
						ch <- testResult{nil, bufCopy}
					}
				}
				done <- true
			}
		}(c, i)
	}

	for i := 0; i < clientCt*msgCt; i++ {
		<-done
	}
}

// Test enqeueing a bunch of messages and dequeueing them.
func TestQueueSend(t *testing.T) {

	// batchSize must divide clientCt; otherwise the sendQueue will block forever.
	batchSize := 2
	clientCt := 4
	msgCt := 3

	timeout, _ := time.ParseDuration("2s")
	sq := NewQueue(network, nil, batchSize, timeout)
	kill := make(chan bool)
	done := make(chan bool)
	dstCh := make(chan testResult)
	dstAddrCh := make(chan string)

	go runDummyServer(clientCt, msgCt, dstCh, dstAddrCh)
	dstAddr := <-dstAddrCh

	go func() {
		sq.DoQueue(kill)
		done <- true
	}()

	go func() {
		sq.DoQueueErrorHandler(nil, kill)
		done <- true
	}()

	conns := make([]net.Conn, clientCt)
	var err error
	for i := 0; i < clientCt; i++ {
		conns[i], err = net.DialTimeout(network, dstAddr, timeout)
		if err != nil {
			t.Error("Couldn't connect to server:", err)
		}
	}

	for round := 0; round < msgCt; round++ {
		// Enqueue some messages.
		for i := 0; i < clientCt; i++ {
			q := new(Queueable)
			q.id = uint64(i)
			q.conn = conns[i]
			q.msg = []byte(
				fmt.Sprintf("I am anonymous, but my ID is %d.", i))
			sq.Enqueue(q)
		}

		// Read results from destination server.
		for i := 0; i < clientCt; i++ {
			res := <-dstCh
			if res.err != nil {
				t.Error(res.err)
				break
			} else {
				t.Log(string(res.msg))
			}
		}
	}

	kill <- true
	kill <- true

	<-done
	<-done
}
