// Copyright (c) 2014, Google, Inc. All rights reserved.
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

package protorpc

import (
	"errors"
	"io"
	"net/rpc"
	"reflect"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/util"
)

// serverUIDCodec is a net/rpc server codec for protobuf messages. It holds a
// uid and a gid that it inserts in request messages. So, valid receivers must
// have a receiving type of the form
//
// type Example struct {
//   uid     int
//   gid     int
//   message *RPCMessage
// }
//
// Due to embedding, all the methods on serverUIDCodec are the same as
// serverCodec, except for ReadRequestBody, which is modified to reflect on the
// type and inject the uid.
type serverUIDCodec struct {
	uid int
	gid int
	*serverCodec
}

// NewUIDServerCodec returns a new rpc.ServerCodec using protobuf messages on
// conn and injecting the given uid and gid as the user and group ids for each
// request on the connection.
func NewUIDServerCodec(conn io.ReadWriteCloser, uid, gid int) rpc.ServerCodec {
	m, ok := conn.(*util.MessageStream)
	if !ok {
		m = util.NewMessageStream(conn)
	}
	return &serverUIDCodec{uid, gid, &serverCodec{m, sync.Mutex{}}}
}

// ErrBadServerStruct specifies that the receiving struct didn't match
// expectations. See serverUIDCodec for those expectations.
var ErrBadServerStruct = errors.New("protouidrpc: bad struct receiver")

// ReadRequestBody receives and decodes a net/rpc request body x.
func (c *serverUIDCodec) ReadRequestBody(x interface{}) (err error) {
	// As in serverCodec, fail if x is nil.
	if x == nil {
		// rpc.Server is telling us to read and discard the request, perhaps because
		// response header was read successfully but contained an unexpected service
		// method string. The client would have encoded an actual message body.
		_, err = c.serverCodec.m.ReadString()
		return
	}

	// Normally, panic/recover shouldn't be used for error handling like
	// this. But some error cases out of our control can cause reflection to
	// panic, like a struct that has unexported fields. Since we have to
	// recover and not panic in that case, we simply walk the reflected data
	// structures and let the panics happen if the struct format doesn't
	// match our expectations.
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = e
			} else if s, ok := r.(string); ok {
				err = errors.New(s)
			} else {
				err = ErrBadServerStruct
			}
		}
	}()

	v := reflect.ValueOf(x)
	vi := reflect.Indirect(v)
	// Inject the uid
	uidAddr, _ := vi.Field(0).Addr().Interface().(*int)
	*uidAddr = c.uid

	// Inject the gid
	gidAddr, _ := vi.Field(1).Addr().Interface().(*int)
	*gidAddr = c.gid

	// Deserialize the protobuf into its field.
	// We need a new value of this type, since pointer elements of structs
	// are always nil by default.
	allocated := reflect.New(vi.Field(2).Type().Elem()).Interface().(proto.Message)
	if err = c.serverCodec.m.ReadMessage(allocated); err != nil {
		return
	}
	vi.Field(2).Set(reflect.ValueOf(allocated))
	return
}
