// Description: Interfaces for streams of delineated things.
//
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

package util

import (
	"code.google.com/p/goprotobuf/proto"
)

// A MessageReader is a stream from which protobuf messages can be read.
type MessageReader interface {
	ReadMessage(m proto.Message) error
}

// A MessageWriter is a stream to which protobuf messages can be written.
type MessageWriter interface {
	WriteMessage(m proto.Message) error
}

// A StringReader is a stream from which strings can be read.
type StringReader interface {
	ReadString() (string, error)
}

// A StringWriter is a stream to which strings can be written.
type StringWriter interface {
	WriteString(s string) (n int, err error)
}
