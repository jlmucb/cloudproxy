// Copyright (c) 2014, Google, Inc..  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// File: messages.go

package simpleexample_messages

import (
	"errors"
	"log"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/util"
)

func PrintMessage(msg *SimpleMessage) {
	log.Printf("Message\n")
	if msg.MessageType != nil {
		log.Printf("\tmessage type: %d\n", *msg.MessageType)
	} else {
		log.Printf("\tmessage type: nil\n")
	}
	if msg.RequestType != nil {
		log.Printf("\trequest_type: %s\n", *msg.RequestType)
	} else {
		log.Printf("\trequest_type: nil\n")
	}
	if msg.Err != nil {
		log.Printf("\terror: %s\n", msg.Err)
	}
	log.Printf("\tdata: ")
	for _, data := range msg.GetData() {
		log.Printf("\t: %x\n", data)
	}
	log.Printf("\n")
}

func SendMessage(ms *util.MessageStream, msg *SimpleMessage) error {
	out, err := proto.Marshal(msg)
	if err != nil {
		return errors.New("SendRequest: Can't encode response")
	}
	send := string(out)
	_, err = ms.WriteString(send)
	if err != nil {
		return errors.New("SendResponse: Writestring error")
	}
	return nil
}

func GetMessage(ms *util.MessageStream) (*SimpleMessage,
	error) {
	resp, err := ms.ReadString()
	if err != nil {
		return nil, err
	}
	msg := new(SimpleMessage)
	err = proto.Unmarshal([]byte(resp), msg)
	if err != nil {
		return nil, errors.New("GetResponse: Can't unmarshal message")
	}
	return msg, nil
}

func SendRequest(ms *util.MessageStream, msg *SimpleMessage) error {
	m1 := int32(MessageType_REQUEST)
	msg.MessageType = &m1
	return SendMessage(ms, msg)
}

func SendResponse(ms *util.MessageStream, msg *SimpleMessage) error {
	m1 := int32(MessageType_RESPONSE)
	msg.MessageType = &m1
	return SendMessage(ms, msg)
}

func GetRequest(ms *util.MessageStream) (*SimpleMessage, error) {
	msg, err := GetMessage(ms)
	if err != nil || *msg.MessageType != int32(MessageType_REQUEST) {
		return nil, errors.New("GetResponse: reception error")
	}
	return msg, nil
}

func GetResponse(ms *util.MessageStream) (*SimpleMessage, error) {
	msg, err := GetMessage(ms)
	if err != nil || *msg.MessageType != int32(MessageType_RESPONSE) {
		return nil, errors.New("GetResponse: reception error")
	}
	return msg, nil
}
