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
// File: domain_helpers.go

package domain_policy

import (
	"crypto/ecdsa"
/*
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

	"github.com/golang/protobuf/proto"

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
*/
)

func GetPublicDerFromEcdsaKey(key ecdsa.PublicKey) ([]byte, error) {
	return nil, nil
}

func GetEcdsaKeyFromDer(der []byte) (*ecdsa.PublicKey, error) {
	return nil, nil
}

func SerializeKeyToInternalName(key *ecdsa.PublicKey) ([]byte, error) {
	return nil, nil
}

func GetKeyHash(der []byte) ([]byte, error) {
	return nil, nil
}

