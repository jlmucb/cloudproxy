// Copyright (c) 2014, Google Inc. All rights reserved.
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
// File: keynegoserver.go

package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"crypto/tls"
	"fmt"
	"os"
	// "errors"
	// "path"
	// "time"
	"flag"
	"net"

	"code.google.com/p/goprotobuf/proto"

	"github.com/jlmucb/cloudproxy/tao"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/tao/auth"
	"github.com/jlmucb/cloudproxy/util"
)

var network = flag.String("network", "tcp", "The network to use for connections")
var addr = flag.String("addr", "localhost:8124", "The address to listen on")
var domainPass = flag.String("password", "nopassword", "The domain password for the policy key")
var configPath = flag.String("config", "tao.config", "The Tao domain config")


// zeroBytes clears the bytes in a slice.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func GetOnDiskPolicyKeys(keyTypes tao.KeyType, password []byte, path string, name *pkix.Name) (*tao.Keys, error) {
	k := &tao.Keys{}
	k.SetMyKeyPath(path)
	k.SetKeyType(keyTypes)
	err:= k.LoadCert()
	if err != nil {
		return nil, err
	}
	fmt.Printf("got Cert\n");

	f, err := os.Open(path+"/signer")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ks, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Got key buffer\n");
	data, err := tao.PBEDecrypt(ks, password)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(data)
	fmt.Printf("Got decrypted signing key\n");

	var cks tao.CryptoKeyset
	if err = proto.Unmarshal(data, &cks); err != nil {
		return nil, err
	}
	ktemp, err := tao.UnmarshalKeyset(&cks)
	if err != nil {
		return nil, err
	}
	k.SigningKey = ktemp.SigningKey
	k.VerifyingKey = ktemp.VerifyingKey
	k.CryptingKey = ktemp.CryptingKey
	k.DerivingKey = ktemp.DerivingKey

	return k, nil
}


// HandleKeyNegoRequest checks a request from a program and responds with a truncated
// delegation signed by the policy key.
func HandleKeyNegoRequest(conn net.Conn, k *tao.Keys, guard tao.Guard) {
	fmt.Printf("HandleKeyNegoRequest\n")
	defer conn.Close()

	s:= k.SigningKey
	// Expect an attestation from the client.
	ms := util.NewMessageStream(conn)
	var a tao.Attestation
	if err := ms.ReadMessage(&a); err != nil {
		fmt.Printf("Couldn't read attestation from channel:", err)
		return
	}
	fmt.Printf("HandleKeyNegoRequest: read message\n")

	peerCert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
	if err := taonet.ValidatePeerAttestation(&a, peerCert, guard); err != nil {
		fmt.Printf("Couldn't validate peer attestation:", err)
		return
	}
	fmt.Printf("HandleKeyNegoRequest: peer attest verified\n")

	truncSays, pe, err := taonet.TruncateAttestation(s.ToPrincipal(), &a)
	if err != nil {
		fmt.Printf("Couldn't truncate the attestation:", err)
		return
	}
	fmt.Printf("HandleKeyNegoRequest: got taonet.TruncateAttestation\n")

	ra, err := tao.GenerateAttestation(s, nil, truncSays)
	if err != nil {
		fmt.Printf("Couldn't attest to the new says statement:", err)
		return
	}
	fmt.Printf("HandleKeyNegoRequest: did first tao.GenerateAttestation\n")

	endorsement := auth.Says{
		Speaker: s.ToPrincipal(),
		Message: auth.Pred{
			Name: "TrustedProgramHash",
			Arg:  []auth.Term{auth.PrinTail{Ext: []auth.PrinExt{pe}}}, // used to be pe
		},
	}
	if truncSays.Time != nil {
		i := *truncSays.Time
		endorsement.Time = &i
	}
	if truncSays.Expiration != nil {
		i := *truncSays.Expiration
		endorsement.Expiration = &i
	}
	ea, err := tao.GenerateAttestation(s, nil, endorsement)
	if err != nil {
		fmt.Printf("Couldn't generate an endorsement for this program:", err)
		return
	}
	fmt.Printf("HandleKeyNegoRequest: did endorsement\n")

	eab, err := proto.Marshal(ea)
	if err != nil {
		fmt.Printf("Couldn't marshal an endorsement:", err)
		return
	}
	ra.SerializedEndorsements = [][]byte{eab}

	if _, err := ms.WriteMessage(ra); err != nil {
		fmt.Printf("Couldn't return the attestation on the channel:", err)
		return
	}
	fmt.Printf("HandleKeyNegoRequest: sent endorsements\n")
	return
}

func main() {
	flag.Parse()
	fmt.Printf("keynegoserver started, config: %s\n", *configPath)
	domain, err := tao.LoadDomain(*configPath, []byte(*domainPass))
	if err != nil {
		fmt.Printf("Couldn't load the config path %s: %s\n", *configPath, err)
		return
	}
	fmt.Printf("loaded domain from: %s\n", *configPath)
	fmt.Printf("", domain)
	fmt.Printf("\n")

	var keyTypes  tao.KeyType
	var pkix_name pkix.Name
	keyTypes= tao.Signing
	var pass []byte
	pass= []byte(*domainPass)

	keypath :=  "/Users/manferdelli/src/github.com/jlmucb/cloudproxy/apps/fileproxy/keynegoserver/test/policy_keys/"
	fmt.Printf("keypath: %s\n", keypath)

	keys, err:= GetOnDiskPolicyKeys(keyTypes, pass, keypath, &pkix_name)
	if(err==nil) {
		fmt.Printf("GetOnDiskPolicyKeys succeeded\n")
	} else {
		fmt.Printf("GetOnDiskPolicyKeys failed\n", err)
	}
	fmt.Printf("got keys: %s\n", keys);
	tlsc, err := taonet.EncodeTLSCert(keys)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't encode a TLS cert:", err)
		return
	}
	conf := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
	}
	sock, err := tls.Listen(*network, *addr, conf)
	fmt.Printf("keynegoserver: accepting connections\n")
	for {
		conn, err := sock.Accept()
		if err != nil {
			fmt.Printf("Couldn't accept a connection on %s: %s\n", *addr, err)
			return
		}
		go HandleKeyNegoRequest(conn, keys, domain.Guard)
	}
	return
}
