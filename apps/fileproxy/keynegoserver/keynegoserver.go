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
	// "io/ioutil"
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
	k, err := tao.NewOnDiskPBEKeys(keyTypes, password, path, nil)
	if err != nil {
		fmt.Printf("Cant get signing keys\n");
		return nil, err
	}
	fmt.Printf("Got signing keys\n");
	k.SetMyKeyPath(path)
	k.SetKeyType(keyTypes)
	err= k.LoadCert()
	if err != nil {
		return nil, err
	}
	fmt.Printf("got Cert\n");
/*
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
 */

	return k, nil
}


// HandleKeyNegoRequest checks a request from a program and responds with a truncated
// delegation signed by the policy key.
func HandleKeyNegoRequest(conn net.Conn, s *tao.Signer, guard tao.Guard) {
	defer conn.Close()

	// Expect an attestation from the client.
	ms := util.NewMessageStream(conn)
	var a tao.Attestation
	if err := ms.ReadMessage(&a); err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't read attestation from channel:", err)
		return
	}

	peerCert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
	if err := taonet.ValidatePeerAttestation(&a, peerCert, guard); err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't validate peer attestation:", err)
		return
	}

	truncSays, pe, err := taonet.TruncateAttestation(s.ToPrincipal(), &a)
//	if err != nil {
//		fmt.Fprintln(os.Stderr, "Couldn't truncate the attestation:", err)
//		return
//	}

	// TODO(tmroeder): fix this to check the time and make sure we're not
	// signing an unbounded attestation to this program.
	ra, err := tao.GenerateAttestation(s, nil, truncSays)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't attest to the new says statement:", err)
		return
	}

	// Add an endorsement to this PrinExt Program hash so the receiver can check
	// it successfully against policy.
	endorsement := auth.Says{
		Speaker: s.ToPrincipal(),
		Message: auth.Pred{
			Name: "TrustedProgramHash",
			Arg:  []auth.Term{auth.PrinTail{Ext: []auth.PrinExt{pe}}}, // used to be pe
		},
	}
//	if truncSays.Time != nil {
//		i := *truncSays.Time
//		endorsement.Time = &i
//	}
//	if truncSays.Expiration != nil {
//		i := *truncSays.Expiration
//		endorsement.Expiration = &i
//	}
	ea, err := tao.GenerateAttestation(s, nil, endorsement)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't generate an endorsement for this program:", err)
		return
	}
	eab, err := proto.Marshal(ea)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't marshal an endorsement:", err)
		return
	}
	ra.SerializedEndorsements = [][]byte{eab}

	if _, err := ms.WriteMessage(ra); err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't return the attestation on the channel:", err)
		return
	}

	return
}

// RequestTruncatedAttestation connects to a CA instance, sends the attestation
// for an X.509 certificate, and gets back a truncated attestation with a new
// principal name based on the policy key.
func KeyNegoRequestTruncatedAttestation(network, addr string, keys *tao.Keys, v *tao.Verifier) (*tao.Attestation, error) {
	if keys.Cert == nil {
		return nil, fmt.Errorf("client: can't dial with an empty client certificate\n")
	}
	tlsCert, err := taonet.EncodeTLSCert(keys)
	if err != nil {
		return nil, err
	}
	conn, err := tls.Dial(network, addr, &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*tlsCert},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Tao handshake: send client delegation.
	ms := util.NewMessageStream(conn)
	if _, err = ms.WriteMessage(keys.Delegation); err != nil {
		return nil, err
	}

	// Read the truncated attestation and check it.
	var a tao.Attestation
	if err := ms.ReadMessage(&a); err != nil {
		return nil, err
	}

	truncStmt, err := auth.UnmarshalForm(a.SerializedStatement)
	if err != nil {
		return nil, err
	}

	says, _, err := taonet.TruncateAttestation(v.ToPrincipal(), keys.Delegation)
	if err != nil {
		return nil, err
	}

	if !taonet.IdenticalDelegations(says, truncStmt) {
		return nil, fmt.Errorf("the statement returned by the TaoCA was different than what we expected")
	}

	ok, err := v.Verify(a.SerializedStatement, tao.AttestationSigningContext, a.Signature)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("invalid attestation signature from Tao CA")
	}

	return &a, nil
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
	fmt.Printf("keys: %s\n", keys);

	endorsement := auth.Says{
		Speaker: keys.SigningKey.ToPrincipal(),
		Message: auth.Pred{
			Name: "TrustedProgramHash",
			Arg:  []auth.Term{auth.PrinTail{Ext: []auth.PrinExt{}}}, //used to be pe
		},
	}
	fmt.Printf("endorsement: ", endorsement)
	fmt.Printf("\n")

	details := tao.X509Details {
		Country: "US",
		Organization: "Google",
		State: "California",
		CommonName: "fileClient Program",}
	subjectname:= tao.NewX509Name(details)
	cert, err := keys.SigningKey.CreateSelfSignedX509(subjectname)
	fmt.Printf("\n")
	fmt.Printf("\n")
	if(err==nil) {
		fmt.Printf("generated cert\n", cert);
		fmt.Printf("\n")
	} else {
		fmt.Printf("failed to generate cert\n");
	}
	// cert := CreateSignedX509(k.Cert, 000, subjectKey *Verifier, subjectName)
	fmt.Printf("\n")
	fmt.Printf("\n")

	return

}
