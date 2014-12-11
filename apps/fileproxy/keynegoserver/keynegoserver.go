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

package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/util"
)

var SerialNumber int64

// First return is terminate flag.
func handleRequest(conn net.Conn, policyKey *tao.Keys, guard tao.Guard) error {
	// Expect an attestation from the client.
	ms := util.NewMessageStream(conn)
	var a tao.Attestation
	if err := ms.ReadMessage(&a); err != nil {
		return err
	}

	peerCert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
	if err := taonet.ValidatePeerAttestation(&a, peerCert, guard); err != nil {
		return err
	}

	// Sign cert and put it in attestation statement
	// a consists of serialized statement, sig and SignerInfo
	// a is a says speaksfor, Delegate of speaksfor is cert and should be DER encoded

	// Get underlying says
	f, err := auth.UnmarshalForm(a.SerializedStatement)
	if err != nil {
		return err
	}

	var saysStatement *auth.Says
	if ptr, ok := f.(*auth.Says); ok {
		saysStatement = ptr
	} else if val, ok := f.(auth.Says); ok {
		saysStatement = &val
	}
	sf, ok := saysStatement.Message.(auth.Speaksfor)
	if ok != true {
		return fmt.Errorf("keynegoserver: says doesn't have a speaksfor message\n")
	}

	kprin, ok := sf.Delegate.(auth.Prin)
	if ok != true {
		return fmt.Errorf("keynegoserver: speaksfor Delegate is not auth.Prin\n")
	}
	subjectPrin, ok := sf.Delegator.(auth.Prin)
	if ok != true {
		return fmt.Errorf("keynegoserver: can't get subject principal\n")
	}
	subjectName := subjectPrin.String()
	details := tao.X509Details{
		Country:            "US",
		Organization:       "Google",
		OrganizationalUnit: subjectName,
		CommonName:         "localhost"}
	subjectname := tao.NewX509Name(details)
	SerialNumber = SerialNumber + 1
	verifier, err := tao.FromPrincipal(kprin)
	if err != nil {
		return errors.New("can't get principal from kprin")
	}
	clientCert, err := policyKey.SigningKey.CreateSignedX509(policyKey.Cert, int(SerialNumber), verifier, subjectname)
	if err != nil {
		return fmt.Errorf("keynegoserver: can't create client certificate: %s\n", err)
	}
	clientDERCert := clientCert.Raw
	err = ioutil.WriteFile("ClientCert", clientDERCert, os.ModePerm)

	nowTime := time.Now().UnixNano()
	expireTime := time.Now().AddDate(1, 0, 0).UnixNano()
	// Replace self signed cert in attest request
	newSpeaksFor := &auth.Speaksfor{
		Delegate:  auth.Bytes(clientDERCert),
		Delegator: sf.Delegator,
	}
	keyNegoSays := auth.Says{
		Speaker:    policyKey.SigningKey.ToPrincipal(),
		Time:       &nowTime,
		Expiration: &expireTime,
		Message:    newSpeaksFor,
	}

	delegator, ok := sf.Delegator.(auth.Prin)
	if !ok {
		return fmt.Errorf("keynegoserver: the delegator must be a principal")
	}
	found := false
	for _, sprin := range delegator.Ext {
		if !found && (sprin.Name == "Program") {
			found = true
		}
		if found {
			kprin.Ext = append(kprin.Ext, sprin)
		}
	}
	ra, err := tao.GenerateAttestation(policyKey.SigningKey, nil, keyNegoSays)
	if err != nil {
		return fmt.Errorf("Couldn't attest to the new says statement:", err)
	}

	if _, err := ms.WriteMessage(ra); err != nil {
		return fmt.Errorf("Couldn't return the attestation on the channel:", err)
	}

	return nil
}

func main() {
	network := flag.String("network", "tcp", "The network to use for connections")
	addr := flag.String("addr", "localhost:8124", "The address to listen on")
	domainPass := flag.String("password", "nopassword", "The domain password for the policy key")
	configPath := flag.String("config", "tao.config", "The Tao domain config")

	flag.Parse()
	domain, err := tao.LoadDomain(*configPath, []byte(*domainPass))
	if err != nil {
		log.Fatalf("keynegoserver: Couldn't load the config path %s: %s\n", *configPath, err)
	}

	// Set up temporary keys for the connection, since the only thing that
	// matters to the remote client is that they receive a correctly-signed new
	// attestation from the policy key.
	// JLM:  I left this in place but I'm not sure what a TLS connection with a
	//   self signed Cert buys in terms of security.  The security of this protocol should
	//   not depend on the confidentiality or intergity of the channel.  All that said,
	//   if we do ever distribute a signed keynegoserver cert for this TLS channel, it would
	//   be good.
	keys, err := tao.NewTemporaryKeys(tao.Signing)
	if err != nil {
		log.Fatalln("keynegoserver: Couldn't set up temporary keys for the connection:", err)
	}
	keys.Cert, err = keys.SigningKey.CreateSelfSignedX509(&pkix.Name{
		Organization: []string{"Google Tao Demo"}})
	if err != nil {
		log.Fatalln("keynegoserver: Couldn't set up a self-signed cert:", err)
	}
	SerialNumber = int64(time.Now().UnixNano()) / (1000000)
	policyKey, err := tao.NewOnDiskPBEKeys(tao.Signing, []byte(*domainPass), "policy_keys", nil)
	if err != nil {
		log.Fatalln("keynegoserver: Couldn't get policy key:", err)
	}

	tlsc, err := taonet.EncodeTLSCert(keys)
	if err != nil {
		log.Fatalln("keynegoserver: Couldn't encode a TLS cert:", err)
	}
	conf := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
	}
	sock, err := tls.Listen(*network, *addr, conf)
	if err != nil {
		log.Printf("keynegoserver: error: %s", err)
	}
	defer sock.Close()

	for {
		conn, err := sock.Accept()
		if err != nil {
			log.Fatalln("keynegoserver: couldn't accept a connection:", err)
		}

		go handleRequest(conn, policyKey, domain.Guard)
	}

	log.Println("keynegoserver: shutting down")
}
