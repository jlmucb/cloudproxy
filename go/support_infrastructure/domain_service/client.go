// Copyright (c) 2016, Google Inc. All rights reserved.
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

package domain_service

// This provides the client stub for using the domain service.
// This code is relatively dull, all it does is marshal/serialize the
// domain service requests and responses.

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log"
	"net"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util"
)

// This function packages a host attestation into a DomainServiceRequest of the type
// DOMAIN_CERT_REQUEST, sends it to the domain service and deserializes the response
// into an attestation that contains the domain program certificate.
func RequestProgramCert(hostAtt *tao.Attestation, verifier *tao.Verifier,
	network string, addr string) (*x509.Certificate, error) {
	serAtt, err := proto.Marshal(hostAtt)
	if err != nil {
		return nil, err
	}
	reqType := DomainServiceRequest_DOMAIN_CERT_REQUEST
	request := &DomainServiceRequest{
		Type: &reqType,
		SerializedHostAttestation: serAtt,
		ProgramKey:                verifier.MarshalKey(),
	}

	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	ms := util.NewMessageStream(conn)
	_, err = ms.WriteMessage(request)
	if err != nil {
		return nil, err
	}
	log.Printf("Sent Program cert request to Domain Service using network %s at address %s.",
		network, addr)
	var response DomainServiceResponse
	err = ms.ReadMessage(&response)
	if err != nil {
		return nil, err
	}
	log.Println("Got response from Domain Service.")

	if errStr := response.GetErrorMessage(); errStr != "" {
		return nil, errors.New(errStr)
	}
	cert, err := x509.ParseCertificate(response.GetDerProgramCert())
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// This function packages a certificate revoke request into a DomainServiceRequest of type
// REVOKE_CERTIFICATE and sends it to the domain service. It expects att to be an attestation
// signed by the domain policy key with a statement of the form:
// policyKey says revoke certificateSerialNumber
func RequestRevokeCertificate(att *tao.Attestation, network, addr string) error {
	serAtt, err := proto.Marshal(att)
	if err != nil {
		return err
	}
	reqType := DomainServiceRequest_REVOKE_CERTIFICATE
	request := &DomainServiceRequest{
		Type: &reqType,
		SerializedPolicyAttestation: serAtt}

	conn, err := net.Dial(network, addr)
	if err != nil {
		return err
	}
	ms := util.NewMessageStream(conn)
	_, err = ms.WriteMessage(request)
	if err != nil {
		return err
	}
	log.Printf("Sent cert revoke request to Domain Service using network %s at address %s.",
		network, addr)

	var response DomainServiceResponse
	err = ms.ReadMessage(&response)
	if err != nil {
		return err
	}
	log.Println("Got response from Domain Service.")
	if errStr := response.GetErrorMessage(); errStr != "" {
		return errors.New(errStr)
	}
	return nil
}

// This function sends a DomainServiceRequest of the type GET_CRL to the domain service,
// and deserializes the response into a pkix.CertificateList containing the revoked certificates.
func RequestCrl(network, addr string) (*pkix.CertificateList, error) {
	reqType := DomainServiceRequest_GET_CRL
	request := &DomainServiceRequest{
		Type: &reqType}

	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	ms := util.NewMessageStream(conn)
	_, err = ms.WriteMessage(request)
	if err != nil {
		return nil, err
	}
	log.Printf("Sent crl request to Domain Service using network %s at address %s.",
		network, addr)
	var response DomainServiceResponse
	err = ms.ReadMessage(&response)
	if err != nil {
		return nil, err
	}
	log.Println("Got response from Domain Service.")
	if errStr := response.GetErrorMessage(); errStr != "" {
		return nil, errors.New(errStr)
	}
	parsedCrl, err := x509.ParseCRL(response.GetCrl())
	return parsedCrl, err
}
