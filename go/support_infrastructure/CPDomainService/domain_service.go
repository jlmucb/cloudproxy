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

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

// This function makes the following checks
// (1) Checks if the attestation signature is valid and the statement is of the form
//     'Speaker says Key speaks for Program'.
// (2) Checks that 'Program' in the above statement is allowed to Execute in the domain policy.
//     In particular, the policy should allow the predicate:
//     Authorized(ProgramTaoName, "Execute")
// (3) Checks that 'Speaker' in the above statement is a key principal endorsed by the policy key,
//     or rootCerts, via an endorsement chain. Each endorsement in this chain endorses the key
//     signing the previous endorsement (starting with the 'Speaker' key).
//
//     An endorsemennt endorses either a host key, in which case it is an attestation,
//     or the root hardware key, in which case it is certificate.
//     This function also checks that each host or root hardware encoutered along this endorsement
//     chain is allowed as per domain policy. In particular the policy should allow the predicates
//     Authorized(HostTaoName, "Host") and Authorized(EncodedMachineInformation, "Root")
//
//     A valid attestation chain must either end in a attestation signed by the policy key
//     or a certificate signed by one of the rootCerts.
//
// If all above checks go through, the function returns the principals: Speaker, Key, Program.
func VerifyHostAttestation(serializedHostAttestation []byte, domain *tao.Domain,
	rootCerts *x509.CertPool) (*auth.Prin, *auth.Prin, *auth.Prin, error) {

	var hostAttestation tao.Attestation
	err := proto.Unmarshal(serializedHostAttestation, &hostAttestation)
	if err != nil {
		return nil, nil, nil, errors.New(
			"domain_service: error deserialiaizng host attestation: " + err.Error())
	}

	// First check if attestation is valid.
	statement, err := hostAttestation.Validate()
	if err != nil {
		return nil, nil, nil, errors.New(
			"domain_service: host attestation fails validation check: " + err.Error())
	}

	// Next, check if SpeaksFor delegator is authorized to execute (i.e. the program is allowed to
	// run as per policy).
	speaker, key, prog, err := parseSaysStatement(&statement)
	if err != nil {
		return nil, nil, nil, err
	}
	if !domain.Guard.IsAuthorized(*prog, "Execute", []string{}) {
		return nil, nil, nil, errors.New(
			"domain_service: program not authorized to run in this domain.")
	}

	// Look for endorsement cert(s), rooted in the policy key, that ultimately certify the
	// key of the signer.
	serializedSigner := hostAttestation.GetSigner()
	signer, err := auth.UnmarshalPrin(serializedSigner)
	if err != nil {
		return nil, nil, nil, err
	}
	if !speaker.Identical(signer) {
		// TODO: first endorsement endorses speaker or signer?
	}

	// Look for endorsement(s) of signer, rooted in policy key.
	serializedEndorsements := hostAttestation.GetSerializedEndorsements()
	var realErr error
	var kPrin *auth.Prin
	kPrin = &signer
	for _, serializedEndorsement := range serializedEndorsements {
		// serializedEndorsement could be X.509 certificate or Tao attestation.
		var attestation tao.Attestation
		err := proto.Unmarshal(serializedEndorsement, &attestation)
		if err == nil {
			kPrin, realErr = validateEndorsementAttestation(&attestation,
				domain.Guard, kPrin)
			if realErr != nil {
				return nil, nil, nil, realErr
			}
		} else if cert, err1 := x509.ParseCertificate(serializedEndorsement); err1 == nil {
			realErr = validateEndorsementCertificate(cert, domain.Guard, kPrin, rootCerts)
			if realErr != nil {
				return nil, nil, nil, realErr
			} else {
				// Endorsement certs are the root of the endorsement chain.
				// If they are valid, then no more checking is required.
				return speaker, key, prog, nil
			}

		} else {
			return nil, nil, nil, errors.New(
				"domain_service: error parsing host endorsement.")
		}
	}
	if domain.Keys.SigningKey.ToPrincipal().Identical(*kPrin) {
		return speaker, key, prog, nil
	}
	return nil, nil, nil, errors.New(
		"domain_service: endorsement chain does not terminate in policy key.")

}

// Checks the following:
// (1) the endorsement attestation is valid
// (2) the key being endorsed is kPrin
// (3) the subject being endorsed is a trusted host
// Finally the function returns the key principal signing the endorsement
func validateEndorsementAttestation(attestation *tao.Attestation, guard tao.Guard,
	kPrin *auth.Prin) (*auth.Prin, error) {
	saysStatement, err := attestation.Validate()
	if err != nil {
		return nil, err
	}
	speaker, key, host, err := parseSaysStatement(&saysStatement)
	if err != nil {
		return nil, err
	}
	if !key.Identical(kPrin) {
		return nil, errors.New(
			"domain_service: endorsement does not endorse signer of attestaton.\n" +
				"Key endorsed: " + key.String() + "\n" +
				"Signer: " + kPrin.String())
	}
	if !guard.IsAuthorized(*host, "Host", []string{}) {
		return nil, errors.New(
			"domain_service: endorsment host not authorized to run in this domain.")
	}
	return speaker, nil
}

// Checks the following:
// (1) cert is valid according to one of the rootCerts.
// (2) the subject key of cert corresponds to kPrin.
// (3) the subject CommonName of cert is allowed by guard.
func validateEndorsementCertificate(cert *x509.Certificate, guard tao.Guard,
	kPrin *auth.Prin, rootCerts *x509.CertPool) error {
	verifyOptions := x509.VerifyOptions{Roots: rootCerts}
	_, err := cert.Verify(verifyOptions)
	if err != nil {
		return err
	}
	verifier, err := tao.FromPrincipal(*kPrin)
	if err != nil {
		return err
	}
	if !verifier.Equals(cert) {
		return errors.New(
			"domain_service: endorsement cert does not endorse signer of attestation.")
	}
	machinePrin := auth.Prin{
		Type: "MachineInfo",
		Key:  auth.Str(cert.Subject.CommonName),
	}
	if !guard.IsAuthorized(machinePrin, "Root", []string{}) {
		return errors.New(
			"domain_service: machine endorsed by certificate is not authorized by policy.")
	}
	return nil
}

func parseSaysStatement(saysStatement *auth.Says) (*auth.Prin, *auth.Prin, *auth.Prin, error) {
	if saysStatement.Speaker == nil {
		return nil, nil, nil,
			errors.New("domain_service: attestation 'Says' does not have a speaker.")
	}
	speaker, ok := saysStatement.Speaker.(auth.Prin)
	if !ok {
		return nil, nil, nil, errors.New(
			"domain_service: attestation 'Says' speaker is not a auth.Prin.")
	}
	if saysStatement.Message == nil {
		return nil, nil, nil, errors.New(
			"domain_service: attestation 'Says' does not have a message.")
	}
	sf, ok := saysStatement.Message.(auth.Speaksfor)
	if !ok {
		return nil, nil, nil, errors.New(
			"domain_service: attestation statement does not have a 'SpeaksFor'.")
	}
	if sf.Delegator == nil {
		return nil, nil, nil, errors.New(
			"domain_service: attestation 'speaksFor' has no delegator.")
	}
	delegator, ok := sf.Delegator.(auth.Prin)
	if !ok {
		return nil, nil, nil, errors.New(
			"domain_service: Endorsement attestation 'speaksFor' delegator is not a auth.Prin.")
	}
	if sf.Delegate == nil {
		return nil, nil, nil, errors.New(
			"domain_service: attestation 'speaksFor' has no delegate.")
	}
	delegate, ok := sf.Delegate.(auth.Prin)
	if !ok {
		return nil, nil, nil, errors.New(
			"domain_service: Endorsement attestation 'speaksFor' delegate is not a auth.Prin.")
	}
	return &speaker, &delegate, &delegator, nil
}

// This function generates a Program Certificate. In particular, it generates an attestation
// signed by the domain policy key, with a statement of the form
// 'policyKey says programCert speaksFor program'
// where programCert is a X509 cert signed by the policy key with subject CommonName being the
// Tao name of the program and subject public key being programKey.
// Certificate expiration time is one year from issuing time.
func GenerateProgramCert(domain *tao.Domain, serialNumber int, programPrin *auth.Prin,
	programKey *auth.Prin) (*tao.Attestation, error) {

	policyCert := domain.Keys.Cert
	x509Info := domain.Config.GetX509Info()
	programName := programPrin.String()
	x509Info.CommonName = &programName
	subjectName := tao.NewX509Name(x509Info)
	verifier, err := tao.FromPrincipal(*programKey)
	if err != nil {
		return nil, err
	}
	clientCert, err := domain.Keys.SigningKey.CreateSignedX509(
		policyCert, serialNumber, verifier, subjectName)
	if err != nil {
		return nil, err
	}
	clientDerCert := clientCert.Raw

	nowTime := time.Now().UnixNano()
	expireTime := time.Now().AddDate(1, 0, 0).UnixNano()

	speaksFor := &auth.Speaksfor{
		Delegate:  auth.Bytes(clientDerCert),
		Delegator: programPrin}
	says := &auth.Says{
		Speaker:    domain.Keys.SigningKey.ToPrincipal(),
		Time:       &nowTime,
		Expiration: &expireTime,
		Message:    speaksFor}

	ra, err := tao.GenerateAttestation(domain.Keys.SigningKey, nil, *says)
	if err != nil {
		return nil, err
	}
	return ra, nil
}
