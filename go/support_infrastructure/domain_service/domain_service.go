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
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

func VerifyAttestation(serializedHostAttestation []byte, domain *tao.Domain) (*auth.Prin,
	*auth.Prin, *auth.Prin, error) {
	var hostAttestation tao.Attestation
	err := proto.Unmarshal(serializedHostAttestation, &hostAttestation)
	if err != nil {
		return nil, nil, nil, err
	}
	signer, err := hostAttestation.ValidSigner()
	if err != nil {
		return nil, nil, nil, err
	}
	f, err := auth.UnmarshalForm(hostAttestation.SerializedStatement)
	if err != nil {
		return nil, nil, nil, err
	}
	var stmt *auth.Says
	if ptr, ok := f.(*auth.Says); ok {
		stmt = ptr
	} else if val, ok := f.(auth.Says); ok {
		stmt = &val
	} else {
		return nil, nil, nil, errors.New(fmt.Sprintf(
			"tao: attestation statement has wrong type: %T", f))
	}
	speaker, key, program, err := parseSaysStatement(stmt)
	if err != nil {
		return nil, nil, nil, err
	}
	// Validate signer
	if auth.SubprinOrIdentical(speaker, signer) {
		// Case 1: speaker is identical or subprincipal of signing principal.
		// Check if signer is either
		// - policy key
		// - TPM key with valid hardware endorsement cert signed by policy key.
		if signer.Identical(domain.Keys.SigningKey.ToPrincipal()) {
			return speaker, key, program, nil
		}
		if *hostAttestation.SignerType == "tpm" || *hostAttestation.SignerType == "tpm2" {
			if hostAttestation.RootEndorsement == nil {
				return nil, nil, nil, errors.New("TPM attestation is missing HW endorsement cert")
			}
			cert, err := x509.ParseCertificate(hostAttestation.RootEndorsement)
			if err != nil {
				return nil, nil, nil, err
			}
			certPool := x509.NewCertPool()
			certPool.AddCert(domain.Keys.Cert)
			verifyOptions := x509.VerifyOptions{Roots: certPool}
			_, err = cert.Verify(verifyOptions)
			if err != nil {
				return nil, nil, nil, err
			}
			hwPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
			if !ok {
				key, ok := cert.PublicKey.(rsa.PublicKey)
				if !ok {
					return nil, nil, nil,
						errors.New("endorsement cert does not contain a valid RSA public key")
				}
				hwPublicKey = &key
			}
			tpmKey, err := x509.MarshalPKIXPublicKey(hwPublicKey)
			if err != nil {
				return nil, nil, nil, err
			}
			if !bytes.Equal(hostAttestation.SignerKey, tpmKey) {
				return nil, nil, nil, errors.New("HW endorsement cert public key does not match signer key")
			}
			return speaker, key, program, nil
		}
		// SignerType is a Tao key principal. Check if the key is endorsed by the policy key.
		if hostAttestation.RootEndorsement != nil {
			cert, err := x509.ParseCertificate(hostAttestation.RootEndorsement)
			if err != nil {
				return nil, nil, nil, err
			}
			certPool := x509.NewCertPool()
			certPool.AddCert(domain.Keys.Cert)
			verifyOptions := x509.VerifyOptions{Roots: certPool}
			_, err = cert.Verify(verifyOptions)
			if err != nil {
				return nil, nil, nil, err
			}
			verifier, err := tao.UnmarshalKey(hostAttestation.SignerKey)
			if err != nil {
				return nil, nil, nil, err
			}
			if !verifier.KeyEqual(cert) {
				return nil, nil, nil, errors.New("Endorsement cert is irrelevant to attestation signer")
			}
			return speaker, key, program, nil
		}
		return nil, nil, nil, errors.New("attestation signer is not endorsed by policy key")
	} else {
		// Case 2: speaker is not a subprincipal of the signing principal.
		// Look for delegation and require that:
		// - delegation conveys delegator says delegate speaksfor delegator,
		// - a.signer speaks for delegate
		// - and delegator speaks for s.Speaker
		if hostAttestation.SerializedDelegation == nil {
			return nil, nil, nil, errors.New("attestation missing delegation")
		}
		var da tao.Attestation
		if err := proto.Unmarshal(hostAttestation.SerializedDelegation, &da); err != nil {
			return nil, nil, nil, err
		}
		delegationStatement, err := da.Validate()
		if err != nil {
			return nil, nil, nil, err
		}
		var delegation *auth.Speaksfor
		if ptr, ok := delegationStatement.Message.(*auth.Speaksfor); ok {
			delegation = ptr
		} else if val, ok := delegationStatement.Message.(auth.Speaksfor); ok {
			delegation = &val
		} else {
			return nil, nil, nil, errors.New("tao: attestation delegation is wrong type")
		}
		if !delegationStatement.Speaker.Identical(delegation.Delegator) {
			return nil, nil, nil, errors.New("tao: attestation delegation is invalid")
		}
		if !auth.SubprinOrIdentical(delegation.Delegate, signer) {
			return nil, nil, nil, errors.New("tao: attestation delegation irrelevant to signer")
		}
		if !auth.SubprinOrIdentical(stmt.Speaker, delegation.Delegator) {
			return nil, nil, nil, errors.New("tao: attestation delegation irrelevant to issuer")
		}
		return speaker, key, program, nil
	}
}

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
//     An endorsement endorses either a host key, in which case it is an attestation,
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
			"host attestation fails validation check: " + err.Error())
	}

	// Next, check if SpeaksFor delegator is authorized to execute (i.e. the program is allowed to
	// run as per policy).
	speaker, key, prog, err := parseSaysStatement(&statement)
	if err != nil {
		return nil, nil, nil, err
	}
	if !domain.Guard.IsAuthorized(*prog, "Execute", []string{}) {
		return nil, nil, nil, errors.New(
			"program not authorized to run in this domain")
	}

	// Look for endorsement cert(s), rooted in the policy key, that ultimately certify the
	// key of the signer.
	signingKey := hostAttestation.GetSignerKey()
	if hostAttestation.SignerType == nil {
		return nil, nil, nil, errors.New("host attestation missing SignerType field")
	}
	signingPrin := auth.NewPrin(*hostAttestation.SignerType, signingKey)
	if !speaker.Identical(signingPrin) {
		// TODO: endorsement endorses speaker or signer?
	}

	// Look for endorsement(s) of signer, rooted in policy key.
	serializedEndorsements := hostAttestation.GetSerializedEndorsements()
	var realErr error
	var kPrin *auth.Prin
	kPrin = &signingPrin
	for _, serializedEndorsement := range serializedEndorsements {
		// serializedEndorsement could be X.509 certificate or Tao attestation.
		var attestation tao.Attestation
		err := proto.Unmarshal(serializedEndorsement, &attestation)
		if err == nil {
			kPrin, realErr = validateEndorsementAttestation(&attestation, domain.Guard, kPrin)
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
			return nil, nil, nil, errors.New("error parsing host endorsement")
		}
	}
	if domain.Keys.SigningKey.ToPrincipal().Identical(*kPrin) {
		return speaker, key, prog, nil
	}
	return nil, nil, nil, errors.New("endorsement chain does not terminate in policy key")

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
	_, key, host, err := parseSaysStatement(&saysStatement)
	if err != nil {
		return nil, err
	}
	if !key.Identical(kPrin) {
		return nil, errors.New("endorsement does not endorse signer of (previous) attestaton")
	}
	if !guard.IsAuthorized(*host, "Host", []string{}) {
		return nil, errors.New("endorsement host not authorized to run in this domain")
	}
	signerType := attestation.SignerType
	if signerType == nil {
		return nil, errors.New("endorsement chain has attestation with missing SignerType")
	}
	signerPrin := auth.NewPrin(*signerType, attestation.SignerKey)
	return &signerPrin, nil
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
	var hwPublicKey *rsa.PublicKey
	hwPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		key, ok := cert.PublicKey.(rsa.PublicKey)
		if !ok {
			return errors.New("endorsement cert does not contain a valid RSA public key")
		}
		hwPublicKey = &key
	}
	ek, err := x509.MarshalPKIXPublicKey(hwPublicKey)
	if err != nil {
		return err
	}
	hashedCertKey := sha256.Sum256(ek)
	if kPrin.Type != "tpm" && kPrin.Type != "tpm2" {
		return errors.New("key principal to be endorsed is not a TPM key, but it's expected to be")
	}
	hashedBytes, ok := kPrin.KeyHash.(auth.Bytes)
	if !ok {
		return errors.New("key principal to be endorsed does not have bytes as its auth.Term")
	}
	if !bytes.Equal(hashedBytes, hashedCertKey[:]) {
		return errors.New(fmt.Sprintf(
			"endorsement cert endorses %v but needs to endorse %v", hashedCertKey, hashedBytes))
	}
	machinePrin := auth.Prin{
		Type:    "MachineInfo",
		KeyHash: auth.Str(cert.Subject.CommonName),
	}
	if !guard.IsAuthorized(machinePrin, "Root", []string{}) {
		return errors.New(
			"machine endorsed by certificate is not authorized by policy")
	}
	return nil
}

func parseSaysStatement(saysStatement *auth.Says) (*auth.Prin, *auth.Prin, *auth.Prin, error) {
	if saysStatement.Speaker == nil {
		return nil, nil, nil,
			errors.New("attestation 'Says' does not have a speaker")
	}
	speaker, ok := saysStatement.Speaker.(auth.Prin)
	if !ok {
		return nil, nil, nil, errors.New(
			"attestation 'Says' speaker is not a auth.Prin")
	}
	if saysStatement.Message == nil {
		return nil, nil, nil, errors.New(
			"attestation 'Says' does not have a message")
	}
	sf, ok := saysStatement.Message.(auth.Speaksfor)
	if !ok {
		return nil, nil, nil, errors.New(
			"attestation statement does not have a 'SpeaksFor'")
	}
	if sf.Delegator == nil {
		return nil, nil, nil, errors.New(
			"attestation 'speaksFor' has no delegator")
	}
	delegator, ok := sf.Delegator.(auth.Prin)
	if !ok {
		return nil, nil, nil, errors.New(
			"attestation 'speaksFor' delegator is not a auth.Prin")
	}
	if sf.Delegate == nil {
		return nil, nil, nil, errors.New(
			"attestation 'speaksFor' has no delegate.")
	}
	delegate, ok := sf.Delegate.(auth.Prin)
	if !ok {
		return nil, nil, nil, errors.New(
			"ttestation 'speaksFor' delegate is not a auth.Prin")
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
	verifier *tao.Verifier, now, expiry time.Time) (*x509.Certificate, error) {

	policyCert := domain.Keys.Cert
	x509Info := domain.Config.GetX509Info()
	programName := programPrin.String()
	localhost := "localhost"
	x509Info.CommonName = &localhost
	x509Info.OrganizationalUnit = &programName
	subjectName := tao.NewX509Name(x509Info)
	pkInt := tao.PublicKeyAlgFromSignerAlg(*domain.Keys.SigningKey.GetCryptoHeaderFromSigner().KeyType)
	sigInt := tao.SignatureAlgFromSignerAlg(*domain.Keys.SigningKey.GetCryptoHeaderFromSigner().KeyType)
	clientCert, err := domain.Keys.SigningKey.CreateSignedX509(
		policyCert, serialNumber, verifier, pkInt, sigInt, subjectName)
	if err != nil {
		return nil, err
	}
	return clientCert, nil
}

// This function reads in trusted entities from a file at trustedEntitiesPath. In particular,
// this file contains the text representation of a trusted_entities proto message, which contains
// the Tao names of trusted programs and hosts, information about trusted machines and trusted
// machine certificates.
// For each such trusted entity, this function adds ACL rules to the domain guard, and saves
// the changes before returning.
func InitAcls(domain *tao.Domain, trustedEntitiesPath string) error {
	text, err := ioutil.ReadFile(trustedEntitiesPath)
	if err != nil {
		log.Printf("Can't open trusted entities file: %s", trustedEntitiesPath)
		return err
	}
	trustedEntities := TrustedEntities{}
	err = proto.UnmarshalText(string(text), &trustedEntities)
	if err != nil {
		log.Printf("Can't parse trusted entities file: %s", trustedEntitiesPath)
		return err
	}
	for _, programTaoName := range trustedEntities.GetTrustedProgramTaoNames() {
		var programPrin auth.Prin
		_, err := fmt.Sscanf(programTaoName, "%v", &programPrin)
		if err != nil {
			log.Printf("Can't create program principal from: %s\nError: %s",
				programTaoName, err)
			return err
		}
		err = domain.Guard.Authorize(programPrin, "Execute", []string{})
		if err != nil {
			log.Printf("Can't authorize principal: %s\nError: %s", programPrin, err)
			return err
		}
	}
	for _, hostTaoName := range trustedEntities.GetTrustedHostTaoNames() {
		var hostPrin auth.Prin
		_, err := fmt.Sscanf(hostTaoName, "%v", &hostPrin)
		if err != nil {
			log.Printf("Can't create host principal from: %s\nError: %s",
				hostTaoName, err)
			return err
		}
		err = domain.Guard.Authorize(hostPrin, "Host", []string{})
		if err != nil {
			log.Printf("Can't authorize principal: %s\nError: %s", hostPrin, err)
			return err
		}
	}
	for _, machineInfo := range trustedEntities.GetTrustedMachineInfos() {
		machinePrin := auth.Prin{
			Type:    "MachineInfo",
			KeyHash: auth.Str(machineInfo),
		}
		err = domain.Guard.Authorize(machinePrin, "Root", []string{})
		if err != nil {
			log.Printf("Can't authorize principal: %s\nError: %s", machinePrin, err)
			return err
		}
	}
	err = domain.Save()
	if err != nil {
		log.Println("Can't save domain.", err)
	}
	return err
}

// This function helps process a certificate revocation request.
// It expects serAtt to be a serialized attestation signed by the domain policy key,
// with a statement of the form:
// policyKey says revoke certificateSerialNumber
// This function gets a list of revoked certificates, updates it if the cert revocation
// request is valid, and returns the updated list.
func RevokeCertificate(serAtt []byte, revokedCerts []pkix.RevokedCertificate,
	domain *tao.Domain) ([]pkix.RevokedCertificate, error) {

	var policyAtt tao.Attestation
	err := proto.Unmarshal(serAtt, &policyAtt)
	if err != nil {
		return revokedCerts, err
	}
	if signer, err := policyAtt.ValidSigner(); err != nil {
		return revokedCerts, err
	} else if !signer.Identical(domain.Keys.SigningKey.ToPrincipal()) {
		return revokedCerts, errors.New("revoke cert request not signed by the policy key")
	}
	saysStmt, err := policyAtt.Validate()
	if err != nil {
		return revokedCerts, err
	}
	if saysStmt.Message == nil {
		return revokedCerts, errors.New("policy attestation 'Says' does not have a message")
	}
	pred, ok := saysStmt.Message.(auth.Pred)
	if !ok {
		return revokedCerts,
			errors.New("policy attestation 'Says' does not have a auth.Pred message")
	}
	if pred.Name != "revoke" {
		return revokedCerts, errors.New("policy attestation predicate name is not 'revoke'")
	}
	if len(pred.Arg) != 1 {
		return revokedCerts,
			errors.New("policy attestation predicate has more or less than one Arg")
	}
	serialNumberBytes, ok := pred.Arg[0].(auth.Bytes)
	if !ok {
		return revokedCerts,
			errors.New("policy attestation serial number is not bytes")
	}
	serialNumber := new(big.Int)
	serialNumber.SetBytes(serialNumberBytes)
	revokedCert := pkix.RevokedCertificate{
		SerialNumber:   serialNumber,
		RevocationTime: time.Now()}
	return append(revokedCerts, revokedCert), nil
}
