// Copyright (c) 2016, Google Inc. All rights reserved.
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

package domain_service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-tpm/tpm"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

var machineName = "Encode Machine Information"

var hostName = &auth.Prin{
	Type:    "program",
	KeyHash: auth.Str("hostHash")}

var programName = &auth.Prin{
	Type:    "program",
	KeyHash: auth.Str("programHash")}

var us = "US"
var google = "Google"
var x509Info = &tao.X509Details{
	Country:      &us,
	Organization: &google}

func TestVerifyHostAttestation_stackedHost(t *testing.T) {
	aikblob, err := ioutil.ReadFile("./aikblob")
	if err != nil {
		t.Skip("Skipping tests, since there's no ./aikblob file")
	}
	tpmtao, err := tao.NewTPMTao("/dev/tpm0", aikblob, []int{17, 18}, nil)
	if err != nil {
		t.Skip("Couldn't create a new TPM Tao:", err)
	}
	tt, ok := tpmtao.(*tao.TPMTao)
	if !ok {
		t.Fatal("Failed to create the right kind of Tao object from NewTPMTao")
	}
	defer tao.CleanUpTPMTao(tt)
	hwPublicKey, err := tpm.UnmarshalRSAPublicKey(aikblob)
	if err != nil {
		t.Fatal(err)
	}

	domain := generateDomain(t)
	policyKey, policyCert := domain.Keys, domain.Keys.Cert
	hwCert := generateEndorsementCertficate(t, policyKey, hwPublicKey, policyCert)
	hostKey, hostAtt := generateTpmAttestation(t, tt, hostName)
	programKey, programAtt := generateAttestation(t, hostKey, programName)
	rawEnd1, err := proto.Marshal(hostAtt)
	if err != nil {
		t.Fatal("Error serializing attestation.")
	}
	rawEnd2 := hwCert.Raw
	programAtt.SerializedEndorsements = [][]byte{rawEnd1, rawEnd2}
	rawAtt, err := proto.Marshal(programAtt)
	if err != nil {
		t.Fatal("Error serializing attestation.")
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(policyCert)
	speaker, key, prog, err := VerifyHostAttestation(rawAtt, domain, certPool)
	if err != nil {
		t.Fatal("Test attesation failed verification checks.", err)
	}
	if !programName.Identical(prog) {
		t.Fatal("Attestation program name not identical to expected program name.")
	}
	if !programKey.SigningKey.ToPrincipal().Identical(key) {
		t.Fatal("Attestation program key not identical to expected program key.")
	}
	if !hostKey.SigningKey.ToPrincipal().Identical(speaker) {
		t.Fatal("Attestation host key not identical to expected host key.")
	}
}

func TestVerifyHostAttestation_rootHost(t *testing.T) {
	domain := generateDomain(t)
	policyKey, policyCert := domain.Keys, domain.Keys.Cert
	hostKey, hostAtt := generateAttestation(t, policyKey, hostName)
	programKey, programAtt := generateAttestation(t, hostKey, programName)
	rawEnd, err := proto.Marshal(hostAtt)
	if err != nil {
		t.Fatal("Error serializing attestation.")
	}
	programAtt.SerializedEndorsements = [][]byte{rawEnd}
	rawAtt, err := proto.Marshal(programAtt)
	if err != nil {
		t.Fatal("Error serializing attestation.")
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(policyCert)
	speaker, key, prog, err := VerifyHostAttestation(rawAtt, domain, certPool)
	if err != nil {
		t.Fatal("Test attesation failed verification checks.", err)
	}
	if !programName.Identical(prog) {
		t.Fatal("Attestation program name not identical to expected program name.")
	}
	if !programKey.SigningKey.ToPrincipal().Identical(key) {
		t.Fatal("Attestation program key not identical to expected program key.")
	}
	if !hostKey.SigningKey.ToPrincipal().Identical(speaker) {
		t.Fatal("Attestation host key not identical to expected host key.")
	}
}

func TestGenerateProgramCert(t *testing.T) {
	domain := generateDomain(t)
	programKey, err := tao.NewTemporaryKeys(tao.Signing)
	if err != nil {
		t.Fatal("Error generating keys.", err)
	}
	cert, err := GenerateProgramCert(domain, 0, programName, programKey.VerifyingKey,
		time.Now(), time.Now().AddDate(1, 0, 0))
	rootCerts := x509.NewCertPool()
	rootCerts.AddCert(domain.Keys.Cert)
	options := x509.VerifyOptions{Roots: rootCerts}
	_, err = cert.Verify(options)
	if err != nil {
		t.Fatal("Program cert fails verification check.", err)
	}
}

func TestValidateEndorsementCert(t *testing.T) {
	aikblob, err := ioutil.ReadFile("./aikblob")
	if err != nil {
		t.Skip("Skipping tests, since there's no ./aikblob file")
	}
	tpmtao, err := tao.NewTPMTao("/dev/tpm0", aikblob, []int{17, 18}, nil)
	if err != nil {
		t.Skip("Couldn't create a new TPM Tao:", err)
	}
	tt, ok := tpmtao.(*tao.TPMTao)
	if !ok {
		t.Fatal("Failed to create the right kind of Tao object from NewTPMTao")
	}
	defer tao.CleanUpTPMTao(tt)
	hwPublicKey, err := tpm.UnmarshalRSAPublicKey(aikblob)
	if err != nil {
		t.Fatal(err)
	}

	domain := generateDomain(t)
	policyKey, policyCert := domain.Keys, domain.Keys.Cert
	hwCert := generateEndorsementCertficate(t, policyKey, hwPublicKey, policyCert)
	rootCerts := x509.NewCertPool()
	rootCerts.AddCert(policyCert)
	taoname, err := tt.GetTaoName()
	if err != nil {
		t.Fatal(err)
	}
	err = validateEndorsementCertificate(hwCert, *generateGuard(t), &taoname, rootCerts)
	if err != nil {
		t.Fatal(err)
	}
}

func TestInitAcls(t *testing.T) {
	if _, err := os.Stat("./tmpdir"); os.IsNotExist(err) {
		err = os.Mkdir("./tmpdir", 0777)
		if err != nil {
			t.Fatal(err)
		}
	}
	trustedEntities := TrustedEntities{
		TrustedProgramTaoNames: []string{fmt.Sprintf("%v", programName)},
		TrustedHostTaoNames:    []string{fmt.Sprintf("%v", hostName)},
		TrustedMachineInfos:    []string{machineName}}
	f, err := os.Create("./tmpdir/TrustedEntities")
	if err != nil {
		t.Fatal(err)
	}
	err = proto.MarshalText(f, &trustedEntities)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	aclGuardType := "ACLs"
	aclGuardPath := "acls"
	cfg := tao.DomainConfig{
		DomainInfo: &tao.DomainDetails{
			GuardType: &aclGuardType},
		AclGuardInfo: &tao.ACLGuardDetails{
			SignedAclsPath: &aclGuardPath}}
	domain, err := tao.CreateDomain(cfg, "./tmpdir/domain", []byte("xxx"))
	if err != nil {
		t.Fatal(err)
	}
	err = InitAcls(domain, "./tmpdir/TrustedEntities")
	if err != nil {
		t.Fatal(err)
	}
	machinePrin := auth.Prin{
		Type:    "MachineInfo",
		KeyHash: auth.Str(machineName),
	}
	if !domain.Guard.IsAuthorized(*programName, "Execute", []string{}) ||
		!domain.Guard.IsAuthorized(*hostName, "Host", []string{}) ||
		!domain.Guard.IsAuthorized(machinePrin, "Root", []string{}) {
		t.Fatal("Authorization checks fail")
	}
	err = os.RemoveAll("./tmpdir")
	if err != nil {
		t.Fatal(err)
	}
}

func TestRevokeCertificate(t *testing.T) {
	k, err := tao.NewTemporaryKeys(tao.Signing)
	if k == nil || err != nil {
		t.Fatal("Can't generate signing key")
	}
	serialNumber := big.NewInt(5)
	says := auth.Says{
		Speaker: k.SigningKey.ToPrincipal(),
		Message: auth.Pred{
			Name: "revoke",
			Arg:  []auth.Term{auth.Bytes(serialNumber.Bytes())}}}

	att, err := tao.GenerateAttestation(k.SigningKey, nil, says)
	if err != nil {
		t.Fatal("Error generating attestation.")
	}
	serAtt, err := proto.Marshal(att)
	if err != nil {
		t.Fatal("Error serializing attestation.")
	}
	revokedCerts := []pkix.RevokedCertificate{}
	revokedCerts, err = RevokeCertificate(serAtt, revokedCerts, &tao.Domain{Keys: k})
	if err != nil {
		t.Fatal(err)
	}
	if num := revokedCerts[0].SerialNumber.Int64(); num != 5 {
		t.Fatal(fmt.Sprintf("Serial number %v doesnt match expected value 5", num))
	}
}

func generateDomain(t *testing.T) *tao.Domain {
	domain := tao.Domain{}
	domain.Keys, domain.Keys.Cert = generatePolicyKey(t)
	domain.Guard = *generateGuard(t)
	domain.Config = tao.DomainConfig{X509Info: x509Info}
	return &domain
}

func generatePolicyKey(t *testing.T) (*tao.Keys, *x509.Certificate) {
	k, err := tao.NewTemporaryKeys(tao.Signing)
	if k == nil || err != nil {
		t.Fatal("Can't generate signing key")
	}
	us := "US"
	google := "Google"
	subjectName := "Policy"
	details := tao.X509Details{
		Country:      &us,
		Organization: &google,
		CommonName:   &subjectName}
	subjectname := tao.NewX509Name(&details)
	cert, err := k.SigningKey.CreateSelfSignedX509(subjectname)
	if err != nil {
		t.Fatal("Can't self sign cert\n")
	}
	return k, cert
}

func generateEndorsementCertficate(t *testing.T, policyKey *tao.Keys, hwPublicKey *rsa.PublicKey,
	policyCert *x509.Certificate) *x509.Certificate {
	us := "US"
	google := "Google"
	details := tao.X509Details{
		Country:      &us,
		Organization: &google,
		CommonName:   &machineName}
	subject := tao.NewX509Name(&details)
	signTemplate := tao.PrepareX509Template(subject)
	derSignedCert, err := x509.CreateCertificate(rand.Reader, signTemplate, policyCert,
		hwPublicKey, policyKey.SigningKey.GetSigner())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(derSignedCert)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func generateTpmAttestation(t *testing.T, tpmtao *tao.TPMTao, delegator *auth.Prin) (*tao.Keys,
	*tao.Attestation) {
	k, err := tao.NewTemporaryKeys(tao.Signing)
	if k == nil || err != nil {
		t.Fatal("Can't generate signing key")
	}
	speaksFor := &auth.Speaksfor{
		Delegate:  k.SigningKey.ToPrincipal(),
		Delegator: delegator,
	}
	taoname, err := tpmtao.GetTaoName()
	if err != nil {
		t.Fatal("Couldn't get the name of the tao:", err)
	}
	says := &auth.Says{
		Speaker:    taoname,
		Time:       nil,
		Expiration: nil,
		Message:    speaksFor,
	}

	att, err := tpmtao.Attest(&taoname, nil, nil, says)
	if err != nil {
		t.Fatal("TPM couldn't attest:", err)
	}
	return k, att
}

func generateAttestation(t *testing.T, signingKey *tao.Keys, delegator *auth.Prin) (*tao.Keys,
	*tao.Attestation) {
	k, err := tao.NewTemporaryKeys(tao.Signing)
	if k == nil || err != nil {
		t.Fatal("Can't generate signing key")
	}
	speaksFor := &auth.Speaksfor{
		Delegate:  k.SigningKey.ToPrincipal(),
		Delegator: delegator,
	}
	says := &auth.Says{
		Speaker:    signingKey.SigningKey.ToPrincipal(),
		Time:       nil,
		Expiration: nil,
		Message:    speaksFor,
	}

	att, err := tao.GenerateAttestation(signingKey.SigningKey, nil, *says)
	if err != nil {
		t.Fatal("Error generating attestation:", err)
	}
	return k, att
}

func generateGuard(t *testing.T) *tao.Guard {
	guard := tao.NewACLGuard(nil, tao.ACLGuardDetails{})
	err := guard.Authorize(*hostName, "Host", []string{})
	if err != nil {
		t.Fatal("Error adding a rule to the guard", err)
	}
	err = guard.Authorize(*programName, "Execute", []string{})
	if err != nil {
		t.Fatal("Error adding a rule to the guard", err)
	}
	machinePrin := auth.Prin{Type: "MachineInfo", KeyHash: auth.Str(machineName)}
	err = guard.Authorize(machinePrin, "Root", []string{})
	if err != nil {
		t.Fatal("Error adding a rule to the guard", err)
	}
	return &guard
}
