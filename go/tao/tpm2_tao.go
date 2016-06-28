// Copyright (c) 2014, Google Inc. All rights reserved.
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

package tao

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/tpm2"
	"github.com/jlmucb/cloudproxy/go/util"
)

func EncodeTwoBytes(b1 []byte, b2 []byte) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, uint16(len(b1)))
	if err != nil {
		return nil
	}
	err = binary.Write(buf, binary.BigEndian, b1)
	if err != nil {
		return nil
	}
	err = binary.Write(buf, binary.BigEndian, uint16(len(b2)))
	if err != nil {
		return nil
	}
	err = binary.Write(buf, binary.BigEndian, b2)
	if err != nil {
		return nil
	}
	return buf.Bytes()
}

func DecodeTwoBytes(b []byte) ([]byte, []byte) {
	buf := bytes.NewBuffer(b)
	var size uint16
	err := binary.Read(buf, binary.BigEndian, &size)
	if err != nil {
		return nil, nil
	}
	b1 := make([]byte, size, size)
	binary.Read(buf, binary.BigEndian, b1)
	err = binary.Read(buf, binary.BigEndian, &size)
	if err != nil {
		return nil, nil
	}
	b2 := make([]byte, size, size)
	binary.Read(buf, binary.BigEndian, b2)
	return b1, b2
}

// A TPM2Tao implements the Tao using a hardware TPM device.
type TPM2Tao struct {
	// rw is the device through which TPM2Tao communicates with the TPM.
	// usually /dev/tpm0.
	rw io.ReadWriteCloser

	// State path (includes config info)
	path string

	// quote-key cert
	rootCert []byte

	// password is the password.
	password string

	// rootHandle is an integer handle for an root held by the TPM.
	rootContext []byte
	rootHandle  tpm2.Handle

	// quoteHandle is an integer handle for an quote key held by the TPM.
	quoteContext []byte
	quotePublic  []byte
	quoteHandle  tpm2.Handle

	// sealHandle is an integer handle for sealing, held by the TPM.
	sealContext []byte
	sealPublic  []byte
	sealHandle  tpm2.Handle

	// session handle
	sessionContext []byte
	sessionHandle  tpm2.Handle

	// verifier is a representation of the root that can be used to verify Attestations.
	verifier *rsa.PublicKey

	// pcrCount is the number of PCRs in the TPM.
	// implementation fixes this at 24.
	pcrCount uint32
	pcrNums  []int
	pcrVals  [][]byte
	pcrs     []int

	// The name of the TPM2Tao is tpm(...K...) with extensions that represent the
	// PCR values (and maybe someday the locality).
	name auth.Prin

	// The current TPM2Tao code uses only locality 0, so this value is never set.
	locality byte
}

func (tt *TPM2Tao) loadRoot() (tpm2.Handle, error) {
	rh, err := tpm2.LoadContext(tt.rw, tt.rootContext)
	if err != nil {
		return tpm2.Handle(0), errors.New("Load Context fails for root")
	}
	return rh, nil
}

func (tt *TPM2Tao) loadQuote() (tpm2.Handle, error) {
	qh, err := tpm2.LoadContext(tt.rw, tt.quoteContext)
	if err != nil {
		return tpm2.Handle(0), errors.New("Load Context fails for quote")
	}
	return qh, nil
}

func (tt *TPM2Tao) loadSeal() (tpm2.Handle, error) {
	sh, err := tpm2.LoadContext(tt.rw, tt.sealContext)
	if err != nil {
		return tpm2.Handle(0), errors.New("Load Context fails for root")
	}
	return sh, nil
}

func (tt *TPM2Tao) loadSession() (tpm2.Handle, []byte, error) {
	sh, digest, err := tpm2.AssistCreateSession(tt.rw,
		tpm2.AlgTPM_ALG_SHA1, tt.pcrs)
	if err != nil {
		return tpm2.Handle(0), nil, err
	}
	return sh, digest, nil
}

func (tt *TPM2Tao) GetPcrNums() []int {
	return tt.pcrs
}

func (tt *TPM2Tao) GetRsaQuoteKey() (*rsa.PublicKey, error) {
	handle, err := tt.loadQuote()
	if err != nil {
		return nil, errors.New("Can't load quote key\n")
	}
	defer tpm2.FlushContext(tt.rw, handle)
	return tpm2.GetRsaKeyFromHandle(tt.rw, handle)
}

func (tt *TPM2Tao) Rand() io.Reader {
	return tt.rw
}

func ReadTPM2PCRs(rw io.ReadWriter, pcrNums []int) ([][]byte, error) {
	fmt.Fprintf(os.Stderr, "Getting the PCRs\n")
	pcrVals := make([][]byte, len(pcrNums))
	for i, v := range pcrNums {
		fmt.Fprintf(os.Stderr, "Working on iteration %d\n", i)
		pcr, _ := tpm2.SetShortPcrs([]int{v})
		fmt.Fprintf(os.Stderr, "set short pcr %v, returned %v\n", v, pcr)
		_, _, _, pv, err := tpm2.ReadPcrs(rw, byte(4), pcr)
		fmt.Fprintf(os.Stderr, "got PCR value % x\n", pv)
		if err != nil {
			return nil, err
		}
		pcrVals[i] = pv
	}
	return pcrVals, nil
}

func MakeTPM2Prin(verifier *rsa.PublicKey, pcrNums []int, pcrVals [][]byte) (auth.Prin, error) {
	root, err := x509.MarshalPKIXPublicKey(verifier)
	if err != nil {
		return auth.Prin{}, err
	}

	name := auth.NewTPM2Prin(root)

	asp := auth.PrinExt{
		Name: "PCRs",
		Arg:  make([]auth.Term, 2),
	}
	var pcrNumStrs []string
	for _, v := range pcrNums {
		pcrNumStrs = append(pcrNumStrs, strconv.Itoa(v))
	}
	asp.Arg[0] = auth.Str(strings.Join(pcrNumStrs, ","))

	var pcrValStrs []string
	for _, p := range pcrVals {
		pcrValStrs = append(pcrValStrs, hex.EncodeToString(p))
	}
	asp.Arg[1] = auth.Str(strings.Join(pcrValStrs, ","))

	// The PCRs are the first extension of the name.
	name.Ext = []auth.PrinExt{asp}

	return name, nil
}

// FinalizeTPM2Tao releases the resources for the TPM2Tao.
func FinalizeTPM2Tao(tt *TPM2Tao) {
	if tt.sessionHandle != 0 {
		tpm2.FlushContext(tt.rw, tpm2.Handle(tt.sessionHandle))
	}
	tt.sessionHandle = 0
	if tt.rootHandle != 0 {
		tpm2.FlushContext(tt.rw, tpm2.Handle(tt.rootHandle))
	}
	tt.rootHandle = 0
	if tt.sealHandle != 0 {
		tpm2.FlushContext(tt.rw, tpm2.Handle(tt.sealHandle))
	}
	tt.sealHandle = 0

	// Release the file handle.
	tt.rw.Close()
}

// Remove this
func (tt *TPM2Tao) TmpRm() {

	if tt.rootHandle != 0 {
		tpm2.FlushContext(tt.rw, tt.rootHandle)
	}
	tt.rootHandle = 0

	if tt.sealHandle != 0 {
		tpm2.FlushContext(tt.rw, tt.sealHandle)
	}
	tt.sealHandle = 0
}

// GetTaoName returns the Tao principal name assigned to the caller.
func (tt *TPM2Tao) GetTaoName() (name auth.Prin, err error) {
	return tt.name, nil
}

// ExtendTaoName irreversibly extends the Tao principal name of the caller.
func (tt *TPM2Tao) ExtendTaoName(subprin auth.SubPrin) error {
	tt.name = tt.name.MakeSubprincipal(subprin)
	return nil
}

// GetRandomBytes returns a slice of n random bytes.
func (tt *TPM2Tao) GetRandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("invalid number of requested random bytes")
	}
	return tpm2.GetRandom(tt.rw, uint32(n))
}

// ReadRandom implements io.Reader to read random bytes from the TPM2Tao.
func (tt *TPM2Tao) ReadRandom(p []byte) (int, error) {
	bytes, err := tt.GetRandomBytes(len(p))
	if err != nil {
		return 0, err
	}

	copy(p, bytes)
	return len(p), nil
}

// GetSharedSecret returns a slice of n secret bytes.
func (tt *TPM2Tao) GetSharedSecret(n int, policy string) (bytes []byte, err error) {
	return nil, errors.New("the TPM2Tao does not implement GetSharedSecret")
}

// NewTPM2Tao creates a new TPM2Tao and returns it under the Tao interface.
func NewTPM2Tao(tpmPath string, statePath string, pcrNums []int) (Tao, error) {
	var err error
	tt := &TPM2Tao{pcrCount: 24,
		password: ""}

	tt.rw, err = tpm2.OpenTPM(tpmPath)
	if err != nil {
		return nil, err
	}

	// Make sure the TPM2Tao releases all its resources
	runtime.SetFinalizer(tt, FinalizeTPM2Tao)

	tt.pcrs = pcrNums

	// Create the root key.
	//
	// TODO(tmroeder): Replace this temporary key with a key read from a
	// file.
	keySize := uint16(1024)
	quotePassword := ""
	var empty []byte
	primaryParams := tpm2.RsaParams{uint16(tpm2.AlgTPM_ALG_RSA),
		uint16(tpm2.AlgTPM_ALG_SHA1), tpm2.FlagStorageDefault,
		empty, uint16(tpm2.AlgTPM_ALG_AES), uint16(128),
		uint16(tpm2.AlgTPM_ALG_CFB), uint16(tpm2.AlgTPM_ALG_NULL),
		uint16(0), keySize, uint32(0x00010001), empty}
	tt.rootHandle, tt.rootContext, err = tpm2.CreatePrimary(tt.rw,
		uint32(tpm2.OrdTPM_RH_OWNER), tt.pcrs, "", "", primaryParams)
	if err != nil {
		return nil, errors.New("CreatePrimary failed")
	}

	// CreateKey (Quote Key)
	keyParams := tpm2.RsaParams{uint16(tpm2.AlgTPM_ALG_RSA), uint16(tpm2.AlgTPM_ALG_SHA1),
		tpm2.FlagSignerDefault, empty, uint16(tpm2.AlgTPM_ALG_NULL), uint16(0),
		uint16(tpm2.AlgTPM_ALG_ECB), uint16(tpm2.AlgTPM_ALG_RSASSA),
		uint16(tpm2.AlgTPM_ALG_SHA1), keySize, uint32(0x00010001), empty}
	tt.quoteContext, tt.quotePublic, err = tpm2.CreateKey(tt.rw,
		uint32(tt.rootHandle), tt.pcrs, "", quotePassword, keyParams)
	if err != nil {
		return nil, errors.New("Can't create quote key")
	}

	tt.quoteHandle, _, err = tpm2.Load(tt.rw, tt.rootHandle, "",
		"", tt.quotePublic, tt.quoteContext)
	if err != nil {
		return nil, errors.New("Load failed for the quote key")
	}

	sealParams := tpm2.RsaParams{uint16(tpm2.AlgTPM_ALG_RSA),
		uint16(tpm2.AlgTPM_ALG_SHA1), tpm2.FlagStorageDefault,
		empty, uint16(tpm2.AlgTPM_ALG_AES), uint16(128),
		uint16(tpm2.AlgTPM_ALG_CFB), uint16(tpm2.AlgTPM_ALG_NULL),
		uint16(0), keySize, uint32(0x00010001), empty}
	tt.sealContext, tt.sealPublic, err = tpm2.CreateKey(tt.rw,
		uint32(tt.rootHandle), tt.pcrs, "", quotePassword, sealParams)
	if err != nil {
		return nil, errors.New("Can't create store key")
	}

	tt.sealHandle, _, err = tpm2.Load(tt.rw, tt.rootHandle, "", "", tt.sealPublic, tt.sealContext)
	if err != nil {
		return nil, errors.New("Load failed for the seal key")
	}

	tt.verifier, err = tpm2.GetRsaKeyFromHandle(tt.rw, tt.quoteHandle)
	if err != nil {
		return nil, err
	}

	// Get the pcr values for the PCR nums.
	tt.pcrNums = make([]int, len(pcrNums))
	for i, v := range pcrNums {
		tt.pcrNums[i] = v
	}

	tt.pcrVals, err = ReadTPM2PCRs(tt.rw, pcrNums)
	if err != nil {
		return nil, err
	}

	// Create principal.
	tt.name, err = MakeTPM2Prin(tt.verifier, tt.pcrNums, tt.pcrVals)
	if err != nil {
		return nil, err
	}

	return tt, nil
}

// Attest requests the Tao host seal a statement on behalf of the caller. The
// optional issuer, time and expiration will be given default values if nil.
func (tt *TPM2Tao) Attest(issuer *auth.Prin, start, expiration *int64,
	message auth.Form) (*Attestation, error) {
	fmt.Fprintf(os.Stderr, "About to load the quote key in attest\n")
	qH := tt.quoteHandle
	//qH, err := tt.loadQuote()
	//if err != nil {
	//return nil, errors.New("Can't load quote key")
	//}
	//defer tpm2.FlushContext(tt.rw, qH)
	if issuer == nil {
		issuer = &tt.name
	} else if !auth.SubprinOrIdentical(*issuer, tt.name) {
		return nil, errors.New("invalid issuer in statement")
	}

	// TODO(tmroeder): we assume here that the PCRs haven't changed (e.g., been
	// extended) since this TPM2Tao was created. If they have, then the PCRs will
	// be wrong when we extend the principal here with them as the first
	// component. This doesn't matter at the moment, since we don't currently
	// support extending the PCRs or clearing them, but it will need to be
	// changed when we do.
	stmt := auth.Says{
		Speaker:    *issuer,
		Time:       start,
		Expiration: expiration,
		Message:    message,
	}

	// This is done in GenerateAttestation, but the TPM attestation is sealed
	// differently, so we do the time calculations here.
	t := time.Now()
	if stmt.Time == nil {
		i := t.UnixNano()
		stmt.Time = &i
	}

	if stmt.Expiration == nil {
		i := t.Add(365 * 24 * time.Hour).UnixNano()
		stmt.Expiration = &i
	}

	ser := auth.Marshal(stmt)

	var pcrVals [][]byte
	toQuote, err := tpm2.FormatTpm2Quote(ser, tt.pcrs, pcrVals)
	if err != nil {
		return nil, errors.New("Can't format tpm2 Quote")
	}

	// TODO(tmroeder): check the pcrVals for sanity once we support extending or
	// clearing the PCRs.
	quote_struct, sig, err := tpm2.Quote(tt.rw, qH, "", tt.password,
		toQuote, tt.pcrs, uint16(tpm2.AlgTPM_ALG_NULL))
	if err != nil {
		return nil, err
	}
	fmt.Printf("toQuote: %x\n", toQuote)
	fmt.Printf("Quote: %x\n", quote_struct)
	fmt.Printf("sig: %x\n", sig)

	// TODO(tmroeder): this shouldn't be the root but rather the quote key.
	root, err := x509.MarshalPKIXPublicKey(tt.verifier)
	if err != nil {
		return nil, err
	}
	// TODO(kwalsh) remove Tpm2QuoteStructure from Attestation structure
	a := &Attestation{
		SerializedStatement: ser,
		Signature:           sig,
		SignerType:          proto.String("tpm2"),
		SignerKey:           root,
		Tpm2QuoteStructure:  quote_struct,
	}
	return a, nil
}

// Seal encrypts data so only certain hosted programs can unseal it. Note that
// at least some TPMs can only seal up to 149 bytes of data. So, we employ a
// hybrid encryption scheme that seals a key and uses the key to encrypt the
// data separately. We use the keys infrastructure to perform secure and
// flexible encryption.
func (tt *TPM2Tao) Seal(data []byte, policy string) ([]byte, error) {
	rH := tt.rootHandle
	//rH, err := tt.loadRoot()
	//if err != nil {
	//return nil, errors.New("Can't load root key")
	//}
	//defer tpm2.FlushContext(tt.rw, rH)
	sK, policy_digest, err := tt.loadSession()
	if err != nil {
		return nil, errors.New("Can't load root key")
	}
	defer tpm2.FlushContext(tt.rw, sK)
	if policy != SealPolicyDefault {
		return nil, errors.New("tpm-specific policies are not yet implemented")
	}

	crypter, err := GenerateCrypter()
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(crypter.aesKey)
	defer ZeroBytes(crypter.hmacKey)

	c, err := crypter.Encrypt(data)
	if err != nil {
		return nil, err
	}

	ck, err := MarshalCrypterProto(crypter)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(ck.Key)

	ckb, err := proto.Marshal(ck)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(ckb)

	priv, pub, err := tpm2.AssistSeal(tt.rw, rH, ckb,
		"", tt.password, tt.pcrs, policy_digest)
	if err != nil {
		return nil, err
	}

	// encode pub and priv
	s := EncodeTwoBytes(pub, priv)

	h := &HybridSealedData{
		SealedKey:     s,
		EncryptedData: c,
	}

	return proto.Marshal(h)
}

// Unseal decrypts data that has been sealed by the Seal() operation, but only
// if the policy specified during the Seal() operation is satisfied.
func (tt *TPM2Tao) Unseal(sealed []byte) (data []byte, policy string, err error) {
	rH, err := tt.loadRoot()
	if err != nil {
		return nil, "", errors.New("Can't load root key")
	}
	defer tpm2.FlushContext(tt.rw, rH)
	sH, policy_digest, err := tt.loadSession()
	if err != nil {
		return nil, "", errors.New("Can't load root key")
	}
	defer tpm2.FlushContext(tt.rw, sH)

	// The sealed data is a HybridSealedData.
	var h HybridSealedData
	if err := proto.Unmarshal(sealed, &h); err != nil {
		return nil, "", err
	}

	// Decode buffer containing pub and priv blobs
	pub, priv := DecodeTwoBytes(h.SealedKey)
	unsealed, _, err := tpm2.AssistUnseal(tt.rw, sH,
		rH, pub, priv, "", tt.password, policy_digest)
	if err != nil {
		return nil, "", err
	}
	defer ZeroBytes(unsealed)

	var ck CryptoKey
	if err := proto.Unmarshal(unsealed, &ck); err != nil {
		return nil, "", err
	}
	defer ZeroBytes(ck.Key)

	crypter, err := UnmarshalCrypterProto(&ck)
	if err != nil {
		return nil, "", err
	}
	defer ZeroBytes(crypter.aesKey)
	defer ZeroBytes(crypter.hmacKey)

	m, err := crypter.Decrypt(h.EncryptedData)
	if err != nil {
		return nil, "", err
	}

	return m, SealPolicyDefault, nil
}

// extractPCRs gets the PCRs from a tpm principal.
func extractTpm2PCRs(p auth.Prin) ([]int, []byte, error) {
	return nil, nil, nil
	if p.Type != "tpm2" {
		return nil, nil, errors.New("can only extract PCRs from a TPM principal")
	}

	// The PCRs are stored as the first subprincipal value, with name "PCRs".
	if len(p.Ext) == 0 {
		return nil, nil, errors.New("no subprincipals available for PCR extraction")
	}

	if p.Ext[0].Name != "PCRs" {
		return nil, nil, errors.New("the first subprincipal must have Name 'PCRs' for PCR extraction to work")
	}

	sp := p.Ext[0]
	if len(sp.Arg) != 2 {
		return nil, nil, errors.New("the PCRs subprincipal must have exactly two arguments")
	}

	// auth.Str is exactly a string.
	arg0, ok0 := sp.Arg[0].(auth.Str)
	arg1, ok1 := sp.Arg[1].(auth.Str)
	if !ok0 || !ok1 {
		return nil, nil, errors.New("both Terms in the PCRs subprincipal must be strings")
	}

	nums := strings.Split(string(arg0), ",")
	vals := strings.Split(string(arg1), ",")
	if len(nums) != len(vals) {
		return nil, nil, errors.New("mismatched count between PCR nums and vals")
	}

	pcrNums := make([]int, len(nums))
	var pcrVals []byte
	for i, v := range nums {
		n, err := strconv.ParseInt(v, 10, 16)
		if err != nil {
			return nil, nil, err
		}
		pcrNums[i] = int(n)

		b, err := hex.DecodeString(vals[i])
		if err != nil {
			return nil, nil, err
		}
		pcrVals = append(pcrVals, b...)
	}
	return pcrNums, pcrVals, nil
}

// extractTPM2Key gets an RSA public key from the TPM key material.
func extractTPM2Key(material []byte) (*rsa.PublicKey, error) {
	return extractTPMKey(material) // same key format as TPM 1.2
}

// Input: Der encoded endorsement cert and handles
// quote key is certified key unlike in the tpm2.go library
// Returns program CertRequestMessage
func Tpm2ConstructClientRequest(rw io.ReadWriter, derEkCert []byte, pcrs []int,
	qH tpm2.Handle, parentPassword string, ownerPassword string,
	keyName string) (*tpm2.ProgramCertRequestMessage, error) {

	// Generate Request
	request := new(tpm2.ProgramCertRequestMessage)
	request.ProgramKey = new(tpm2.ProgramKeyParameters)
	request.EndorsementCertBlob = derEkCert
	req_id := "001"
	request.RequestId = &req_id

	// Quote key
	keyBlob, tpm2QuoteName, _, err := tpm2.ReadPublic(rw, qH)
	if err != nil {
		return nil, err
	}
	rsaQuoteParams, err := tpm2.DecodeRsaBuf(keyBlob)
	if err != nil {
		return nil, err
	}

	modSize := int32(rsaQuoteParams.Mod_sz)

	keyType := "rsa"
	request.ProgramKey.ProgramName = &keyName
	request.ProgramKey.ProgramKeyType = &keyType
	request.ProgramKey.ProgramBitModulusSize = &modSize

	request.ProgramKey.ProgramKeyExponent = []byte{0, 1, 0, 1}
	request.ProgramKey.ProgramKeyModulus = rsaQuoteParams.Modulus
	serializedProgramKey := proto.CompactTextString(request.ProgramKey)
	sha1Hash := sha1.New()
	sha1Hash.Write([]byte(serializedProgramKey))
	hashProgramKey := sha1Hash.Sum(nil)

	sigAlg := uint16(tpm2.AlgTPM_ALG_NULL)
	attest, sig, err := tpm2.Quote(rw, qH, parentPassword, ownerPassword,
		hashProgramKey, pcrs, sigAlg)
	if err != nil {
		return nil, err
	}

	// Quote key info.
	request.QuoteKeyInfo = new(tpm2.QuoteKeyInfoMessage)
	request.QuoteKeyInfo.Name = tpm2QuoteName
	request.QuoteKeyInfo.PublicKey = new(tpm2.PublicKeyMessage)
	request.QuoteKeyInfo.PublicKey.RsaKey = new(tpm2.RsaPublicKeyMessage)
	request.QuoteKeyInfo.PublicKey.RsaKey.KeyName = &keyName

	var encAlg string
	var hashAlg string
	if rsaQuoteParams.Enc_alg == tpm2.AlgTPM_ALG_RSA {
		encAlg = "rsa"
	} else {
		return nil, err
	}
	if rsaQuoteParams.Hash_alg == tpm2.AlgTPM_ALG_SHA1 {
		hashAlg = "sha1"
	} else if rsaQuoteParams.Hash_alg == tpm2.AlgTPM_ALG_SHA256 {
		hashAlg = "sha256"
	} else {
		return nil, err
	}
	request.QuoteKeyInfo.PublicKey.KeyType = &encAlg
	request.QuoteKeyInfo.PublicKey.RsaKey.BitModulusSize = &modSize
	request.QuoteKeyInfo.PublicKey.RsaKey.Modulus = rsaQuoteParams.Modulus
	request.QuoteSignAlg = &encAlg
	request.QuoteSignHashAlg = &hashAlg

	request.ProgramKey = new(tpm2.ProgramKeyParameters)
	request.ProgramKey.ProgramName = &keyName
	request.ProgramKey.ProgramKeyType = &encAlg
	request.ProgramKey.ProgramBitModulusSize = &modSize
	request.ProgramKey.ProgramKeyModulus = rsaQuoteParams.Modulus

	request.QuotedBlob = attest
	request.QuoteSignature = sig
	return request, nil
}

// Output is der encoded Program Cert
func Tpm2ClientDecodeServerResponse(rw io.ReadWriter,
	protectorHandle tpm2.Handle,
	quoteHandle tpm2.Handle, password string,
	response tpm2.ProgramCertResponseMessage) ([]byte, error) {
	certBlob := append(response.IntegrityHMAC, response.EncIdentity...)
	certInfo, err := tpm2.ActivateCredential(rw, quoteHandle,
		protectorHandle, password, "", certBlob, response.Secret)
	if err != nil {
		return nil, err
	}

	// Decrypt cert.
	_, out, err := tpm2.EncryptDataWithCredential(false,
		uint16(tpm2.AlgTPM_ALG_SHA1),
		certInfo, response.EncryptedCert, response.EncryptedCertHmac)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Return attest certificate
func (tt *TPM2Tao) Tpm2Certify(network, addr string, keyName string) ([]byte, error) {

	// Establish connection wtih the CA.
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	rk, err := tt.loadRoot()
	qH, err := tt.loadQuote()

	ms := util.NewMessageStream(conn)
	programCertMessage, err := Tpm2ConstructClientRequest(tt.rw,
		tt.rootCert, tt.pcrs,
		qH, "", tt.password, keyName)
	_, err = ms.WriteMessage(programCertMessage)
	if err != nil {
		return nil, err
	}

	var resp tpm2.ProgramCertResponseMessage
	err = ms.ReadMessage(&resp)
	if err != nil {
		return nil, err
	}
	attestCert, err := Tpm2ClientDecodeServerResponse(tt.rw, rk, qH,
		tt.password, resp)
	return attestCert, nil
}
