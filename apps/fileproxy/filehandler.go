// Copyright (c) 2014, Google, Inc.  All rights reserved.
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
// File: filehandler.go

package fileproxy

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log"
	"path"
	"time"

	"code.google.com/p/goprotobuf/proto"

	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/util"
)

const NonceSize = 32
const ChallengeContext = "fileproxy-challenge"

// A ResourceType is the type of resource managed by the handler.
type ResourceType int

// These constants represent the different types of resources.
const (
	File ResourceType = iota
)

// A ResourceStatus is the state in which a resource finds itself.
type ResourceStatus int

// These constants represent the difference states of resources.
const (
	Created ResourceStatus = iota
)

// A Resource represents a resource managed by a handler.
type Resource struct {
	Name              string
	Type              ResourceType
	Status            ResourceStatus
	Location          string
	Size              int
	Owner             string
	DateCreated       time.Time
	DateModified      time.Time
	AuthenticatorType string
	Authenticator     [][]byte
}

// A PrincipalStatus gives the current state of a principal on a channel.
type PrincipalStatus int

// These constants represent the different states of principals.
const (
	Authenticated PrincipalStatus = iota
)

// A Principal represents a principal authenticated on a channel (or trying
// to authenticate on a channel).
type Principal struct {
	Name    string
	CertDER []byte
	Cert    *x509.Certificate
	Status  PrincipalStatus
}

// A ResourceMaster manages a set of resources for a set of principals, using a
// Guard to make authorization decisions.
type ResourceMaster struct {
	ProgramName   string
	Guard         tao.Guard
	BaseDirectory string
	Resources     map[string]*Resource
	Principals    map[string]*Principal
	Policy        []string
}

// Policy for managing files in the fileserver.
var policy = []string{
	// Fileserver owns everything.
	"forall FS: forall R: FileServer(FS) and Resource(R) implies Owner(FS, R)",
	// Creators are owners.
	"forall C: forall R: Creator(C, R) implies Owner(C, R)",
	// Owners can perform all actions and make all delegations.
	"forall O: forall A: forall R: Owner(O, R) and Resource(R) and Action(A) implies Authorized(O, \"delegate\", A, R)",
	"forall O: forall A: forall R: Owner(O, R) and Resource(R) and Action(A) implies Authorized(O, A, R)",
	// Principals have namespaces where they can create things.
	// The guard needs to understand that Authorized(P, "create-subdir",
	// path) means that P can create a path with its name underneath (or
	// something like the hash of its name).
	"forall P: Authorized(P, \"execute\") implies Authorized(P, \"create-subdir\", \"/principals\")",
	// Basic Delegation.
	"forall U1: forall U2: forall R: forall A: Authorized(U1, \"delegate\", A, R) and Delegate(U1, U2, A, R) implies Authorized(U2, A, R)",
	// Redelegation.
	"forall U1: forall U2: forall R: forall A: Authorized(U1, \"delegate\", A, R) and Delegate(U1, U2, \"delegate\", A, R) implies Authorized(U2, \"delegate\", A, R)",
	"Action(\"create\")",
	"Action(\"getfile\")",
	"Action(\"sendfile\")",
	"Action(\"delete\")",
	// Some simple test rules for fileclient
	"Authorized(\"jlm\", \"create\", \"originalTestFile\")",
	"Authorized(\"jlm\", \"write\", \"originalTestFile\")",
	"Authorized(\"jlm\", \"read\", \"originalTestFile\")",
}

// delegateResource adds a delegation statement to the policy for a given
// operation on a resource.
func (m *ResourceMaster) delegateResource(owner, delegate, op, res string) error {
	r := fmt.Sprintf("Delegate\"%s\", \"%s\", \"%s\", \"%s\")", owner, delegate, op, res)
	return m.Guard.AddRule(r)
}

// redelegateResource adds a redelegation statement to the policy for a given
// operation on a resource.
func (m *ResourceMaster) redelegateResource(owner, delegate, op, res string) error {
	r := fmt.Sprintf("Delegate(\"%s\", \"%s\", \"delegate\", \"%s\", \"%s\")", owner, delegate, op, res)
	return m.Guard.AddRule(r)
}

// addResource adds Resource() and Creator() statements for a given resource
// with a given creator.
func (m *ResourceMaster) addResource(creator, resource string) error {
	r := fmt.Sprintf("Resource(\"%s\")", resource)
	if err := m.Guard.AddRule(r); err != nil {
		return err
	}

	c := fmt.Sprintf("Creator(\"%s\", \"%s\")", creator, resource)
	return m.Guard.AddRule(c)
}

// makeQuery formulates the simple Authorized query for a given (subject,
// action, resource) tuple.
func makeQuery(subject string, action string, resource string) string {
	return fmt.Sprintf("Authorized(\"%s\", \"%s\", \"%s\")", subject, action, resource)
}

// checkFileAuth checks the given file operation to see if it is authorized
// according to the Guard in the ResourceMaster.
func (m *ResourceMaster) checkFileAuth(msg *Message, fop *FileOperation) error {
	subject, err := m.certToAuthenticatedName(fop.Subject)
	if err != nil {
		return err
	}

	var action string
	switch *msg.Type {
	case MessageType_CREATE:
		action = "create"
	case MessageType_DELETE:
		action = "delete"
	case MessageType_READ:
		action = "read"
	case MessageType_WRITE:
		action = "write"
	default:
		return fmt.Errorf("invalid action type %d\n", *msg.Type)
	}

	q := makeQuery(subject, action, *fop.Name)
	ok, err := m.Query(q)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("the authorization query '%s' didn't pass verification", q)
	}
	return nil
}

// Query checks the query against the guard to see if it is authorized.
func (m *ResourceMaster) Query(query string) (bool, error) {
	return m.Guard.Query(query)
}

// FindResource looks up the resource by its name.
func (m *ResourceMaster) FindResource(name string) *Resource {
	return m.Resources[name]
}

// InsertResource adds a resource with a given path, name, and owner.
func (m *ResourceMaster) InsertResource(dir string, name string, owner string) *Resource {
	r := m.Resources[name]
	if r != nil {
		// TODO(tmroeder): This should be an error if the two resources
		// differ in some other way. For now, though, we'll return the
		// old resource.
		return r
	}
	r = &Resource{
		Name:     name,
		Type:     File,
		Status:   Created,
		Location: path.Join(dir, name),
		Owner:    owner,
	}
	// TODO(tmroeder): note that this means that there can only be one
	// resource with a given filename, even if the other resource with the
	// same name is in another directory. This could be fixed by making the
	// name of the resource its full path, or using something like struct
	// keys in the map with {dir, name} as the key.
	m.Resources[name] = r
	return r
}

// FindPrincipal looks up a Principal by name
func (m *ResourceMaster) FindPrincipal(name string) *Principal {
	return m.Principals[name]
}

// InsertPrincipal adds a given principal with a given certificate to the set of
// principals. It marks this principal with the given authentication status.
// Note that if a principal already exists with the same name, then it just
// returns that principal and makes no attempt to reconcile to the two
// principals.
func (m *ResourceMaster) InsertPrincipal(name string, cert []byte, authStatus PrincipalStatus) (*Principal, error) {
	p := m.Principals[name]
	if p != nil {
		return p, nil
	}
	x, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}
	p = &Principal{
		Name:    name,
		CertDER: cert,
		Cert:    x,
		Status:  authStatus,
	}
	m.Principals[name] = p
	return p, nil
}

// EncodeMaster encodes information about a ResourceMaster as a protobuf.
func (m *ResourceMaster) EncodeMaster() ([]byte, error) {
	p := &ResourceMasterInfo{
		PrinName:          proto.String(m.ProgramName),
		BaseDirectoryName: proto.String(m.BaseDirectory),
		NumFileInfos:      proto.Int(len(m.Resources)),
	}
	return proto.Marshal(p)
}

// DecodeMaster decodes information about a ResourceMaster from a protobuf.
// TODO(tmroeder): It would be more idiomatic to have this be something like
// NewResourceMaster and take in something to read the protobuf bytes from.
func (m *ResourceMaster) DecodeMaster(in []byte) error {
	var message ResourceMasterInfo
	if err := proto.Unmarshal(in, &message); err != nil {
		return err
	}
	m.ProgramName = *message.PrinName
	m.BaseDirectory = *message.BaseDirectoryName
	return nil
}

// PrintMaster prints the ResourceMaster into the log.
func (m *ResourceMaster) PrintMaster(printResources bool) {
	log.Printf("Program principal: %s\n", m.ProgramName)
	log.Printf("Base Directory: %s\n", m.BaseDirectory)
	log.Printf("%d resources\n", len(m.Resources))
	if printResources {
		for _, r := range m.Resources {
			r.PrintResource()
		}
	}
}

// EncodeResource creates a protobuf that represents a resource.
// TODO(tmroeder): map the types and statuses to protobuf enums properly.
func (r *Resource) EncodeResource() ([]byte, error) {
	m := &ResourceInfo{
		Name:     proto.String(r.Name),
		Type:     proto.Int32(int32(r.Type)),
		Status:   proto.Int32(int32(r.Status)),
		Location: proto.String(r.Location),
		Size:     proto.Int(r.Size),
		Owner:    proto.String(r.Owner),
	}
	return proto.Marshal(m)
}

// DecodeResource fills a resource from the information in a protobuf. Note that
// this would be more idiomatic as a NewResource method that took in a byte
// slice.
func (r *Resource) DecodeResource(in []byte) error {
	var ri ResourceInfo
	if err := proto.Unmarshal(in, &ri); err != nil {
		return err
	}
	r.Name = *ri.Name
	r.Type = ResourceType(*ri.Type)
	r.Status = ResourceStatus(*ri.Status)
	r.Location = *ri.Location
	r.Size = int(*ri.Size)
	r.Owner = *ri.Owner
	return nil
}

// PrintResource prints a resource to the log.
func (r *Resource) PrintResource() {
	log.Printf("Resource name: %s\n", r.Name)
	log.Printf("Resource type: %s\n", r.Type)
	log.Printf("Resource status: %s\n", r.Status)
	log.Printf("Resource location: %s\n", r.Location)
	log.Printf("Resource size: %d\n", r.Size)
	log.Printf("Resource creation date: %s\n", r.DateCreated)
	log.Printf("Resource modified date: %s\n", r.DateModified)
	log.Printf("\n")
}

// EncodePrincipal encodes information about a principal into a protobuf.
func (p *Principal) EncodePrincipal() ([]byte, error) {
	pi := &PrincipalInfo{
		Name:   proto.String(p.Name),
		Cert:   p.CertDER,
		Status: proto.Int32(int32(p.Status)),
	}
	return proto.Marshal(pi)
}

// DecodePrincipal deserializes a principal from a protobuf. Note that this
// would be more idiomatic as a NewPrincipal method that took in a byte slice.
func (p *Principal) DecodePrincipal(in []byte) error {
	var pi PrincipalInfo
	if err := proto.Unmarshal(in, &pi); err != nil {
		return err
	}

	p.Name = *pi.Name
	p.CertDER = pi.Cert
	var err error
	if p.Cert, err = x509.ParseCertificate(p.CertDER); err != nil {
		return err
	}
	p.Status = PrincipalStatus(*pi.Status)
	return nil
}

// PrintPrincipal prints information about a principal to the log.
func (p *Principal) PrintPrincipal() {
	log.Printf("Principal name: %s\n", p.Name)
	log.Printf("Principal status: %s\n", p.Status)
	log.Printf("Principal cert: % x\n", p.CertDER)
	log.Printf("\n")
}

// PrintAllPolicy prints all policy info to the log.
func (m *ResourceMaster) PrintAllPolicy() {
	for i := range m.Policy {
		log.Printf("Rule: %s\n", m.Policy[i])
	}
}

// InitGuard initializes the datalog guard with a rule file.
func (m *ResourceMaster) InitGuard(rf string) error {
	return nil
}

// readResult reads an OperationResult and returns its value or an error.
func readResult(ms *util.MessageStream) (bool, error) {
	// Read the response wrapper message.
	var arm Message
	if err := ms.ReadMessage(&arm); err != nil {
		return false, err
	}
	if *arm.Type != MessageType_OP_RES {
		return false, fmt.Errorf("didn't receive OP_RES from the server")
	}

	var opr OperationResult
	if err := proto.Unmarshal(arm.Data, &opr); err != nil {
		return false, err
	}
	return *opr.Result, nil
}

// sendResult sends an OperationResult with the given value on the given stream.
func sendResult(ms *util.MessageStream, result bool) error {
	res := &OperationResult{Result: proto.Bool(result)}
	ar := &Message{
		Type: MessageType_OP_RES.Enum(),
	}
	var err error
	if ar.Data, err = proto.Marshal(res); err != nil {
		return err
	}

	if _, err := ms.WriteMessage(ar); err != nil {
		return err
	}

	return nil
}

// AuthenticatePrincipal runs a synchronous protocol to authenticate a single
// principal on a single channel. In this toy implementation, it is assumed that
// there are no other principals on the channel and that there are no other
// simultaneous channels.
func (m *ResourceMaster) AuthenticatePrincipal(ms *util.MessageStream, msg *Message, programPolicy *ProgramPolicy) ([]byte, error) {
	// The certificate message is passed in by the caller as the first
	// message.

	// Process the certificate. For AUTH_CERT, the data is just the
	// certificate.
	cert, err := x509.ParseCertificate([]byte(msg.Data))
	if err != nil {
		log.Printf("couldn't Parse Certificate in AuthenticatePrincipal\n")
		return nil, err
	}

	// Set up a nonce challenge for the reply. For NONCE_CHALL, the data is
	// also just the message itself.
	reply := &Message{
		Type: MessageType_NONCE_CHALL.Enum(),
		Data: make([]byte, NonceSize),
	}
	if _, err = rand.Read(reply.Data); err != nil {
		return nil, err
	}

	// Step 1: Send a nonce to the principal.
	if _, err := ms.WriteMessage(reply); err != nil {
		return nil, err
	}

	// Step 2: Wait for the signed response.
	var s Message
	if err := ms.ReadMessage(&s); err != nil {
		return nil, err
	}
	if *s.Type != MessageType_SIGNED_NONCE {
		return nil, fmt.Errorf("received message was not SIGNED_NONCE")
	}

	// Verify the certificate against the root.
	// TODO(tmroeder): move the VerifyOptions up into the ResourceMaster.
	var opts x509.VerifyOptions
	roots := x509.NewCertPool()
	policyCert, err := x509.ParseCertificate(programPolicy.PolicyCert)
	if err != nil || policyCert == nil {
		return nil, err
	}
	roots.AddCert(policyCert)
	opts.Roots = roots
	chains, err := cert.Verify(opts)
	if chains == nil || err != nil {
		return nil, err
	}
	v, err := tao.FromX509(cert)
	if err != nil {
		return nil, err
	}
	ok, err := v.Verify(reply.Data, ChallengeContext, s.Data)
	if err != nil {
		return nil, err
	}

	if err := sendResult(ms, ok); err != nil {
		return nil, fmt.Errorf("failed to return a result to the client")
	}

	if !ok {
		return nil, fmt.Errorf("the nonce signature did not pass verification")
	}

	return msg.Data, nil
}

// Read causes the bytes of the file to be decrypted and read to the message
// stream. By the time this function is called, the remote principal has already
// been authenticated and the operation has already been authorized.
func (m *ResourceMaster) Read(ms *util.MessageStream, fop *FileOperation, key []byte) error {
	ri := m.FindResource(*fop.Name)
	if ri == nil {
		return sendResult(ms, false)
	}
	if err := sendResult(ms, true); err != nil {
		return err
	}
	return SendFile(ms, m.BaseDirectory, *fop.Name, key)
}

// Write causes the bytes of the file to be encrypted and integrity-protected
// and written to disk as they are read from the MessageStream.
func (m *ResourceMaster) Write(ms *util.MessageStream, fop *FileOperation, key []byte) error {
	// Note that a file has be created before it can be written to.
	ri := m.FindResource(*fop.Name)
	if ri == nil {
		return sendResult(ms, false)
	}
	if err := sendResult(ms, true); err != nil {
		return err
	}
	return GetFile(ms, m.BaseDirectory, *fop.Name, key)
}

// Create creates a file in the resource info in the ResourceMaster, but it
// doesn't write any bits to disk about this file.
func (m *ResourceMaster) Create(ms *util.MessageStream, fop *FileOperation) error {
	ri := m.FindResource(*fop.Name)
	if ri != nil {
		// Can't create a file that already exists.
		return sendResult(ms, false)
	}

	owner, err := m.certToAuthenticatedName(fop.Subject)
	if err != nil {
		// Failed to get the name from the cert.
		return sendResult(ms, false)
	}
	ri = m.InsertResource(m.BaseDirectory, *fop.Name, owner)
	if ri == nil {
		// Couldn't insert the resource
		return sendResult(ms, false)
	}
	if err := m.addResource(owner, *fop.Name); err != nil {
		if e := sendResult(ms, false); e != nil {
			return e
		}
		return err
	}

	return sendResult(ms, true)

}

// certToAuthenticatedName looks up a cert in the principals to make sure it's
// known and has been authenticated. If so, it returns the name of this
// principal.
func (m *ResourceMaster) certToAuthenticatedName(cert []byte) (string, error) {
	if len(cert) == 0 {
		return "", fmt.Errorf("couldn't parse a null cert")
	}
	name, err := PrincipalNameFromDERCert(cert)
	if err != nil {
		return "", err
	}
	prin := m.FindPrincipal(name)
	if prin == nil {
		return "", fmt.Errorf("couldn't find principal with name '%s'\n", name)
	}
	if bytes.Equal(prin.CertDER, []byte(name)) {
		return "", fmt.Errorf("invalid principal name")
	}
	return name, nil
}

// RunMessageLoop handles messages from a client on a given message stream until
// it gets an error trying to read a message.
func (m *ResourceMaster) RunMessageLoop(ms *util.MessageStream, programPolicy *ProgramPolicy) error {
	for {
		var msg Message
		if err := ms.ReadMessage(&msg); err != nil {
			return err
		}

		var fop FileOperation
		t := *msg.Type
		if t == MessageType_CREATE || t == MessageType_DELETE || t == MessageType_READ || t == MessageType_WRITE {
			if err := proto.Unmarshal(msg.Data, &fop); err != nil {
				log.Printf("Couldn't unmarshal FileOperation for operation %d\n", t)
				continue
			}

			if err := m.checkFileAuth(&msg, &fop); err != nil {
				log.Printf("The file operation %d didn't pass authorization: %s\n", t, err)
				continue
			}
		}

		switch *msg.Type {
		case MessageType_AUTH_CERT:
			cert, err := m.AuthenticatePrincipal(ms, &msg, programPolicy)
			if err != nil {
				log.Printf("Failed to authenticate a principal: %s\n", err)
				continue
			}

			owner, err := PrincipalNameFromDERCert(cert)
			if err != nil {
				log.Printf("Couldn't get the owner name from the cert: %s\n", err)
				continue
			}
			_, err = m.InsertPrincipal(owner, cert, Authenticated)
			if err != nil {
				log.Printf("Couldn't set the principal as authenticated")
			}
		case MessageType_CREATE:
			if err := m.Create(ms, &fop); err != nil {
				log.Printf("Couldn't create the file %s: %s\n", *fop.Name, err)
			}
		case MessageType_READ:
			if err := m.Read(ms, &fop, programPolicy.SymKeys); err != nil {
				log.Printf("Couldn't create the file %s: %s\n", *fop.Name, err)
			}
		case MessageType_WRITE:
			if err := m.Write(ms, &fop, programPolicy.SymKeys); err != nil {
				log.Printf("Couldn't create the file %s: %s\n", *fop.Name, err)
			}
		default:
			if err := sendResult(ms, false); err != nil {
				log.Printf("Couldn't signal failure for the invalid operation: %s", err)
			}
			log.Printf("Invalid initial message type %d\n", *msg.Type)
		}
	}

	return nil
}

// NewResourceMaster creates a ResourceMaster from the static ruleset and
// initializes it to manage the given directory.
func NewResourceMaster(filepath string) *ResourceMaster {
	m := &ResourceMaster{
		Guard:         tao.NewTemporaryDatalogGuard(),
		BaseDirectory: filepath,
		Resources:     make(map[string]*Resource),
		Principals:    make(map[string]*Principal),
		Policy:        policy, // the global policy value.
	}

	for _, p := range m.Policy {
		if err := m.Guard.AddRule(p); err != nil {
			log.Printf("Couldn't add run '%s': %s\n", p, err)
			return nil
		}
	}
	return m
}

// The following are client methods that can be used to access the
// ResourceMaster.

// recvResult waits for a OperationResult on a MessageStream
func recvResult(ms *util.MessageStream) (bool, error) {
	var m Message
	if err := ms.ReadMessage(&m); err != nil {
		return false, err
	}
	var res OperationResult
	if err := proto.Unmarshal(m.Data, &res); err != nil {
		return false, err
	}

	return *res.Result, nil
}

// wrapResult takes a bool and an error and returns an error if the error is
// non-nil or if the bool is false.
func wrapResult(ok bool, err error) error {
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("the operation failed")
	}
	return nil
}

// sendOperation is a helper method that sets up the data structures needed for
// a FileOperation message like CREATE, WRITE, or READ, and sends this message
// on the MessageStream.
func sendOperation(ms *util.MessageStream, mt MessageType, cert []byte, name string) error {
	fop := &FileOperation{
		Subject: cert,
		Name:    proto.String(name),
	}

	fopb, err := proto.Marshal(fop)
	if err != nil {
		return err
	}
	m := &Message{
		Type: mt.Enum(),
		Data: fopb,
	}

	if _, err := ms.WriteMessage(m); err != nil {
		return err
	}

	return nil
}

// CreateFile creates a file with a given creator and name.
func CreateFile(ms *util.MessageStream, ownerCert []byte, name string) error {
	if err := sendOperation(ms, MessageType_CREATE, ownerCert, name); err != nil {
		return err
	}

	return wrapResult(recvResult(ms))
}

// WriteFile writes a local file, using SendFile without any keys to read the
// file from disk and send it on the MessageStream.
func WriteFile(ms *util.MessageStream, userCert []byte, dir, name string) error {
	if err := sendOperation(ms, MessageType_WRITE, userCert, name); err != nil {
		return err
	}

	if err := wrapResult(recvResult(ms)); err != nil {
		return err
	}

	return SendFile(ms, dir, name, nil)
}

// ReadFile reads a file from the server and writes it to a local file, using
// GetFile without any keys to read the file from the network and write it to
// the disk.
func ReadFile(ms *util.MessageStream, userCert []byte, dir, name, output string) error {
	if err := sendOperation(ms, MessageType_READ, userCert, name); err != nil {
		return err
	}

	if err := wrapResult(recvResult(ms)); err != nil {
		return err
	}

	return GetFile(ms, dir, output, nil)
}

// AuthenticatePrincipal is a client method used to send a request to a
// ResourceMaster to authenticate a principal with a given certificate and a
// given set of keys.
func AuthenticatePrincipal(ms *util.MessageStream, key *tao.Keys, derCert []byte) error {
	// Send the authentication request, which supposes that a server is
	// waiting to receive this request.
	c := &Message{
		Type: MessageType_AUTH_CERT.Enum(),
		Data: derCert,
	}
	if _, err := ms.WriteMessage(c); err != nil {
		return err
	}

	// Receive a challenge nonce from the server.
	var nc Message
	if err := ms.ReadMessage(&nc); err != nil {
		return err
	}
	if *nc.Type != MessageType_NONCE_CHALL {
		return fmt.Errorf("didn't receive NONCE_CHALL from the server")
	}

	// Sign the nonce.
	sn := &Message{
		Type: MessageType_SIGNED_NONCE.Enum(),
	}
	var err error
	if sn.Data, err = key.SigningKey.Sign(nc.Data, ChallengeContext); err != nil {
		return err
	}
	if _, err := ms.WriteMessage(sn); err != nil {
		return err
	}

	// Get the result from the server after verificaton.
	res, err := readResult(ms)
	if err != nil {
		return err
	}

	if !res {
		return fmt.Errorf("the signed nonce failed verification")
	}
	return nil
}
