// Copyright (c) 2014, Google Inc.  All rights reserved.
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
	"errors"
	"io"
	"io/ioutil"
	"path"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

// A LinuxHost is a Tao host environment in which hosted programs are Linux
// processes. A Unix domain socket accepts administrative commands for
// controlling the host, e.g., for starting hosted processes, stopping hosted
// processes, or shutting down the host. A LinuxTao can be run in stacked mode
// (on top of a host Tao) or in root mode (without an underlying host Tao).
type LinuxHost struct {
	Host               Host
	path               string
	guard              Guard
	childFactory       HostedProgramFactory
	hostedPrograms     []*LinuxHostChild
	hpm                sync.RWMutex
	nextChildID        uint
	idm                sync.Mutex
	saveTableThreshold int
	sealsSinceSave     int
	rbTable            *RollbackCounterTable
	rbdm               sync.Mutex
}

// NewStackedLinuxHost creates a new LinuxHost as a hosted program of an existing
// host Tao.
func NewStackedLinuxHost(path string, guard Guard, hostTao Tao, childFactory HostedProgramFactory) (*LinuxHost, error) {
	lh := &LinuxHost{
		path:         path,
		guard:        guard,
		childFactory: childFactory,
	}

	if err := hostTao.ExtendTaoName(guard.Subprincipal()); err != nil {
		return nil, err
	}

	k, err := NewOnDiskTaoSealedKeys(Signing|Crypting|Deriving, hostTao, path, SealPolicyDefault)
	if err != nil {
		return nil, err
	}

	lh.Host, err = NewTaoStackedHostFromKeys(k, hostTao)
	if err != nil {
		return nil, err
	}

	return lh, nil
}

// NewRootLinuxHost creates a new LinuxHost as a standalone Host that can
// provide the Tao to hosted Linux processes.
func NewRootLinuxHost(path string, guard Guard, password []byte, childFactory HostedProgramFactory) (*LinuxHost, error) {
	lh := &LinuxHost{
		guard:        guard,
		childFactory: childFactory,
	}
	k, err := NewOnDiskPBEKeys(Signing|Crypting|Deriving, password, path, nil)
	if err != nil {
		return nil, err
	}

	rootHost, err := NewTaoRootHostFromKeys(k)
	if err != nil {
		return nil, err
	}
	rootHost.taoHostName = rootHost.taoHostName.MakeSubprincipal(guard.Subprincipal())

	lh.Host = rootHost

	return lh, nil
}

// LinuxHostChild holds state associated with a running child program.
// TODO(kwalsh) Nothing in this is linux specific. Move channel and ChildSubprin
// into (getter methods of) interface HostedProgram and eliminate this struct?
// Also merge channel cleanup into HostedProgram.Cleanup()
type LinuxHostChild struct {
	channel      io.ReadWriteCloser
	ChildSubprin auth.SubPrin
	Cmd          HostedProgram
}

// GetTaoName returns the Tao name for the child.
func (lh *LinuxHost) GetTaoName(child *LinuxHostChild) auth.Prin {
	return lh.Host.HostName().MakeSubprincipal(child.ChildSubprin)
}

// ExtendTaoName irreversibly extends the Tao principal name of the child.
func (lh *LinuxHost) ExtendTaoName(child *LinuxHostChild, ext auth.SubPrin) error {
	child.ChildSubprin = append(child.ChildSubprin, ext...)
	return nil
}

// GetRandomBytes returns a slice of n random bytes for the child.
func (lh *LinuxHost) GetRandomBytes(child *LinuxHostChild, n int) ([]byte, error) {
	return lh.Host.GetRandomBytes(child.ChildSubprin, n)
}

// GetSharedSecret returns a slice of n secret bytes for the child.
func (lh *LinuxHost) GetSharedSecret(child *LinuxHostChild, n int, policy string) ([]byte, error) {
	// Compute a tag based on the policy identifier and the child's subprin.
	var tag string
	switch policy {
	case SharedSecretPolicyDefault, SharedSecretPolicyConservative:
		// We are using a master key-deriving key shared among all
		// similar LinuxHost instances. For LinuxHost, the default
		// and conservative policies means any process running the same
		// program binary as the caller hosted on a similar
		// LinuxHost.
		// TODO(kwalsh) conservative policy could include PID or other
		// child info.
		tag = policy + "|" + child.ChildSubprin.String()
	case SharedSecretPolicyLiberal:
		// The most liberal we can do is allow any hosted process
		// running on a similar LinuxHost instance.
		tag = policy
	default:
		return nil, newError("policy not supported for GetSharedSecret: " + policy)
	}
	return lh.Host.GetSharedSecret(tag, n)
}

// Seal encrypts data for the child. This call also zeroes the data parameter.
func (lh *LinuxHost) Seal(child *LinuxHostChild, data []byte, policy string) ([]byte, error) {
	defer ZeroBytes(data)
	lhsb := &LinuxHostSealedBundle{
		Policy: proto.String(policy),
		Data:   data,
	}

	switch policy {
	case SharedSecretPolicyDefault, SharedSecretPolicyConservative:
		// We are using a master key-deriving key shared among all
		// similar LinuxHost instances. For LinuxHost, the default
		// and conservative policies means any process running the same
		// program binary as the caller hosted on a similar
		// LinuxHost.
		lhsb.PolicyInfo = proto.String(child.ChildSubprin.String())
	case SharedSecretPolicyLiberal:
		// The most liberal we can do is allow any hosted process
		// running on a similar LinuxHost instance. So, we don't set
		// any policy info.
	default:
		// Try to parse this statement as a tao/auth policy. If it
		// parses, then use it as the policy statement.
		return nil, newError("policy not supported for Seal: " + policy)
	}

	m, err := proto.Marshal(lhsb)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(m)

	return lh.Host.Encrypt(m)
}

// Unseal decrypts data for the child, but only if the policy is satisfied.
func (lh *LinuxHost) Unseal(child *LinuxHostChild, sealed []byte) ([]byte, string, error) {
	decrypted, err := lh.Host.Decrypt(sealed)
	if err != nil {
		return nil, "", err
	}
	defer ZeroBytes(decrypted)

	var lhsb LinuxHostSealedBundle
	if err := proto.Unmarshal(decrypted, &lhsb); err != nil {
		return nil, "", err
	}

	if lhsb.Policy == nil {
		return nil, "", newError("invalid policy in sealed data")
	}

	policy := *lhsb.Policy
	switch policy {
	case SharedSecretPolicyConservative, SharedSecretPolicyDefault:
		if lhsb.PolicyInfo == nil || child.ChildSubprin.String() != *lhsb.PolicyInfo {
			return nil, "", newError("principal not authorized for unseal")
		}
	case SharedSecretPolicyLiberal:
		// Allow all
		break
	default:
		return nil, "", newError("policy not supported for Unseal: " + policy)
	}
	return lhsb.Data, policy, nil
}

// Attest signs a statement on behalf of the child.
func (lh *LinuxHost) Attest(child *LinuxHostChild, issuer *auth.Prin, time, expiration *int64, stmt auth.Form) (*Attestation, error) {
	return lh.Host.Attest(child.ChildSubprin, issuer, time, expiration, stmt)
}

// StartHostedProgram starts a new hosted program.
func (lh *LinuxHost) StartHostedProgram(spec HostedProgramSpec) (auth.SubPrin, int, error) {
	lh.idm.Lock()
	id := lh.nextChildID
	if lh.nextChildID != 0 {
		lh.nextChildID++
	}
	lh.idm.Unlock()

	spec.Id = id

	prog, err := lh.childFactory.NewHostedProgram(spec)
	if err != nil {
		return auth.SubPrin{}, 0, err
	}

	// We allow multiple hosted programs with the same subprincipal name,
	// so we don't check here to make sure that there isn't another program
	// with the same subprincipal.

	// TODO(tmroeder): do we want to support concurrent updates to policy?
	// Then we need a lock here, too.
	hostName := lh.Host.HostName()
	subprin := prog.Subprin()
	childName := hostName.MakeSubprincipal(subprin)
	if !lh.guard.IsAuthorized(childName, "Execute", []string{}) {
		return auth.SubPrin{}, 0, newError("Hosted program %s denied authorization to execute on host %s", subprin, hostName)
	}

	channel, err := prog.Start()
	if err != nil {
		return auth.SubPrin{}, 0, err
	}
	child := &LinuxHostChild{channel, subprin, prog}
	glog.Infof("Started hosted program with pid %d ...\n  path: %s\n  subprincipal: %s\n", child.Cmd.Pid(), spec.Path, subprin)

	go NewLinuxHostTaoServer(lh, child).Serve(channel)
	pid := child.Cmd.Pid()

	lh.hpm.Lock()
	lh.hostedPrograms = append(lh.hostedPrograms, child)
	lh.hpm.Unlock()

	go func() {
		<-child.Cmd.WaitChan()
		glog.Infof("Hosted program with pid %d exited", child.Cmd.Pid())
		lh.hpm.Lock()
		for i, lph := range lh.hostedPrograms {
			if child == lph {
				var empty []*LinuxHostChild
				lh.hostedPrograms = append(append(empty, lh.hostedPrograms[:i]...), lh.hostedPrograms[i+1:]...)
				break
			}
		}
		lh.hpm.Unlock()
	}()

	return subprin, pid, nil
}

// StopHostedProgram stops a running hosted program.
func (lh *LinuxHost) StopHostedProgram(subprin auth.SubPrin) error {
	lh.hpm.Lock()
	defer lh.hpm.Unlock()
	for _, lph := range lh.hostedPrograms {
		if lph.ChildSubprin.Identical(subprin) {
			lph.channel.Close()
			if err := lph.Cmd.Stop(); err != nil {
				glog.Errorf("Couldn't stop hosted program %d, subprincipal %s: %s\n", lph.Cmd.Pid(), subprin, err)
			}
		}
	}
	return nil
}

// ListHostedPrograms returns a list of running hosted programs.
func (lh *LinuxHost) ListHostedPrograms() ([]auth.SubPrin, []int, error) {
	lh.hpm.RLock()
	subprins := make([]auth.SubPrin, len(lh.hostedPrograms))
	pids := make([]int, len(lh.hostedPrograms))
	for i, v := range lh.hostedPrograms {
		subprins[i] = v.ChildSubprin
		pids[i] = v.Cmd.Pid()
	}
	lh.hpm.RUnlock()
	return subprins, pids, nil
}

// WaitHostedProgram waits for a running hosted program to exit.
func (lh *LinuxHost) WaitHostedProgram(pid int, subprin auth.SubPrin) (int, error) {
	lh.hpm.Lock()
	var p *LinuxHostChild
	for _, lph := range lh.hostedPrograms {
		if lph.Cmd.Pid() == pid && lph.ChildSubprin.Identical(subprin) {
			p = lph
			break
		}
	}
	lh.hpm.Unlock()
	if p == nil {
		return -1, newError("no such hosted program")
	}
	<-p.Cmd.WaitChan()
	return p.Cmd.ExitStatus()
}

// KillHostedProgram kills a running hosted program.
func (lh *LinuxHost) KillHostedProgram(subprin auth.SubPrin) error {
	lh.hpm.Lock()
	defer lh.hpm.Unlock()
	for _, lph := range lh.hostedPrograms {
		if lph.ChildSubprin.Identical(subprin) {
			lph.channel.Close()
			if err := lph.Cmd.Kill(); err != nil {
				glog.Errorf("Couldn't kill hosted program %d, subprincipal %s: %s\n", lph.Cmd.Pid(), subprin, err)
			}
		}
	}
	return nil
}

// HostName returns the name of the Host used by the LinuxHost.
func (lh *LinuxHost) HostName() auth.Prin {
	return lh.Host.HostName()
}

// Shutdown stops all hosted programs. If any remain after 10 seconds, they are
// killed.
func (lh *LinuxHost) Shutdown() error {
	glog.Infof("Stopping all hosted programs")
	lh.hpm.Lock()
	// Request each child stop
	for _, lph := range lh.hostedPrograms {
		// lph.channel.Close()
		glog.Infof("Stopping hosted program %d\n", lph.Cmd.Pid())
		if err := lph.Cmd.Stop(); err != nil {
			glog.Errorf("Couldn't stop hosted program %d, subprincipal %s: %s\n", lph.Cmd.Pid(), lph.Cmd.Subprin(), err)
		}
	}
	timeout := make(chan bool, 1)
	waiting := make(chan bool, 1)
	go func() {
		time.Sleep(1 * time.Second)
		waiting <- true
		time.Sleep(9 * time.Second)
		timeout <- true
		close(timeout)
	}()
	// If timeout expires before child is done, kill child
	for _, lph := range lh.hostedPrograms {
	childWaitLoop:
		for {
			select {
			case <-lph.Cmd.WaitChan():
				break childWaitLoop
			case <-waiting:
				glog.Infof("Waiting for hosted programs to stop")
			case <-timeout:
				glog.Infof("Killing hosted program %d, subprincipal %s\n", lph.Cmd.Pid(), lph.Cmd.Subprin())
				if err := lph.Cmd.Kill(); err != nil {
					glog.Errorf("Couldn't kill hosted program %d, subprincipal %s: %s\n", lph.Cmd.Pid(), lph.Cmd.Subprin(), err)
				}
				break childWaitLoop
			}
		}
	}
	// Reap all children
	for _, lph := range lh.hostedPrograms {
		<-lph.Cmd.WaitChan()
	}
	lh.hostedPrograms = nil
	lh.hpm.Unlock()
	return nil
}

// InitCounter initializes the child's counter for the given label.
// If label is empty string, just read in the table
func (lh *LinuxHost) InitCounter(child *LinuxHostChild, label string, c int64) error {
	sealedRollbackKeysFile := path.Join(lh.path, "SealedRollbackTableKeys.bin")
	encryptedRollbackTableFile := path.Join(lh.path, "EncryptedRollbackTable.bin")

	// Initialize counter, if not already set.
	if lh.rbTable == nil {
		// Read rollback protected sealed keys
		sealedKeys, err := ioutil.ReadFile(sealedRollbackKeysFile)
		if err == nil {
			// Stacked host will have a hostTao
			// reflect.TypeOf(lh.Host).String() == "*tao.StackedHost"
			// Unseal table keys
			tableKeys, _, err := lh.Host.RollbackProtectedUnseal(sealedKeys)
			if err == nil {
				// Init rollback table
				lh.rbTable = ReadRollbackTable(encryptedRollbackTableFile, tableKeys)
				if label == "" {
					// Init was called just to read table
					return nil
				}
			}
		}
	}
	if lh.rbTable == nil {
		lh.rbTable = new(RollbackCounterTable)
	}
	if label == "" {
		return nil
	}
	lh.rbdm.Lock()
	programName := lh.Host.HostName().MakeSubprincipal(child.ChildSubprin).String()
	e := lh.rbTable.LookupRollbackEntry(programName, label)
	lh.rbdm.Unlock()
	if e == nil || e.Counter == nil || *e.Counter <= c {
		lh.rbdm.Lock()
		_ = lh.rbTable.UpdateRollbackEntry(programName, label, &c)
		lh.rbdm.Unlock()
	}
	return nil
}

// GetCounter gets the child's counter for the given label.
func (lh *LinuxHost) GetCounter(child *LinuxHostChild, label string) (int64, error) {
	programName := lh.Host.HostName().MakeSubprincipal(child.ChildSubprin).String()
	if lh.rbTable == nil {
		err := lh.InitCounter(child, "", int64(0))
		if err != nil {
			return int64(0), errors.New("Counter not initialized")
		}
	}
	lh.rbdm.Lock()
	e := lh.rbTable.LookupRollbackEntry(programName, label)
	lh.rbdm.Unlock()
	if e == nil || e.Counter == nil {
		return int64(0), errors.New("No such counter")
	}
	return *e.Counter, nil
}

// RollbackProtectedSeal seals the data associated with the given label with rollback protection.
func (lh *LinuxHost) RollbackProtectedSeal(child *LinuxHostChild, label string, data []byte, policy string) ([]byte, error) {
	programName := lh.Host.HostName().MakeSubprincipal(child.ChildSubprin).String()
	c, err := lh.GetCounter(child, label)
	if err != nil {
		return nil, errors.New("Can't get current counter")
	}
	c = c + 1
	e := lh.rbTable.UpdateRollbackEntry(programName, label, &c)
	if e == nil {
		return nil, errors.New("Can't update rollback entry")
	}

	sd := new(RollbackSealedData)
	sd.Entry = new(RollbackEntry)
	sd.Entry.HostedProgramName = &programName
	sd.Entry.EntryLabel = &label
	sd.Entry.Counter = &c
	sd.ProtectedData = data
	toSeal, err := proto.Marshal(sd)
	if err != nil {
		return nil, errors.New("Can't marshal rollback data")
	}
	sealed, err := lh.Seal(child, toSeal, policy)
	if err != nil {
		return nil, errors.New("Can't seal rollback data")
	}

	// TODO(jlm): Should be initialized from domain.
	lh.saveTableThreshold = 1
	lh.sealsSinceSave = lh.sealsSinceSave + 1

	// Encrypt and save rollback table if necessary
	if lh.rbTable != nil && lh.sealsSinceSave >= lh.saveTableThreshold {
		sealedRollbackKeysFile := path.Join(lh.path, "SealedRollbackTableKeys.bin")
		encryptedRollbackTableFile := path.Join(lh.path, "EncryptedRollbackTable.bin")
		ok := lh.rbTable.SaveHostRollbackTableWithNewKeys(lh, child, sealedRollbackKeysFile, encryptedRollbackTableFile)
		if ok {
			lh.sealsSinceSave = 0
		}
	}
	return sealed, nil
}

// RollbackProtectedUnseal unseals the data associated with the given label with rollback protection.
func (lh *LinuxHost) RollbackProtectedUnseal(child *LinuxHostChild, sealed []byte) ([]byte, string, error) {
	b, policy, err := lh.Unseal(child, sealed)
	if err != nil {
		return nil, "", errors.New("RollbackProtectedUnseal can't unseal")
	}
	var sd RollbackSealedData
	err = proto.Unmarshal(b, &sd)
	if err != nil {
		return nil, "", errors.New("RollbackProtectedUnseal can't Unmarshal")
	}
	if sd.Entry == nil || sd.Entry.EntryLabel == nil {
		return nil, "", errors.New("RollbackProtectedUnseal bad entry")
	}
	c, err := lh.GetCounter(child, *sd.Entry.EntryLabel)
	if err != nil {
		return nil, "", errors.New("RollbackProtectedUnseal: Can't get counter")
	}
	if *sd.Entry.Counter != c {
		return nil, "", errors.New("RollbackProtectedUnseal bad counter")
	}

	return sd.ProtectedData, policy, nil
}
