// Copyright (c) 2016, Google Inc.  All rights reserved.
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
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strconv"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

// A VmConfig contains the details needed to start a new custom VM.
type VmConfig struct {
	Name        string
	KernelPath  string
	InitRamPath string
	DiskPath    string
	Memory      int
	// The socket on the host that will be connected to virtio-serial on the guest.
	// This is used for stacked CP hosts on the VM to connect to the host CP.
	SocketPath string
	// The port on the host that will be forwarded to port 22 on the guest for SSH.
	Port string
}

// A KvmCustomContainer represents a hosted program running as a VM on
// KVM. It uses os/exec.Cmd to send commands to QEMU/KVM to start the VM.
// This use of os/exec is to avoid having to rewrite or hook into
// libvirt for now.
type KvmCustomContainer struct {

	// The spec from which this vm was created.
	spec HostedProgramSpec

	// Hash of the kernel image.
	KernelHash []byte

	// Hash fo the InitRam image.
	InitRamHash []byte

	// The factory responsible for the vm.
	Factory *LinuxKVMCustomFactory

	// Configuration details for VM, mostly obtained from the factory.
	// TODO(kwalsh) what is a good description for this?
	Cfg *VmConfig

	// The underlying vm process.
	QCmd *exec.Cmd

	// A channel to be signaled when the vm is done.
	Done chan bool
}

// WaitChan returns a chan that will be signaled when the hosted vm is done.
func (kcc *KvmCustomContainer) WaitChan() <-chan bool {
	return kcc.Done
}

// Kill sends a SIGKILL signal to a QEMU instance.
func (kcc *KvmCustomContainer) Kill() error {
	// Kill the qemu command directly.
	// TODO(tmroeder): rewrite this using qemu's communication/management
	// system; sending SIGKILL is definitely not the right way to do this.
	return kcc.QCmd.Process.Kill()
}

// Start starts a QEMU/KVM CoreOS container using the command line.
func (kcc *KvmCustomContainer) startVM() error {

	cfg := kcc.Cfg
	qemuProg := "qemu-system-x86_64"
	qemuArgs := []string{"-name", cfg.Name,
		"-m", strconv.Itoa(cfg.Memory),
		// Networking.
		"-net", "nic,vlan=0,model=virtio",
		"-net", "user,vlan=0,hostfwd=tcp::" + kcc.spec.Args[2] + "-:22,hostname=" + cfg.Name,
		// Tao communications through virtio-serial. With this
		// configuration, QEMU waits for a server on cfg.SocketPath,
		// then connects to it.
		"-chardev", "socket,path=" + cfg.SocketPath + ",id=port0-char",
		"-device", "virtio-serial",
		"-device", "virtserialport,id=port1,name=tao,chardev=port0-char",
		// The kernel and initram image to boot from.
		"-kernel", cfg.KernelPath,
		"-initrd", cfg.InitRamPath,
	}

	kcc.QCmd = exec.Command(qemuProg, qemuArgs...)
	kcc.QCmd.Stdin = os.Stdin
	kcc.QCmd.Stdout = os.Stdout
	kcc.QCmd.Stderr = os.Stderr
	// TODO(kwalsh) set up env, dir, and uid/gid.
	return kcc.QCmd.Start()
}

// Stop sends a SIGSTOP signal to a docker container.
func (kcc *KvmCustomContainer) Stop() error {
	// Stop the QEMU/KVM process with SIGSTOP.
	// TODO(tmroeder): rewrite this using qemu's communication/management
	// system; sending SIGSTOP is definitely not the right way to do this.
	return kcc.QCmd.Process.Signal(syscall.SIGSTOP)
}

// Pid returns a numeric ID for this container.
func (kcc *KvmCustomContainer) Pid() int {
	return kcc.QCmd.Process.Pid
}

// ExitStatus returns an exit code for the container.
func (kcc *KvmCustomContainer) ExitStatus() (int, error) {
	s := kcc.QCmd.ProcessState
	if s == nil {
		return -1, fmt.Errorf("Child has not exited")
	}
	if code, ok := (*s).Sys().(syscall.WaitStatus); ok {
		return int(code), nil
	}
	return -1, fmt.Errorf("Couldn't get exit status\n")
}

// A LinuxKVMCustomFactory manages hosted programs started as QEMU/KVM instances.
type LinuxKVMCustomFactory struct {
	Cfg *VmConfig
}

// NewLinuxKVMCustomFactory returns a new HostedProgramFactory that can
// create docker containers to wrap programs.
func NewLinuxKVMCustomFactory(cfg *VmConfig) HostedProgramFactory {
	return &LinuxKVMCustomFactory{
		Cfg: cfg,
	}
}

// MakeSubprin computes the hash of a QEMU/KVM CoreOS image to get a
// subprincipal for authorization purposes.
func (lkcf *LinuxKVMCustomFactory) NewHostedProgram(spec HostedProgramSpec) (child HostedProgram, err error) {
	// TODO(tmroeder): the combination of TeeReader and ReadAll doesn't seem
	// to copy the entire image, so we're going to hash in place for now.
	// This needs to be fixed to copy the image so we can avoid a TOCTTOU
	// attack.

	// The spec args must contain the kernel and initram paths as well as the port to use for SSH.
	if len(spec.Args) != 3 {
		glog.Errorf("Expected %d args, but got %d", 3, len(spec.Args))
		for i, a := range spec.Args {
			glog.Errorf("Arg %d: %s", i, a)
		}
		err = errors.New("KVM Custom guest Tao requires args: <kernel image> <initram image> <SSH port>")
		return
	}

	b, err := ioutil.ReadFile(spec.Args[0])
	if err != nil {
		return
	}
	h1 := sha256.Sum256(b)

	b, err = ioutil.ReadFile(spec.Args[1])
	if err != nil {
		return
	}
	h2 := sha256.Sum256(b)

	sockName := getRandomFileName(nameLen)
	sockPath := path.Join(lkcf.Cfg.SocketPath, sockName)

	cfg := VmConfig{
		Name:        getRandomFileName(nameLen),
		KernelPath:  spec.Args[0],
		InitRamPath: spec.Args[1],
		Memory:      lkcf.Cfg.Memory,
		SocketPath:  sockPath,
		Port:        spec.Args[2],
	}

	child = &KvmCustomContainer{
		spec:        spec,
		KernelHash:  h1[:],
		InitRamHash: h2[:],
		Factory:     lkcf,
		Done:        make(chan bool, 1),
		Cfg:         &cfg,
	}
	return
}

// Subprin returns the subprincipal representing the hosted vm.
func (kcc *KvmCustomContainer) Subprin() auth.SubPrin {
	subprin := FormatCustomVmSubprin(kcc.spec.Id, kcc.KernelHash, kcc.InitRamHash)
	return subprin
}

// FormatCustomVmSubprin produces a subprincipal with the given ID and hash.
func FormatCustomVmSubprin(id uint, kernelHash []byte, initramHash []byte) auth.SubPrin {
	var args []auth.Term
	if id != 0 {
		args = append(args, auth.Int(id))
	}
	args = append(args, auth.Bytes(kernelHash), auth.Bytes(initramHash))
	return auth.SubPrin{auth.PrinExt{Name: "CustomVM", Arg: args}}
}

// Spec returns the specification used to start the hosted vm.
func (kcc *KvmCustomContainer) Spec() HostedProgramSpec {
	return kcc.spec
}

// Start launches a QEMU/KVM CoreOS instance, connects to it with SSH to start
// the LinuxHost on it, and returns the socket connection to that host.
func (kcc *KvmCustomContainer) Start() (channel io.ReadWriteCloser, err error) {

	// Create the listening server before starting the connection. This lets
	// QEMU start right away. See the comments in Start, above, for why this
	// is.
	channel = util.NewUnixSingleReadWriteCloser(kcc.Cfg.SocketPath)
	defer func() {
		if err != nil {
			channel.Close()
			channel = nil
		}
	}()
	if err = kcc.startVM(); err != nil {
		return
	}
	// TODO(kwalsh) reap and cleanup when vm dies; see linux_process_factory.go

	// We need some way to wait for the socket to open before we can connect
	// to it and return the ReadWriteCloser for communication.
	tc := time.After(10 * time.Second)
	glog.Info("Waiting for at most 10 seconds before returning channel")
	<-tc

	return
}

func (kcc *KvmCustomContainer) Cleanup() error {
	// TODO(kwalsh) maybe also kill vm if still running?
	return nil
}
