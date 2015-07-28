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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strings"
	"syscall"

	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

// A LinuxProcessFactory supports methods for creating Linux processes as
// hosted programs. LinuxProcessFactory implements HostedProgramFactory.
type LinuxProcessFactory struct {
	channelType string
	socketPath  string
}

// NewLinuxProcessFactory returns a new HostedProgramFactory that can create
// linux processes.
func NewLinuxProcessFactory(channelType, socketPath string) HostedProgramFactory {
	return &LinuxProcessFactory{
		channelType: channelType,
		socketPath:  socketPath,
	}
}

// A LinuxProcess represents a hosted program that executes as a linux process.
type HostedProcess struct {

	// The spec from which this process was created.
	spec HostedProgramSpec

	// A secured, private copy of the executable.
	Temppath string

	// A temporary directory for storing the temporary executable.
	Tempdir string

	// Hash of the executable.
	Hash []byte

	// The underlying process.
	Cmd exec.Cmd

	// The factory responsible for the hosted process.
	Factory *LinuxProcessFactory

	// A channel to be signaled when the process is done.
	Done chan bool
}

// NewHostedProgram initializes, but does not start, a hosted process.
func (lpf *LinuxProcessFactory) NewHostedProgram(spec HostedProgramSpec) (child HostedProgram, err error) {

	// To avoid a time-of-check-to-time-of-use error, we copy the file
	// bytes to a temp file as we read them. This temp-file path is
	// returned so it can be used to start the program.
	tempdir, err := ioutil.TempDir("/tmp", "cloudproxy_linux_host")
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			os.RemoveAll(tempdir)
		}
	}()
	if err = os.Chmod(tempdir, 0755); err != nil {
		return
	}

	temppath := path.Join(tempdir, "hosted_program")
	tf, err := os.OpenFile(temppath, os.O_CREATE|os.O_RDWR, 0700)
	defer tf.Close()
	if err != nil {
		return
	}
	if err = tf.Chmod(0755); err != nil {
		return
	}

	inf, err := os.Open(spec.Path)
	defer inf.Close()
	if err != nil {
		return
	}

	// Read from the input file and write to the temp file.
	tr := io.TeeReader(inf, tf)
	b, err := ioutil.ReadAll(tr)
	if err != nil {
		return
	}

	h := sha256.Sum256(b)

	child = &HostedProcess{
		spec:     spec,
		Temppath: temppath,
		Tempdir:  tempdir,
		Hash:     h[:],
		Factory:  lpf,
		Done:     make(chan bool, 1),
	}
	return
}

// Use 24 bytes for the socket name.
const sockNameLen = 24

// Start starts the the hosted process and returns a tao channel to it.
func (p *HostedProcess) Start() (channel io.ReadWriteCloser, err error) {
	var extraFiles []*os.File
	var evar string
	switch p.Factory.channelType {
	case "pipe":
		// Get a pipe pair for communication with the child.
		var serverRead, clientRead, serverWrite, clientWrite *os.File
		serverRead, clientWrite, err = os.Pipe()
		if err != nil {
			return
		}
		defer clientWrite.Close()

		clientRead, serverWrite, err = os.Pipe()
		if err != nil {
			serverRead.Close()
			return
		}
		defer clientRead.Close()

		channel = util.NewPairReadWriteCloser(serverRead, serverWrite)
		extraFiles = []*os.File{clientRead, clientWrite} // fd 3, fd 4

		// Note: ExtraFiles below ensures readfd=3, writefd=4 in child
		evar = HostSpecEnvVar + "=tao::RPC+tao::FDMessageChannel(3, 4)"
	case "unix":
		// Get a random name for the socket.
		nameBytes := make([]byte, sockNameLen)
		if _, err = rand.Read(nameBytes); err != nil {
			return
		}
		sockName := base64.URLEncoding.EncodeToString(nameBytes)
		sockPath := path.Join(p.Factory.socketPath, sockName)
		channel = util.NewUnixSingleReadWriteCloser(sockPath)
		if channel == nil {
			err = fmt.Errorf("Couldn't create a new Unix channel\n")
			return
		}
		evar = HostSpecEnvVar + "=" + sockPath
	default:
		err = fmt.Errorf("invalid channel type '%s'\n", p.Factory.channelType)
		return
	}
	defer func() {
		if err != nil {
			channel.Close()
			channel = nil
		}
	}()

	stdin, stdout, stderr, extraFds := util.NewStdio(p.spec.Fds)
	extraFiles = append(extraFiles, extraFds...)

	env := p.spec.Env
	if env == nil {
		env = os.Environ()
	}
	// Make sure that the child knows to use the right kind of channel.
	etvar := HostChannelTypeEnvVar + "=" + p.Factory.channelType
	replaced := false
	replacedType := false
	for i, pair := range env {
		if strings.HasPrefix(pair, HostSpecEnvVar+"=") {
			env[i] = evar
			replaced = true
		}

		if strings.HasPrefix(pair, HostChannelTypeEnvVar+"=") {
			env[i] = etvar
			replacedType = true
		}
	}
	if !replaced {
		env = append(env, evar)
	}

	if !replacedType {
		env = append(env, etvar)
	}

	if (p.spec.Uid == 0 || p.spec.Gid == 0) && !p.spec.Superuser {
		err = fmt.Errorf("Uid and Gid must be nonzero unless Superuser is set\n")
		return
	}

	spa := &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(p.spec.Uid),
			Gid: uint32(p.spec.Uid),
		},
	}
	p.Cmd = exec.Cmd{
		Path:        p.Temppath,
		Dir:         p.Tempdir,
		Args:        p.spec.Args,
		Stdin:       stdin,
		Stdout:      stdout,
		Stderr:      stderr,
		Env:         env,
		ExtraFiles:  extraFiles,
		SysProcAttr: spa,
	}

	if err = p.Cmd.Start(); err != nil {
		return
	}

	// Reap the child when the process dies.
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGCHLD)
	go func() {
		<-sc
		p.Cmd.Wait()
		signal.Stop(sc)
		os.RemoveAll(p.Tempdir)
		p.Done <- true
		close(p.Done) // prevent any more blocking
	}()

	// TODO(kwalsh) put channel into p, remove the struct in linux_host.go

	return
}

// WaitChan returns a chan that will be signaled when the hosted process is
// done.
func (p *HostedProcess) WaitChan() <-chan bool {
	return p.Done
}

// Kill kills an os/exec.Cmd process.
func (p *HostedProcess) Kill() error {
	return p.Cmd.Process.Kill()
}

const sigterm = 15

// Stop tries to send SIGTERM to a process.
func (p *HostedProcess) Stop() error {
	return syscall.Kill(p.Cmd.Process.Pid, syscall.Signal(sigterm))
}

// Spec returns the specification used to start the hosted process.
func (p *HostedProcess) Spec() HostedProgramSpec {
	return p.spec
}

// ID returns the PID of the underlying os/exec.Cmd instance.
func (p *HostedProcess) ID() int {
	return p.Cmd.Process.Pid
}

// Subprin returns the subprincipal representing the hosted process.
func (p *HostedProcess) Subprin() auth.SubPrin {
	return FormatProcessSubprin(p.spec.Id, p.Hash)
}

// FormatProcessSubprin produces a string that represents a subprincipal with
// the given ID and hash.
func FormatProcessSubprin(id uint, hash []byte) auth.SubPrin {
	var args []auth.Term
	if id != 0 {
		args = append(args, auth.Int(id))
	}
	args = append(args, auth.Bytes(hash))
	return auth.SubPrin{auth.PrinExt{Name: "Program", Arg: args}}
}

func (p *HostedProcess) Cleanup() error {
	// TODO(kwalsh) close channel, maybe also kill process if still running?
	os.RemoveAll(p.Tempdir)
	return nil
}
