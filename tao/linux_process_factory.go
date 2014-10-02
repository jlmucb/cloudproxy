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
	"crypto/sha256"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"

	"github.com/jlmucb/cloudproxy/tao/auth"
	"github.com/jlmucb/cloudproxy/util"
)

// A Process wraps os/exec.Cmd and adds a Kill method to match the HostedProgram
// interface.
type Process struct {
	*exec.Cmd
}

// Kill kills an os/exec.Cmd process.
func (p *Process) Kill() error {
	return p.Process.Kill()
}

const sigterm = 15

// Stop tries to send SIGTERM to a process.
func (p *Process) Stop() error {
	return syscall.Kill(p.Process.Pid, syscall.Signal(sigterm))
}

// ID returns the PID of the underlying os/exec.Cmd instance.
func (p *Process) ID() int {
	return p.Process.Pid
}

// A LinuxProcessFactory supports methods for creating Linux processes as
// hosted programs. LinuxProcessFactory implements HostedProgramFactory.
type LinuxProcessFactory struct{}

// FormatSubprin produces a string that represents a subprincipal with the given
// ID and hash.
func FormatSubprin(id uint, hash []byte) auth.SubPrin {
	var args []auth.Term
	if id != 0 {
		args = append(args, auth.Int(id))
	}
	args = append(args, auth.Bytes(hash))
	return auth.SubPrin{auth.PrinExt{Name: "Program", Arg: args}}
}

// MakeHostedProgramSubprin computes the hash of a program to get its
// hosted-program subprincipal. In the process, it copies the program to a
// temporary file controlled by this code and returns the path to that new
// binary.
func (lpf *LinuxProcessFactory) MakeSubprin(id uint, prog string) (subprin auth.SubPrin, temppath string, err error) {
	// To avoid a time-of-check-to-time-of-use error, we copy the file
	// bytes to a temp file as we read them. This temp-file path is
	// returned so it can be used to start the program.
	td, err := ioutil.TempDir("/tmp", "cloudproxy_linux_host")
	if err != nil {
		return
	}

	temppath = path.Join(td, "hosted_program")
	tf, err := os.OpenFile(temppath, os.O_CREATE|os.O_RDWR, 0700)
	defer tf.Close()
	if err != nil {
		return
	}

	inf, err := os.Open(prog)
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
	subprin = FormatSubprin(id, h[:])
	return
}

// LaunchHostedProgram uses a path and arguments to fork a new process.
func (lpf *LinuxProcessFactory) Launch(prog string, args []string) (io.ReadWriteCloser, HostedProgram, error) {
	// Get a pipe pair for communication with the child.
	serverRead, clientWrite, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	defer clientWrite.Close()

	clientRead, serverWrite, err := os.Pipe()
	if err != nil {
		serverRead.Close()
		return nil, nil, err
	}
	defer clientRead.Close()

	env := os.Environ()
	// Note: ExtraFiles below ensures readfd=3, writefd=4 in child
	evar := HostTaoEnvVar + "=tao::TaoRPC+tao::FDMessageChannel(3, 4)"
	// Make sure that the child knows to use a pipe variable.
	etvar := HostTaoTypeEnvVar + "=pipe"
	replaced := false
	replacedType := false
	for i, pair := range env {
		if strings.HasPrefix(pair, HostTaoEnvVar+"=") {
			env[i] = evar
			replaced = true
		}

		if strings.HasPrefix(pair, HostTaoTypeEnvVar+"=") {
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

	channel := util.NewPairReadWriteCloser(serverRead, serverWrite)
	cmd := &Process{
		&exec.Cmd{
			Path:       prog,
			Args:       args,
			Stdin:      os.Stdin,
			Stdout:     os.Stdout,
			Stderr:     os.Stderr,
			Env:        env,
			ExtraFiles: []*os.File{clientRead, clientWrite}, // fd 3, fd 4
			// TODO(tmroeder): change the user of the hosted program here.
		},
	}

	if err := cmd.Start(); err != nil {
		channel.Close()
		return nil, nil, err
	}

	return channel, cmd, nil
}
