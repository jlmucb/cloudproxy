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
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"

	"cloudproxy/tao/auth"
	"cloudproxy/util"
)

// In the C++ Tao, these functions are methods on a stateless class. So, in Go,
// the struct is empty. But we don't make them functions on their own, since we
// want to support multiple hosted-program factory implementations against an
// interface in the future.

// A LinuxProcessFactory supports methods for creating Linux processes as
// hosted programs.
type LinuxProcessFactory struct{}

// FormatHostedProgramSubprin produces a string that represents a subprincipal
// with the given ID and hash.
func FormatHostedProgramSubprin(id uint, hash []byte) auth.SubPrin {
	var args []auth.Term
	if id != 0 {
		args = append(args, auth.Int(id))
	}
	hashstr := fmt.Sprintf("%x", hash)
	args = append(args, auth.Str(hashstr))
	return auth.SubPrin{auth.PrinExt{Name: "Program", Arg: args}}
}

// MakeHostedProgramSubprin computes the hash of a program to get its
// hosted-program subprincipal. In the process, it copies the program to a
// temporary file controlled by this code and returns the path to that new
// binary.
func (LinuxProcessFactory) MakeHostedProgramSubprin(id uint, prog string) (subprin auth.SubPrin, temppath string, err error) {
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
	subprin = FormatHostedProgramSubprin(id, h[:])
	return
}

// ForkHostedProgram uses a path and arguments to fork a new process.
func (LinuxProcessFactory) ForkHostedProgram(prog string, args []string) (io.ReadWriteCloser, *exec.Cmd, error) {
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

	channel := util.NewPairReadWriteCloser(serverRead, serverWrite)
	cmd := &exec.Cmd{
		Path:       prog,
		Args:       args,
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		ExtraFiles: []*os.File{clientRead, clientWrite},
		// TODO(tmroeder): change the user of the hosted program here.
	}

	if err := cmd.Start(); err != nil {
		channel.Close()
		return nil, nil, err
	}

	return channel, cmd, nil
}
