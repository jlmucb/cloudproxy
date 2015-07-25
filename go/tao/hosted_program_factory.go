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
	"io"

	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

// TODO(kwalsh) Refactor this entire file. For the factory, use one function,
// which returns a HostedProgram that isn't yet launched. From that, we can
// query the subprin name and then launch it. This way we only have to pass all
// the configuration variables once. Also, usa a struct to hold all the
// configuration variables. We can also avoid the silliness with returning
// temppath then taking it as a parameter in the very next call.

// A HostedProgram is an abstraction of a process, and it is closely related to
// os/exec.Cmd and github.com/docker/docker/daemon.Container.
type HostedProgram interface {
	Start() error
	Kill() error
	Stop() error
	ID() int
}

// A HostedProgramFactory manages the creation of hosted programs. For example,
// on Linux, it might create processes using fork, or it might create processes
// running on docker containers. It might also start a virtual machine
// containing a new instance of an operating system.
type HostedProgramFactory interface {

	// Create a subprincipal to describe a hosted program soon to be created.
	// The ID is chosen by the host. The path specifies a file, e.g. an
	// executable or a vm image, to be hashed in some factory-specific way. The
	// uid and gid are the unix user and group IDs under which the hosted
	// program is to be executed. This returns the subprin. It also returns
	// temppath, which is the location of a secured copy of the file that was
	// hashed.
	MakeSubprin(id uint, path string, uid, gid int) (subprin auth.SubPrin, temppath string, err error)

	// Launch a hosted program. The temppath is the path returned from
	// MakeSubprin. The args are arguments to be passed to the hosted program,
	// e.g. as command line arguments. The uid and gid are the unix user and
	// group IDs under which the hosted program will execute. The fds are
	// file descriptors to be used for the hosted program's stdin, stdout,
	// stderr, along with other file descriptors to be shared with the hosted
	// program. This returns a tao channel to the hosted program, along with the
	// hosted program itself.
	Launch(temppath string, args []string, uid, gid int, fds []int) (io.ReadWriteCloser, HostedProgram, error)
}
