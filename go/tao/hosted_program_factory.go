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
	"os"

	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

// A HostedProgramSpec contains all of the information that might be needed to
// start a hosted program. Some factories may not use all of this information,
// and the semantics of each field vary by factory.
type HostedProgramSpec struct {

	// Id is an optional number to be included in the subprincipal name. If
	// zero, it will be omitted.
	Id uint

	// Path specifies a file, e.g. an executable or a vm image, to be
	// executed in some factory-specific way.
	Path string

	// Args are passed to the hosted program in some factory-specific way,
	// e.g. as command line arguments.
	Args []string

	// ContainerArgs are used to configure the factory-specific container in
	// which the hosted program is executed, e.g. by being passed as parameters
	// to `docker run`.
	ContainerArgs []string

	// Uid is a the linux uid under which the hosted program is to be executed.
	// Zero is not a legal value unless Superuser is set.
	Uid int

	// Gid is a the linux uid under which the hosted program is to be executed.
	// Zero is not a legal value unless Superuser is set.
	Gid int

	// Superuser enables running the hosted program with Uid or Gid 0. This
	// field is meant to prevent an accidentally omitted Uid from being
	// interpreted as a request to run the hosted program as superuser. Instead,
	// superuser must explicitly be set.
	Superuser bool

	// Stdin, Stdout, and Stderr are open file descriptors to be shared with the
	// hosted program in a factory-specific way. If nil, factory-specific
	// default values are used, e.g. perhaps /dev/null or inheriting from the
	// tao host server. If not nil, these must have a File.Fd().
	Stdin, Stdout, Stderr *os.File

	// Dir is the directory in which to start the program. If empty, a
	// factory-specific default will be used, e.g. perhaps the tao host server's
	// directory, or perhaps dirname(Path).
	Dir string

	// Env specifies the environment of the hosted program. If Env is nil, a
	// factory-specific default environment will be used. Some factories may
	// modify the environment, e.g. to pass certain parameters across a fork.
	Env []string
}

// A HostedProgram is an abstraction of a process. It is closely related to
// os/exec.Cmd and github.com/docker/docker/daemon.Container.
type HostedProgram interface {

	// Spec returns the specification used to start the hosted program.
	Spec() HostedProgramSpec

	// Subprin returns the subprincipal representing the hosted program.
	Subprin() auth.SubPrin

	// Extend adds components to the subprincipal for the hosted program.
	Extend(ext auth.SubPrin)

	// Start starts the the hosted program.
	Start() error

	// Kill kills the hosted program and cleans up resources.
	Kill() error

	// Stop stops the hosted program and cleans up resources.
	Stop() error

	// Channel returns the channel the child uses for the tao api.
	Channel() io.ReadWriteCloser

	// WaitChan returns a chan that will be signaled when the hosted process is
	// done.
	WaitChan() <-chan bool

	// Cleanup cleans up resources, such as temporary files.
	Cleanup() error

	// Pid returns a factory-specific numeric identifier.
	Pid() int

	// ExitStatus returns a factory-specific exit status code if
	// the hosted program has exited.
	ExitStatus() (int, error)
}

// A HostedProgramFactory manages the creation of hosted programs. For example,
// on Linux, it might create processes using fork, or it might create processes
// running on docker containers. It might also start a virtual machine
// containing a new instance of an operating system.
type HostedProgramFactory interface {

	// NewHostedProgram initializes, but does not start, a hosted program.
	NewHostedProgram(spec HostedProgramSpec) (HostedProgram, error)
}
