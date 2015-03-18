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
	MakeSubprin(uint, string, int, int) (auth.SubPrin, string, error)
	Launch(string, []string, int, int) (io.ReadWriteCloser, HostedProgram, error)
}
