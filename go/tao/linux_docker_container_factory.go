// Copyright (c) 2014, Google, Inc.  All rights reserved.
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
	"os"
	"os/exec"
	"path"
	"syscall"

	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

// A DockerContainer represents a hosted program running as a Docker container.
// It uses os/exec.Cmd and the `docker` program to send commands to the Docker
// daemon rather than using the docker client API directly. This is so that this
// code doesn't depend on the docker code for now.
type DockerContainer struct {

	// The spec from which this process was created.
	spec HostedProgramSpec

	// Hash of the docker image.
	Hash []byte

	// The factory responsible for the hosted process.
	Factory *LinuxDockerContainerFactory

	ContainerName string
	ImageName     string
	SocketPath    string
	RulesPath     string

	// The underlying docker process.
	Cmd *exec.Cmd

	// A channel to be signaled when the vm is done.
	Done chan bool
}

// WaitChan returns a chan that will be signaled when the hosted vm is done.
func (dc *DockerContainer) WaitChan() <-chan bool {
	return dc.Done
}

// Kill sends a SIGKILL signal to a docker container.
func (dc *DockerContainer) Kill() error {
	c := exec.Command("docker", "kill", dc.ContainerName)
	return c.Run()
}

// StartDocker starts a docker container using the docker run subcommand.
func (dc *DockerContainer) StartDocker() error {
	cmdArgs := []string{"run", "--rm=true", "-v", dc.SocketPath + ":/tao"}
	if dc.RulesPath != "" {
		cmdArgs = append(cmdArgs, "-v", dc.RulesPath+":/"+path.Base(dc.RulesPath))
	}
	// ContainerArgs are passed directly to docker, i.e. before image name.
	// Args are passed to the ENTRYPOINT within the Docker image, i.e. after
	// image name.
	cmdArgs = append(cmdArgs, dc.spec.ContainerArgs...)
	cmdArgs = append(cmdArgs, dc.ImageName)
	cmdArgs = append(cmdArgs, dc.spec.Args...)
	dc.Cmd = exec.Command("docker", cmdArgs...)
	dc.Cmd.Stdin = dc.spec.Stdin
	dc.Cmd.Stdout = dc.spec.Stdout
	dc.Cmd.Stderr = dc.spec.Stderr
	// Note: Uid, Gid, Dir, and Env do not apply to docker hosted programs.
	// TODO(kwalsh) reap and cleanup
	return dc.Cmd.Start()
}

// Stop sends a SIGSTOP signal to a docker container.
func (dc *DockerContainer) Stop() error {
	c := exec.Command("docker", "kill", "-s", "STOP", dc.ContainerName)
	return c.Run()
}

// Pid returns a numeric ID for this docker container.
func (dc *DockerContainer) Pid() int {
	return dc.Cmd.Process.Pid
}

// ExitStatus returns an exit code for the container.
func (dc *DockerContainer) ExitStatus() (int, error) {
	s := dc.Cmd.ProcessState
	if s == nil {
		return -1, fmt.Errorf("Child has not exited")
	}
	if code, ok := (*s).Sys().(syscall.WaitStatus); ok {
		return int(code), nil
	}
	return -1, fmt.Errorf("Couldn't get exit status\n")
}

// A LinuxDockerContainerFactory manages hosted programs started as docker
// containers over a given docker image.
type LinuxDockerContainerFactory struct {
	SocketPath string
	RulesPath  string
}

// NewLinuxDockerContainerFactory returns a new HostedProgramFactory that can
// create docker containers to wrap programs.
func NewLinuxDockerContainerFactory(sockPath, rulesPath string) HostedProgramFactory {
	return &LinuxDockerContainerFactory{
		SocketPath: sockPath,
		RulesPath:  rulesPath,
	}
}

// NewHostedProgram initializes, but does not start, a hosted docker container.
func (ldcf *LinuxDockerContainerFactory) NewHostedProgram(spec HostedProgramSpec) (child HostedProgram, err error) {

	img := getRandomFileName(nameLen)

	inf, err := os.Open(spec.Path)
	defer inf.Close()
	if err != nil {
		return
	}

	// Build the docker image, and hash the image as it is sent.
	hasher := sha256.New()
	build := exec.Command("docker", "build", "-t", img, "-q", "-")
	build.Stdin = io.TeeReader(inf, hasher)
	if err = build.Run(); err != nil {
		return
	}

	hash := hasher.Sum(nil)

	child = &DockerContainer{
		spec:      spec,
		ImageName: img,
		Hash:      hash,
		Factory:   ldcf,
		Done:      make(chan bool, 1),
	}

	return
}

// Spec returns the specification used to start the hosted docker container.
func (dc *DockerContainer) Spec() HostedProgramSpec {
	return dc.spec
}

// Subprin returns the subprincipal representing the hosted docker container..
func (dc *DockerContainer) Subprin() auth.SubPrin {
	return FormatProcessSubprin(dc.spec.Id, dc.Hash)
}

// FormatDockerSubprin produces a string that represents a subprincipal with the
// given ID and hash.
func FormatDockerSubprin(id uint, hash []byte) auth.SubPrin {
	var args []auth.Term
	if id != 0 {
		args = append(args, auth.Int(id))
	}
	args = append(args, auth.Bytes(hash))
	return auth.SubPrin{auth.PrinExt{Name: "Container", Arg: args}}
}

// Start builds the docker container from the tar file and launches it.
func (dc *DockerContainer) Start() (channel io.ReadWriteCloser, err error) {

	sockName := getRandomFileName(nameLen)
	dc.SocketPath = path.Join(dc.Factory.SocketPath, sockName)

	dc.RulesPath = dc.Factory.RulesPath

	channel = util.NewUnixSingleReadWriteCloser(dc.SocketPath)
	defer func() {
		if err != nil {
			channel.Close()
			channel = nil
		}
	}()

	// TODO(kwalsh) inline StartDocker() here.
	if err = dc.StartDocker(); err != nil {
		return
	}

	return
}

func (p *DockerContainer) Cleanup() error {
	// TODO(kwalsh) close channel, maybe also kill process if still running?
	return nil
}
