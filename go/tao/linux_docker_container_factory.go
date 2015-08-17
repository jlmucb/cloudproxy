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
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/golang/glog"
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

	ImageName   string
	SocketPath  string
	CidfilePath string
	RulesPath   string

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
	cid, err := dc.ContainerName()
	if err != nil {
		return err
	}
	return docker(nil, "kill", cid)
}

func (dc *DockerContainer) ContainerName() (string, error) {
	b, err := ioutil.ReadFile(dc.CidfilePath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func docker(stdin io.Reader, args ...string) error {
	c := exec.Command("docker", args...)
	var b bytes.Buffer
	c.Stdin = stdin
	c.Stdout = &b
	c.Stderr = &b
	err := c.Run()
	if err != nil {
		glog.Errorf("Docker error %v: args=%v\n"+
			"begin docker output\n"+
			"%v\n"+
			"end docker output\n", err, args, b.String())
	}
	return err
}

// StartDocker starts a docker container using the docker run subcommand.
func (dc *DockerContainer) StartDocker() error {
	args := []string{"run", "--rm=true", "-v", dc.SocketPath + ":/tao"}
	args = append(args, "--cidfile", dc.CidfilePath)
	if dc.RulesPath != "" {
		args = append(args, "-v", dc.RulesPath+":/"+path.Base(dc.RulesPath))
	}
	// ContainerArgs has a name plus args passed directly to docker, i.e. before
	// image name. Args are passed to the ENTRYPOINT within the Docker image,
	// i.e. after image name.
	// Note: Uid, Gid, Dir, and Env do not apply to docker hosted programs.
	if len(dc.spec.ContainerArgs) > 1 {
		args = append(args, dc.spec.ContainerArgs[1:]...)
	}
	args = append(args, dc.ImageName)
	args = append(args, dc.spec.Args...)
	dc.Cmd = exec.Command("docker", args...)
	dc.Cmd.Stdin = dc.spec.Stdin
	dc.Cmd.Stdout = dc.spec.Stdout
	dc.Cmd.Stderr = dc.spec.Stderr

	err := dc.Cmd.Start()
	if err != nil {
		return err
	}
	// Reap the child when the process dies.
	go func() {
		sc := make(chan os.Signal, 1)
		signal.Notify(sc, syscall.SIGCHLD)
		<-sc
		dc.Cmd.Wait()
		signal.Stop(sc)

		time.Sleep(1 * time.Second)
		docker(nil, "rmi", dc.ImageName)
		dc.Done <- true
		os.Remove(dc.CidfilePath)
		close(dc.Done) // prevent any more blocking
	}()

	return nil
	// TODO(kwalsh) put channel into p, remove the struct in linux_host.go
}

// Stop sends a SIGSTOP signal to a docker container.
func (dc *DockerContainer) Stop() error {
	cid, err := dc.ContainerName()
	if err != nil {
		return err
	}
	return docker(nil, "kill", "-s", "STOP", cid)
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
	SocketDir string
	RulesPath string
}

// NewLinuxDockerContainerFactory returns a new HostedProgramFactory that can
// create docker containers to wrap programs.
func NewLinuxDockerContainerFactory(sockDir, rulesPath string) HostedProgramFactory {
	return &LinuxDockerContainerFactory{
		SocketDir: sockDir,
		RulesPath: rulesPath,
	}
}

// NewHostedProgram initializes, but does not start, a hosted docker container.
func (ldcf *LinuxDockerContainerFactory) NewHostedProgram(spec HostedProgramSpec) (child HostedProgram, err error) {

	// The imagename for the child is given by spec.ContainerArgs[0]
	argv0 := "cloudproxy"
	if len(spec.ContainerArgs) >= 1 {
		argv0 = spec.ContainerArgs[0]
	}
	img := argv0 + ":" + getRandomFileName(nameLen)

	inf, err := os.Open(spec.Path)
	defer inf.Close()
	if err != nil {
		return
	}

	// Build the docker image, and hash the image as it is sent.
	hasher := sha256.New()
	err = docker(io.TeeReader(inf, hasher), "build", "-t", img, "-q", "-")
	if err != nil {
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

	s := path.Join(dc.Factory.SocketDir, getRandomFileName(nameLen))
	dc.SocketPath = s + ".sock"
	dc.CidfilePath = s + ".cid"

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
