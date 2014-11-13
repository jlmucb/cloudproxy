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

	"github.com/jlmucb/cloudproxy/tao/auth"
	"github.com/jlmucb/cloudproxy/util"
)

// A DockerContainer is a simple wrapper for Docker containers. It uses
// os/exec.Cmd to send commands to the Docker daemon rather than using the
// docker client API directly. This is so that this code doesn't depend on the
// docker code for now.
type DockerContainer struct {
	ContainerName string
	ImageName     string
	SocketPath    string
	RulesPath     string
	Args          []string
}

// Kill sends a SIGKILL signal to a docker container.
func (dc *DockerContainer) Kill() error {
	c := exec.Command("docker", "kill", dc.ContainerName)
	return c.Run()
}

// Start starts a docker container using the docker run subcommand.
func (dc *DockerContainer) Start() error {
	cmdArgs := []string{"run", "--rm=true",
		"-v", dc.RulesPath + ":" + dc.RulesPath,
		"-v", dc.SocketPath + ":/tao",
		dc.ImageName}
	cmdArgs = append(cmdArgs, dc.Args...)
	c := exec.Command("docker", cmdArgs...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Start()
}

// Stop sends a SIGSTOP signal to a docker container.
func (dc *DockerContainer) Stop() error {
	c := exec.Command("docker", "kill", "-s", "STOP", dc.ContainerName)
	return c.Run()
}

// ID returns a numeric ID for this docker container. For now, this ID is 0.
func (dc *DockerContainer) ID() int {
	return 0
}

// Build uses the provided path to a tar file to build a Docker image.
func (dc *DockerContainer) Build(tarPath string) error {
	tarFile, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer tarFile.Close()

	buildCmd := exec.Command("docker", "build", "-t", dc.ImageName, "-q", "-")
	buildCmd.Stdin = tarFile
	if err := buildCmd.Run(); err != nil {
		return err
	}

	return nil
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

// MakeSubprin computes the hash of a docker container to get a subprincipal for
func (ldcf *LinuxDockerContainerFactory) MakeSubprin(id uint, image string) (auth.SubPrin, string, error) {
	var empty auth.SubPrin
	// To avoid a time-of-check-to-time-of-use error, we copy the file
	// bytes to a temp file as we read them. This temp-file path is
	// returned so it can be used to start the docker container.
	td, err := ioutil.TempDir("/tmp", "cloudproxy_linux_docker_container")
	if err != nil {
		return empty, "", err
	}

	temppath := path.Join(td, "image")
	tf, err := os.OpenFile(temppath, os.O_CREATE|os.O_RDWR, 0700)
	defer tf.Close()
	if err != nil {
		return empty, "", err
	}

	inf, err := os.Open(image)
	defer inf.Close()
	if err != nil {
		return empty, "", err
	}

	// Read from the input file and write to the temp file.
	tr := io.TeeReader(inf, tf)
	b, err := ioutil.ReadAll(tr)
	if err != nil {
		return empty, "", err
	}

	h := sha256.Sum256(b)
	subprin := FormatDockerSubprin(id, h[:])
	return subprin, temppath, nil
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

// Launch builds a docker container from a tar file and launches it with the
// given arguments.
func (ldcf *LinuxDockerContainerFactory) Launch(tarPath string, args []string) (io.ReadWriteCloser, HostedProgram, error) {
	if len(args) == 0 {
		return nil, nil, fmt.Errorf("invalid args to Launch docker container")
	}

	sockName := getRandomFileName(nameLen)
	sockPath := path.Join(ldcf.SocketPath, sockName)

	// Create a new docker image from the filesystem tarball, and use it to
	// build a container and launch it.
	dc := &DockerContainer{
		ImageName:  getRandomFileName(nameLen),
		SocketPath: sockPath,
		RulesPath:  ldcf.RulesPath,
		Args:       args,
	}
	rwc := util.NewUnixSingleReadWriteCloser(sockPath)
	if err := dc.Build(tarPath); err != nil {
		rwc.Close()
		return nil, nil, err
	}

	if err := dc.Start(); err != nil {
		rwc.Close()
		return nil, nil, err
	}

	return rwc, dc, nil
}
