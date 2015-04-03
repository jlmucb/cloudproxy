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
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

// A CoreOSConfig contains the details needed to start a new CoreOS VM.
type CoreOSConfig struct {
	Name       string
	ImageFile  string
	Memory     int
	RulesPath  string
	SSHKeysCfg string
	SocketPath string
}

// A KvmCoreOSContainer is a simple wrapper for CoreOS running on KVM. It uses
// os/exec.Cmd to send commands to QEMU/KVM to start CoreOS then uses SSH to
// connect to CoreOS to start the LinuxHost there with a virtio-serial
// connection for its communication with the Tao running on Linux in the guest.
// This use of os/exec is to avoid having to rewrite or hook into libvirt for
// now.
type KvmCoreOSContainer struct {
	Cfg      *CoreOSConfig
	HostFile string
	Args     []string
	QCmd     *exec.Cmd
	LHPath   string
}

// Kill sends a SIGKILL signal to a QEMU instance.
func (kcc *KvmCoreOSContainer) Kill() error {
	// Kill the qemu command directly.
	// TODO(tmroeder): rewrite this using qemu's communication/management
	// system; sending SIGKILL is definitely not the right way to do this.
	return kcc.QCmd.Process.Kill()
}

// Start starts a QEMU/KVM CoreOS container using the command line.
func (kcc *KvmCoreOSContainer) Start() error {
	// Create a temporary directory for the config drive.
	td, err := ioutil.TempDir("", "coreos")
	if err != nil {
		return err
	}
	// TODO(tmroeder): save this path and remove it on Stop/Kill.
	// defer os.RemoveAll(td)

	// Create a temporary directory for the linux_host image. Note that the
	// args were validated in Launch before this call.
	tdDocker := kcc.Args[1]

	// Expand the host file into the directory.
	// TODO(tmroeder): save this path and remove it on Stop/Kill.
	// defer os.RemoveAll(tdDocker)
	linuxHostFile, err := os.Open(kcc.HostFile)
	if err != nil {
		return err
	}

	zipReader, err := gzip.NewReader(linuxHostFile)
	if err != nil {
		return err
	}
	defer zipReader.Close()

	unzippedImage, err := ioutil.ReadAll(zipReader)
	if err != nil {
		return err
	}
	unzippedReader := bytes.NewReader(unzippedImage)
	tarReader := tar.NewReader(unzippedReader)
	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		fi := hdr.FileInfo()
		outputName := path.Join(tdDocker, hdr.Name)
		if fi.IsDir() {
			if err := os.Mkdir(outputName, fi.Mode()); err != nil {
				return err
			}
		} else {

			outputFile, err := os.OpenFile(outputName, os.O_CREATE|os.O_TRUNC|os.O_RDWR, fi.Mode())
			if err != nil {
				return err
			}

			if _, err := io.Copy(outputFile, tarReader); err != nil {
				outputFile.Close()
				return err
			}
			outputFile.Close()
		}
	}

	latestDir := path.Join(td, "openstack/latest")
	if err := os.MkdirAll(latestDir, 0700); err != nil {
		return err
	}

	cfg := kcc.Cfg
	userData := path.Join(latestDir, "user_data")
	if err := ioutil.WriteFile(userData, []byte(cfg.SSHKeysCfg), 0700); err != nil {
		return err
	}

	// Copy the rules into the mirrored filesystem for use by the Linux host
	// on CoreOS.
	if cfg.RulesPath != "" {
		rules, err := ioutil.ReadFile(cfg.RulesPath)
		if err != nil {
			return err
		}
		rulesFile := path.Join(tdDocker, path.Base(cfg.RulesPath))
		if err := ioutil.WriteFile(rulesFile, []byte(rules), 0700); err != nil {
			return err
		}
	}

	qemuProg := "qemu-system-x86_64"
	qemuArgs := []string{"-name", cfg.Name,
		"-m", strconv.Itoa(cfg.Memory),
		"-machine", "accel=kvm:tcg",
		// Networking.
		"-net", "nic,vlan=0,model=virtio",
		"-net", "user,vlan=0,hostfwd=tcp::" + kcc.Args[2] + "-:22,hostname=" + cfg.Name,
		// Tao communications through virtio-serial. With this
		// configuration, QEMU waits for a server on cfg.SocketPath,
		// then connects to it.
		"-chardev", "socket,path=" + cfg.SocketPath + ",id=port0-char",
		"-device", "virtio-serial",
		"-device", "virtserialport,id=port1,name=tao,chardev=port0-char",
		// The CoreOS image to boot from.
		"-drive", "if=virtio,file=" + cfg.ImageFile,
		// A Plan9P filesystem for SSH configuration (and our rules).
		"-fsdev", "local,id=conf,security_model=none,readonly,path=" + td,
		"-device", "virtio-9p-pci,fsdev=conf,mount_tag=config-2",
		// Another Plan9P filesystem for the linux_host files.
		"-fsdev", "local,id=tao,security_model=none,path=" + tdDocker,
		"-device", "virtio-9p-pci,fsdev=tao,mount_tag=tao",
		// Machine config.
		"-cpu", "host",
		"-smp", "4",
		"-nographic"} // for now, we add -nographic explicitly.
	// TODO(tmroeder): append args later.
	//qemuArgs = append(qemuArgs, kcc.Args...)

	qemuCmd := exec.Command(qemuProg, qemuArgs...)
	// Don't connect QEMU/KVM to any of the current input/output channels,
	// since we'll connect over SSH.
	//qemuCmd.Stdin = os.Stdin
	//qemuCmd.Stdout = os.Stdout
	//qemuCmd.Stderr = os.Stderr
	kcc.QCmd = qemuCmd
	kcc.LHPath = tdDocker
	return kcc.QCmd.Start()
}

// Stop sends a SIGSTOP signal to a docker container.
func (kcc *KvmCoreOSContainer) Stop() error {
	// Stop the QEMU/KVM process with SIGSTOP.
	// TODO(tmroeder): rewrite this using qemu's communication/management
	// system; sending SIGSTOP is definitely not the right way to do this.
	return kcc.QCmd.Process.Signal(syscall.SIGSTOP)
}

// ID returns a numeric ID for this container. For now, this ID is 0.
func (kcc *KvmCoreOSContainer) ID() int {
	return 0
}

// A LinuxKVMCoreOSFactory manages hosted programs started as QEMU/KVM
// instances over a given CoreOS image.
type LinuxKVMCoreOSFactory struct {
	Cfg        *CoreOSConfig
	SocketPath string
	HostFile   string
	Mutex      sync.Mutex
	PublicKey  string
	PrivateKey ssh.Signer
}

// NewLinuxKVMCoreOSFactory returns a new HostedProgramFactory that can
// create docker containers to wrap programs.
func NewLinuxKVMCoreOSFactory(sockPath string, cfg *CoreOSConfig) HostedProgramFactory {

	// Create a key to use to connect to the instance and set up LinuxHost
	// there.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		glog.Fatalf("couldn't create a 2048-bit RSA key: %s", err)
	}
	sshpk, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		glog.Fatalf("couldn't create a SSH public key from the RSA key: %s", err)
	}
	pkstr := "ssh-rsa " + base64.StdEncoding.EncodeToString(sshpk.Marshal()) + " linux_host"

	sshpriv, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		glog.Fatalf("couldn't create an SSH private key from the RSA key: %s", err)
	}

	return &LinuxKVMCoreOSFactory{
		Cfg:        cfg,
		SocketPath: sockPath,
		PublicKey:  pkstr,
		PrivateKey: sshpriv,
	}
}

// CloudConfigFromSSHKeys converts an ssh authorized-keys file into a format
// that can be used by CoreOS to authorize incoming SSH connections over the
// Plan9P-mounted filesystem it uses. This also adds the SSH key used by the
// factory to configure the virtual machine.
func CloudConfigFromSSHKeys(keysFile string) (string, error) {
	sshKeys := "#cloud-config\nssh_authorized_keys:"
	sshFile, err := os.Open(keysFile)
	if err != nil {
		return "", err
	}
	scanner := bufio.NewScanner(sshFile)
	for scanner.Scan() {
		sshKeys += "\n - " + scanner.Text()
	}

	return sshKeys, nil
}

// MakeSubprin computes the hash of a QEMU/KVM CoreOS image to get a
// subprincipal for authorization purposes.
func (lkcf *LinuxKVMCoreOSFactory) MakeSubprin(id uint, image string, uid, gid int) (auth.SubPrin, string, error) {
	var empty auth.SubPrin
	// TODO(tmroeder): the combination of TeeReader and ReadAll doesn't seem
	// to copy the entire image, so we're going to hash in place for now.
	// This needs to be fixed to copy the image so we can avoid a TOCTTOU
	// attack.
	b, err := ioutil.ReadFile(lkcf.Cfg.ImageFile)
	if err != nil {
		return empty, "", err
	}

	h := sha256.Sum256(b)
	subprin := FormatCoreOSSubprin(id, h[:])

	bb, err := ioutil.ReadFile(image)
	if err != nil {
		return empty, "", err
	}
	hh := sha256.Sum256(bb)
	lhSubprin := FormatLinuxHostSubprin(id, hh[:])

	subprin = append(subprin, lhSubprin...)
	return subprin, image, nil
}

// FormatLinuxHostSubprin produces a string that represents a subprincipal with
// the given ID and hash.
func FormatLinuxHostSubprin(id uint, hash []byte) auth.SubPrin {
	var args []auth.Term
	if id != 0 {
		args = append(args, auth.Int(id))
	}
	args = append(args, auth.Bytes(hash))
	return auth.SubPrin{auth.PrinExt{Name: "LinuxHost", Arg: args}}
}

// FormatCoreOSSubprin produces a string that represents a subprincipal with the
// given ID and hash.
func FormatCoreOSSubprin(id uint, hash []byte) auth.SubPrin {
	var args []auth.Term
	if id != 0 {
		args = append(args, auth.Int(id))
	}
	args = append(args, auth.Bytes(hash))
	return auth.SubPrin{auth.PrinExt{Name: "CoreOS", Arg: args}}
}

func getRandomFileName(n int) string {
	// Get a random name for the socket.
	nameBytes := make([]byte, n)
	if _, err := rand.Read(nameBytes); err != nil {
		return ""
	}
	return hex.EncodeToString(nameBytes)
}

var nameLen = 10

// Launch launches a QEMU/KVM CoreOS instance, connects to it with SSH to start
// the LinuxHost on it, and returns the socket connection to that host.
func (lkcf *LinuxKVMCoreOSFactory) Launch(imagePath string, args []string, uid, gid int) (io.ReadWriteCloser, HostedProgram, error) {
	// The args must contain the directory to write the linux_host into, as
	// well as the port to use for SSH.
	if len(args) != 3 {
		glog.Errorf("Expected %d args, but got %d", 3, len(args))
		for i, a := range args {
			glog.Errorf("Arg %d: %s", i, a)
		}
		return nil, nil, errors.New("KVM/CoreOS guest Tao requires args: <linux_host image> <temp directory for linux_host> <SSH port>")
	}
	// Build the new Config and start it. Make sure it has a random name so
	// it doesn't conflict with other virtual machines. Note that we need to
	// assign fresh local SSH ports for each new virtual machine, hence the
	// mutex and increment operation.
	sockName := getRandomFileName(nameLen)
	sockPath := path.Join(lkcf.SocketPath, sockName)
	sshCfg := lkcf.Cfg.SSHKeysCfg + "\n - " + string(lkcf.PublicKey)

	cfg := &CoreOSConfig{
		Name:       getRandomFileName(nameLen),
		ImageFile:  lkcf.Cfg.ImageFile, // the VM image
		Memory:     lkcf.Cfg.Memory,
		RulesPath:  lkcf.Cfg.RulesPath,
		SSHKeysCfg: sshCfg,
		SocketPath: sockPath,
	}

	// Create a new docker image from the filesystem tarball, and use it to
	// build a container and launch it.
	kcc := &KvmCoreOSContainer{
		Cfg:      cfg,
		HostFile: imagePath, // The linux_host image
		Args:     args,
	}

	// Create the listening server before starting the connection. This lets
	// QEMU start right away. See the comments in Start, above, for why this
	// is.
	rwc := util.NewUnixSingleReadWriteCloser(cfg.SocketPath)
	if err := kcc.Start(); err != nil {
		return nil, nil, err
	}

	// We need some way to wait for the socket to open before we can connect
	// to it and return the ReadWriteCloser for communication. Also we need
	// to connect by SSH to the instance once it comes up properly. For now,
	// we just wait for a timeout before trying to connect and listen.
	tc := time.After(10 * time.Second)

	// Set up an ssh client config to use to connect to CoreOS.
	conf := &ssh.ClientConfig{
		// The CoreOS user for the SSH keys is currently always 'core'
		// on the virtual machine.
		User: "core",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(lkcf.PrivateKey)},
	}

	glog.Info("Waiting for at most 10 seconds before trying to connect")
	<-tc

	hostPort := net.JoinHostPort("localhost", args[2])
	client, err := ssh.Dial("tcp", hostPort, conf)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't dial '%s': %s", hostPort, err)
	}

	// We need to run a set of commands to set up the LinuxHost on the
	// remote system.
	// Mount the filesystem.
	mount, err := client.NewSession()
	mount.Stdout = os.Stdout
	mount.Stderr = os.Stderr
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't establish a mount session on SSH: %s", err)
	}
	if err := mount.Run("sudo mkdir /media/tao && sudo mount -t 9p -o trans=virtio,version=9p2000.L tao /media/tao && sudo chmod -R 755 /media/tao"); err != nil {
		return nil, nil, fmt.Errorf("couldn't mount the tao filesystem on the guest: %s", err)
	}
	mount.Close()

	// Start the linux_host on the container.
	start, err := client.NewSession()
	start.Stdout = os.Stdout
	start.Stderr = os.Stderr
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't establish a start session on SSH: %s", err)
	}
	if err := start.Start("sudo /media/tao/linux_host --host_type stacked --host_spec 'tao::RPC+tao::FileMessageChannel(/dev/virtio-ports/tao)' --host_channel_type file --config_path /media/tao/tao.config"); err != nil {
		return nil, nil, fmt.Errorf("couldn't start linux_host on the guest: %s", err)
	}
	start.Close()

	return rwc, kcc, nil
}
