// Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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

package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
)

func main() {
	// General configuration options.
	configPath := flag.String("config_path", "", "Location of tao domain configuration")
	hostPath := flag.String("path", "linux_tao_host", "Name of relative path to the location of linux host configuration")
	quiet := flag.Bool("quiet", false, "Be more quiet.")
	pathFile := flag.String("tmppath", "", "Write the path to the tmp configuration directory to this file if a filename is provided")

	// Absent any flags indicating other options, the default configuration of
	// linux_host runs in root mode with a fresh key (so with a soft Tao), and with
	// its configuration stored in a fresh temporary directory, and with a liberal
	// guard policy. Its default method of creating hosted programs is as processes
	// with pipe communication.
	hostType := flag.String("host_type", "root", "The type of Tao host to implement ('root' or 'stacked').")
	pass := flag.String("pass", "BogusPass", "Password for unlocking keys if running in root host mode")
	hostSpec := flag.String("host_spec", "", "The spec to use for communicating with the parent (e.g., '/dev/tpm0')")
	hostChannelType := flag.String("host_channel_type", "", "The type of the host channel (e.g., 'tpm', 'file', or 'unix')")
	hostedProgramType := flag.String("hosted_program_type", "process", "The type of hosted program to create ('process', 'docker', or 'kvm_coreos')")
	hostedProgramSocketPath := flag.String("hosted_program_socket_path", "linux_tao_host", "The directory in which to create unix sockets for hosted-program communication")

	// QEMU/KVM CoreOS configuration with some reasonable defaults.
	coreOSImage := flag.String("kvm_coreos_img", "coreos.img", "The path to a CoreOS image")
	vmMemory := flag.Int("kvm_coreos_vm_memory", 1024, "The amount of RAM to give the VM")
	sshFile := flag.String("kvm_coreos_ssh_auth_keys", "auth_ssh_coreos", "A path to the authorized keys file for SSH connections to the CoreOS guest")

	// An action for the service to take.
	action := flag.String("action", "start", "The action to take ('init', 'show', 'start', or 'stop')")
	flag.Parse()

	var verbose io.Writer
	if *quiet {
		verbose = ioutil.Discard
	} else {
		verbose = os.Stderr
	}

	var dir string
	var absConfigPath string
	var err error
	// If the configPath doesn't exist, then create a temp path for the
	// configuration. This also handles the case where the config path is
	// empty.
	if _, err = os.Stat(*configPath); err != nil {
		dir, err = ioutil.TempDir("", "linux_host")
		if err != nil {
			glog.Fatalf("Couldn't create a temporary directory for linux host: %s", err)
		}
		if err := os.Chmod(dir, 0777); err != nil {
			glog.Fatalf("Couldn't change permissions on %s to 777: %s", dir, err)
		}

		cfg := tao.DomainConfig{
			DomainInfo: &tao.DomainDetails{
				Name:           proto.String("testing"),
				PolicyKeysPath: proto.String("policy_keys"),
				GuardType:      proto.String("AllowAll"),
			},
			X509Info: &tao.X509Details{
				CommonName:   proto.String("testing"),
				Country:      proto.String("US"),
				State:        proto.String("WA"),
				Organization: proto.String("CloudProxy"),
			},
		}
		trivialConfig := proto.MarshalTextString(&cfg)
		absConfigPath = path.Join(dir, "tao.config")
		if err = ioutil.WriteFile(absConfigPath, []byte(trivialConfig), 0644); err != nil {
			glog.Fatalf("Couldn't write a trivial Tao config to %s: %s", absConfigPath, err)
		}

		// If we're creating a temporary directory, then create a set of
		// fake policy keys as well, using the password provided.
		if len(*pass) == 0 {
			glog.Fatalf("Must provide a password for temporary keys")
		}

		_, err = tao.CreateDomain(cfg, absConfigPath, []byte(*pass))
		fatalIf(err)
	} else {
		absConfigPath, err = filepath.Abs(*configPath)
		if err != nil {
			glog.Fatalf("Couldn't get an absolute version of the config path %s: %s", *configPath, err)
		}
		dir = path.Dir(absConfigPath)
	}

	absHostPath := path.Join(dir, *hostPath)
	sockPath := path.Join(absHostPath, "admin_socket")

	// Load the domain.
	domain, err := tao.LoadDomain(absConfigPath, nil)
	fatalIf(err)
	glog.Info("Domain guard: ", domain.Guard)

	tc := tao.Config{
		HostType:        tao.HostTaoTypeMap[*hostType],
		HostChannelType: tao.HostTaoChannelMap[*hostChannelType],
		HostSpec:        *hostSpec,
		HostedType:      tao.HostedProgramTypeMap[*hostedProgramType],
	}

	if tc.HostChannelType == tao.TPM {
		// Look up the TPM information in the domain config.
		if domain.Config.TpmInfo == nil {
			glog.Infof("must provide TPM configuration info in the domain to use a TPM")
			return
		}

		tc.TPMAIKPath = domain.Config.TpmInfo.GetAikPath()
		tc.TPMPCRs = domain.Config.TpmInfo.GetPcrs()
		tc.TPMDevice = domain.Config.TpmInfo.GetTpmPath()
	}

	// Check to see if this directory information should be written to a
	// file.
	if *pathFile != "" {
		pf, err := os.OpenFile(*pathFile, os.O_RDWR, 0600)
		if err != nil {
			glog.Fatalf("Couldn't open the provided temporary path file %s: %s", *pathFile, err)
		}

		fmt.Fprintf(pf, dir)
		pf.Close()
	}

	absChannelSocketPath := path.Join(dir, *hostedProgramSocketPath)

	// Get the Tao parent from the config information if possible.
	if tc.HostType == tao.Stacked {
		if tao.ParentFromConfig(tc) == nil {
			glog.Fatalf("error: no host tao available, check $%s or set --host_channel_type", tao.HostChannelTypeEnvVar)
		}
	}

	switch *action {
	case "init", "show", "start":
		rules := domain.RulesPath()
		var rulesPath string
		if rules != "" {
			rulesPath = path.Join(dir, rules)
		}

		// TODO(cjpatton) How do the NewLinuxDockerContainterFactory and the
		// NewLinuxKVMCoreOSFactory need to be modified to support the new
		// CachedGuard? They probably don't.
		var childFactory tao.HostedProgramFactory
		switch tc.HostedType {
		case tao.ProcessPipe:
			childFactory = tao.NewLinuxProcessFactory("pipe", absChannelSocketPath)
		case tao.DockerUnix:
			childFactory = tao.NewLinuxDockerContainerFactory(absChannelSocketPath, rulesPath)
		case tao.KVMCoreOSFile:
			if *sshFile == "" {
				glog.Fatal("Must specify an SSH authorized_key file for CoreOS")
			}
			sshKeysCfg, err := tao.CloudConfigFromSSHKeys(*sshFile)
			if err != nil {
				glog.Fatalf("Couldn't load the ssh files file '%s': %s", *sshFile, err)
			}

			if *coreOSImage == "" {
				glog.Fatal("Must specify a CoreOS image file for the CoreOS hosted-program factory")
			}

			// Construct the CoreOS configuration from the flags.
			cfg := &tao.CoreOSConfig{
				ImageFile:  *coreOSImage,
				Memory:     *vmMemory,
				RulesPath:  rulesPath,
				SSHKeysCfg: sshKeysCfg,
			}
			childFactory = tao.NewLinuxKVMCoreOSFactory(absChannelSocketPath, cfg)
		default:
			glog.Fatalf("Unknown hosted-program factory '%d'", tc.HostedType)
		}

		var host *tao.LinuxHost
		switch tc.HostType {
		case tao.Root:
			if len(*pass) == 0 {
				glog.Fatal("password is required")
			}
			host, err = tao.NewRootLinuxHost(absHostPath, domain.Guard, []byte(*pass), childFactory)
			fatalIf(err)
		case tao.Stacked:

			if tao.ParentFromConfig(tc) == nil {
				glog.Fatalf("error: no host tao available, check $%s or set --host_channel_type", tao.HostChannelTypeEnvVar)
			}
			host, err = tao.NewStackedLinuxHost(absHostPath, domain.Guard, tao.ParentFromConfig(tc), childFactory)
			fatalIf(err)
		default:
			glog.Fatal("error: must specify either --host_type as either 'root' or 'stacked'")
		}

		switch *action {
		case "show":
			fmt.Printf("%v", host.HostName())
		case "start":
			// Make sure callers can read the directory that
			// contains the socket.
			err := os.Chmod(path.Dir(sockPath), 0755)
			fatalIf(err)

			// The Serve method on the linux host admin server
			// requires a UnixListener, since it uses this listener
			// to get the UID and GID of callers. So, we have to use
			// the Unix-based net functions rather than the generic
			// ones.
			uaddr, err := net.ResolveUnixAddr("unix", sockPath)
			fatalIf(err)
			sock, err := net.ListenUnix("unix", uaddr)
			fatalIf(err)
			defer sock.Close()
			err = os.Chmod(sockPath, 0666)
			fatalIf(err)

			fmt.Fprintf(verbose, "Linux Tao Service (%s) started and waiting for requests\n", host.HostName())
			tao.NewLinuxHostAdminServer(host).Serve(sock)
		}
	case "shutdown":
		glog.Fatal("not yet implemented")
	default:
	}

	glog.Flush()
}

func fatalIf(err error) {
	if err != nil {
		glog.Fatal(err)
	}
}
