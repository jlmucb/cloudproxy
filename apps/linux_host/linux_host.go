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
	"log"
	"net"
	"os"
	"path"
	"path/filepath"

	"github.com/jlmucb/cloudproxy/tao"
)

func main() {
	// General configuration options.
	configPath := flag.String("config_path", "", "Location of tao domain configuration")
	hostPath := flag.String("path", "linux_tao_host", "Name of relative path to the location of linux host configuration")
	rules := flag.String("rules", "rules", "Name of the rules file for auth")
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

	// TPM configuration for the case where we are communicating with a TPM
	// host Tao.
	tpmAIKPath := flag.String("tpm_aik_path", "tpm/aikblob", "The path to the TPM AIK blob file, relative to the location of the tao domain configuration")
	tpmPCRs := flag.String("tpm_pcrs", "", "The PCR values, in the format PCRs(\"<PCR num>,<PCR num>,...,<PCR num>\", \"<PCR value>,<PCR value>,...,<PCR value>\")")
	tpmDevice := flag.String("tpm_device", "/dev/tpm0", "The absolute path to the TPM device")

	// QEMU/KVM CoreOS configuration with some reasonable defaults.
	coreOSImage := flag.String("kvm_coreos_img", "coreos.img", "The path to a CoreOS image")
	sshStartPort := flag.Int("kvm_coreos_ssh_port", 2222, "The starting port for SSH connections to CoreOS VMs")
	vmMemory := flag.Int("kvm_coreos_vm_memory", 1024, "The amount of RAM to give the VM")
	sshFile := flag.String("kvm_coreos_ssh_auth_keys", "auth_ssh_coreos", "A path to the authorized keys file for SSH connections to the CoreOS guest")
	hostImage := flag.String("kvm_coreos_host_docker_img", "linux_host.img.tgz", "The path to the Docker image for the Linux host to run under CoreOS")

	// An action for the service to take.
	action := flag.String("action", "start", "The action to take ('init', 'show', 'start', or 'stop')")
	flag.Parse()

	var verbose io.Writer
	if *quiet {
		verbose = ioutil.Discard
	} else {
		verbose = os.Stderr
	}

	tc := tao.TaoConfig{
		HostType:        tao.HostTaoTypeMap[*hostType],
		HostChannelType: tao.HostTaoChannelMap[*hostChannelType],
		HostSpec:        *hostSpec,
		HostedType:      tao.HostedProgramTypeMap[*hostedProgramType],
	}

	if tc.HostChannelType == tao.TPM {
		tc.TPMAIKPath = *tpmAIKPath
		tc.TPMPCRs = *tpmPCRs
		tc.TPMDevice = *tpmDevice
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
			log.Fatalf("Couldn't create a temporary directory for linux host: %s\n", err)
		}

		trivialConfig := `
# Tao Domain Configuration file

[Domain]
Name = testing
PolicyKeysPath = policy_keys
GuardType = AllowAll

[X509Details]
CommonName = testing`
		absConfigPath = path.Join(dir, "tao.config")
		if err = ioutil.WriteFile(absConfigPath, []byte(trivialConfig), 0700); err != nil {
			log.Fatalf("Couldn't write a trivial Tao config to %s: %s\n", absConfigPath, err)
		}

		emptyRules := make([]byte, 0)
		if err = ioutil.WriteFile(path.Join(dir, "rules"), emptyRules, 0700); err != nil {
			log.Fatalf("Couldn't write an empty rules file: %s\n", err)
		}

		// If we're creating a temporary directory, then create a set of
		// fake policy keys as well, using the password provided.
		if len(*pass) == 0 {
			log.Fatalf("Must provide a password for temporary keys")
		}

		var cfg tao.DomainConfig
		cfg.Domain.Name = "testing"
		cfg.X509Details.CommonName = "testing"
		cfg.Domain.GuardType = "AllowAll"

		_, err = tao.CreateDomain(cfg, absConfigPath, []byte(*pass))
		fatalIf(err)
	} else {
		absConfigPath, err = filepath.Abs(*configPath)
		if err != nil {
			log.Fatalf("Couldn't get an absolute version of the config path %s: %s\n", *configPath, err)
		}
		dir = path.Dir(absConfigPath)
	}

	absHostPath := path.Join(dir, *hostPath)
	sockPath := path.Join(absHostPath, "admin_socket")

	// Check to see if this directory information should be written to a
	// file.
	if *pathFile != "" {
		pf, err := os.OpenFile(*pathFile, os.O_RDWR, 0600)
		if err != nil {
			log.Fatalf("Couldn't open the provided temporary path file %s: %s\n", *pathFile, err)
		}

		fmt.Fprintf(pf, dir)
		pf.Close()
	}

	absChannelSocketPath := path.Join(dir, *hostedProgramSocketPath)

	switch *action {
	case "init", "show", "start":
		domain, err := tao.LoadDomain(absConfigPath, nil)
		fatalIf(err)

		rulesPath := path.Join(dir, *rules)

		var childFactory tao.HostedProgramFactory
		switch tc.HostedType {
		case tao.ProcessPipe:
			childFactory = tao.NewLinuxProcessFactory("pipe", absChannelSocketPath)
		case tao.DockerUnix:
			childFactory = tao.NewLinuxDockerContainerFactory(absChannelSocketPath, rulesPath)
		case tao.KVMCoreOSFile:
			if *sshFile == "" {
				log.Fatal("Must specify an SSH authorized_key file for CoreOS")
			}
			sshKeysCfg, err := tao.CloudConfigFromSSHKeys(*sshFile)
			if err != nil {
				log.Fatalf("Couldn't load the ssh files file '%s': %s\n", *sshFile, err)
			}

			if *coreOSImage == "" {
				log.Fatal("Must specify a CoreOS image file for the CoreOS hosted-program factory")
			}

			// Construct the CoreOS configuration from the flags.
			cfg := &tao.CoreOSConfig{
				ImageFile:  *coreOSImage,
				SSHPort:    *sshStartPort,
				Memory:     *vmMemory,
				RulesPath:  rulesPath,
				SSHKeysCfg: sshKeysCfg,
			}
			childFactory = tao.NewLinuxKVMCoreOSFactory(absChannelSocketPath, *hostImage, cfg)
		default:
			log.Fatalf("Unknown hosted-program factory '%d'\n", tc.HostedType)
		}

		var host *tao.LinuxHost
		switch tc.HostType {
		case tao.Root:
			if len(*pass) == 0 {
				log.Fatal("password is required")
			}
			host, err = tao.NewRootLinuxHost(absHostPath, domain.Guard, []byte(*pass), childFactory)
			fatalIf(err)
		case tao.Stacked:

			if tao.ParentFromConfig(tc) == nil {
				log.Fatalf("error: no host tao available, check $%s or set --host_channel_type\n", tao.HostChannelTypeEnvVar)
			}
			host, err = tao.NewStackedLinuxHost(absHostPath, domain.Guard, tao.ParentFromConfig(tc), childFactory)
			fatalIf(err)
		default:
			log.Fatal("error: must specify either --host_type as either 'root' or 'stacked'")
		}

		switch *action {
		case "create":
			fmt.Printf("LinuxHost Service: %s\n", host.TaoHostName())
		case "show":
			fmt.Printf("%v\n", host.TaoHostName())
		case "start":
			sock, err := net.Listen("unix", sockPath)
			fatalIf(err)
			defer sock.Close()
			fmt.Fprintf(verbose, "Linux Tao Service (%s) started and waiting for requests\n", host.TaoHostName())
			fatalIf(err)
			tao.NewLinuxHostAdminServer(host).Serve(sock)
		}
	case "shutdown":
		log.Fatal("not yet implemented")
	default:
	}
}

func fatalIf(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
