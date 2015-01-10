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
	"github.com/jlmucb/cloudproxy/util"
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
	mode := flag.String("mode", "root", "Tao mode to run ('root' or 'stacked').")
	pass := flag.String("pass", "BogusPass", "Password for unlocking keys if running in root mode")
	channelType := flag.String("channel_type", "pipe", "The type of channel for hosted-program communication ('pipe', or 'unix').")
	channelSocketPath := flag.String("channel_socket_path", "linux_tao_host", "The directory in which to create unix sockets for hosted-program communication")
	factoryType := flag.String("factory_type", "process", "The type of hosted program factory to use ('process', 'docker', or 'coreos')")

	// QEMU/KVM CoreOS configuration with some reasonable defaults.
	coreOSImage := flag.String("coreos_img", "coreos.img", "The path to a CoreOS image")
	sshStartPort := flag.Int("coreos_ssh_port", 2222, "The starting port for SSH connections to CoreOS VMs")
	vmMemory := flag.Int("vm_memory", 1024, "The amount of RAM to give the VM")
	sshFile := flag.String("ssh_auth_keys", "auth_ssh_coreos", "A path to the authorized keys file for SSH connections to the CoreOS guest")
	hostImage := flag.String("host_img", "linux_host.img.tgz", "The path to the Docker image for the Linux host to run under CoreOS")

	// An action for the service to take.
	action := flag.String("action", "start", "The action to take ('init', 'show', 'start', or 'stop')")
	util.UseEnvFlags("GLOG", "TAO", "TAO_HOST")
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

	absChannelSocketPath := path.Join(dir, *channelSocketPath)

	switch *action {
	case "init", "show", "start":
		domain, err := tao.LoadDomain(absConfigPath, nil)
		fatalIf(err)

		rulesPath := path.Join(dir, *rules)

		var childFactory tao.HostedProgramFactory
		switch *factoryType {
		case "process":
			childFactory = tao.NewLinuxProcessFactory(*channelType, absChannelSocketPath)
		case "docker":
			childFactory = tao.NewLinuxDockerContainerFactory(absChannelSocketPath, rulesPath)
		case "coreos":
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
			log.Fatalf("Unknown hosted-program factory '%s'\n", *factoryType)
		}

		var host *tao.LinuxHost
		switch *mode {
		case "root":
			if len(*pass) == 0 {
				log.Fatal("password is required")
			}
			host, err = tao.NewRootLinuxHost(absHostPath, domain.Guard, []byte(*pass), childFactory)
			fatalIf(err)
		case "stacked":
			if !tao.Hosted() {
				log.Fatalf("error: no host tao available, check $%s\n", tao.HostTaoEnvVar)
			}
			host, err = tao.NewStackedLinuxHost(absHostPath, domain.Guard, tao.Parent(), childFactory)
			fatalIf(err)
		default:
			log.Fatal("error: must specify either -root or -stacked")
		}

		switch *action {
		case "create":
			fmt.Printf("LinuxHost Service: %s\n", host.TaoHostName())
		case "show":
			fmt.Printf("export GOOGLE_TAO_LINUX='%v'\n", host.TaoHostName())
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
