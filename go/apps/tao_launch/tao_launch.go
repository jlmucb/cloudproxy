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

package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

func main() {
	// child PID is output to fd 3, if it exists, otherwise to stdout
	pidOut := os.Stdout
	if util.IsValidFD(3) {
		pidOut = util.NewFile(3)
	}

	operation := flag.String("operation", "run", "The operation to perform ('run', 'stop', 'kill', 'list', or 'name').")
	sockPath := flag.String("sock", "linux_tao_host/admin_socket", "The path to the socket for the linux_host")
	docker := flag.String("docker_img", "", "The path to a tarball to use to create a docker image")

	if *sockPath == "" {
		glog.Fatalf("Must supply a socket patch for the linux host")
	}

	flag.Parse()

	conn, err := net.Dial("unix", *sockPath)
	if err != nil {
		glog.Fatal(err)
	}
	defer conn.Close()
	client := tao.NewLinuxHostAdminClient(conn)
	switch *operation {
	case "run":
		if flag.NArg() == 0 {
			glog.Fatal("missing program path")
		}
		if *docker == "" {
			subprin, pid, err := client.StartHostedProgram(flag.Arg(0), flag.Args()...)
			if err != nil {
				glog.Exit(err)
			}
			glog.Infof("%d %v\n", pid, subprin)
			pidOut.Write([]byte(fmt.Sprintf("%d\n", pid)))
		} else {
			// Drop the first arg for Docker, since it will
			// be handled by the Dockerfile directly.
			if flag.NArg() == 1 {
				subprin, pid, err := client.StartHostedProgram(*docker)
				if err != nil {
					glog.Exit(err)
				}
				glog.Infof("%d %v\n", pid, subprin)
			} else {
				subprin, pid, err := client.StartHostedProgram(*docker, flag.Args()[1:]...)
				if err != nil {
					glog.Exit(err)
				}
				glog.Infof("%d %v\n", pid, subprin)
			}
		}
	case "stop":
		for _, s := range flag.Args() {
			var subprin auth.SubPrin
			if _, err := fmt.Sscanf(s, "%v", &subprin); err != nil {
				glog.Exit(err)
			}
			if err = client.StopHostedProgram(subprin); err != nil {
				glog.Exit(err)
			}
		}
	case "kill":
		for _, s := range flag.Args() {
			var subprin auth.SubPrin
			if _, err := fmt.Sscanf(s, "%v", &subprin); err != nil {
				glog.Exit(err)
			}
			if err = client.KillHostedProgram(subprin); err != nil {
				glog.Exit(err)
			}
		}
	case "list":
		name, pid, err := client.ListHostedPrograms()
		if err != nil {
			glog.Exit(err)
		}
		for i, p := range pid {
			glog.Infof("pid=%d %v\n", p, name[i])
		}
		glog.Infof("%d processes\n", len(pid))
	case "name":
		name, err := client.HostName()
		if err != nil {
			glog.Exit(err)
		}
		glog.Infof("LinuxHost: %v\n", name)
	default:
		glog.Fatalf("Unknown operation '%s'", *operation)
	}

	return
}
