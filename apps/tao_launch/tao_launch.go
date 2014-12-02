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
	"log"
	"net"

	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
)

func main() {
	operation := flag.String("operation", "run", "The operation to perform ('run', 'stop', 'kill', 'list', or 'name').")
	sockPath := flag.String("sock", "linux_tao_host/admin_socket", "The path to the socket for the linux_host")
	docker := flag.String("docker_img", "", "The path to a tarball to use to create a docker image")

	if *sockPath == "" {
		log.Fatalf("Must supply a socket patch for the linux host")
	}

	flag.Parse()

	conn, err := net.Dial("unix", *sockPath)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	client := tao.NewLinuxHostAdminClient(conn)
	switch *operation {
	case "run":
		if flag.NArg() == 0 {
			log.Fatal("missing program path")
		}
		if *docker == "" {
			subprin, pid, err := client.StartHostedProgram(flag.Arg(0), flag.Args()...)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%d %v\n", pid, subprin)
		} else {
			// Drop the first arg for Docker, since it will
			// be handled by the Dockerfile directly.
			if flag.NArg() == 1 {
				subprin, pid, err := client.StartHostedProgram(*docker)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Printf("%d %v\n", pid, subprin)
			} else {
				subprin, pid, err := client.StartHostedProgram(*docker, flag.Args()[1:]...)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Printf("%d %v\n", pid, subprin)
			}
		}
	case "stop":
		for _, s := range flag.Args() {
			var subprin auth.SubPrin
			if _, err := fmt.Sscanf(s, "%v", &subprin); err != nil {
				log.Fatal(err)
			}
			if err = client.StopHostedProgram(subprin); err != nil {
				log.Fatal(err)
			}
		}
	case "kill":
		for _, s := range flag.Args() {
			var subprin auth.SubPrin
			if _, err := fmt.Sscanf(s, "%v", &subprin); err != nil {
				log.Fatal(err)
			}
			if err = client.KillHostedProgram(subprin); err != nil {
				log.Fatal(err)
			}
		}
	case "list":
		name, pid, err := client.ListHostedPrograms()
		if err != nil {
			log.Fatal(err)
		}
		for i, p := range pid {
			fmt.Printf("pid=%d %v\n", p, name[i])
		}
		fmt.Printf("%d processes\n", len(pid))
	case "name":
		name, err := client.TaoHostName()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("LinuxHost: %v\n", name)
	default:
		log.Fatalf("Unknown operation '%s'", *operation)
	}

	return
}
