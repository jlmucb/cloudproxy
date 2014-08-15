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
	"net/rpc"
	"os"
	"path"

	"cloudproxy/tao"
	"cloudproxy/util"
	"cloudproxy/util/protorpc"
)

var configPath = flag.String("config_path", "tao.config", "Location of tao domain configuration")
var hostPath = flag.String("path", "linux_tao_host", "Location of linux host configuration")
var quiet = flag.Bool("quiet", false, "Be more quiet.")
var root = flag.Bool("root", false, "Run in root mode")
var stacked = flag.Bool("stacked", false, "Run in stacked mode")
var pass = flag.String("pass", "", "Password for unlocking keys if running in root mode")

var create = flag.Bool("create", false, "Create a new LinuxHost service.")
var show = flag.Bool("show", false, "Show principal name for LinuxHost service.")
var service = flag.Bool("service", false, "Start the LinuxHost service.")
var shutdown = flag.Bool("shutdown", false, "Shut down the LinuxHost service.")

var run = flag.Bool("run", false, "Start a hosted program (path and args follow --).")
var list = flag.Bool("list", false, "List hosted programs.")
var stop = flag.Bool("stop", false, "Stop a hosted program (names follow --).")
var kill = flag.Bool("kill", false, "Kill a hosted program (names follow --).")
var name = flag.Bool("name", false, "Show the principal name of running LinuxHost.")

func countSet(vars ...interface{}) int {
	var n int
	for _, v := range vars {
		switch v := v.(type) {
		case string:
			if v != "" {
				n++
			}
		case bool:
			if v {
				n++
			}
		default:
			n++
		}
	}
	return n
}

var verbose io.Writer

func main() {
	help := "Administrative utility for LinuxHost.\n"
	help += "Usage:\n"
	help += "%[1]s [options] -create\n"
	help += "%[1]s [options] -show\n"
	help += "%[1]s [options] -service\n"
	help += "%[1]s [options] -shutdown\n"
	help += "%[1]s [options] -run -- program args...\n"
	help += "%[1]s [options] -stop -- progname...\n"
	help += "%[1]s [options] -kill -- progname...\n"
	help += "%[1]s [options] -list\n"
	help += "%[1]s [options] -name\n"
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, help, os.Args[0])
		flag.PrintDefaults()
	}
	util.UseEnvFlags("GLOG", "TAO", "TAO_HOST")
	flag.Parse()

	if *quiet {
		verbose = ioutil.Discard
	} else {
		verbose = os.Stdout
	}

	if countSet(*create, *show, *service, *shutdown, *run, *stop, *kill, *list, *name) > 1 {
		log.Fatal("specify at most one of the command options")
	}

	hostSocket := path.Join(*hostPath, "admin_socket")

	if *create || *service || *show {
		fmt.Fprintf(verbose, "Loading configuration from: %s\n", *configPath)
		domain, err := tao.LoadDomain(*configPath, nil)
		fatalIf(err)
		var host *tao.LinuxHost
		if *root {
			if len(*pass) == 0 {
				log.Fatal("password is required")
			}
			host, err = tao.NewRootLinuxHost(*hostPath, domain.Guard, []byte(*pass))
		} else if *stacked {
			if !tao.HostAvailable() {
				log.Fatal("error: no host tao available, check $%s\n", tao.HostTaoEnvVar)
			}
			host, err = tao.NewStackedLinuxHost(*hostPath, domain.Guard, tao.Host())
		} else {
			log.Fatal("error: must specify either -root or -stacked")
		}
		fatalIf(err)
		if *create {
			fmt.Printf("LinuxHost Service: %s\n", host.TaoHostName())
		} else if *show {
			fmt.Printf("export GOOGLE_TAO_LINUX='%v'\n", host.TaoHostName())
		} else /* service */ {
			err := adminSocketServe(hostSocket, host)
			fatalIf(err)
		}
	} else {
		// connect
		if *shutdown {
			log.Fatal("not yet implemented")
		} else if *run {
			log.Fatal("not yet implemented")
		} else if *kill || *stop {
			log.Fatal("not yet implemented")
		} else if *list {
			log.Fatal("not yet implemented")
		} else if *name {
			client, err := adminSocketConnect(hostSocket)
			fatalIf(err)
			req := &LinuxAdminRPCRequest{}
			resp := new(LinuxAdminRPCResponse)
			err = client.Call("LinuxHost.GetTaoHostName", req, resp)
			fatalIf(err)
			fmt.Println(string(resp.data))
		} else {
			log.Fatal("LinuxHost: %s\n", "not yet implemented")
		}
	}
}

func fatalIf(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func adminSocketServe(sockPath string, host *tao.LinuxHost) error {
	sock, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	defer sock.Close()

	fmt.Fprintf(verbose, "Linux Tao Service started and waiting for requests\n")
	for {
		conn, err := sock.Accept()
		if err != nil {
			return err
		}
		fmt.Fprintf(verbose, "Accepted admin connection\n")
		go rpc.ServeCodec(protorpc.NewServerCodec(conn))
	}
}

func adminSocketDial(sockPath string) (*rpc.Client, error) {
	conn, err := net.Dial("unix","", sockPath)
	if err != nil {
		return nil, err
	}
	// defer c.Close()
	return rpc.NewClientWithCodec(protorpc.NewClientCodec(conn))
}
