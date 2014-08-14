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
	"log"
	"os"

	"cloudproxy/tao"
	"cloudproxy/util"
)

var configPath = flag.String("config_path", "tao.config", "Location of tao domain configuration")
var path = flag.String("path", "linux_tao_host", "Location of linux host configuration")
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
	util.UseEnvFlags("GLOG", "TAO")
	flag.Parse()

	if countSet(*create, *show, *service, *shutdown, *run, *stop, *kill, *list, *name) > 1 {
		log.Fatal("specify at most one of the command options")
	}

	if *create || *service || *show {
		fmt.Printf("Loading configuration from: %s\n", *configPath)
		domain, err := tao.LoadDomain(*configPath, nil)
		fatalIf(err)
		var host *tao.LinuxHost
		if *root {
			host, err = tao.NewRootLinuxHost(*path, domain.Guard, []byte(*pass))
		} else if *stacked {
			if !tao.HostAvailable() {
				log.Fatal("error: no host tao available, check $%s\n", tao.HostTaoEnvVar)
			}
			host, err = tao.NewStackedLinuxHost(*path, domain.Guard, tao.Host())
		} else {
			fmt.Printf("error: must specify either -root or -stacked")
		}
		fatalIf(err)
		if *create {
			fmt.Printf("LinuxHost Service: %s\n", host.TaoHostName())
		} else if *show {
      fmt.Printf("export GOOGLE_TAO_LINUX='%v'\n", host.TaoHostName())
		} else /* service */ {
      fmt.Printf("Linux Tao Service started and waiting for requests\n")
			// listen
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
			fmt.Printf("%v\n", "not yet implemented")
		} else {
			fmt.Printf("LinuxHost: %s\n", "not yet implemented")
		}
	}
}

func fatalIf(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
