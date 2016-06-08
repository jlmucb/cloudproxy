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
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/golang/crypto/ssh/terminal"
)

func isCtty(fd int) bool {
	// One would hope there was a simple way to figure out what our controlling
	// tty is. Or at least check if stdin is coming from our controlling tty (as
	// opposed to just any old terminal). Alas, the infuriating morass that
	// passes for job control provides no such ability. Of no help:
	// stat(/dev/tty), readlink(/dev/fd/0), open(/dev/stdin), open(/dev/tty),
	// cat(/proc/self/fdinfo/0), stat(/proc/self/fd/0), ioctl, tty_ioctl, TIOC*,
	// anything to do with sid, pgrp, pgid, /dev/console, the tty command, $TTY,
	// $SSH_TTY. Since I am on a mission, I delved into the source for /bin/ps
	// to discover /proc/self/stat contains the major/minor numbers for the
	// controlling tty. And stat(stdin).Rdev provides the same info. If they
	// differ, I'm going to conclude -- oh so tentatively -- that stdin is NOT
	// our controlling tty. If they match, or anything goes wrong, we will
	// assume that stdin, if it is a terminal, is our ctty.
	if !terminal.IsTerminal(fd) {
		return false
	}
	var s syscall.Stat_t
	err := syscall.Fstat(fd, &s)
	if err != nil {
		fmt.Fprintf(noise, "[warning: fstat(%d) failed: %v]\n", fd, err)
		return true
	}
	name := "/proc/self/stat"
	f, err := os.Open(name)
	if err != nil {
		fmt.Fprintf(noise, "[warning: open(%q) failed: %v]\n", name, err)
		return true
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Fprintf(noise, "[warning: read(%q) failed: %v]\n", name, err)
		return true
	}
	a := strings.Split(string(b), " ")
	tty_nr := 6
	if len(a) <= tty_nr {
		fmt.Fprintf(noise, "[warning: read(%q) borked: only %d fields]\n", name, len(a))
		return true
	}
	ctty, err := strconv.Atoi(a[tty_nr])
	if err != nil {
		fmt.Fprintf(noise, "[warning: read(%q) borked: tty_nr = %v]\n", name, a[tty_nr])
		return true
	}
	if uint64(ctty) != s.Rdev {
		fmt.Fprintf(noise, "[warning: stdin is a tty, but not ctty]\n")
		return false
	}
	return true
}

