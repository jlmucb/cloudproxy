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

// Job control, signals, and stdio for running hosted programs:
//
// If stdin is a terminal, we proxy input over a pipe instead of handing it
// directly to the hosted program. We also proxy a few signals, like SIGINT,
// SIGKILL, SIGHUP, SIGTSTP, and SIGCONT. This mostly lets you use normal job
// control with Control-C, Control-V, &, fg, and bg.
//
// Known bugs and limitations:
//  - SIGTTOU and `stty stop` is not supported at all
//  - Attempting to run in the background as the head of a pipeline is broken;
//    the hosted program will run, but all other processes in the pipeline will
//    probably stop due to a misleading SIGTTIN.
//  - Running in the background (not as part of a pipeline) works, but the shell
//    (and ps) will report that we are stopped waiting for input.
//  - There are various race conditions if signals arrive back-to-back.
//
// Otherwise, simple job control, signals, and redirection mostly kinda works.
// But the implementation is all a bit fragile and broken. Here is why.
//
// Handing stdin to a hosted program causes problems with job control. Normally,
// a process gets a SIGTTIN (which, by default, causes it to stop) when it
// writes to a stream if all of these are true:
//   (1) the stream is a tty,
//   (2) the tty is the controlling terminal of the process,
//   (3) the process is in the background (or maybe non-foreground?) group for
//       the session associated with that tty
// When we hand stdin to a hosted program, (2) and maybe (3) are false, so it
// never gets the signal. The terminal is associated with our session, and there
// isn't a reliable way for the hosted program to join our session. We could
// possibly create a new pty, but that seems complex. So we aren't going to ever
// meet conditions (2) and (3). There is one problematic scenario: if stdin is
// our controlling tty, and when we are put into the background, then the hosted
// program will steal input from the console. Unfortunately, this seems like a
// common scenario.
//
// If we proxy stdin, the hosted program will read from our pipe, while we
// continously read from the tty and write to the pipe. When we are put into the
// background, we will get SIGTTIN almost immediately, because we are
// continuously reading. We have a few options for handling the SIGTTIN:
//   (a) We can stop ourselves with a SIGSTOP. The shell will report that we are
//       stopped waiting for input. That won't stop the hosted program
//       immediately, but it will probably block on stdin eventually. If we
//       proxy stdout and stderr, those would stop too, unfortunately, breaking
//       background mode. So we shouldn't proxy stdout and stderr in this case.
//       There is a downside to this, explained below. And, the shell's notice
//       that we are stopped waiting for input will be misleading, since the
//       output will keep going. Moreover, the SIGTTIN will cause other
//       processes in our process group (e.g. other parts of a pipeline) to
//       stop.
//   (b) We can try to stop only the input proxying when we get a SIGTTIN. The
//       The downside is that the shell will not realize that the hosted program is
//       blocked waiting for input, since we don't actually stop. This seems
//       like a minor problem.
// Sadly, (b) is apparently impossible in go: go installs the SIGTTIN handler as
// SA_RESTART, there is no way to suspend the proxying goroutine nor a way to
// cause its read of stdin to return EINTR or EIO, and there is no way within go
// to ignore SIGTTIN at the OS level.
//
// Handing stdout or stderr to a hosted program may cause slight problems.
// Normally, a process gets a SIGTTOU (which, by default, causes it to stop)
// when it writes to a stream if the above (1), (2), and (3) are true, and:
//   (4) and 'stty tostop' is in effect for that tty.
// Again, we aren't going to meet conditions (2) and (3). Fortunately, (4) is
// probably false in most cases anyway. Or, at least, I have never heard of it
// before and have never set that option. So having broken SIGTTOU delivery is
// probably okay.
//
// If we proxy stdout and stderr instead, when the hosted program writes to our
// pipe, we will read it, then write to the tty. If a SIGTTOU is needed, it will
// be delivered to us. We can catch it, stop the hosted program with a SIGTTOU,
// and stop ourselves with a SIGSTOP. The hosted program can ignore the SIGTTOU
// and keep writing, but it will get buffered in the pipe and not appear on
// screen.
//
// In summary, our best options are:
//
//   Option 1: Don't proxy stdout or stderr. If stdin is our controlling
//   terminal, then proxy it. When put into the background, the shell will
//   immediately report that we are stopped waiting for input, but confusingly
//   the output may keep going. SIGTTOU is not supported at all. The code is at
//   least somewhat clean.
//
//   Option 2: Proxy anything that is our controlling terminal. When put into
//   the background, then shell will never report that we are stopped waiting
//   for input. When we get SIGTTIN, catch the signal and cause the proxying on
//   stdin to stop, but allow the proxying on stdout and stderr to continue.
//   Unfortunately, this is tricky in go. There is a goroutine that continuously
//   does read() on stdin. When we catch SIGTTIN, the read() on stdin seems to
//   get restarted (via ERESTART?) immediately, leading to another SIGTTIN, and
//   so on, in a tight loop. If we could set SIGTTIN to SIG_IGN, then I believe
//   read() would fail with EIO instead of restarting, allowing the goroutine to
//   detect the error and stop trying to read() the tty. Sadly, it isn't obvious
//   how to call sigaction SIG_IGN in go, and it isn't clear if that would
//   interfere with go's own signal handling efforts.

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
	"unsafe"

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"golang.org/x/crypto/ssh/terminal"
)

var opts = []options.Option{
	// Flags for all commands
	{"tao_domain", "", "<dir>", "Tao domain configuration directory", "all,all+run"},
	{"host", "", "<dir>", "Host configuration, relative to domain directory or absolute", "all,all+run"},
}

var run_opts = []options.Option{
	// Flags for run
	{"pidfile", "", "<file>", "Write hosted program pid to this file", "run,all+run"},
	{"namefile", "", "<file>", "Write hosted program subprin name to this file", "run,all+run"},
	{"disown", false, "", "Don't wait for hosted program to exit", "run,all+run"},
	{"daemon", false, "", "Don't pipe stdio or wait for hosted program to exit", "run,all+run"},
	{"verbose", false, "", "Be more verbose", "run,all+run"},
}

func init() {
	options.Add(opts...)
	switch path.Base(os.Args[0]) {
	case "tao_stop", "tao_kill", "tao_list":
	case "tao_run":
		options.Add(run_opts...)
	default:
		options.Add(run_opts...)
	}
}

var noise = ioutil.Discard

func help() {
	w := new(tabwriter.Writer)
	w.Init(os.Stderr, 4, 0, 2, ' ', 0)
	av0 := path.Base(os.Args[0])

	switch av0 {
	case "tao_stop", "tao_kill":
		fmt.Fprintf(w, "Usage: %s [options] <subprin> [subprin...]\n", av0)
		categories := []options.Category{
			{"all", "Options"},
			{"logging", "Options to control log output"},
		}
		options.ShowRelevant(w, categories...)
	case "tao_list":
		fmt.Fprintf(w, "Usage: %s [options]\n", av0)
		categories := []options.Category{
			{"all", "Options"},
			{"logging", "Options to control log output"},
		}
		options.ShowRelevant(w, categories...)
	case "tao_run":
		fmt.Fprintf(w, "Usage: %s [options] <prog> [args...]\n", av0)
		categories := []options.Category{
			{"all+run", "Options"},
			{"logging", "Options to control log output"},
		}
		options.ShowRelevant(w, categories...)
	default:
		fmt.Fprintf(w, "Tao Hosted Program Utility\n")
		fmt.Fprintf(w, "Usage:\n")
		fmt.Fprintf(w, "  %s run [options] [process:]<prog> [args...]\t Run a new hosted process\n", av0)
		fmt.Fprintf(w, "  %s run [options] docker:<img> [dockerargs...] [-- [imgargs...]]\t Run a new hosted docker image\n", av0)
		fmt.Fprintf(w, "  %s run [options] kvm_coreos:<img> [dockerargs...] [-- [imgargs...]]\t Run a new hosted QEMU/kvm CoreOS image\n", av0)
		fmt.Fprintf(w, "  %s list [options]\t List hosted programs\n", av0)
		fmt.Fprintf(w, "  %s stop [options] subprin [subprin...]\t Stop hosted programs\n", av0)
		fmt.Fprintf(w, "  %s stop [options] subprin [subprin...]\t Kill hosted programs\n", av0)
		categories := []options.Category{
			{"all", "Basic options for all commands"},
			{"run", "Options for 'run' command"},
			{"logging", "Options to control log output"},
		}
		options.ShowRelevant(w, categories...)
	}
	w.Flush()
}

func main() {
	flag.Usage = help

	cmd := "help"
	switch av0 := path.Base(os.Args[0]); av0 {
	case "tao_run", "tao_list", "tao_stop", "tao_kill":
		cmd = av0[4:]
		flag.Parse()
	default:
		// Get options before the command verb
		flag.Parse()
		// Get command verb
		if flag.NArg() > 0 {
			cmd = flag.Arg(0)
		}
		// Get options after the command verb
		if flag.NArg() > 1 {
			flag.CommandLine.Parse(flag.Args()[1:])
		}
	}

	if b, ok := options.Bool["verbose"]; ok && *b {
		noise = os.Stderr
	}

	sockPath := path.Join(hostPath(), "admin_socket")
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{sockPath, "unix"})
	failIf(err, "Can't connect to host admin socket")
	defer conn.Close()

	client := tao.NewLinuxHostAdminClient(conn)
	switch cmd {
	case "help":
		help()
	case "run":
		runHosted(&client, flag.Args())
	case "stop":
		for _, s := range flag.Args() {
			var subprin auth.SubPrin
			_, err := fmt.Sscanf(s, "%v", &subprin)
			failIf(err, "Not a subprin: %s", s)
			err = client.StopHostedProgram(subprin)
			failIf(err, "Could not stop %s", s)
		}
	case "kill":
		for _, s := range flag.Args() {
			var subprin auth.SubPrin
			failIf(err, "Not a subprin: %s", s)
			err = client.KillHostedProgram(subprin)
			failIf(err, "Could not kill %s", s)
		}
	case "list":
		names, pids, err := client.ListHostedPrograms()
		failIf(err, "Can't list hosted programs")
		for i, p := range pids {
			fmt.Printf("pid=%d subprin=%v\n", p, names[i])
		}
		fmt.Printf("%d hosted programs\n", len(pids))
	default:
		usage("Unrecognized command: %s", cmd)
	}

	return
}

const moment = 100 * time.Millisecond

func split(a []string, delim string) (before []string, after []string) {
	for i, s := range a {
		if s == delim {
			before = append(before, a[0:i]...)
			after = append(after, a[i+1:]...)
			return
		}
	}
	before = append(before, a...)
	return
}

func runHosted(client *tao.LinuxHostAdminClient, args []string) {
	var err error

	if len(args) == 0 {
		usage("Missing program path and arguments")
	}

	spec := new(tao.HostedProgramSpec)

	ctype := "process"
	spec.Path = args[0]
	for _, prefix := range []string{"process", "docker", "kvm_coreos"} {
		if strings.HasPrefix(spec.Path, prefix+":") {
			ctype = prefix
			spec.Path = strings.TrimPrefix(spec.Path, prefix+":")
		}
	}

	switch ctype {
	case "process":
		dirs := util.LiberalSearchPath()
		binary := util.FindExecutable(args[0], dirs)
		if binary == "" {
			fail(nil, "Can't find `%s` on path '%s'", args[0], strings.Join(dirs, ":"))
		}
		spec.ContainerArgs = []string{spec.Path}
		spec.Args = args[1:]
		spec.Path = binary
	case "docker", "kvm_coreos":
		spec.ContainerArgs, spec.Args = split(args[1:], "--")
	}

	pidfile := *options.String["pidfile"]
	var pidOut *os.File
	if pidfile == "-" {
		pidOut = os.Stdout
	} else if pidfile != "" {
		pidOut, err = os.Create(pidfile)
		failIf(err, "Can't open pid file")
	}

	namefile := *options.String["namefile"]
	var nameOut *os.File
	if namefile == "-" {
		nameOut = os.Stdout
	} else if namefile != "" {
		nameOut, err = os.Create(namefile)
		failIf(err, "Can't open name file")
	}

	daemon := *options.Bool["daemon"]
	disown := *options.Bool["disown"]

	var pr, pw *os.File
	proxying := false
	tty := isCtty(int(os.Stdin.Fd()))
	if daemon {
		// stdio is nil
	} else if disown {
		// We are assuming that if stdin is a terminal, it is our controlling
		// terminal. I don't know any way to verify it, but it seems likely.
		if tty {
			// stdin is nil, else they would steal input from tty
		} else {
			spec.Stdin = os.Stdin
		}
		spec.Stdout = os.Stdout
		spec.Stderr = os.Stderr
	} else {
		// interactive
		proxying = tty
		if proxying {
			pr, pw, err = os.Pipe()
			failIf(err, "Can't pipe")
			spec.Stdin = pr
		} else {
			spec.Stdin = os.Stdin
		}
		spec.Stdout = os.Stdout
		spec.Stderr = os.Stderr
		fmt.Fprintf(noise, "[proxying stdin]\n")
	}

	spec.Dir, err = os.Getwd()
	failIf(err, "Can't get working directory")

	// Start catching signals early, buffering a few, so we don't miss any. We
	// don't proxy SIGTTIN. However, we do catch it and stop ourselves, rather
	// than letting the OS stop us. This is necessary so that we can send
	// SIGCONT to the child at the right times.
	// Here is the easy case
	//   we start in background
	//   we fork (output starts going)
	//   we are background, so leave SIGTTIN handling at the default
	//   we read and get SIGTTIN, so are stopped
	//   child is not stopped, it keeps outputting, as desired
	//   upon fg, we get SIGCONT, start dropping SIGTTIN and looping for input and signals
	// Here is the tricky case:
	//   we start in foreground
	//   we fork (output starts going)
	//   we are foreground, so catch and drop SIGTTIN (we use SIGTSTP instead)
	//   we get SIGTSTP via ctrl-z
	//   we send child SIGTSTP, so it stops
	//      [we are still dropping SIGTTIN]
	//   we send ourselves SIGSTOP, so we stop
	//   we get SIGCONT via either bg or fg
	//      [if bg, now furiously catching and dropping SIGTTIN]
	//      [if fg, dropping too, but there should not be any SIGTTIN]
	//   send child the SIGCONT
	//   if we are foreground, so go back to top of loop
	//   if we are background, reset SIGTTIN which causes us to stop
	//
	// The basic invariant we are trying to maintain is that when we are
	// foreground we catch and drop SIGTTIN, allowing us to properly handle
	// SIGTSTP events. There shouldn't be any SIGTTIN anyway, except for the
	// brief moments when we are transitioning to stopped.
	// And when the child is supposed to be running in the background, we should
	// leave the default SIGTTIN behavior, so that the OS will stop our read
	// loop.

	signals := make(chan os.Signal, 10) // some buffering
	signal.Notify(signals,
		syscall.SIGINT,  // Ctrl-C
		syscall.SIGTERM, // SIGINT wannabe (e.g. via kill)
		syscall.SIGQUIT, // Ctrl-\
		syscall.SIGTSTP, // Ctrl-Z
		syscall.SIGHUP,  // tty hangup (e.g. via disown)
		syscall.SIGABRT, // abort (e.g. via kill)
		syscall.SIGUSR1, // user-defined (e.g. via kill)
		syscall.SIGUSR2, // user-defined (e.g. via kill)
	)

	// Start the hosted program
	subprin, pid, err := client.StartHostedProgram(spec)
	failIf(err, "Can't start hosted program")
	fmt.Fprintf(noise, "[started hosted program with pid %d]\n", pid)
	fmt.Fprintf(noise, "[subprin is %v]\n", subprin)

	if pidOut != nil {
		fmt.Fprintln(pidOut, pid)
		pidOut.Close()
	}

	if nameOut != nil {
		fmt.Fprintln(nameOut, subprin)
		nameOut.Close()
	}

	if disown || daemon {
		return
	}

	// Listen for exit status from host
	status := make(chan int, 1)
	go func() {
		s, _ := client.WaitHostedProgram(pid, subprin)
		// For short programs, we often lose the race, so
		// we get a "no such hosted program" error.
		// failIf(err, "Can't wait for hosted program exit")
		status <- s
	}()

	wasForeground := false
	if proxying && isForeground() {
		fmt.Fprintf(noise, "[in foreground]\n")
		dropSIGTTIN()
		wasForeground = true
	}

	// Proxy stdin, if needed
	if proxying {
		pr.Close()
		go func() {
			_, err := io.Copy(pw, os.Stdin)
			warnIf(err, "Can't copy from stdin to pipe")
			pw.Close()
		}()
	}

	// If we are proxying and (were) background, we should probably
	// have done a read() by now and gotten SIGTTIN and stopped. Let's
	// pause a moment to be sure the read() happens.
	time.Sleep(moment)

	// By this point, if we had been foreground, we might still be. Or, we might
	// have been foreground but just gotten SIGTSTP and are now madly dropping
	// SIGTTIN until we get into the loop below to handle the SIGTSTP.
	//
	// Alternatively, if we had been background, we would have been stopped by
	// the default SIGTTIN, so the only way we would be here is if we later got
	// pulled foreground via fg. We want to be dropping SIGTTIN in case we get a
	// SIGTSTP.
	if proxying && !wasForeground {
		dropSIGTTIN()
	}

	next := cont
	for next != done {
		select {
		case s := <-status:
			fmt.Fprintf(noise, "[hosted program exited, %s]\n", exitCode(s))
			next = done
		case sig := <-signals:
			next = handle(sig, pid)
		}
		if next == resumed && proxying && !isForeground() {
			// Need to toggle SIGTTIN handling and block (that's the only way to
			// stop spinning on SIGTTIN), but only after handling all pending
			// signals (e.g. SIGCONT then SIGHUP, or SIGCONT then SIGTERM).
			for next == resumed {
				select {
				case s := <-status:
					fmt.Fprintf(noise, "[hosted program exited, %s]\n", exitCode(s))
					next = done
				case sig := <-signals:
					next = handle(sig, pid)
					if next == cont {
						next = resumed
					}
				default:
					next = cont
					defaultSIGTTIN()
					time.Sleep(moment)
					dropSIGTTIN()
				}
			}
		}
	}
	signal.Stop(signals)
}

type todo int

const (
	done    todo = iota // we are done, time to exit
	resumed             // we just woke up
	cont                // neither of the above
)

func handle(sig os.Signal, pid int) todo {
	switch sig {
	case syscall.SIGTSTP:
		send(pid, syscall.SIGTSTP)
		fmt.Fprintf(noise, "[stopping]\n")
		syscall.Kill(syscall.Getpid(), syscall.SIGSTOP)
		time.Sleep(moment)
		fmt.Fprintf(noise, "[resuming]\n")
		send(pid, syscall.SIGCONT)
		return resumed
	case syscall.SIGHUP: // tty hangup (e.g. via disown)
		noise = ioutil.Discard
		os.Stdin.Close()
		os.Stdout.Close()
		os.Stderr.Close()
		send(pid, sig.(syscall.Signal))
		// Our tty is gone, so there is little left to do. We could hang
		// around proxying signals (e.g. those sent via kill). But those
		// could be just as easily sent directly to the hosted program,
		// so let's not bother.
		return done
	default:
		send(pid, sig.(syscall.Signal))
	}
	return cont
}

var discard = make(chan os.Signal, 1) // minimal buffering

func defaultSIGTTIN() {
	fmt.Fprintf(noise, "[default SIGTTIN handling]\n")
	signal.Stop(discard)
}

func dropSIGTTIN() {
	fmt.Fprintf(noise, "[dropping SIGTTIN]\n")
	signal.Notify(discard, syscall.SIGTTIN)
}

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
		fmt.Println(noise, "[warning: open(%q) failed: %v]\n", name, err)
		return true
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Println(noise, "[warning: read(%q) failed: %v]\n", name, err)
		return true
	}
	a := strings.Split(string(b), " ")
	tty_nr := 6
	if len(a) <= tty_nr {
		fmt.Println(noise, "[warning: read(%q) borked: only %d fields]\n", name, len(a))
		return true
	}
	ctty, err := strconv.Atoi(a[tty_nr])
	if err != nil {
		fmt.Println(noise, "[warning: read(%q) borked: tty_nr = %v]\n", name, a[tty_nr])
		return true
	}
	if uint64(ctty) != s.Rdev {
		fmt.Println(noise, "[warning: stdin is a tty, but not ctty]\n")
		return false
	}
	return true
}

func isForeground() bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {

	}
	fpgrp := 0
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, tty.Fd(), syscall.TIOCGPGRP, uintptr(unsafe.Pointer(&fpgrp)))
	if errno != 0 {
	}
	return syscall.Getpgrp() == fpgrp
}

// Note: There is a slight race here. If pids are reused very quickly, we might
// end up sending a signal to the wrong child just after the hosted program
// exits. That seems unlikely. To fix it, we would have to coordinate with
// linux_host, e.g. have linux_host send the signal on our behalf.
func send(pid int, sig syscall.Signal) {
	fmt.Fprintf(noise, "[sending %s to hosted program]\n", sigName(sig))
	// fmt.Fprintf(noise, "[signal %v (%d)]\n", sig, int(sig.(syscall.Signal)))
	syscall.Kill(pid, sig)
}

func sigName(sig syscall.Signal) string {
	var name string
	switch sig {
	case syscall.SIGINT:
		name = "SIGINT"
	case syscall.SIGTERM:
		name = "SIGTERM"
	case syscall.SIGQUIT:
		name = "SIGQUIT"
	case syscall.SIGTSTP:
		name = "SIGTSTP"
	case syscall.SIGHUP:
		name = "SIGHUP"
	case syscall.SIGABRT:
		name = "SIGABRT"
	case syscall.SIGUSR1:
		name = "SIGUSR1"
	case syscall.SIGUSR2:
		name = "SIGUSR2"
	case syscall.SIGCONT:
		name = "SIGCONT"
	case syscall.SIGSTOP:
		name = "SIGSTOP"
	}
	return fmt.Sprintf("%s (%d)", name, int(sig))
}

func exitCode(s int) string {
	ws := syscall.WaitStatus(s)
	if ws.Exited() {
		return fmt.Sprintf("status %d", ws.ExitStatus())
	} else if ws.Signaled() && ws.CoreDump() {
		return fmt.Sprintf("signal %v, with core dump", ws.Signal())
	} else if ws.Signaled() {
		return fmt.Sprintf("signal %v", ws.Signal())
	} else if ws.Stopped() {
		return fmt.Sprintf("stopped by %v", ws.StopSignal())
	} else if ws.Continued() {
		return fmt.Sprintf("continued")
	} else {
		return fmt.Sprintf("exit status unknown")
	}
}

func domainPath() string {
	if path := *options.String["tao_domain"]; path != "" {
		return path
	}
	if path := os.Getenv("TAO_DOMAIN"); path != "" {
		return path
	}
	usage("Must supply -tao_domain or set $TAO_DOMAIN")
	return ""
}

func hostPath() string {
	hostPath := *options.String["host"]
	if hostPath == "" {
		// usage("Must supply a -host path")
		hostPath = "linux_tao_host"
	}
	if !path.IsAbs(hostPath) {
		hostPath = path.Join(domainPath(), hostPath)
	}
	return hostPath
}

func failIf(err error, msg string, args ...interface{}) {
	if err != nil {
		fail(err, msg, args...)
	}
}

func fail(err error, msg string, args ...interface{}) {
	s := fmt.Sprintf(msg, args...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v: %s\n", err, s)
	} else {
		fmt.Fprintf(os.Stderr, "error: %s\n", s)
	}
	os.Exit(2)
}

func warnIf(err error, msg string, args ...interface{}) {
	if err != nil {
		s := fmt.Sprintf(msg, args...)
		fmt.Fprintf(os.Stderr, "warning: %v: %s\n", err, s)
	}
}

func usage(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	fmt.Fprintf(os.Stderr, "Try -help instead!\n")
	// help()
	os.Exit(1)
}
