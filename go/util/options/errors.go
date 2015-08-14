// Copyright (c) 2015, Kevin Walsh.  All rights reserved.
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

// Package options works in concert with flag, adding prettier printing of
// options.
package options

import (
	"fmt"
	"os"
)

// FailIf does the same thing as Fail, but only if err is not nil.
func FailIf(err error, msg string, args ...interface{}) {
	if err != nil {
		Fail(err, msg, args...)
	}
}

// WarnIf prints an error and accompanying message, but only if err is not nil.
func WarnIf(err error, msg string, args ...interface{}) {
	if err != nil {
		s := fmt.Sprintf(msg, args...)
		fmt.Fprintf(os.Stderr, "warning: %v: %s\n", err, s)
	}
}

// Fail prints an error and accompanying message to os.Stderr, then exits the
// program with status 2. The err parameter can be nil.
func Fail(err error, msg string, args ...interface{}) {
	s := fmt.Sprintf(msg, args...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v: %s\n", err, s)
	} else {
		fmt.Fprintf(os.Stderr, "error: %s\n", s)
	}
	os.Exit(2)
}

// Usage prints a message to os.Stderr, along with a note about the -help
// option, then exits the program with status 1.
func Usage(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	fmt.Fprintf(os.Stderr, "Try -help instead!\n")
	os.Exit(1)
}
