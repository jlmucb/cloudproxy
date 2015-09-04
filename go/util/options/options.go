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
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	_ "github.com/golang/glog"
)

// Option is like flag.Flag, but supports prettier printing.
type Option struct {
	// Name for this flag, e.g. "pass"
	Name string

	// Default value, e.g. "BogusPassword"
	Default interface{}

	// Placeholder description of the argument e.g. "<password>"
	Prototype string

	// Help message, e.g. "Password for decryption"
	Help string

	// Relevance is a comma-separated list of words, used to group the flags
	// into categories.
	Relevance string
}

// Category describes a group of related command-line flags.
type Category struct {

	// Name for this group of flags.
	Name string

	// Description for this group of flags.
	Description string
}

var (
	// Options is like flag.CommandLine, the current set of options. It is not kept
	// in lexicographical order. Initially, it will contain (at least) all the flags
	// from golang/glog.
	Options = []Option{}

	// String maps from name to value for string options added with Add.
	String = make(map[string]*string)

	// Bool maps from name to value for boolean options added with Add.
	Bool = make(map[string]*bool)

	// Int maps from name to value for int options added with Add.
	Int = make(map[string]*int)

	// Strings maps from name to value for []string options added with Add.
	Strings = make(map[string][]string)

	// Duration maps from name to value for time.Duration options added with
	// Add.
	Duration = make(map[string]*time.Duration)
)

type namedStringList string

func (name namedStringList) Set(v string) error {
	s := strings.Split(v, ",")
	Strings[string(name)] = append(Strings[string(name)], s...)
	return nil
}

func (name namedStringList) String() string {
	return strings.Join(Strings[string(name)], ",")
}

func init() {
	// Add to options all existing flags, which presumably come from golang/glog
	// since we import that package.
	flag.VisitAll(func(f *flag.Flag) {
		defval := f.Value.(flag.Getter).Get()
		option := Option{f.Name, defval, "", f.Usage, "logging"}
		switch defval.(type) {
		case int:
			option.Prototype = "<n>"
		case bool:
			option.Prototype = ""
		default:
			option.Prototype = "<arg>"
		}
		Options = append(Options, option)
	})
}

// Add adds one or more options to Options, to the flag package's list, and to
// the approprate map (String, Bool, Int, etc.).
func Add(option ...Option) {
	Options = append(Options, option...)
	for _, o := range option {
		switch defval := o.Default.(type) {
		case string:
			String[o.Name] = flag.String(o.Name, defval, o.Help)
		case []string:
			Strings[o.Name] = defval
			flag.Var(namedStringList(o.Name), o.Name, o.Help)
		case bool:
			Bool[o.Name] = flag.Bool(o.Name, defval, o.Help)
		case int:
			Int[o.Name] = flag.Int(o.Name, defval, o.Help)
		case time.Duration:
			Duration[o.Name] = flag.Duration(o.Name, defval, o.Help)
		default:
			panic(fmt.Sprintf("Option type not yet supported: %T", o.Default))
		}
	}
}

// ShowRelevant pretty-prints all options relevant to one or more categories.
func ShowRelevant(out io.Writer, category ...Category) {
	w, ok := out.(*tabwriter.Writer)
	if !ok {
		w = new(tabwriter.Writer)
		w.Init(out, 4, 0, 2, ' ', 0)
	}
	for i, c := range category {
		if i != 0 {
			fmt.Fprintf(w, "\t\n")
		}
		fmt.Fprintf(w, "%s:\n", c.Description)
		Show(w, c.Name)
	}
	if !ok {
		w.Flush()
	}
}

// Show pretty-prints all options. If a category is given, only those are shown.
func Show(out io.Writer, category string) {
	w, ok := out.(*tabwriter.Writer)
	if !ok {
		w = new(tabwriter.Writer)
		w.Init(out, 4, 0, 2, ' ', 0)
	}
	for _, opt := range Options {
		for _, r := range strings.Split(opt.Relevance, ",") {
			if category == "" || category == r {
				// -name <prototype>     help
				//                         (default is <default>)
				fmt.Fprintf(w, "  -%s %s\t %s\n", opt.Name, opt.Prototype, opt.Help)
				if opt.Default != "" && opt.Default != false && opt.Default != nil {
					fmt.Fprintf(w, "  \t   (default is %v)\n", opt.Default)
				}
			}
		}
	}
	if !ok {
		w.Flush()
	}
}

// Show pretty-prints all options.
func ShowAll(out io.Writer) {
	Show(out, "")
}
