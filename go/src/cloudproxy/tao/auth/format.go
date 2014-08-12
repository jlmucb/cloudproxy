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

package auth

// This file implements Format() functions for pretty-printing elements.
// When printed with format verb %v, the "verbose" long form is used.
// When printed with format verb %s, the "short" elided form is used.
// When printed with other verbs, the output format is unspecified.

import (
	"fmt"
)

// Format outputs a pretty-printed Form or Term.
func format(out fmt.State, verb rune, e AuthLogicElement) {
	if verb == 's' {
		fmt.Fprintf(out, "%s", e.ShortString())
	} else {
		fmt.Fprintf(out, "%s", e.String())
	}
}

// Format outputs a pretty-printed Prin using short or long formats.
func (e Prin) Format(out fmt.State, verb rune) {
	format(out, verb, e)
}

// Format outputs a pretty-printed SubPrin using short or long formats.
func (e Says) Format(out fmt.State, verb rune) {
	format(out, verb, e)
}

// Format outputs a pretty-printed Str using short or long formats.
func (e Str) Format(out fmt.State, verb rune) {
	format(out, verb, e)
}

// Format outputs a pretty-printed Int using short or long formats.
func (e Int) Format(out fmt.State, verb rune) {
	format(out, verb, e)
}

// Format outputs a pretty-printed Pred using short or long formats.
func (e Pred) Format(out fmt.State, verb rune) {
	format(out, verb, e)
}

// Format outputs a pretty-printed Const using short or long formats.
func (e Const) Format(out fmt.State, verb rune) {
	format(out, verb, e)
}

// Format outputs a pretty-printed Not using short or long formats.
func (e Not) Format(out fmt.State, verb rune) {
	format(out, verb, e)
}

// Format outputs a pretty-printed And using short or long formats.
func (e And) Format(out fmt.State, verb rune) {
	format(out, verb, e)
}

// Format outputs a pretty-printed Or using short or long formats.
func (e Or) Format(out fmt.State, verb rune) {
	format(out, verb, e)
}

// Format outputs a pretty-printed Implies using short or long formats.
func (e Implies) Format(out fmt.State, verb rune) {
	format(out, verb, e)
}

// Format outputs a pretty-printed Speaksfor using short or long formats.
func (e Speaksfor) Format(out fmt.State, verb rune) {
	format(out, verb, e)
}

// Format outputs a pretty-printed Says using short or long formats.
func (e Says) Format(out fmt.State, verb rune) {
	format(out, verb, e)
}
