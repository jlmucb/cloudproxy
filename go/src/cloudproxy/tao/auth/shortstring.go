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

import (
	"fmt"
)

// Note: Yes, all of these functions are identical, but I don't see a way of
// making this shorter in Go.

// ShortString returns an elided pretty-printed Prin.
func (e Prin) ShortString() string {
	return fmt.Sprintf("%s", e)
}

// ShortString returns an elided pretty-printed PrinExt.
func (e PrinExt) ShortString() string {
	return fmt.Sprintf("%s", e)
}

// ShortString returns an elided pretty-printed SubPrin.
func (e SubPrin) ShortString() string {
	return fmt.Sprintf("%s", e)
}

// ShortString returns an elided pretty-printed Int.
func (e Int) ShortString() string {
	return fmt.Sprintf("%s", e)
}

// ShortString returns an elided pretty-printed Str.
func (e Str) ShortString() string {
	return fmt.Sprintf("%s", e)
}

// ShortString returns a pretty-printed Bytes.
func (e Bytes) ShortString() string {
	return fmt.Sprintf("%s", e)
}

// ShortString returns an elided pretty-printed TermVar.
func (e TermVar) ShortString() string {
	return fmt.Sprintf("%s", e)
}

// ShortString returns an elided pretty-printed Pred.
func (e Pred) ShortString() string {
	return fmt.Sprintf("%s", e)
}

// ShortString returns an elided pretty-printed Const.
func (e Const) ShortString() string {
	return fmt.Sprintf("%s", e)
}

// ShortString returns an elided pretty-printed Not.
func (e Not) ShortString() string {
	return fmt.Sprintf("%s", e)
}

// ShortString returns an elided pretty-printed And.
func (e And) ShortString() string {
	return fmt.Sprintf("%s", e)
}

// ShortString returns an elided pretty-printed Or.
func (e Or) ShortString() string {
	return fmt.Sprintf("%s", e)
}

// ShortString returns an elided pretty-printed Implies.
func (e Implies) ShortString() string {
	return fmt.Sprintf("%s", e)
}

// ShortString returns an elided pretty-printed Speaksfor.
func (e Speaksfor) ShortString() string {
	return fmt.Sprintf("%s", e)
}

// ShortString returns an elided pretty-printed Says.
func (e Says) ShortString() string {
	return fmt.Sprintf("%s", e)
}

// ShortString returns an elided pretty-printed Forall.
func (e Forall) ShortString() string {
	return fmt.Sprintf("%s", e)
}

// ShortString returns an elided pretty-printed Exists.
func (e Exists) ShortString() string {
	return fmt.Sprintf("%s", e)
}
