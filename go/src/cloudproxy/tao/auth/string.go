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

// String returns a pretty-printed Prin.
func (e Prin) String() string {
	return fmt.Sprintf("%v", e)
}

// String returns a pretty-printed PrinExt.
func (e PrinExt) String() string {
	return fmt.Sprintf("%v", e)
}

// String returns a pretty-printed SubPrin.
func (e SubPrin) String() string {
	return fmt.Sprintf("%v", e)
}

// String returns a pretty-printed Int.
func (e Int) String() string {
	return fmt.Sprintf("%v", e)
}

// String returns a pretty-printed Str.
func (e Str) String() string {
	return fmt.Sprintf("%v", e)
}

// String returns a pretty-printed Bytes.
func (e Bytes) String() string {
	return fmt.Sprintf("%v", e)
}

// String returns a pretty-printed TermVar.
func (e TermVar) String() string {
	return fmt.Sprintf("%v", e)
}

// String returns a pretty-printed Pred.
func (e Pred) String() string {
	return fmt.Sprintf("%v", e)
}

// String returns a pretty-printed Const.
func (e Const) String() string {
	return fmt.Sprintf("%v", e)
}

// String returns a pretty-printed Not.
func (e Not) String() string {
	return fmt.Sprintf("%v", e)
}

// String returns a pretty-printed And.
func (e And) String() string {
	return fmt.Sprintf("%v", e)
}

// String returns a pretty-printed Or.
func (e Or) String() string {
	return fmt.Sprintf("%v", e)
}

// String returns a pretty-printed Implies.
func (e Implies) String() string {
	return fmt.Sprintf("%v", e)
}

// String returns a pretty-printed Speaksfor.
func (e Speaksfor) String() string {
	return fmt.Sprintf("%v", e)
}

// String returns a pretty-printed Says.
func (e Says) String() string {
	return fmt.Sprintf("%v", e)
}

// String returns a pretty-printed Forall.
func (e Forall) String() string {
	return fmt.Sprintf("%v", e)
}

// String returns a pretty-printed Exists.
func (e Exists) String() string {
	return fmt.Sprintf("%v", e)
}
