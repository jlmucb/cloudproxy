// Copyright 2016 The Roughtime Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License. */

// Package monotime provides access to the system's monotonic clock.
package monotime

import (
	"unsafe"
	"time"
)

var _ = unsafe.Sizeof(0)

//go:noescape
//go:linkname nanotime runtime.nanotime
func nanotime() int64

// Now returns the monotonic duration since an unspecified epoch.
func Now() time.Duration {
	return time.Duration(nanotime()) * time.Nanosecond
}
