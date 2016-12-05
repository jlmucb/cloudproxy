// Copyright (c) 2016, Google, Inc.  All rights reserved.
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

// This file contains all the constants used in Tao
package tao

// Rollback related consts
const (
	RB_IV       = 16
	RB_AESKEY   = 16
	RB_HMACKEY  = 32
	RB_KEY_LEN  = 32
	RB_HMAC     = 32
	RB_OVERHEAD = RB_HMAC + RB_IV
)
