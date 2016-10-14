// Copyright (c) 2016, Google Inc. All rights reserved.
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

package mixnet

import "errors"

const (
	// CellBytes specifies the length of a cell.
	CellBytes = 1 << 10

	// MaxMsgBytes specifies the maximum length of a message.
	MaxMsgBytes = 1 << 16
)

const (
	msgCell = iota
	dirCell
)

const (
	ID_SIZE  = 8
	LEN_SIZE = 8
)

const (
	ID   = 0
	TYPE = ID + ID_SIZE
	BODY = 9
)

var errCellLength = errors.New("incorrect cell length")
var errCellType = errors.New("incorrect cell type")
var errBadCellType = errors.New("unrecognized cell type")
var errBadDirective = errors.New("received bad directive")
var errMsgLength = errors.New("message too long")

var dirCreated = &Directive{Type: DirectiveType_CREATED.Enum()}
var dirDestroy = &Directive{Type: DirectiveType_DESTROY.Enum()}
var dirDestroyed = &Directive{Type: DirectiveType_DESTROYED.Enum()}
