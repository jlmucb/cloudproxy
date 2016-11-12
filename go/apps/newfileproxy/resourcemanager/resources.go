// Copyright (c) 2016, Google, Inc.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// File: resources.go

package resourcemanager;

import (
	// "fmt"
	// "log"
	// "path"
	"time"

	// "github.com/golang/protobuf/proto"
	// "github.com/jlmucb/cloudproxy/go/tao"
	// "github.com/jlmucb/cloudproxy/go/util"
)

func EncodeTime(t time.Time) (string, error) {
	const longForm = "2006-01-02T15:04:05.999999999Z07:00"
	return t.Format(longForm), nil
}

func DecodeTime(s string) (*time.Time, error) {
	const longForm = "2006-01-02T15:04:05.999999999Z07:00"
	tt, err := time.Parse(longForm, s)
	if err != nil {
		return nil, err
	}
	return &tt, nil
}

// MakeCombinedPrincipal
func MakeCombinedPrincipal(appPricipal *string, userPrincipal *string) *CombinedPrincipal {
	return nil
}

// IsOwner
func (info *ResourceInfo) IsOwner(p CombinedPrincipal) bool {
	return false
}

// IsReader
func (info *ResourceInfo) IsReader(p CombinedPrincipal) bool {
	return false
}

// IsWriter
func (info *ResourceInfo) IsWriter(p CombinedPrincipal) bool {
	return false
}

// Add Owner
func (info *ResourceInfo) AddOwner(p CombinedPrincipal) error {
	return nil
}

// Delete Owner
func (info *ResourceInfo) DeleteOwner(p CombinedPrincipal) error {
	return nil
}

// Add Reader
func (info *ResourceInfo) AddReader(p CombinedPrincipal) error {
	return nil
}

// Delete Reader
func (info *ResourceInfo) DeleteReader(p CombinedPrincipal) error {
	return nil
}

// Add Writer
func (info *ResourceInfo) AddWriter(p CombinedPrincipal) error {
	return nil
}

// Delete Writer.
func (info *ResourceInfo) DeleteWriter(p CombinedPrincipal) error {
	return nil
}

// FindResource looks up the resource by its name.
func (m *ResourceMasterInfo) FindResource(resourceName string) *ResourceInfo {
	return nil
}

// InsertResource adds a resource.
func (m *ResourceMasterInfo) InsertResource(info *ResourceInfo) error {
	return nil
}

// DeleteResource deletes a resource.
func (m *ResourceMasterInfo) DeleteResource(resourceName string) error {
	return nil
}

// PrintMaster prints the ResourceMaster into the log.
func (m *ResourceMasterInfo) PrintMaster(printResources bool) {
}

// PrintResource prints a resource to the log.
func (r *ResourceInfo) PrintResource() {
}

// Read causes the bytes of the file to be decrypted and read to the message
// stream. By the time this function is called, the remote principal has already
// been authenticated and the operation has already been authorized.
func (m *ResourceInfo) Read(directory string) ([]byte, error) {
	return nil, nil
}

// Write causes the bytes of the file to be encrypted and integrity-protected
// and written to disk as they are read from the MessageStream.
func (m *ResourceInfo) Write(directory string, fileContents []byte) error {
	return nil
}

