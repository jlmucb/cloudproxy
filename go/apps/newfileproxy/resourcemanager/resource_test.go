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

package resourcemanager;

import (
	"fmt"
	"testing"
	"time"
)

func TestTimeEncode(t *testing.T) {
	now := time.Now()
	s, err := EncodeTime(now)
	if err != nil {
		t.Fatal("EncodeTime fails\n")
	}
	fmt.Printf("Encoded time: %s\n", s)
	tt, err := DecodeTime(s)
	if err != nil {
		t.Fatal("DecodeTime fails\n")
	}
	if !now.Equal(*tt) {
		t.Fatal("TestTimeEncode not equal\n")
	}
	fmt.Printf("TestTimeEncode succeeds")
}

func TestResourceInfo(t *testing.T) {
	return
	/*
	time.Now()
	t.String()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)
	ta, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", *obj.NotAfter)
	Time.RFC1123Z
	a := new(PrincipalInfo)
	b := new(ResourceInfo)
	c := new(ResourceMasterInfo)
	*/

	// EncodeTime(t time.Time) (string, error)
	// DecodeTime(s string) (*time.Time, error)
	// t.Fatal("TestResourceInfo fails\n")
	// fmt.Printf("TestResourceInfo succeeds\n")
	// MakeCombinedPrincipal(appPricipal *string, userPrincipal *string) *CombinedPrincipal
	// (info *ResourceInfo) IsOwner(p CombinedPrincipal) bool
	// (info *ResourceInfo) IsReader(p CombinedPrincipal) bool
	// (info *ResourceInfo) IsWriter(p CombinedPrincipal) bool
	// (info *ResourceInfo) AddOwner(p CombinedPrincipal) error
	// (info *ResourceInfo) DeleteOwner(p CombinedPrincipal) error
	// (info *ResourceInfo) AddReader(p CombinedPrincipal) error
	// (info *ResourceInfo) DeleteReader(p CombinedPrincipal) error
	// (info *ResourceInfo) AddWriter(p CombinedPrincipal) error
	// (info *ResourceInfo) DeleteWriter(p CombinedPrincipal) error
	// (m *ResourceMasterInfo) FindResource(resourceName string) *ResourceInfo
	// (m *ResourceMasterInfo) InsertResource(info *ResourceInfo) error
	// (m *ResourceMasterInfo) InsertResource(resourceName string) error
	// (m *ResourceMasterInfo) PrintMaster(printResources bool)
	// (r *ResourceInfo) PrintResource()
	// (m *ResourceInfo) Read(directory string) ([]byte, error)
	// (m *ResourceInfo) Write(directory string, fileContents []byte) error
}
