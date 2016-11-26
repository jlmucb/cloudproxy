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

package resourcemanager

import (
	"fmt"
	"io/ioutil"
	"path"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/apps/simpleexample/taosupport"
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

// MakeCombinedPrincipalFromOne
func MakeCombinedPrincipalFromOne(appPrincipal *PrincipalInfo) *CombinedPrincipal {
	cp := new(CombinedPrincipal)
	cp.Principals = append(cp.Principals, appPrincipal)
	return cp
}

// MakeCombinedPrincipalFromTwo
func MakeCombinedPrincipalFromTwo(appPrincipal *PrincipalInfo, userPrincipal *PrincipalInfo) *CombinedPrincipal {
	cp := new(CombinedPrincipal)
	cp.Principals = append(cp.Principals, appPrincipal)
	cp.Principals = append(cp.Principals, userPrincipal)
	return cp
}

func SameCombinedPrincipal(p1 CombinedPrincipal, p2 CombinedPrincipal) bool {
	if len(p1.Principals) != len(p2.Principals) {
		return false
	}
	for i := 0; i < len(p1.Principals); i++ {
		if *p1.Principals[i].Name != *p2.Principals[i].Name {
			return false
		}
	}
	return true
}

// Add Owner
func (info *ResourceInfo) AddOwner(p CombinedPrincipal, mutex *sync.RWMutex) error {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}
	info.Owners = append(info.Owners, &p)
	return nil
}

// Add Reader
func (info *ResourceInfo) AddReader(p CombinedPrincipal, mutex *sync.RWMutex) error {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}
	info.Readers = append(info.Readers, &p)
	return nil
}

// Add Writer
func (info *ResourceInfo) AddWriter(p CombinedPrincipal, mutex *sync.RWMutex) error {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}
	info.Writers = append(info.Writers, &p)
	return nil
}

// FindCombinedPrincipalPosition looks up the resource by its name and returns position in stack.
func FindCombinedPrincipalPosition(toFind CombinedPrincipal, cpList []*CombinedPrincipal) int {
	// No mutex is needed since enclosing function should lock.
	for i := 0; i < len(cpList); i++ {
		if SameCombinedPrincipal(toFind, *cpList[i]) {
			return i
		}
	}
	return -1
}
// TODO(jlm): add test
// Delete Owner
func (info *ResourceInfo) DeleteOwner(p CombinedPrincipal, mutex *sync.RWMutex) error {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}
	n := FindCombinedPrincipalPosition(p, info.Owners)
	if n < 0 {
		return nil
	}
	info.Owners[n] = info.Owners[len(info.Owners)-1]
	info.Owners = info.Owners[:len(info.Owners)-1]
	return nil
}
// TODO(jlm): add test
// Delete Reader
func (info *ResourceInfo) DeleteReader(p CombinedPrincipal, mutex *sync.RWMutex) error {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}
	n := FindCombinedPrincipalPosition(p, info.Readers)
	if n < 0 {
		return nil
	}
	info.Readers[n] = info.Readers[len(info.Readers)-1]
	info.Readers = info.Readers[:len(info.Readers)-1]
	return nil
}

// TODO(jlm): add test
// Delete Writer.
func (info *ResourceInfo) DeleteWriter(p CombinedPrincipal, mutex *sync.RWMutex) error {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}
	n := FindCombinedPrincipalPosition(p, info.Writers)
	if n < 0 {
		return nil
	}
	// TODO(jlm): add test
	info.Writers[n] = info.Writers[len(info.Owners)-1]
	info.Writers = info.Writers[:len(info.Owners)-1]
	return nil
}

// FindResource looks up the resource by its name.
func (m *ResourceMasterInfo) FindResource(resourceName string, mutex *sync.RWMutex) *ResourceInfo {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}
	for i := 0; i < len(m.Resources); i++ {
		if *m.Resources[i].Name == resourceName {
			return m.Resources[i]
		}
	}
	return nil
}

// InsertResource adds a resource.
func (m *ResourceMasterInfo) InsertResource(info *ResourceInfo, mutex *sync.RWMutex) error {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}
	l := m.FindResource(*info.Name, nil)
	if l != nil {
		return nil
	}
	m.Resources = append(m.Resources, info)
	return nil
}

// DeleteResource deletes a resource.
func (m *ResourceMasterInfo) DeleteResource(resourceName string, mutex *sync.RWMutex) error {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}
	return nil
}

func (p *PrincipalInfo) PrintPrincipal() {
	if p.Name == nil || p.Cert == nil {
		return
	}
	fmt.Printf("Name: %s\nCertificate: %x\n", *p.Name, p.Cert)
}

func (cp *CombinedPrincipal) PrintCombinedPrincipal() {
	if cp == nil {
		return
	}
	// principals
	for i := 0; i < len(cp.Principals); i++ {
		cp.Principals[i].PrintPrincipal()
	}
}

func PrintPrincipalList(pl []*CombinedPrincipal) {
	if pl == nil {
		fmt.Printf("Empty\n")
		return
	}
	for i := 0; i < len(pl); i++ {
		pl[i].PrintCombinedPrincipal()
		fmt.Printf("\n")
	}
}

// PrintResource prints a resource to the log.
func (r *ResourceInfo) PrintResource(directory string, printContents bool) {
	if r == nil {
		return
	}
	fmt.Printf("\n")
	if r.Name != nil {
		fmt.Printf("Name: %s\n", *r.Name)
	} else {
		fmt.Printf("Name: empty\n");
	}
	if r.Type!= nil {
	fmt.Printf("Type: %d, ", *r.Type)
	} else {
		fmt.Printf("Type: empty, ");
	}
	if r.Size!= nil {
		fmt.Printf("size: %d\n", *r.Size)
	} else {
		fmt.Printf("Size: empty\n");
	}
	if r.DateCreated != nil && r.DateModified != nil {
		fmt.Printf("Created: %s, modified: %s\n", *r.DateCreated, *r.DateModified)
	} else {
		fmt.Printf("Created adn Modified names are empty\n")
	}
	fmt.Printf("Owners: \n")
	PrintPrincipalList(r.Owners)
	fmt.Printf("Readers: \n")
	PrintPrincipalList(r.Readers)
	fmt.Printf("Writers:\n")
	PrintPrincipalList(r.Writers)
	if printContents {
		fileName := path.Join(directory, *r.Name)
		contents, err := r.Read(fileName)
		if err != nil {
			fmt.Printf("File: %s\n", contents)
		}
	}
	fmt.Printf("\n")
}

// PrintMaster prints the ResourceMaster into the log.
func (m *ResourceMasterInfo) PrintMaster(printResources bool) {
	fmt.Printf("ServiceName: %s\n", *m.ServiceName)
	fmt.Printf("BaseDirectoryName: %s\n", *m.BaseDirectoryName)
	fmt.Printf("PolicyCert: %s\n", m.PolicyCert)
	fmt.Printf("Number of resources: %d\n", len(m.Resources))
	if printResources {
		for i := 0; i < len(m.Resources); i++ {
			m.Resources[i].PrintResource(*m.BaseDirectoryName, true)
			fmt.Printf("\n")
		}
	}
}

// Read causes the bytes of the file to be decrypted and read to the message
// stream. By the time this function is called, the remote principal has already
// been authenticated and the operation has already been authorized.
func (r *ResourceInfo) Read(directory string) ([]byte, error) {
	var err error
	var out []byte
	filename := path.Join(directory, *r.Name)
	bytes_read, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if len(r.Keys) >= 32 {
		out, err = taosupport.Unprotect(r.Keys, bytes_read)
	} else {
		out = bytes_read
	}
	size := int32(len(out))
	if err == nil {
		r.Size = &size
	}
	return out, err
}

// Write causes the bytes of the file to be encrypted and integrity-protected
// and written to disk as they are read from the MessageStream.
func (r *ResourceInfo) Write(directory string, fileContents []byte) error {
	filename := path.Join(directory, *r.Name)
	if len(r.Keys) >= 32 {
		// Encrypt
		encrypted, err := taosupport.Protect(r.Keys, fileContents)
		if err != nil {
		}
		err = ioutil.WriteFile(filename, encrypted, 0644)
		if err == nil {
			size := int32(len(fileContents))
			r.Size = &size
		}
		return err
	} else {
		err := ioutil.WriteFile(filename, fileContents, 0644)
		if err == nil {
			size := int32(len(fileContents))
			r.Size = &size
		}
		return err
	}
}

func ReadTable(table *ResourceMasterInfo, tableFileName string, fileSecrets []byte, mutex *sync.RWMutex) bool {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}
	encryptedTable, err := ioutil.ReadFile(tableFileName)
	if err == nil {
		serializedTable, err := taosupport.Unprotect(fileSecrets, encryptedTable)
		if err != nil {
			return false
		}
		err = proto.Unmarshal(serializedTable, table)
		if err != nil {
			return false
		}
	}
	return true
}

func SaveTable(table *ResourceMasterInfo, tableFileName string, fileSecrets []byte, mutex *sync.RWMutex) bool {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}
	serializedTable, err := proto.Marshal(table)
	if err != nil {
		return false
	}
	encryptedTable, err := taosupport.Unprotect(fileSecrets, serializedTable)
	if err != nil {
		return false
	}	
	err = ioutil.WriteFile(tableFileName, encryptedTable, 0666)
	if err != nil {
		return false
	}	
	return true
}
