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

package util

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang/glog"
)

// WritePath writes data to a file after creating any necessary directories.
func WritePath(path string, data []byte, dirPerm, filePerm os.FileMode) error {
	dir := filepath.Dir(path)
	err := os.MkdirAll(dir, dirPerm)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, data, filePerm)
}

// CreatePath creates a file after creating any necessary directories.
func CreatePath(path string, dirPerm, filePerm os.FileMode) (*os.File, error) {
	dir := filepath.Dir(path)
	err := os.MkdirAll(dir, dirPerm)
	if err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, filePerm)
}

// FindExecutable searches for an executable in a path. If the name is
// already an absolute  slash, the search path is ignored. If the search fails,
// emptystring is returned.
func FindExecutable(name string, dirs []string) string {
	if filepath.IsAbs(name) {
		// For absolute names, the file need not be executable
		return name
	}
	for _, dir := range dirs {
		path := filepath.Join(dir, name)
		if IsExecutable(path) {
			return path
		}
	}
	return ""
}

// SystemPath returns the elements of $PATH
func SystemPath() []string {
	var dirs []string
	if pathenv := os.Getenv("PATH"); pathenv != "" {
		for _, dir := range strings.Split(pathenv, ":") {
			if dir == "" {
				dir = "." // Unix shell semantics: "" in $PATH means "."
			}
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// GoBinPath returns dir/bin for each dir in $GOPATH
func GoBinPath() []string {
	var dirs []string
	gopath := os.Getenv("GOPATH")
	if gopath != "" {
		for _, dir := range strings.Split(gopath, ":") {
			dirs = append(dirs, dir+"/bin")
		}
	}
	return dirs
}

// LocalPath returns the directory of the current executable
func LocalPath() []string {
	path, err := filepath.Abs(os.Args[0])
	if err != nil {
		glog.Errorf("%v: Can't get path of '%s'", err, os.Args[0])
		return nil
	} else {
		return []string{filepath.Dir(path)}
	}
}

// LiberalSearchPath returns LocalPath, GoBinPath, and SystemPath together, in
// that order.
func LiberalSearchPath() []string {
	var dirs []string
	dirs = append(dirs, LocalPath()...)
	dirs = append(dirs, GoBinPath()...)
	dirs = append(dirs, SystemPath()...)
	return dirs
}

// IsExecutable checks whether the file has an executable bits set.
func IsExecutable(file string) bool {
	d, err := os.Stat(file)
	return err == nil && !d.Mode().IsDir() && d.Mode()&0111 != 0
}

// IsDir checks whether the path is a directory.
func IsDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
