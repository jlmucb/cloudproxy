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
	"bytes"
	"fmt"
	"io"
	"reflect"
)

// PrintAsConfig prints s, a struct, using git-style config file syntax. Only
// the exported fields of s are printed, and only those fields that are either
// builtin types (int, string, etc.) or structs, or aliases of those. For nested
// structs, only builtin types are printed, all grouped under a "[section]"
// header.
func PrintAsGitConfig(out io.Writer, s interface{}, comment string) error {
	if reflect.ValueOf(s).Kind() != reflect.Struct {
		return fmt.Errorf("not a struct: %s", reflect.TypeOf(s))
	}
	fmt.Fprintf(out, "# %s\n", comment)
	return gitConfigDump(out, 0, "", s)
}

func gitConfigDump(out io.Writer, depth int, name string, s interface{}) error {
	v := reflect.ValueOf(s)
	if s == reflect.Zero(v.Type()).Interface() {
		return nil
	}
	switch v.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64, reflect.String:
		fmt.Fprintf(out, "%s = %v\n", name, v)
	case reflect.Struct:
		if depth > 1 {
			return fmt.Errorf("double-nested struct: %s", name)
		}
		section := new(bytes.Buffer)
		for i := 0; i < v.NumField(); i++ {
			typ := v.Type()
			err := gitConfigDump(section, depth+1, typ.Field(i).Name, v.Field(i).Interface())
			if err != nil {
				return err
			}
		}
		contents := section.String()
		if depth > 0 && len(contents) > 0 {
			fmt.Fprintf(out, "\n[%s]\n", name)
		}
		fmt.Fprint(out, contents)
	default:
		return fmt.Errorf("incompatable type: %v", v.Kind())
	}
	return nil
}
