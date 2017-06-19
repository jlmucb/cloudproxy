//  Copyright (c) 2017, John Manferdelli, All rights reserved.
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

package tao

func ptrFromString(str string) *string {
	return &str
}

func CrypterTypeFromSuiteName(suiteName string) *string {
	switch suiteName {
	case Basic128BitCipherSuite:
		return ptrFromString("aes128-ctr-hmacsha256")
	case Basic256BitCipherSuite:
		return ptrFromString("aes256-ctr-hmacsha384")
	default:
		return nil
	}
	return nil
}

func SignerTypeFromSuiteName(suiteName string) *string {
	switch suiteName {
	case Basic128BitCipherSuite:
		return ptrFromString("ecdsap256")
	case Basic256BitCipherSuite:
		return ptrFromString("ecdsap384")
	default:
		return nil
	}
	return nil
}

func DeriverTypeFromSuiteName(suiteName string) *string {
	switch suiteName {
	case Basic128BitCipherSuite, Basic256BitCipherSuite:
		return ptrFromString("hdkf-sha256")
	default:
		return nil
	}
	return nil
}

func HmacTypeFromSuiteName(suiteName string) *string {
	switch suiteName {
	case Basic128BitCipherSuite:
		return ptrFromString("hmacsha256")
	case Basic256BitCipherSuite:
		return ptrFromString("hmacsha384")
	default:
		return nil
	}
	return nil
}
