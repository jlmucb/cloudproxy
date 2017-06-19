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

package tao;

func CrypterTypeFromSuiteName(suiteName string) *string {
	switch(suiteName) {
	case Basic128BitCipherSuite:
		return "aes128-ctr-hmacsha256"
	case Basic256BitCipherSuite:
		return "aes256-ctr-hmacsha384"
	default:
		return nil
	}
	return nil
}

func SignerTypeFromSuiteName(suiteName string) *string {
	switch(suiteName) {
	case Basic128BitCipherSuite:
		return "ecdsap256"
	case Basic256BitCipherSuite:
		return "ecdsap384"
	default:
		return nil
	}
	return nil
}

func DeriverTypeFromSuiteName(suiteName string) *string {
	switch(suiteName) {
	case Basic128BitCipherSuite, case Basic256BitCipherSuite:
		return "hdkf-sha256"
	default:
		return nil
	}
	return nil
}

func HmacTypeFromSuiteName(suiteName string) *string {
	switch(suiteName) {
	case Basic128BitCipherSuite:
		return "hmacsha256"
	case Basic256BitCipherSuite:
		return "hmacsha384"
	default:
		return nil
	}
	return nil
}

