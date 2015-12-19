// Copyright (c) 2014, Google Inc. All rights reserved.
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

package tpm

// TPM generated
const(
	ordTPM_GENERATED_VALUE uint32 = 0xff544347
)

// Supported Algorithms.
const(
	algTPM_ALG_RSA      uint16 = 0x0001
	algTPM_ALG_SHA1     uint16 = 0x0004
	algTPM_ALG_AES      uint16 = 0x0006
	algTPM_ALG_SHA256   uint16 = 0x000B
	algTPM_ALG_SHA384   uint16 = 0x000C
	algTPM_ALG_SHA512   uint16 = 0x000D
	algTPM_ALG_NULL     uint16 = 0x0010
	algTPM_ALG_RSASSA   uint16 = 0x0014
	algTPM_ALG_RSAES    uint16 = 0x0015
	algTPM_ALG_RSAPSS   uint16 = 0x0016
	algTPM_ALG_OAEP     uint16 = 0x0017
	algTPM_ALG_ECDSA    uint16 = 0x0018
	algTPM_ALG_ECDH     uint16 = 0x0019
	algTPM_ALG_ECDAA    uint16 = 0x001A
	algTPM_ALG_ECC      uint16 = 0x0023
	algTPM_ALG_CTR      uint16 = 0x0040
	algTPM_ALG_OFB      uint16 = 0x0041
	algTPM_ALG_CBC      uint16 = 0x0042
	algTPM_ALG_CFB      uint16 = 0x0043
	algTPM_ALG_ECB      uint16 = 0x0044
	algTPM_ALG_LAST     uint16 = 0x0044
)

// Policy
const(
	ordTPM_SE_POLICY  uint8 = 0x01
)

// Reserved Handles and Properties
const(
	ordTPM_RH_OWNER            uint32 = 0x40000001
	ordTPM_RH_REVOKE           uint32 = 0x40000002
	ordTPM_RH_TRANSPORT        uint32 = 0x40000003
	ordTPM_RH_OPERATOR         uint32 = 0x40000004
	ordTPM_RH_ADMIN            uint32 = 0x40000005
	ordTPM_RH_EK               uint32 = 0x40000006
	ordTPM_RH_NULL             uint32 = 0x40000007
	ordTPM_RH_UNASSIGNED       uint32 = 0x40000008
	ordTPM_RS_PW               uint32 = 0x40000009
	ordTPM_RH_LOCKOUT          uint32 = 0x4000000A
	ordTPM_RH_ENDORSEMENT      uint32 = 0x4000000B
	ordTPM_RH_PLATFORM         uint32 = 0x4000000C
	ordTPM_CAP_TPM_PROPERTIES  uint32 = 0x00000006
	ordTPM_CAP_HANDLES         uint32 = 0x00000001
)

// Tags
const(
	tagNO_SESSIONS uint16 = 0x8001
	tagSESSIONS    uint16 = 0x8002
)

// Supported TPM operations.
const (
	cmdEvictControl            uint32 = 0x00000120
	cmdClockSet                uint32 = 0x00000128
	cmdPCR_Allocate            uint32 = 0x0000012B
	cmdCreatePrimary           uint32 = 0x00000131
	cmdCreate                  uint32 = 0x00000153
	cmdStirRandom              uint32 = 0x00000146
	cmdActivateCredential      uint32 = 0x00000147
	cmdCertify                 uint32 = 0x00000148
	cmdLoad                    uint32 = 0x00000157
	cmdQuote                   uint32 = 0x00000158
	cmdUnseal                  uint32 = 0x0000015E
	cmdContextLoad             uint32 = 0x00000161
	cmdContextSave             uint32 = 0x00000162
	cmdFlushContext            uint32 = 0x00000165
	cmdLoadExternal            uint32 = 0x00000167
	cmdMakeCredential          uint32 = 0x00000168
	cmdReadPublic              uint32 = 0x00000173
	cmdStartAuthSession        uint32 = 0x00000176
	cmdGetCapability           uint32 = 0x0000017A
	cmdGetRandom               uint32 = 0x0000017B
	cmdPCR_Read                uint32 = 0x0000017E
	cmdPolicyPCR               uint32 = 0x0000017F
	cmdReadClock               uint32 = 0x00000181
	cmdPCR_Extend              uint32 = 0x00000182
	cmdPolicyGetDigest         uint32 = 0x00000189
	cmdPolicyPassword          uint32 = 0x0000018C
)

const maxTPMResponse = 4096

