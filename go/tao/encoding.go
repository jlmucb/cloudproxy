//  Copyright (c) 2016, Google Inc.  All rights reserved.
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

// This file implements encoding/decoding for the cryptographic keys,
// so we can manage them explicitly. When proto.Marshal is called on
// the keys, functions in this file are called.
package tao

import (
	"encoding/binary"

	"github.com/golang/protobuf/proto"
)

func (k *CryptoKey) Marshal() ([]byte, error) {
	buf, err := MakeSensitive(4*3 + 4 + len(k.Key))
	binary.BigEndian.PutUint32(buf[:4], uint32(*(k.Version)))
	binary.BigEndian.PutUint32(buf[4:8], uint32(*(k.Purpose)))
	binary.BigEndian.PutUint32(buf[8:12], uint32(*(k.Algorithm)))
	binary.BigEndian.PutUint32(buf[12:16], uint32(len(k.Key)))
	copy(buf[16:], k.Key)
	return buf, err
}

func (k *CryptoKey) Unmarshal(buf []byte) error {
	k.Reset()
	var err error
	k.Version = CryptoVersion(binary.BigEndian.Uint32(buf[:4])).Enum()
	k.Purpose = CryptoKey_CryptoPurpose(binary.BigEndian.Uint32(buf[4:8])).Enum()
	k.Algorithm = CryptoKey_CryptoAlgorithm(binary.BigEndian.Uint32(buf[8:12])).Enum()
	k.Key, err = MakeSensitive(int(binary.BigEndian.Uint32(buf[12:16])))
	copy(k.Key, buf[16:])
	return err
}

func (k *CryptoKeyset) Marshal() ([]byte, error) {
	var err error
	keys := make([][]byte, len(k.Keys))
	for k, key := range k.Keys {
		keys[k], err = proto.Marshal(key)
		if err != nil {
			return nil, err
		}
		defer ClearSensitive(keys[k])
	}

	// Delegation is not sensitive, so no need to clear sensitive
	db := []byte{}
	if k.Delegation != nil {
		db, err = proto.Marshal(k.Delegation)
		if err != nil {
			return nil, err
		}
	}

	size := 4 + 4*len(k.Keys) + 4
	for _, key := range keys {
		size += len(key)
	}
	size += len(db)

	buf, err := MakeSensitive(size)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(buf[:4], uint32(len(keys)))
	idx := 4
	for _, key := range keys {
		binary.BigEndian.PutUint32(buf[idx:idx+4], uint32(len(key)))
		idx += 4
		if key != nil {
			copy(buf[idx:idx+len(key)], key)
			idx += len(key)
		}
	}
	binary.BigEndian.PutUint32(buf[idx:idx+4], uint32(len(db)))
	if k.Delegation != nil {
		idx += 4
		copy(buf[idx:idx+len(db)], db)
	}

	return buf, err
}

func (k *CryptoKeyset) Unmarshal(buf []byte) error {
	k.Reset()
	var err error

	size := binary.BigEndian.Uint32(buf[:4])
	idx := 4
	kbs := make([]*CryptoKey, size)
	for k := range kbs {
		size = binary.BigEndian.Uint32(buf[idx : idx+4])
		idx += 4
		if size > 0 {
			key, err := MakeSensitive(int(size))
			if err != nil {
				return err
			}
			defer ClearSensitive(key)
			copy(key, buf[idx:idx+int(size)])
			idx += int(size)
			kbs[k] = &CryptoKey{}
			err = proto.Unmarshal(key, kbs[k])
			if err != nil {
				return err
			}
		}
	}
	size = binary.BigEndian.Uint32(buf[idx : idx+4])
	idx += 4
	if size > 0 {
		db := make([]byte, size)
		copy(db, buf[idx:idx+int(size)])
		k.Delegation = &Attestation{}
		err = proto.Unmarshal(db, k.Delegation)
	}
	k.Keys = kbs

	return err
}

func (k *AES_CTR_HMAC_SHA_CryptingKeyV1) Marshal() ([]byte, error) {
	buf, err := MakeSensitive(4*3 + len(k.AesPrivate) + len(k.HmacPrivate))
	if err != nil {
		return nil, err
	}
	idx := 0
	binary.BigEndian.PutUint32(buf[idx:idx+4], uint32(*k.Mode))
	idx += 4
	binary.BigEndian.PutUint32(buf[idx:idx+4], uint32(len(k.AesPrivate)))
	idx += 4
	copy(buf[idx:idx+len(k.AesPrivate)], k.AesPrivate)
	idx += len(k.AesPrivate)
	binary.BigEndian.PutUint32(buf[idx:idx+4], uint32(len(k.HmacPrivate)))
	idx += 4
	copy(buf[idx:idx+len(k.HmacPrivate)], k.HmacPrivate)

	return buf, err
}

func (k *AES_CTR_HMAC_SHA_CryptingKeyV1) Unmarshal(buf []byte) error {
	k.Reset()
	idx := 0
	k.Mode = CryptoCipherMode(int32(binary.BigEndian.Uint32(buf[idx : idx+4]))).Enum()
	idx += 4
	size := int(binary.BigEndian.Uint32(buf[idx : idx+4]))
	idx += 4
	aesKey, err := MakeSensitive(size)
	if err != nil {
		return err
	}
	copy(aesKey, buf[idx:idx+size])
	idx += size

	size = int(binary.BigEndian.Uint32(buf[idx : idx+4]))
	idx += 4
	hmacKey, err := MakeSensitive(size)
	if err != nil {
		return err
	}
	copy(hmacKey, buf[idx:idx+size])

	k.AesPrivate = aesKey
	k.HmacPrivate = hmacKey

	return nil
}

func (k *ECDSA_SHA_SigningKeyV1) Marshal() ([]byte, error) {
	buf, err := MakeSensitive(4*3 + len(k.EcPrivate) + len(k.EcPublic))
	if err != nil {
		return nil, err
	}
	idx := 0
	binary.BigEndian.PutUint32(buf[idx:idx+4], uint32(*k.Curve))
	idx += 4
	binary.BigEndian.PutUint32(buf[idx:idx+4], uint32(len(k.EcPrivate)))
	idx += 4
	copy(buf[idx:idx+len(k.EcPrivate)], k.EcPrivate)
	idx += len(k.EcPrivate)
	binary.BigEndian.PutUint32(buf[idx:idx+4], uint32(len(k.EcPublic)))
	idx += 4
	copy(buf[idx:idx+len(k.EcPublic)], k.EcPublic)

	return buf, err
}

func (k *ECDSA_SHA_SigningKeyV1) Unmarshal(buf []byte) error {
	k.Reset()
	idx := 0
	k.Curve = NamedEllipticCurve(int32(binary.BigEndian.Uint32(buf[idx : idx+4]))).Enum()
	idx += 4
	size := int(binary.BigEndian.Uint32(buf[idx : idx+4]))
	idx += 4
	private, err := MakeSensitive(size)
	if err != nil {
		return err
	}
	copy(private, buf[idx:idx+size])
	idx += size

	size = int(binary.BigEndian.Uint32(buf[idx : idx+4]))
	idx += 4
	public, err := MakeSensitive(size)
	if err != nil {
		return err
	}
	copy(public, buf[idx:idx+size])

	k.EcPrivate = private
	k.EcPublic = public

	return nil
}

func (k *HMAC_SHA_DerivingKeyV1) Marshal() ([]byte, error) {
	buf, err := MakeSensitive(4*2 + len(k.HmacPrivate))
	if err != nil {
		return nil, err
	}
	idx := 0
	binary.BigEndian.PutUint32(buf[idx:idx+4], uint32(*k.Mode))
	idx += 4
	binary.BigEndian.PutUint32(buf[idx:idx+4], uint32(len(k.HmacPrivate)))
	idx += 4
	copy(buf[idx:idx+len(k.HmacPrivate)], k.HmacPrivate)

	return buf, err
}

func (k *HMAC_SHA_DerivingKeyV1) Unmarshal(buf []byte) error {
	k.Reset()
	idx := 0
	k.Mode = CryptoDerivingMode(int32(binary.BigEndian.Uint32(buf[idx : idx+4]))).Enum()
	idx += 4
	size := int(binary.BigEndian.Uint32(buf[idx : idx+4]))
	idx += 4
	private, err := MakeSensitive(size)
	if err != nil {
		return err
	}
	copy(private, buf[idx:idx+size])

	k.HmacPrivate = private

	return nil
}
