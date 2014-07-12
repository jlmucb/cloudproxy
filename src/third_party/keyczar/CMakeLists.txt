# Copyright 2014 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set(SD ${CMAKE_CURRENT_SOURCE_DIR}/cpp/src)
set(KSD ${SD}/keyczar)
set(OSD ${KSD}/openssl)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-function -Wno-unused-variable -Wno-sign-compare")
include_directories(${SD})

set(KEYCZAR_SOURCES
    ${KSD}/aes_key.cc
    ${KSD}/cipher_mode.cc
    ${KSD}/crypto_factory.cc
    ${KSD}/dsa_private_key.cc
    ${KSD}/dsa_public_key.cc
    ${KSD}/ecdsa_impl.cc
    ${KSD}/ecdsa_private_key.cc
    ${KSD}/ecdsa_public_key.cc
    ${KSD}/hmac_impl.cc
    ${KSD}/hmac_key.cc
    ${KSD}/key.cc
    ${KSD}/keyczar.cc
    ${KSD}/key_purpose.cc
    ${KSD}/keyset.cc
    ${KSD}/keyset_metadata.cc
    ${KSD}/key_status.cc
    ${KSD}/key_type.cc
    ${KSD}/key_util.cc
    ${KSD}/message_digest_impl.cc
    ${KSD}/pbe_impl.cc
    ${KSD}/private_key.cc
    ${KSD}/public_key.cc
    ${KSD}/rsa_private_key.cc
    ${KSD}/rsa_public_key.cc
    ${KSD}/secret_key.cc
    ${KSD}/session.cc
    ${KSD}/util.cc
    ${KSD}/base/base64w.cc
    ${KSD}/base/command_line.cc
    ${KSD}/base/file_path.cc
    ${KSD}/base/file_util.cc
    ${KSD}/base/file_util_posix.cc
    ${KSD}/base/json_reader.cc
    ${KSD}/base/json_value_serializer.cc
    ${KSD}/base/json_writer.cc
    ${KSD}/base/logging.cc
    ${KSD}/base/ref_counted.cc
    ${KSD}/base/stl_util-inl.cc
    ${KSD}/base/string_escape.cc
    ${KSD}/base/string_util.cc
    ${KSD}/base/values.cc
    ${KSD}/base/zlib.cc
    ${KSD}/base/modp/modp_b64w.cc
    ${KSD}/rw/keyset_encrypted_file_reader.cc
    ${KSD}/rw/keyset_encrypted_file_writer.cc
    ${KSD}/rw/keyset_file_reader.cc
    ${KSD}/rw/keyset_file_writer.cc
    ${KSD}/rw/keyset_reader.cc
    ${KSD}/rw/keyset_writer.cc
    ${OSD}/aes.cc
    ${OSD}/dsa.cc
    ${OSD}/ecdsa.cc
    ${OSD}/hmac.cc
    ${OSD}/message_digest.cc
    ${OSD}/pbe.cc
    ${OSD}/rand.cc
    ${OSD}/rsa.cc
    ${OSD}/util.cc
   )

set(KEYCZAR_HEADERS
    ${KSD}/aes_impl.h
    ${KSD}/aes_key.h
    ${KSD}/cipher_mode.h
    ${KSD}/crypto_factory.h
    ${KSD}/dsa_impl.h
    ${KSD}/dsa_private_key.h
    ${KSD}/dsa_public_key.h
    ${KSD}/ecdsa_impl.h
    ${KSD}/ecdsa_private_key.h
    ${KSD}/ecdsa_public_key.h
    ${KSD}/hmac_impl.h
    ${KSD}/hmac_key.h
    ${KSD}/keyczar.h
    ${KSD}/key.h
    ${KSD}/key_purpose.h
    ${KSD}/keyset.h
    ${KSD}/keyset_metadata.h
    ${KSD}/key_status.h
    ${KSD}/key_type.h
    ${KSD}/key_util.h
    ${KSD}/message_digest_impl.h
    ${KSD}/pbe_impl.h
    ${KSD}/private_key.h
    ${KSD}/public_key.h
    ${KSD}/rand_impl.h
    ${KSD}/rsa_impl.h
    ${KSD}/rsa_private_key.h
    ${KSD}/rsa_public_key.h
    ${KSD}/secret_key.h
    ${KSD}/session.h
    ${KSD}/util.h
    ${KSD}/base/base64w.h
    ${KSD}/base/basictypes.h
    ${KSD}/base/build_config.h
    ${KSD}/base/command_line.h
    ${KSD}/base/compiler_specific.h
    ${KSD}/base/file_path.h
    ${KSD}/base/file_util.h
    ${KSD}/base/json_reader.h
    ${KSD}/base/json_value_serializer.h
    ${KSD}/base/json_writer.h
    ${KSD}/base/logging.h
    ${KSD}/base/observer_list.h
    ${KSD}/base/port.h
    ${KSD}/base/ref_counted.h
    ${KSD}/base/scoped_handle.h
    ${KSD}/base/scoped_handle_win.h
    ${KSD}/base/scoped_ptr.h
    ${KSD}/base/stl_util-inl.h
    ${KSD}/base/string_escape.h
    ${KSD}/base/string_util.h
    ${KSD}/base/string_util_posix.h
    ${KSD}/base/string_util_win.h
    ${KSD}/base/values.h
    ${KSD}/base/zlib.h
    ${KSD}/base/modp/modp_b64w_data.h
    ${KSD}/base/modp/modp_b64w.h
    ${KSD}/rw/keyset_encrypted_file_reader.h
    ${KSD}/rw/keyset_encrypted_file_writer.h
    ${KSD}/rw/keyset_file_reader.h
    ${KSD}/rw/keyset_file_writer.h
    ${KSD}/rw/keyset_reader.h
    ${KSD}/rw/keyset_writer.h
    ${OSD}/aes.h
    ${OSD}/dsa.h
    ${OSD}/ecdsa.h
    ${OSD}/hmac.h
    ${OSD}/message_digest.h
    ${OSD}/pbe.h
    ${OSD}/rand.h
    ${OSD}/rsa.h
    ${OSD}/util.h
   )

add_library(keyczar STATIC ${KEYCZAR_SOURCES} ${KEYCZAR_HEADERS})

# TODO(tmroeder): there's a way to add an OpenSSL dependency, like FindOpenSSL.
target_link_libraries(keyczar crypto)
