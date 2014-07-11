//  File: util.h
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Useful functions for CloudProxy
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
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
#ifndef CLOUDPROXY_UTIL_H_
#define CLOUDPROXY_UTIL_H_

// #include <stdio.h>

/// These basic utilities from the standard library are used extensively
/// throughout the CloudProxy implementation, so we include them here.
#include <list>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <openssl/ssl.h>

/// Tao provides utilities that are used extensively throughout the CloudProxy
/// implementation, so we include it here.
#include "tao/util.h"

namespace tao {
class Signer;
}

namespace cloudproxy {
/// These Tao, third-party, and standard library utilities are used extensively
/// throughout the CloudProxy implementation, so import them into the cloudproxy
/// namespace here.
/// @{

using std::list;
using std::set;
using std::string;
using std::stringstream;
using std::unique_ptr;
// using std::make_unique;  // see tao::make_unique()

using chromium::base::CreateDirectory;    // NOLINT
using chromium::base::FilePath;           // NOLINT
using chromium::base::ReadFileToString;   // NOLINT
using chromium::base::DeleteFile;         // NOLINT
using chromium::base::DirectoryExists;    // NOLINT
using chromium::base::PathExists;         // NOLINT
using chromium::base::WriteStringToFile;  // NOLINT

using tao::Base64WDecode;     // NOLINT
using tao::Base64WEncode;     // NOLINT
using tao::ScopedSafeString;  // NOLINT
using tao::make_unique;       // NOLINT
using tao::unique_free_ptr;   // NOLINT

/// @}


/// Clean up an OpenSSL SSL connection.
/// @param ssl The connection to clean up.
void ssl_cleanup(SSL *ssl);

/// A smart pointer to an OpenSSL SSL_CTX.
typedef unique_free_ptr<SSL_CTX, SSL_CTX_free> ScopedSSLCtx;

/// A smart pointer to an SSL object.
typedef unique_free_ptr<SSL, ssl_cleanup> ScopedSSL;

/// Prepare an SSL_CTX for a server to accepts connections from clients.
/// Peer certificates will be required.
/// @param key The private signing key and x509 certificate to use.
/// @param cert A serialized PEM-format x509 certificate for the key.
/// @param ctx The OpenSSL context to prepare.
bool SetUpSSLServerCtx(const tao::Signer &key, const string &cert,
                       ScopedSSLCtx *ctx);

/// Prepare an SSL_CTX for a client to connect to a server.
/// @param key The private signing key and x509 certificate to use.
/// @param ctx The OpenSSL context to prepare.
bool SetUpSSLClientCtx(const tao::Signer &key, const string &cert,
                       ScopedSSLCtx *ctx);

}  // namespace cloudproxy
#endif  // CLOUDPROXY_UTIL_H_
