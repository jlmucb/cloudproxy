//  File: https_echo_server.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
// Description: Implementation of the HttpsEchoServer class that echoes
// https requests.
//
//  Copyright (c) 2013, Kevin Walsh  All rights reserved.
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

#include <sys/socket.h>
#include <sys/unistd.h>

#include <sstream>
#include <string>
#include <thread>

#include <glog/logging.h>
#include <google/protobuf/text_format.h>
#include <keyczar/base/file_util.h>
#include <keyczar/crypto_factory.h>

#include "cloudproxy/cloud_server_thread_data.h"
#include "cloudproxy/https_echo_server.h"
#include "tao/attestation.pb.h"
#include "tao/keys.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::string;
using std::stringstream;
using std::thread;

using google::protobuf::TextFormat;
using keyczar::base::ReadFileToString;
using keyczar::base::WriteStringToFile;

using tao::ConnectToTCPServer;
using tao::Keys;
using tao::OpenSSLSuccess;
using tao::OpenTCPSocket;
using tao::ScopedFd;
using tao::ScopedX509;
using tao::SerializeX509;
using tao::TaoChildChannel;
using tao::TaoDomain;

#define READ_BUFFER_LEN 16384

namespace cloudproxy {

HttpsEchoServer::HttpsEchoServer(const string &server_config_path,
                                 const string &host, const string &port,
                                 TaoChildChannel *channel, TaoDomain *admin)
    : admin_(admin),
      rand_(keyczar::CryptoFactory::Rand()),
      host_(host),
      port_(port),
      host_channel_(channel),
      keys_(new Keys(server_config_path, "https echo server", Keys::Signing)) {

  // FIXME(kwalsh) merge most of this with CloudServer
  CHECK(keys_->InitHosted(*host_channel_))
      << "Could not initialize HttpsEchoServer keys";

  // TODO(kwalsh) x509 details should come from elsewhere
  if (keys_->HasFreshKeys()) {
    string details = "country: \"US\" "
                     "state: \"Washington\" "
                     "organization: \"Google\" "
                     "commonname: \"127.0.0.1\"";
    if (!GetTaoCAX509Chain(details)) {
      LOG(ERROR) << "Could not get x509 chain";
      CHECK(false);
    }
  }

  // set up the SSL context and SSLs for getting client connections
  CHECK(SetUpPermissiveSSLServerCtx(*keys_, &context_))
      << "Could not set up server TLS";

  CHECK(rand_->Init()) << "Could not initialize the random-number generator";
}

bool HttpsEchoServer::Listen(bool single_channel) {
  // Set up a TCP connection for the given host and port.
  ScopedFd sock(new int(-1));

  if (!OpenTCPSocket(host_, port_, sock.get())) {
    LOG(ERROR) << "Could not open a TCP socket on port " << host_ << ":"
               << port_;
    return false;
  }

  while (true) {
    int accept_sock = accept(*sock, NULL, NULL);
    if (accept_sock == -1) {
      PLOG(ERROR) << "Could not accept a connection on the socket";
      return false;
    }

    if (single_channel) {
      HandleConnection(accept_sock);
      return true;
    } else {
      VLOG(1) << "Received SSL connection attempt";
      thread t(&HttpsEchoServer::HandleConnection, this, accept_sock);
      t.detach();
    }
  }

  return true;
}

void HttpsEchoServer::HandleConnection(int accept_sock) {
  // Create a new SSL context to handle this connection and do a handshake on
  // it. The ScopedSSL will close the fd in its cleanup routine.
  ScopedSSL ssl(SSL_new(context_.get()));
  SSL_set_fd(ssl.get(), accept_sock);
  CHECK(OpenSSLSuccess());

  SSL_accept(ssl.get());
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << accept_sock
               << " Could not accept an SSL connection on the socket";
    return;
  }

  // Don't delete this X.509 certificate, since it is owned by the SSL_CTX and
  // will be deleted there. Putting this cert in a ScopedX509 leads to a
  // double-free error.
  X509 *self_cert = SSL_get_certificate(ssl.get());
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << accept_sock << " Could not get X.509 self certificate";
    return;
  }
  ScopedX509 peer_cert(SSL_get_peer_certificate(ssl.get()));
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << accept_sock << " Could not get X.509 peer certificate";
    return;
  }
  if (peer_cert.get() == nullptr) {
    LOG(ERROR)
        << accept_sock
        << " No X.509 certificate received from the client, proceeding anyway";
    // return;
  }

  string serialized_peer_cert = "";
  if (peer_cert.get() != nullptr) {
    SerializeX509(peer_cert.get(), &serialized_peer_cert);
    if (!OpenSSLSuccess()) {
      LOG(ERROR) << accept_sock
                 << " Could not serialize the X.509 peer certificate";
      return;
    }
  }

  string serialized_self_cert;
  SerializeX509(self_cert, &serialized_self_cert);
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << accept_sock << " Could not serialize X.509 self certificate";
    return;
  }

  CloudServerThreadData cstd(serialized_peer_cert, serialized_self_cert);

  size_t buffer_len = READ_BUFFER_LEN;
  scoped_array<char> buf(new char[buffer_len]);

  // read up to, and including, the first "\r\n\r\n"
  size_t filled_len = 0;
  int request_len = 0;
  while (request_len == 0 && filled_len < buffer_len) {
    int in_len =
        ReceivePartialData(ssl.get(), buf.get(), filled_len, buffer_len);
    if (in_len < 0) {
      LOG(ERROR) << accept_sock
                 << " Connection failed before request could be read";
      return;
    }
    if (in_len == 0) {
      LOG(ERROR) << accept_sock
                 << " Connection closed before request could be read";
      return;
    }

    filled_len += in_len;
    for (unsigned int i = filled_len - in_len; i < filled_len; i++) {
      if (i >= 4 && !memcmp(buf.get() + i - 4 + 1, "\r\n\r\n", 4)) {
        request_len = i + 1;
        break;
      }
    }
  }

  if (request_len == 0) {
    LOG(ERROR) << accept_sock << " HTTP request was invalid";
    return;
  }

  string https_request(buf.get(), request_len);

  bool reply = true;
  string http_response;
  bool rv = HandleHttpsRequest(https_request, &reply, &http_response, cstd);

  if (rv && reply) {
    unsigned int response_len = http_response.length();
    int out_len = SSL_write(ssl.get(), http_response.c_str(), response_len);
    if (!OpenSSLSuccess() || out_len < 0)
      LOG(ERROR) << "HTTPS session failed before response was sent\n";
    else if (out_len == 0)
      LOG(ERROR) << "HTTPS session closed before response was sent\n";
    else if (static_cast<unsigned int>(out_len) != response_len)
      LOG(ERROR) << "Failed to send complete http response.";
  }
}

bool HttpsEchoServer::HandleHttpsRequest(
    const string &https_request, bool *reply, string *https_response,
    CloudServerThreadData &cstd) {  // NOLINT
  VLOG(1) << "Processing https request\n"
          << "---- BEGIN HTTPS REQUEST ----";
  VLOG(1) << https_request << "----- END HTTPS REQUEST -----";

  stringstream msg;
  string status;
  if (https_request.length() > 4 && https_request.substr(0, 4) == "GET ") {
    status = "HTTP/1.1 200 OK";
    msg << "<html><head><title>Echo</title></head>"
        << "<body>"
        << "<h3>Echo</h3>"
        << "<pre>" << https_request << "</pre>"
        << "</body>"
        << "</html>";
  } else {
    status = "HTTP/1.1 404 Not Found";
    msg << "<html><head><title>Sorry</title></head>"
        << "<body>"
        << "<h3>Sorry...</h3>"
        << "<p>Invalid request.</p>"
        << "</body>"
        << "</html>";
  }
  stringstream out;
  out << status << "\r\n"
      << "Content-Type: text/html; charset=UTF-8\r\n"
      << "Content-Length: " << msg.str().length() << "\r\n"
      << "Connection: close\r\n"
      << "\r\n" << msg.str();
  https_response->assign(out.str());
  return true;
}

// TODO(kwalsh) Move this method to tao::Keys or some future TaoCA class
bool HttpsEchoServer::GetTaoCAX509Chain(const string &details_text) {
  // The TCCA will convert our attestation into a new attestation signed by the
  // policy key.
  tao::TaoCARequest req;
  req.set_type(tao::TAO_CA_REQUEST_ATTESTATION);
  string serialized_attestation;
  if (!ReadFileToString(keys_->AttestationPath(), &serialized_attestation)) {
    LOG(ERROR) << "Could not load the self-signed attestation";
    return false;
  }
  if (!req.mutable_attestation()->ParseFromString(serialized_attestation)) {
    LOG(ERROR) << "Could not deserialize the attestation to our key";
    return false;
  }
  string host = admin_->GetTaoCAHost();
  string port = admin_->GetTaoCAPort();
  ScopedFd sock(new int(-1));
  if (!ConnectToTCPServer(host, port, sock.get())) {
    LOG(ERROR) << "Could not connect to tcca";
    return false;
  }
  if (!TextFormat::ParseFromString(details_text, req.mutable_x509details())) {
    LOG(ERROR) << "Could not parse x509 details";
    return false;
  }

  if (!tao::SendMessage(*sock, req)) {
    LOG(ERROR) << "Could not send request to the TCCA";
    return false;
  }

  tao::TaoCAResponse resp;
  if (!tao::ReceiveMessage(*sock, &resp)) {
    LOG(ERROR) << "Could not get response from the TCCA";
    return false;
  }
  if (resp.type() != tao::TAO_CA_RESPONSE_SUCCESS) {
    LOG(ERROR) << "TCCA returned error: " << resp.reason();
    return false;
  }
  if (!resp.has_x509chain()) {
    LOG(ERROR) << "Missing x509 chain in TCCA response";
    return false;
  }
  string pem_cert = resp.x509chain();

  // TODO(kwalsh) validate the certificate chain here

  if (!WriteStringToFile(keys_->SigningX509CertificatePath(), pem_cert)) {
    LOG(ERROR) << "Could not store the x509 for our signing key";
    return false;
  }
  return true;
}

}  // namespace cloudproxy
