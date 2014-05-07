//  File: tao_ca.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Implementation of a Tao Certificate Authority server.
//
//  Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
#include "tao/tao_ca_server.h"

#include <netinet/in.h>
#include <signal.h>
#include <sys/types.h>

#include <sstream>

#include <glog/logging.h>
#include <keyczar/base/base64w.h>
#include <keyczar/keyczar.h>

#include "tao/attestation.h"
#include "tao/attestation.pb.h"
#include "tao/keys.h"
#include "tao/keys.pb.h"
#include "tao/tao_ca.pb.h"
#include "tao/tao_domain.h"

using std::stringstream;

using keyczar::Verifier;
using keyczar::base::Base64WDecode;

using tao::DeserializePublicKey;
using tao::OpenTCPSocket;
using tao::ReceiveMessage;
using tao::SendMessage;
using tao::TaoCARequest;
using tao::TaoCAResponse;
using tao::TaoDomain;
using tao::X509Details;

namespace tao {

TaoCAServer::TaoCAServer(TaoDomain *admin)
    : admin_(admin),
      sock_(new int(-1)),
      host_(admin->GetTaoCAHost()),
      port_(admin->GetTaoCAPort()) {}

TaoCAServer::~TaoCAServer() {}

bool TaoCAServer::Init() {
  if (!OpenTCPSocket(host_, port_, sock_.get())) {
    LOG(ERROR) << "Could not open TCP socket on " << host_ << ":" << port_;
    return false;
  }
  return true;
}

bool TaoCAServer::Listen() {
  LOG(INFO) << "TaoCAServer listening for connections on " << host_ << ":"
            << port_;
  if (*sock_ == -1) {
    LOG(ERROR) << "The UnixFdTaoChannel must be initialized with Init";
    return false;
  }
  ScopedSelfPipeFd stop_fd(new int(GetSelfPipeSignalFd(SIGTERM)));
  if (*stop_fd < 0) {
    LOG(ERROR) << "Could not create self-pipe";
    return false;
  }

  bool graceful_shutdown = false;
  while (!graceful_shutdown) {
    fd_set read_fds;
    FD_ZERO(&read_fds);
    int max = 0;

    FD_SET(*stop_fd, &read_fds);
    if (*stop_fd > max) max = *stop_fd;

    FD_SET(*sock_, &read_fds);
    if (*sock_ > max) max = *sock_;

    for (int fd : descriptors_) {
      FD_SET(fd, &read_fds);
      if (fd > max) max = fd;
    }

    int err = select(max + 1, &read_fds, nullptr, nullptr, nullptr);
    if (err == -1 && errno == EINTR) {
      // Do nothing.
      continue;
    }
    if (err == -1) {
      PLOG(ERROR) << "Error in calling select";
      break;  // Abnormal termination.
    }

    if (FD_ISSET(*stop_fd, &read_fds)) {
      char b;
      if (read(*stop_fd, &b, 1) < 0) {
        PLOG(ERROR) << "Error reading signal number";
        break;  // Abnormal termination.
      }
      int signum = 0xff & static_cast<int>(b);
      LOG(INFO) << "TaoCAServer listener received signal " << signum;
      graceful_shutdown = true;
      continue;
    }

    list<int> sockets_to_close;
    for (int fd : descriptors_) {
      if (FD_ISSET(fd, &read_fds)) {
        TaoCARequest req;
        bool eof;
        if (!ReceiveMessage(fd, &req, &eof) || eof) {
          if (!eof)
            LOG(ERROR)
                << "Could not receive a TaoCAServer request from the socket";
          sockets_to_close.push_back(fd);
          continue;
        }
        if (!HandleRequest(fd, req, &graceful_shutdown)) {
          LOG(WARNING) << "TaoCARequest failed";
          sockets_to_close.push_back(fd);
          continue;
        }
      }
    }
    for (int fd : sockets_to_close) {
      LOG(INFO) << "Closing TaoCAServer connection " << fd;
      close(fd);
      descriptors_.remove(fd);
    }

    if (FD_ISSET(*sock_, &read_fds)) {
      int fd = accept(*sock_, nullptr, nullptr);
      if (fd == -1) {
        if (errno != EINTR) {
          PLOG(ERROR) << "Could not accept a connection on TaoCAServer socket";
        }
      } else {
        LOG(INFO) << "Accepted TaoCAServer connection " << fd;
        descriptors_.push_back(fd);
      }
    }
  }

  return graceful_shutdown;
}

bool TaoCAServer::Destroy() {
  LOG(INFO) << "TaoCAServer on " << host_ << ":" << port_ << " shutting down";
  sock_.reset(new int(-1));  // Causes socket to close.
  for (int fd : descriptors_) close(fd);
  descriptors_.clear();
  return true;
}

bool TaoCAServer::HandleRequest(int fd, const TaoCARequest &req,
                                bool *requests_shutdown) {
  TaoCAResponse resp;
  string subject_key;
  bool ok = true;
  switch (req.type()) {
    case tao::TAO_CA_REQUEST_SHUTDOWN:
      *requests_shutdown = true;
      break;
    case tao::TAO_CA_REQUEST_ATTESTATION:
      if (!HandleRequestAttestation(req, &subject_key, &resp)) {
        resp.set_reason("Attestation failed");
        ok = false;
      }
      if (ok && req.has_x509details()) {
        if (!HandleRequestX509Chain(req, subject_key, &resp)) {
          resp.set_reason("Certificate chain generation failed");
          ok = false;
        }
      }
      break;
    default:
      LOG(ERROR) << "Unknown TaoCAServer request type";
      resp.set_reason("Unknown TaoCAServer request type");
      ok = false;
      break;
  }
  resp.set_type(ok ? tao::TAO_CA_RESPONSE_SUCCESS
                   : tao::TAO_CA_RESPONSE_FAILURE);

  if (!SendMessage(fd, resp)) {
    LOG(ERROR) << "Could not send a Tao CA response";
    return false;
  }

  return true;
}

bool TaoCAServer::HandleRequestAttestation(const TaoCARequest &req,
                                           string *key_prin,
                                           TaoCAResponse *resp) {
  if (!req.has_attestation()) {
    LOG(ERROR) << "Request is missing attestation";
    return false;
  }

  if (!req.has_desired_name()) {
    LOG(ERROR) << "Request is missing desired name";
    return false;
  }

  string existing_name;
  if (!ValidateKeyNameBinding(req.attestation(), CurrentTime(), key_prin,
                              &existing_name)) {
    LOG(ERROR) << "The provided attestation is not valid";
    return false;
  }

  // TODO(kwalsh) Maybe use validity period from existing attestation?

  if (!admin_->IsAuthorizedNickname(existing_name, req.desired_name())) {
    LOG(ERROR) << "Principal is not authorized to claim desired name";
    return false;
  }

  string attestation;
  if (!admin_->AttestKeyNameBinding(*key_prin, req.desired_name(),
                                    &attestation)) {
    LOG(ERROR) << "Could not generate new attestation";
    return false;
  }
  resp->set_attestation(attestation);

  LOG(INFO) << "TaoCAServer generated attestation for " << req.desired_name();
  return true;
}

bool TaoCAServer::HandleRequestX509Chain(const TaoCARequest &req,
                                         const string &key_prin,
                                         TaoCAResponse *resp) {
  if (!req.has_x509details()) {
    LOG(ERROR) << "Request is missing x509 certificate";
    return false;
  }
  if (!req.has_attestation() || !resp->has_attestation()) {
    LOG(ERROR) << "Request is missing valid attestation";
    return false;
  }

  string key_data, key_text;
  stringstream in(key_prin);
  skip(in, "Key(");
  getQuotedString(in, &key_text);
  skip(in, ")");
  if (!in || !in.str().empty()) {
    LOG(ERROR) << "Bad key format for x509 certificate";
    return false;
  }

  scoped_ptr<Verifier> v;
  if (!Base64WDecode(key_text, &key_data) ||
      !DeserializePublicKey(key_data, &v)) {
    LOG(ERROR) << "Could not deserialize key for x509 certificate";
    return false;
  }

  const X509Details &subject_details = req.x509details();

  // Get a version number
  int cert_serial = admin_->GetFreshX509CertificateSerialNumber();
  if (cert_serial == -1) {
    LOG(ERROR) << "Could not get fresh x509 serial number";
    return false;
  }

  // TODO(kwalsh) Check authorization for claiming these x509 details.

  if (!admin_->GetPolicyKeys()->CreateCASignedX509(
          cert_serial, *v, subject_details, resp->mutable_x509chain())) {
    resp->clear_x509chain();
    LOG(ERROR) << "Could not generate x509 chain";
    return false;
  }

  LOG(INFO) << "TaoCAServer generated x509 chain for "
            << subject_details.commonname();
  return true;
}

}  // namespace tao
