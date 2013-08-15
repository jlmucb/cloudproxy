//  File: file_server.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Implementation of the FileServer class that manages
// files for FileClient
// 
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.

// ------------------------------------------------------------------------

#include "cloudproxy/file_server.h"

// for stat(2)
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mutex>

using std::lock_guard;
using std::mutex;

namespace cloudproxy {

FileServer::FileServer(
    const string &file_path, const string &meta_path, const string &tls_cert,
    const string &tls_key, const string &tls_password,
    const string &public_policy_keyczar, const string &public_policy_pem,
    const string &acl_location, const string &whitelist_location,
    const string &server_key_location, const string &host, ushort port)
    : CloudServer(tls_cert, tls_key, tls_password, public_policy_keyczar,
                  public_policy_pem, acl_location, whitelist_location, host,
                  port),
      main_key_(keyczar::Signer::Read(server_key_location.c_str())),
      enc_key_(new string()),
      hmac_key_(new string()),
      file_path_(file_path),
      meta_path_(meta_path) {
  LOG(INFO) << "now in the file server constructor";
  // check to see if these paths actually exist
  struct stat st;
  CHECK_EQ(stat(file_path_.c_str(), &st), 0) << "Could not stat the directory "
                                             << file_path_;
  CHECK(S_ISDIR(st.st_mode)) << "The path " << file_path_
                             << " is not a directory";

  CHECK_EQ(stat(meta_path_.c_str(), &st), 0) << "Could not stat the directory "
                                             << meta_path_;
  CHECK(S_ISDIR(st.st_mode)) << "The path " << meta_path_
                             << " is not a directory";

  // get binary data from the hmac
  main_key_->set_encoding(keyczar::Keyczar::NO_ENCODING);

  LOG(INFO) << "About to derive keys";

  // generate keys
  CHECK(DeriveKeys(main_key_.get(), &enc_key_, &hmac_key_))
      << "Could not derive keys for authenticated encryption";

  CHECK(DeriveKeys(main_key_.get(), &enc_key_, &hmac_key_))
      << "Could not derive enc and hmac keys for authenticated encryption";
}

bool FileServer::HandleCreate(const Action &action, BIO *bio, string *reason,
                              bool *reply, CloudServerThreadData &cstd) {
  // check to see if the file exists
  if (!action.has_object()) {
    LOG(ERROR) << "The CREATE request did not specify a file";
    reason->assign("No file given for CREATE");
    return false;
  }

  // TODO(tmroeder): make this locking more fine-grained so that locks only
  // apply to individual files. Need a locking data structure for this.
  string path = file_path_ + string("/") + action.object();
  string meta_path = meta_path_ + string("/") + action.object();
  {
    lock_guard<mutex> l(data_m_);
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
      LOG(ERROR) << "File " << path << " already exists";
      reason->assign("Already exists");
      return false;
    }

    if (stat(meta_path.c_str(), &st) == 0) {
      LOG(ERROR) << "File " << meta_path << " already exists";
      reason->assign("Already exists");
      return false;
    }

    ScopedFile f(fopen(path.c_str(), "w"));
    if (nullptr == f.get()) {
      LOG(ERROR) << "Could not create the file " << path;
      reason->assign("Could not create the file");
      return false;
    }

    ScopedFile mf(fopen(meta_path.c_str(), "w"));
    if (nullptr == mf.get()) {
      LOG(ERROR) << "Could not create the file " << meta_path;
      reason->assign("Could not create the file");
      return false;
    }
  }

  LOG(INFO) << "Created the file " << path << " and its metadata " << meta_path;
  return true;
}

bool FileServer::HandleDestroy(const Action &action, BIO *bio, string *reason,
                               bool *reply, CloudServerThreadData &cstd) {
  if (!action.has_object()) {
    LOG(ERROR) << "The DESTROY request did not specify a file";
    reason->assign("No file given for DESTROY");
    return false;
  }

  string path = file_path_ + string("/") + action.object();
  string meta_path = meta_path_ + string("/") + action.object();
  {
    lock_guard<mutex> l(data_m_);
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
      LOG(ERROR) << "File " << path << " does not exist";
      reason->assign("Does not exist");
      return false;
    }

    if (stat(meta_path.c_str(), &st) != 0) {
      LOG(ERROR) << "File " << meta_path << " does not exist";
      reason->assign("Does not exist");
      return false;
    }

    // ideally, this should be transactional, since the current instantiation of
    // this code can get files into a state that can't be written and can't be
    // destroyed
    if (unlink(path.c_str()) != 0) {
      LOG(ERROR) << "Could not unlink the file " << path;
      reason->assign("Could not delete the file");
      return false;
    }

    if (unlink(meta_path.c_str()) != 0) {
      LOG(ERROR) << "Could not unlink the file " << meta_path;
      reason->assign("Could not delete the file");
      return false;
    }
  }

  return true;
}

bool FileServer::HandleWrite(const Action &action, BIO *bio, string *reason,
                             bool *reply, CloudServerThreadData &cstd) {
  string path = file_path_ + string("/") + action.object();
  string meta_path = meta_path_ + string("/") + action.object();
  {
    lock_guard<mutex> l(data_m_);
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
      LOG(ERROR) << "File " << path << " does not exist";
      reason->assign("Does not exist");
      return false;
    }

    if (stat(meta_path.c_str(), &st) != 0) {
      LOG(ERROR) << "File " << meta_path << " does not exist";
      reason->assign("Does not exist");
      return false;
    }

    // send a reply before receiving the stream data
    // the reply tells the FileClient that it can send the data
    string error;
    if (!SendReply(bio, true, error)) {
      LOG(ERROR) << "Could not send a message to the client to ask it to write";

      // don't try to send another message, since we just failed to send this
      // one
      *reply = false;
      return false;
    }

    if (!ReceiveAndEncryptStreamData(bio, path, meta_path, action.object(),
                                     enc_key_, hmac_key_, main_key_.get())) {
      LOG(ERROR) << "Could not receive data from the client and write it"
                    " encrypted to disk";
      reason->assign("Receiving failed");
      return false;
    }
  }

  return true;
}

bool FileServer::HandleRead(const Action &action, BIO *bio, string *reason,
                            bool *reply, CloudServerThreadData &cstd) {
  string path = file_path_ + string("/") + action.object();
  string meta_path = meta_path_ + string("/") + action.object();
  {
    lock_guard<mutex> l(data_m_);
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
      LOG(ERROR) << "File " << path << " does not exist";
      reason->assign("Does not exist");
      return false;
    }

    if (stat(meta_path.c_str(), &st) != 0) {
      LOG(ERROR) << "File " << meta_path << " does not exist";
      reason->assign("Does not exist");
      return false;
    }

    // send a reply before sending the stream data
    // the reply tells the FileClient that it should expect the data
    string error;
    if (!SendReply(bio, true, error)) {
      LOG(ERROR) << "Could not send a message to the client to tell it to read";

      // don't try to send another message, since we just failed to send this
      // one
      *reply = false;
      return false;
    }

    if (!DecryptAndSendStreamData(path, meta_path, action.object(), bio,
                                  enc_key_, hmac_key_, main_key_.get())) {
      LOG(ERROR) << "Could not stream data from the file to the client";
      reason->assign("Could not stream data to the client");
      return false;
    }
  }

  return true;
}

}  // namespace cloudproxy
