#include "file_server.h"

// for stat(2)
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mutex>

using std::lock_guard;
using std::mutex;

namespace cloudproxy {

FileServer::FileServer(const string &file_path,
	       const string &tls_cert,
	       const string &tls_key,
		const string &tls_password,
		const string &public_policy_keyczar,
		const string &public_policy_pem,
		const string &acl_location,
		const string &server_key_location,
		const string &host,
		ushort port)
  : CloudServer(tls_cert,
      tls_key,
      tls_password,
      public_policy_keyczar,
      public_policy_pem,
      acl_location,
      server_key_location,
      host,
      port),
    file_path_(file_path) {
  // check to see if this path actually exists
  struct stat st;
  CHECK_EQ(stat(file_path_.c_str(), &st), 0) << "Could not stat the directory "
    << file_path_;

  CHECK(S_ISDIR(st.st_mode)) << "The path " << file_path_  << " is not a directory";
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
  {
    lock_guard<mutex> l(data_m_);
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
      LOG(ERROR) << "File " << path << " already exists";
      reason->assign("Already exists");
      return false;
    }

    FILE *f = fopen(path.c_str(), "w");
    if (nullptr == f) {
      LOG(ERROR) << "Could not create the file " << path;
      reason->assign("Could not create the file");
      return false;
    }

    fclose(f);
  }
  
  LOG(INFO) << "Create the file " << path;
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
  {
    lock_guard<mutex> l(data_m_);
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
      LOG(ERROR) << "File " << path << " does not exist";
      reason->assign("Does not exist");
      return false;
    }

    if (unlink(path.c_str()) != 0) {
      LOG(ERROR) << "Could not unlink the file " << path;
      reason->assign("Could not delete the file");
      return false;
    }
  }

  return true;
}

bool FileServer::HandleWrite(const Action &action, BIO *bio, string *reason,
		    bool *reply, CloudServerThreadData &cstd) {


  string path = file_path_ + string("/") + action.object();
  {
    lock_guard<mutex> l(data_m_);
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
      LOG(ERROR) << "File " << path << " does not exist";
      reason->assign("Does not exist");
      return false;
    }

    // send a reply before receiving the stream data
    // the reply tells the FileClient that it can send the data
    string error;
    if (!SendReply(bio, true, error)) {
      LOG(ERROR) << "Could not send a message to the client to ask it to write";
  
      // don't try to send another message, since we just failed to send this one
      *reply = false;
      return false;
    }
  
    if (!ReceiveStreamData(bio, path)) {
      LOG(ERROR) << "Could not receive data from the client";
      reason->assign("Receiving failed");
      return false;
    }
  }

  return true;
}

bool FileServer::HandleRead(const Action &action, BIO *bio, string *reason,
		    bool *reply, CloudServerThreadData &cstd) {
  string path = file_path_ + string ("/") + action.object();
  {
    lock_guard<mutex> l(data_m_);
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
      LOG(ERROR) << "File " << path << " does not exist";
      reason->assign("Does not exist");
      return false;
    }

    // send a reply before sending the stream data
    // the reply tells the FileClient that it should expect the data
    string error;
    if (!SendReply(bio, true, error)) {
      LOG(ERROR) << "Could not send a message to the client to tell it to read";
  
      // don't try to send another message, since we just failed to send this one
      *reply = false;
      return false;
    }
  
    if (!SendStreamData(path, st.st_size, bio)) {
      LOG(ERROR) << "Could not stream data from the file to the client";
      reason->assign("Could not stream data to the client");
      return false;
    }
  }

  return true;
}

} // namespace cloudproxy
