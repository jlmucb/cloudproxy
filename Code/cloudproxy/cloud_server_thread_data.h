#ifndef CLOUDPROXY_CLOUD_SERVER_THREAD_DATA_H_
#define CLOUDPROXY_CLOUD_SERVER_THREAD_DATA_H_

#include <keyczar/keyczar.h>

#include <set>
#include <string>
#include <map>

using std::set;
using std::string;
using std::map;

namespace cloudproxy {

// a class for managing thread data: outstanding challenges and user
// authentication information
class CloudServerThreadData {
 public:
  CloudServerThreadData() {}
  virtual ~CloudServerThreadData() {}

  bool GetChallenge(const string &user, string *chall);
  bool AddChallenge(const string &user, const string &chall);
  bool RemoveChallenge(const string &user);

  bool SetAuthenticated(const string &user);
  bool IsAuthenticated(const string &user);
  bool RemoveAuthenticated(const string &user);

 private:

  // the set of outstanding challenges on this channel
  map<string, string> challenges_;

  // the set of users that have successfully authenticated on this channel
  set<string> auth_;

  DISALLOW_COPY_AND_ASSIGN(CloudServerThreadData);
};
}

#endif  // CLOUDOPROXY_CLOUD_SERVER_THREAD_DATA_H_
