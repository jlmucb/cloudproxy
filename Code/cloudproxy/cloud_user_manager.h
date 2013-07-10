#ifndef CLOUDPROXY_CLOUD_USER_MANAGER_H_
#define CLOUDPROXY_CLOUD_USER_MANAGER_H_

#include <keyczar/keyczar.h>
#include "cloudproxy.pb.h"

#include <map>
#include <memory>
#include <set>
#include <string>

using std::set;
using std::shared_ptr;
using std::string;
using std::map;

namespace cloudproxy {
class CloudUserManager {
  public:
    CloudUserManager() : users_() { }
    
    bool HasKey(const string &user) const;
    bool GetKey(const string &user, shared_ptr<keyczar::Keyczar> *key);
    bool AddKey(const string &user, const string &key, const string &meta);
    bool AddKey(const SignedSpeaksFor &ssf, keyczar::Keyczar *verifier);

    void SetAuthenticated(const string &user);
    bool IsAuthenticated(const string &user);
  private:
    map<string, shared_ptr<keyczar::Keyczar> > users_;
    set<string> authenticated_;

    DISALLOW_COPY_AND_ASSIGN(CloudUserManager);
};
}

#endif // CLOUDPROXY_CLOUD_USER_MANAGER_H_
