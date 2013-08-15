#ifndef TAO_WHITELIST_AUTHORIZATION_MANAGER_H_
#define TAO_WHITELIST_AUTHORIZATION_MANAGER_H_

#include "tao/tao_authorization_manager.h"
#include <keyczar/keyczar.h>
#include <map>
#include <set>

using std::map;
using std::set;

namespace tao {
class WhitelistAuthorizationManager : public TaoAuthorizationManager {
public:
  WhitelistAuthorizationManager() : whitelist_(), hash_whitelist_() { }
  virtual ~WhitelistAuthorizationManager() { }
  bool Init(const string &whitelist_path, const keyczar::Keyczar &public_policy_key);
  virtual bool IsAuthorized(const string &program_hash) const;
  virtual bool IsAuthorized(const string &program_name, const string &program_hash) const;
private:
  map<string, string> whitelist_;
  set<string> hash_whitelist_;

  DISALLOW_COPY_AND_ASSIGN(WhitelistAuthorizationManager);
};
} // namespace tao

#endif // TAO_WHITELIST_AUTHORIZATION_MANAGER_H_
