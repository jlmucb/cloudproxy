#ifndef TAO_AUTHORIZATION_MANAGER_H_
#define TAO_AUTHORIZATION_MANAGER_H_

#include <string>

using std::string;

namespace tao {
class TaoAuthorizationManager {
public:
  virtual ~TaoAuthorizationManager() { }
  virtual bool IsAuthorized(const string &program_hash) const = 0;
  virtual bool IsAuthorized(const string &program_name, const string &program_hash) const = 0;
};
} // namespace tao

#endif // TAO_AUTHORIZATION_MANAGER_H_
