#include "cloudproxy/cloud_server_thread_data.h"

namespace cloudproxy {
bool CloudServerThreadData::GetChallenge(const string &user, string *chall) {
  CHECK(chall) << "null challenge pointer";

  auto c_it = challenges_.find(user);
  if (challenges_.end() == c_it) return false;

  chall->assign(c_it->second.data(), c_it->second.length());
  return true;
}

bool CloudServerThreadData::AddChallenge(const string &user,
                                         const string &chall) {
  challenges_[user] = chall;
  return true;
}

bool CloudServerThreadData::RemoveChallenge(const string &user) {
  auto c_it = challenges_.find(user);
  if (challenges_.end() == c_it) return false;

  challenges_.erase(c_it);
  return true;
}

bool CloudServerThreadData::SetAuthenticated(const string &user) {
  auth_.insert(user);
  return true;
}

bool CloudServerThreadData::IsAuthenticated(const string &user) {
  return auth_.find(user) != auth_.end();
}

bool CloudServerThreadData::RemoveAuthenticated(const string &user) {
  auto a_it = auth_.find(user);
  if (auth_.end() == a_it) return false;
  auth_.erase(a_it);
  return true;
}
}  // namespace cloudproxy
