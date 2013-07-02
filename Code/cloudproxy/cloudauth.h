#ifndef CLOUDAUTH_H_
#define CLOUDAUTH_H_

#include "cloudproxy.pb.h"

#include <string>

using std::string;

namespace cloudproxy {
class CloudAuth{
    // Instantiates the Auth class with a serialized representation of a
    // cloudproxy::ACL object.
    CloudAuth(const string &acl);

    virtual ~CloudAuth();

    // Checks to see if this operation is permitted by the ACL
    bool Permitted(const string &subject, cloudproxy::Op op,
		   const string &object);

    // Removes a given entry from the ACL if it exists
    bool Delete(const string &subject, cloudproxy::Op op,
		const string &object);

    // Adds a given entry to the ACL
    bool Insert(const string &subect, cloudproxy::Op op,
		const string &object);

    // serializes the ACL into a given string
    bool Serialize(string *data);
  private:
    ACL acl_;
};
}

#endif // CLOUDAUTH_H_
