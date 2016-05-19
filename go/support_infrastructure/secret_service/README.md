The CPSecretService maintains a database of domain rooted keys which are epoch qualified.
Each such key has an ACL list consisting of (ProgramName, Property).  Properties are Read,
Write, Create.  The service accepts requests for programs over Tao Channels requesting
keys operations by name and satisfies the request if it is authorized.

Each CPSecretService service usually provides these key services for a single "zone."

All service requests and responses are logged.


