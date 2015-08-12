Mixnet over CloudProxy
======================

A mixnet router facilitates anonymous communications among a set of peers.
Alice wants to send Msg to Bob; she encrypts, authenticates, and sends the
message (Msg, Bob) to Molly, a mixnet router. Molly waits until she has _n-1_
more messages from _n-1_ other peers, then transmits the messages to their
respective destinations simultaneously, thus anonymizing Alice among a set of n
peers. Such a service is only useful if Molly can be trusted to not divulge the
link (Alice, Bob). This document specifies a simple mixnet built on the
CloudProxy platform that reduces this trust to the knowledge of a public key
and trust in the owner of that key.

Security goals and threat model
-------------------------------
There are three principals in our protocol: the sender, recipient, and the
policy owner. Our goal is to design a protocol that provides anonymity for
senders without requiring the recipient to execute the protocol. The policy
owner controls the root policy private key that is used to attest to the
instantiation of mixnet routers using the CloudProxy platform. CloudProxy
exposes the code to the users, as well as the operating system in which it is
running. To instantiate a mixnet router, a TPM coupled with the hardware
platform generates a public key, which is attested to by the policy owner by
signing it with the private policy key. When the machine boots, the OS is
measured and generates a private/public key pair, which is attested to by the
TPM; finally, the mixnet code itself is measured and generates a private/public
key pair, which is attested to by the OS. Hence, trust in the mixnet
routers to faithfully carry out the protocol is reduced to correct
provisioning of the policy key.

We consider a global passive adversary who observes all communications between
senders and mixnet routers, mixnet routers and other mixnet routers, and mixnet
routers and recipients. The adversary may also send messages on channels it
observes. Since the service is anonymous, the adversary is allowed to control
any number of senders or recipients. The effect is that the state of that peer
is exposed, including any and all cryptographic keys. We assume that the policy
key was correctly provisioned; if the code implements the protocol correctly and
is properly isolated during its execution, we claim this precludes the
possibility of exposing a router’s state. (This is a strong claim offered here
without proof. CloudProxy provides assurance that the expected program is
running; assuming the code does not contain any bugs that allow it to be
comprimised, a formal treatment of our protocol should reduce the adversary's
control of the routers to standard cryptographic assumptions: in particular,
CDH on elliptic curves, as well as the integrity and confidentiality of the
cipher suite underyling TLS.)

The intended property of communications over the mixnet is unlinkability in the
sense of [1]. Consider a set of senders _S_ where _|S| = n_ and a set of
recipients _T_. Each sender chooses one recipient as well as a message to send
so that _M : S → T_ is an onto mapping. The messages are transmitted to their
respective recipients over the mixnet; the adversary succeeds if it outputs
_(s, t)_ such that _M(s) = t_, unless it controls both _s_ and _t_. We say that
communication over the mixnet is _unlinkable_ if for any adversary the
probability of success is less than _1/n_ plus some negligible value.

_Alternative definition:_ as above, except the adversary chooses the messages to
be sent. This change may make it easier to analyze the unlinkability of a
particular protocol. However, this would require the recipients to participate
in the protocol, since messages exiting the mixnet must be encrypted.

For a protocol to achieve security in this sense, the messages must all have the
same length; of course, this is not always reasonable in practice. Mixnets
address this by splitting messages into fixed-length cells. Senders split
messages into cells (zero-padding the last cell as needed) and send them to the
first router where they are added to a queue. At each round the router waits
until there are _m_ cells in the queue from _m_ distinct senders and transmits
these simultaneously to achieve anonymity.

Extending the definition of unlinkability to a mixnet that divides messages into
cells and transmits at rounds is challenging: the presence of
variable-length messages exposes traffic patterns to the adversary. One way to
mitigate this problem is to zero-pad all messages to the length of the longest
message. This achieves a property called _unobservability_ [1] which is too
expensive for our purposes.

Another appraoch is to weaken the security model to one in which the adversary
may only observe a fraction of the network at any one time; relaying messages
over circuits of routers may make it more difficult to perform traffic
analysis. This is the case for the design of the Tor onion-routing protocol [2].
We will consider extending our protocol to a network of routers to achieve
security in this model. This approach may have the added benifit of reducing
latency of messages traversing the mixnet.

Design
------

We designed the mixnet to proxy client/server protocols. There are
two main components of the protocol: the _proxy_ (`mixnet_proxy`) accepts
arbitrary TCP connections from a client and relays messages over the
mixnet to the server; the _router_ (`mixnet_router`) accepts connections
from a proxy and performs the mixnet operations. The proxy and router perform
a one-way authenticated TLS handshake to exchange a key for wrapping
(encrypting and authenticating) messages sent between them. Messages sent
between proxies and routers (or routers and routers) are fixed length cells.

The protocol for a single proxy and router is as follows.
To send a message to a server, the client sends the message to the proxy
which divides the message into cells and sends them to the router. The
router waits until it has received all the cells, then assembles them into
the original message. Once the router has queued messages from enough senders, it
transmits the message to the server. It then waits for a reply from the server,
divides the reply into cells, and queues the cells to be transmitted back to
the proxy. The proxy waits until it has received all the reply cells, assembles
them into the complete message, and sends it back to the client.

The router maintains two data structures: the _sendQueue_ for sender to recipient
traffic, and the _replyQueue_ for recipient to sender traffic. They are
functionally equivalent (see `queue.go`); they receive cells from proxies (or other routers)
and replies from recipients, and they send cells to proxies (or other routers)
and messages to recipients. The _batchSize_ specifies how many messages/cells
are waiting in the queue from distinct peers before transmitting
them. When its time to transmit, a connection to the destination is established
(if it hasn't been established already) and the messages are sent in a random
order.

A cell is either a chunk of a message or a _directive_. A directive contains
instructions for a router or proxy and are implemented as protocol buffers
(`mixnet.proto`):

 * ERROR: something went wrong.
 * CREATE: the proxy instructs the router to create a circuit over the mixnet
           to a destination address. The response is either ERROR or CREATED.
 * CREATED: the router informs the proxy that the circuit was created.
 * DESTROY: the proxy instructs the router to destroy the circuit.

Note that when a circuit is created, all that happens is the router is
informed of the destination server. The connection is established when the
router is ready to dequeue; otherwise, the TCP handshake would allow the
adversary to correlate the wrapped CREATE directive with the TCP handshake.

The router (`router.go`) is a Tao-delegated program and will only run when launched in a
Tao environment. The proxy (`proxy.go`) is not launched in the Tao and is expected to run
locally on the client's machine. It is assumed that the client has a copy
of the root public policy key. When the proxy dials the router, the router
attests to its identity, and the attestation is verified by the proxy using
the policy key; if verification fails, the proxy exits. Both the proxy and
router communicate with the TaoCA to obtain a copy of the policy.

The proxy implements SOCKS [3], a widely a widely used protocol
that allows a server to proxy client internet traffic. (See `socks.go`.)
Our proxy only
partially implements the server role; see `SocksListener.Accept()`
for details. For example, it only allows the client to specify
IPv4 addresses, which excludes DNS-based host names.

Our implementation so far only allows a mixnet with a single router;
router-to-router communication and construction/destruction of multi-hop
circuits still need to be implemented. Notice that our design makes no attempt
to preserve the confidentiality or integrity of cells _on the routers_; as a
result, every router a message traverses would learn its intended destination,
as well as the contents of the message. This problem is addressed in Tor using onion-routing,
a technique that ensures each router knows only the previous and next hops in the circuit.
Doing this in a way that preserves forward secrecy makes the circuit
construction expensive, since the proxy needs to exchange a key with each hop
successively. Since the client can be assured of the identity of the routers
via the root of trust, and trusting the code is secure, we could construct the
circuit in one pass.

References
----------

[1] Andreas Pfitzman, 2010. _A terminology for talking about privacy by data_
    _minimization: Anonymity, Unlinkability, Undetectability, Unobservability,_
	_Pseudonymity, and Identity Management._
	https://dud.inf.tu-dresden.de/literatur/Anon_Terminology_v0.34.pdf

[2] Tor specification. https://svn.torproject.org/svn/projects/design-paper/tor-design.pdf

[3] SOCKS Protocol Version 5. http://tools.ietf.org/html/rfc1928
