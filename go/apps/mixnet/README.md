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
key pair, which is attested to by the OS. Hence, trust in the mixnet routers to
faithfully carry out the protocol is reduced to correct provisioning of the
policy key.

We consider a global adversary who observes all communications between senders
and mixnet routers, mixnet routers and other mixnet routers, and mixnet routers
and recipients. The adversary can also control many senders and recipients, and
therefore could send and receive messages. The effect is that the state of that
peer is exposed, including any and all cryptographic keys. We assume that the
policy key was correctly provisioned and the code is written correctly. We claim
this precludes the possibility of exposing routers' private states. (This is a
strong claim offered here without proof. CloudProxy provides assurance that the
expected program is running; assuming the code does not contain any bugs that
allow it to be compromised, a formal treatment of our protocol should reduce the
adversary's control of the routers to standard cryptographic assumptions: in
particular, CDH on elliptic curves, as well as the integrity and confidentiality
of the cipher suite underlying TLS.) The adversary may also try to inject
packets into the network, though any packets injected through an invalid channel
(i.e., not via a sender or recipient) will not be authenticated and thus
ignored by the routers.

The desired security property of communications over the mixnet is called
_unlinkability_ in the sense of [1]. Consider a set of senders _S_ where _|S| =
n_ and a set of recipients _T_. Each sender chooses one recipient as well as a
message to send so that _M : S → T_ is an onto mapping. The messages are
transmitted to their respective recipients over the mixnet; the adversary
succeeds if it outputs _(s, t)_ such that _M(s) = t_, unless it controls both
_s_ and _t_. We say that communication over the mixnet is _unlinkable_ if for
any adversary the probability of success is less than _1/n_ plus some negligible
value.

_Alternative definition:_ as above, except the adversary chooses the messages to
be sent. This change may make it easier to analyze the unlinkability of a
particular protocol. However, this would require the recipients to participate
in the protocol, since messages exiting the mixnet must be encrypted. We could
instead have a challenger that randomly assigns messages to avoid involving the
recipients, or model the senders via an oracle to avoid this problem.

For a protocol to achieve security in this sense, the messages must all have the
same length. Mixnets address this by splitting messages into fixed-length cells;
messages are broken in to multiple cells, and shorter messages are padded.
Generally, mixnets guarantees are proved for one cell of communication, and also
in a synchronous matter. That is, mixnets provide the unlinkability within the
cells submitted at the same time. Extending the security notion to multiple
rounds of communication that involves different number of cells in each
connection is challenging. The presence of variable-length messages exposes
traffic patterns to the adversary. One way to mitigate this problem is to
zero-pad all messages to the length of the longest message. This achieves a
property called _unobservability_ [1] which is too expensive for our purposes.

Another appraoch is to weaken the security model to one in which the adversary
may only observe a fraction of the network at any one time; relaying messages
over circuits of routers may make it more difficult to perform traffic
analysis. This is the case for the design of the Tor onion-routing protocol [2].
We will consider extending our protocol to a network of routers to achieve
security in this model. This approach may have the added benifit of reducing
latency of messages traversing the mixnet.

Design Overview
---------------

Our mixnet design consists of two major component, _router_ and _proxy_, and one
administrative component, _directory_. A router (`mixnet_router`), or a _mix_,
shuffles and routes users' messages, and a proxy (`mixnet_proxy`) accepts any
TCP connections via a SOCKS5 proxy from a user and relays the packets through
the mixnet. A directory (`mixnet_directory`) acts as a synchronization point,
and manages a list of available routers in the mixnet currently for other
routers and proxies to use.

At a high level, our design is, at least at the moment, an asynchronous
free-flow mixnet. Unlike cascade-mixnets, a free-flow mixnet allows different
messages to be routed through different paths through the network of mixes. It
is also asynchronous in the sense that each mix makes their own routing
decisions without coordinating with rest of the mixes in the network.

All mixnet routers occasionally check-in to a directory, and the directories
if there are more than one, reach a consensus every fixed period of time.
A typical messaging session for two end-to-end users, Alice and Bob, works as
follows.

1. Proxy accepts a connection from Alice, and receives a message to send to Bob.

2. Proxy picks an _entry_ mix. It then establishes a one-way authenticated TLS
   connection with the entry (the mix attests that it is running CloudProxy),
   and requests to establish a _circuit_ to Bob. A circuit is a path of mixes in
   the network the messages for this particular end-to-end connection will be
   routed through.

3. The entry mix selects random mixes to form a circuit. It establishes a
   two-way authenticated TLS connection to the next mix in the circuit, and it
   relays the circuit creation request to the next hop. The next mix does the
   same until the circuit reaches the _exit_ mix.

4. Once the circuit is established, the proxy sends the message over to the
   entry mix. Every packet exchanged between a mix and a proxy, called a _cell_,
   is of fixed length. If the message is shorter than a cell, then the message
   is padded to the fixed length. If the message is longer, then it is broken
   down into multiple cells.

5. Once enough cells from different proxies are available at the entry mix, it
   permutes the cells, and sends the cells to the next mix in the circuit.
   Similarly, the intermediate mixes in circuits wait for enough cells from
   different circuits, and permute the cells, and send the cells to the next
   hops. The exit mix reconstructs the message from cells, and send the message
   to Bob.

6. Bob can respond to the message, and the message will traverse the mixnet
   using the same circuit in reverse.

The design and the implementation assumes sufficient number of Alices and Bobs
for availability. If there is only one Alice and Bob, then routers may not
be able to collect sufficient number of messages, and will not execute step 5.

Note that in step 3, the entry mix picks the circuit through the network, not
Bob. This is because the entry mix, which is CloudProxy authenticated, is
assumed to be secure, and disabling malicious users (who are not authenticated)
from selecting the path will likely enable better security. We currently allow
users to pick the circuit as well. This is done for testing, as randomized paths
do not work well for smaller scale tests.

The design also made several design decisions that trades-off security and
performance. For instance, it may result in less latency to allow a mix in step
5 to treat connections from proxies and other routers the same way, and thus
requires less connections from proxies. This, however, could reduce the
anonymity set size of the proxies. Such design choices may change as we analyze
the security of the system further.

Code Overview
-------------

Some of the important files are

* `queue.go`: Implements the batching and mixing functionality for cells.
* `router.go` Handles connections from/to proxies, routers, and end points. Uses
  a queue from `queue.go` to maintain 3 different queues for (1) cells sent from
  proxies, (2) cells sent to proxies, and (3) cells to/from other routers. This
  is required to be run in CloudProxy environment.
* `socks5.go`: Implements a simple SOCKS5[3] proxy that proxy uses to listen to
  end users.
* `proxy.go`: Uses SOCKS5 to receive messages from end-users, breaks the
  messages into cells, and handles communication with the entry mix.
* `conn.go`, `listener.go`, `circuit.go`: Used to manage different network
  connections and circuits.
* `mixnet.proto`: Specifies the directives (e.g., creating/destroying circuits)
  used by proxies and routers.

Parameters
----------

There are server system wide parameters that impact the security and performance
of the system.

* Batch size (`batchsize`): This determines how many cells from different circuits
  or proxies a router needs to collect before mixing and sending them to the next
  hop in the circuit.

* Hop length: Currently, the default number of hops in the circuit is set to 3.
  Longer circuits will likely provide better anonymity, at the cost of increased
  latency, and vice-versa. The hop count also need not be fixed for all circuits,
  but we assume it is for simpler design and analysis.

* Cell size: Each cell is fixed at 1024B currently. This should be at most 65KB,
  the maximum packet length for TCP.

Tests
-----

`mixnet_test.go` and other test files contain unit tests and integration tests
that can be run natively in Go. The largest integration test uses 20 proxies,
6 routers, and there are four paths through the routers used by 20 proxies.
The messages are then echoed back to the proxies by a simple server at the
end of the circuit.

The scripts in `scripts` runs a full Tao test (currently with soft-tao). It
implements essentially the same integration test as the one in `mixnet_test.go`,
except it runs it with Tao. The script assumes that typical Tao testing
environment is setup (i.e., Tao is installed, `/Domains` exists, etc.). To run
the test, simple run

    ./initmixnet.sh
    ./run.sh

All tests currently use localhost. A large multi-machine test is currently left
as future work.

References
----------

[1] Andreas Pfitzman, 2010. _A terminology for talking about privacy by data_
    _minimization: Anonymity, Unlinkability, Undetectability, Unobservability,_
	_Pseudonymity, and Identity Management._
	https://dud.inf.tu-dresden.de/literatur/Anon_Terminology_v0.34.pdf

[2] Tor specification. https://svn.torproject.org/svn/projects/design-paper/tor-design.pdf

[3] SOCKS Protocol Version 5. http://tools.ietf.org/html/rfc1928
