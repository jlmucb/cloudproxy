Mixnet testing scripts
======================

This directory contains some testing scripts for mixnet project.

Local tests
-----------

To run the test on local machine, run

    ./initmixnet.sh
    ./run.sh

Currently, it ues 16 clients (proxies) with 6 directories and 1 directory. The
16 clients connect to an echo server using TLS, and there are 4 fixed circuits
that the 16 clients use. After a successful run, you will see "My name is <num>"
for num = 0, ... ,16 in a random order.


Network tests
-------------

We also provide scripts to run a test across machines. This assumes, again, that
CloudProxy is installed on all the machines. We then have to manually start the
different components:

* Directory: the directory for mix-net
* Router(s): the routers for mix-net. We need at least 1, but could have more.

For testing, it also needs two more instances:

* Client(s): the clients that will be used for testing
* Server: the echo server that will echo msgs back to the client

For the simplest test, we will run a one client and one router, which means hop
counter of 1 and batch size 1.

To run the test, first open up different terminals for the different instances,
then follow the steps.

1. On terminal 1: Start the directory by running
   `go/apps/mixnet/run_directory.sh`. The password for soft_tao is all `mixnet`.

2. On terminal 2 and 3: First write the address of the directory to
   `/tmp/directories`. E.g., run

    `echo 10.138.0.2:8000 > /tmp/directories`

3. On terminal 2: Start the router by running

    `go/apps/mixnet/run_router.sh 10.138.0.3 1`

   where the first argument is the ip address and the second is the batch size
   (1 for this simple test).

4. On terminal 3: Start the echo server by running

    `./run_echoserver.sh`

5. On terminal 4: Start the client by running

    `./run_client.sh 9000 1 10.138.0.4:10000`

   where the first argument is the port number of the proxy, the second argument
   is number of hops (in this case, just 1), and the third argument is the
   destination address.

If the run is successful, you should see `Got: My name is 0.` on the client,
which was echoed back by the echo server.
