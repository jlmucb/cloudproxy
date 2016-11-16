Simple HTTP Server
==================

This is a simple HTTP server that runs on top of linux_host and
SoftTao, meaning that the root of trust is a piece of software rather
than a hardware TPM. This is meant to demonstrate how one can start a
CloudProxy protected server.

This application manages a value (byte slice called "Secret" in the
program), and services the value to the clients. The first time the
server runs, it generates 64 random bytes, and uses CloudProxy's
protection mechanism ("seal") to store it in the hard drive. This
sealed data is then only accessible by the server. Any subsequent
times the server starts, it reads the sealed data (via "unseal"),
and services that to any clients.

This application does not really have any meaningful security as the
connection is on plaintext HTTP and provides no authentication (i.e.,
no TLS); it is meant as a simplest demonstration of getting a server
running on top of CloudProxy and linux_host in particular. This will
be shown in another example.


Dependencies
------------

This server tries to minimize dependencies. Apart from the standard Go
libraries, it depends on

1. `github.com/jlmucb/cloudproxy/go/tao`: Implementation of Tao.

2. `github.com/jlmucb/cloudproxy/go/apps/host` and
`github.com/jlmucb/cloudproxy/go/apps/linux_host`: Implementation of
the linux_host. In a real deployment, `linux_host` will serve as
the root of trust for applications running on top of linux.


Files
-----


- `allowall.cfg`: Sample configuration file for Tao. This is an
"allow all" policy, meaning it will let any application run on top
of this Tao.

- `README.md`: This README.

- `run.sh`: Script to compile and run the application.

- `server.go`: Code for a simple HTTP server using Tao.


Running the example
-------------------

To run this application, run

    ./run.sh

This sets up all the necessary files, and runs the server. This
requires sudo access since the linux hosts run with root privilege. It
will also prompt the user for the password used for SoftTao, which is
currently set to `httptest`. Once the server is running, you can open
a browser and visit `localhost:8123` to see the secret the server is
storing. `run.sh` describes what each command does in more detail.
