Installing CloudProxy Integration Tests
=======================================

CloudProxy provides an install script to set up simple integration tests for
multiple variants of the CloudProxy system. To install the simplest tests in a
directory `test`, run

    ./install.sh -notpm test

This will output something like

    Installing tao test scripts into: /home/tmroeder/src/github.com/jlmucb/cloudproxy/test
    Done installing.
      /home/tmroeder/src/github.com/jlmucb/cloudproxy/test/bin               # Link to /usr/local/google/home/tmroeder/bin.
      /home/tmroeder/src/github.com/jlmucb/cloudproxy/test/logs              # Log files.
      /home/tmroeder/src/github.com/jlmucb/cloudproxy/test/scripts           # Useful scripts.
      /home/tmroeder/src/github.com/jlmucb/cloudproxy/test/tao.env           # Environment variables.
    Typical next steps:
      cd /home/tmroeder/src/github.com/jlmucb/cloudproxy/test/
      ./scripts/setup.sh           # Create keys, hashes, ACLs, etc.
      ./scripts/start.sh           # Run Tao CA and Linux Tao server.
      ./scripts/host.sh ./bin/demo # Run a demo application.
      ./scripts/stop.sh            # Kill all Tao programs.
      ./scripts/refresh.sh         # Refresh hashes, ACLs, etc.
    Run /home/tmroeder/src/github.com/jlmucb/cloudproxy/test/scripts/help.sh for more info.

Follow these instructions; run setup.sh, then start.sh, then host.sh on the
demo app. For this last step to work, the `$GOPATH` variable must be set up
correctly, and the cloudproxy binaries must be installed in `$GOPATH/bin`. To
install these binaries, run

    go install github.com/jlmucb/cloudproxy/...

To get the TPM version to work, you must have already taken ownership of the
TPM. There is an
[application](https://github.com/google/go-tpm/tree/master/examples/tpm-takeownership)
in go-tpm that can take ownership. Note that the
`TPM_TakeOwnership` operation only works if there is no TPM Owner and TPM
presence has been asserted. The way to assert physical presence varies between
platforms.

Additionally, to use the TPM, you must have built and installed
[genaik](https://github.com/google/go-tpm/tree/master/examples/genaik) from
and installed it in `$GOPATH/bin`. You
can do this with the command

    go install github.com/google/go-tpm/...

Running the Datalog CloudProxy Integration Tests
================================================

The `install.sh` script contains a simple authorization policy that can be
translated to Datalog and used as a guard. To set up a version of the
integration tests with TPM support and Datalog authorization, run

    ./install.sh -tpm -datalog test

Note that the datalog policy is very specific about the path of programs that
can be hosted, since the arguments to a program (including the path to the
program in `argv[0]`) become part of the name of the program, and this name is
used to check hosted-program authorization in Datalog. The default policy in
`install.sh` only authorizes the full path to the program. So, for example, if
the test directory is located in `/home/tmroeder/test`, then the command

    ./scripts/host.sh ./bin/demo

will fail with authorization errors (since `argv[0]` will be `./bin/demo`, and
that will not be authorized), but the command

    ./scripts/host.sh /home/tmroeder/test/bin/demo

will work.

The default policy in `install.sh` also authorizes communication with tcca, the
Tao CA. To execute a version of the TPM/Datalog demo with tcca, run the
following commands in the test directory after setting it up with `./install.sh
-tpm -datalog`

    ./scripts/setup.sh
    ./scripts/start.sh
    ./bin/tcca &
    ./scripts/host.sh /home/tmroeder/test/bin/demo -ca=localhost:8124
