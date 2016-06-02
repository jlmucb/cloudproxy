Installing CloudProxy Integration Tests
=======================================

Projects that use CloudProxy provide their own scripts to run tests. For
examples, see apps/demo/run.sh or apps/fileproxy/run.sh. Before running these
scripts, the CloudProxy code must be built and installed into $GOPATH/bin.  To
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

There are other needed packages including libvirt-dev, libtspi-dev and
protobuf-compiler. The future plan is to incorporate all installation instructions
in "CloudProxy Nuts and Bolts" and make this current and authoritative.  Similarly,
we hope to have authoritative installation and deployment instructions in the
CloudProxy Deployment Nuts and Bolts guide.
