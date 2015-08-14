This directory contains the definitions of protocol buffers used in CloudProxy.
The `tao` package expects the protobufs to be in the same package; in order to
build the package, they need to be compiled into Go code in the parent
directory. To do this, run the following in the current directory:

``$ protoc --go_out=.. *.proto``

This will overwrite the `../*.pb.go` files. To get the protocol buffer
compiler running on your system, visit https://github.com/google/protobuf.
