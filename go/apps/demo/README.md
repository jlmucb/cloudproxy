Linux Process Demo
------------------

The Linux-process version of the demo requires `demo_server` and `demo_client`
to have been built, e.g., by

	go install github.com/jlmucb/cloudproxy/...

The following steps set up a Linux-process-based `linux_host` and run the demo
server and client on it. These commands assume that the cloudproxy binaries are
in $GOPATH and that $GOPATH is in $PATH.

	linux_host &
	export DIR=/tmp/linux_host<something output by linux_host>
	tao_launch -sock ${DIR}/linux_tao_host/admin_socket -- <path/to/demo_server> -config ${DIR}/tao.config
	tao_launch -sock ${DIR}/linux_tao_host/admin_socket -- <path/to/demo_client> -config ${DIR}/tao.config

Linux Docker Demo
-----------------
The first step in setting up the demo application under Docker is building the
Docker containers for the demo.

First, build `demo_server` and `demo_client` as standalone binaries as follows.

	CGO_ENABLED=0 go install -a -ldflags '-s' github.com/jlmucb/cloudproxy/...

To build `demo_server.img.tgz` and `demo_client.img.tgz`, execute the following
commands.

	cd <some empty directory>
	cp ${DEMO_DIR}/demo_server/Dockerfile .
	mkdir bin
	cp ${GOPATH}/bin/demo_server bin/demo_server
	mkdir policy_keys
	cp <path/to/policy/cert> policy_keys/cert

	echo >tao.config <<EOF
	# Tao Domain Configuration file

	[Domain]
	Name = testing
	PolicyKeysPath = policy_keys
	GuardType = AllowAll

	[X509Details]
	CommonName = testing	
	EOF

	touch rules
	tar -czf ${DEMO_DIR}/demo_server/demo_server.img.tgz *	

To run this demo under the tao, perform the following steps. Note that you can
get the name of the container from the output of `docker ps` after starting the
demo server.

	linux_host --factory_type docker &
	export DIR=<location of linux_host tmp dir>
	export DEMO_DIR=<the demo directory>
	cd $DIR
	tao_launch -docker_img ${DEMO_DIR}/demo_server/demo_server.img.tgz -- ${DEMO_DIR}/demo_server/demo_server.img.tgz
	tao_launch -docker_img ${DEMO_DIR}/demo_client/demo_client.img.tgz -- ${DEMO_DIR}/demo_client/demo_client.img.tgz --link <name of container>:server

