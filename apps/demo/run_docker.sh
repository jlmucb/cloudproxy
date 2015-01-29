#!/bin/sh

t=`mktemp /tmp/loc.XXXXXXXX`
linux_host -hosted_program_type=docker -tmppath=$t &
status=$?
hostpid=$!
if [ "$status" != "0" ]; then
	echo "Couldn't start the linux_host in a temporary directory"
	exit 1
fi

echo "Waiting for linux_host to start"
sleep 5

DIR=`cat $t`
DEMO_DIR=$(readlink -e $(dirname $0))

# Build the Docker images for demo_server and demo_client.
${DEMO_DIR}/build.sh $DIR/policy_keys/cert

cd $DIR
tao_launch -docker_img ${DEMO_DIR}/demo_server/docker.img.tgz -- ${DEMO_DIR}/demo_server/docker.img.tgz
echo "Waiting for docker to update its list of running containers"
sleep 2
container_name=$(docker inspect $(docker ps -q -l) | grep Name | tail -1 | cut -d' ' -f6 | sed 's?^"/\(.*\)",$?\1?g')
tao_launch -docker_img ${DEMO_DIR}/demo_client/docker.img.tgz -- ${DEMO_DIR}/demo_client/docker.img.tgz --link ${container_name}:server

echo "Waiting for the tests to complete"
sleep 5

echo "Cleaning up docker containers"
docker stop $container_name
kill $hostpid
