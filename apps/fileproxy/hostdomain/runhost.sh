#
export TAO_HOST_DIR=/Users/manferdelli/src/github.com/jlmucb/cloudproxy/apps/fileproxy/hostdomain
export TAO_ROOTDIR=/Users/manferdelli/src/github.com/jlmucb/cloudproxy
cd $TAO_HOST_DIR
linux_host -create -root -pass nopassword
linux_host -service -root -pass nopassword &
