#
export TAO_TEST=/Users/manferdelli/cloudproxy/apps/testcode/test
export TAO_ROOTDIR=/Users/manferdelli/cloudproxy
cd $TAO_TEST
mkdir linux_tao_host
mkdir policy_keys
export TAO_USE_TPM=no
export TAO_config_path=$TAO_TEST/tao.config
export TAO_guard=AllowAll
tao_admin -create -name testing -pass nopassword
linux_host -create -root -pass nopassword
linux_host -service -root -pass nopassword
go build jlmtest.go
cd test
linux_host -run -- ../jlmtest

