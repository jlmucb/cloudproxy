#
export TAO_HOST_DIR=/Users/manferdelli/src/github.com/jlmucb/cloudproxy/apps/fileproxy/hostdomain
export TAO_ROOTDIR=/Users/manferdelli/src/github.com/jlmucb/cloudproxy
cd $TAO_HOST_DIR
mkdir linux_tao_host
mkdir policy_keys
export TAO_USE_TPM=no
export TAO_config_path=$TAO_HOST_DIR/tao.config
export TAO_guard=AllowAll
tao_admin -create -name fileproxy -pass nopassword
