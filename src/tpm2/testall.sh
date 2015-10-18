#
./tpm2_util.exe --command=Flushall
./tpm2_util.exe --command=KeyCombinedTest --pcr_num=7
./tpm2_util.exe --command=Flushall
./tpm2_util.exe --command=SealCombinedTest --pcr_num=7
./tpm2_util.exe --command=Flushall
./tpm2_util.exe --command=QuoteCombinedTest --pcr_num=7
./tpm2_util.exe --command=Flushall
./tpm2_util.exe --command=ContextCombinedTest --pcr_num=7
./tpm2_util.exe --command=Flushall
./tpm2_util.exe --command=NvCombinedTest --pcr_num=7
./tpm2_util.exe --command=Flushall
./tpm2_util.exe --command=EndorsementCombinedTest --pcr_num=7
./tpm2_util.exe --command=Flushall

./GeneratePolicyKey.exe --algorithm=RSA --exponent=0x010001 \
--modulus_size_in_bits=2048 --signing_instructions=signing_instructions \
--key_name=test_key1 --cloudproxy_key_file=cloudproxy_key_file

./SigningInstructions.exe --issuer=JohnsCloudProxyCa --can_sign=true

./SelfSignPolicyCert.exe --signing_instructions_file=signing_instructions \
--key_file=cloudproxy_key_file --policy_identifier=test-policy-domain --cert_file=policy_key_cert

./GetEndorsementKey.exe --machine_identifier="John's Nuc" --endorsement_info_file=endorsement_key_info_file

./CloudProxySignEndorsementKey.exe \
--cloudproxy_private_key_file=cloudproxy_key_file \
--endorsement_info_file=endorsement_key_info_file \
--signing_instructions_file=signing_instructions \
--signed_endorsement_cert=endorsement_cert

./CreateAndSaveCloudProxyKeyHierarchy.exe \
--slot_primary=1 \
--slot_seal=2 \
--slot_quote=3 \
--pcr_hash_alg_name=sha256

openssl x509 -inform DER -in endorsement_cert -purpose -text


