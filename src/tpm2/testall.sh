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


