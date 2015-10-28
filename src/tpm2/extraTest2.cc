void test_paul(RSA* p_key) {
printf("\n\n*** \n paultest \n\n");
  int seed_size = 0x10;
  byte seed_buf[] = {
    0xe0, 0xbf, 0x4e, 0x1c, 0xb6, 0x0b, 0x4c, 0xbb,
    0x6f, 0x53, 0x6b, 0x37, 0x5a, 0x60, 0xdb, 0x4f
  };
  int name_size = 22;
  byte name_buf[] = {
    0x00, 0x04, 0xb9, 0x94, 0xef, 0x4d, 0x93, 0x15,
    0xb4, 0xd0, 0x70, 0x16, 0x80, 0xfd, 0xef, 0x8c, 
    0x9a, 0x76, 0xf8, 0xae, 0x83, 0x83
  };
  string name;
  name.assign((const char*)name_buf, name_size);
  string label("IDENTITY");
  int test_size;
  byte test_buf[4096];
  string contextV;
  int size_hmacKey = 20;

  TPM2B_DIGEST marshaled_credential;
  TPM2B_DIGEST unmarshaled_credential;
  unmarshaled_credential.size = 0x14;

  byte credential_buf[] = {
    0xb8, 0x19, 0x40, 0x46, 0x30, 0x32, 0x04, 0x95, 
    0x3f, 0x82, 0xa8, 0x7a, 0xae, 0x81, 0xc0, 0x5f, 
    0x1c, 0x9f, 0x44, 0x43
  };
  memcpy(unmarshaled_credential.buffer, credential_buf,
         unmarshaled_credential.size);
  ChangeEndian16(&unmarshaled_credential.size, &marshaled_credential.size);
  memcpy(marshaled_credential.buffer, credential_buf, unmarshaled_credential.size);

  printf("symKey should be: 6d1d2858 20df1eab 4254839b a13979b3\n");
  printf("encId should be: 2e1aa996 3f555eda ca3e04b3 2368b4c1 911c0344 85e1\n");
  printf("hmacKey should be: 1f44b597 9aafa320 90e6a5e9 f93489d5 ea84dd88\n");
  printf("outerHmac should be: 44441767 90c9ebf1 3a3ff0dc d7a9f01d fb4597ee\n");
  printf("actBlob should be: 00144444 176790c9 ebf13a3f f0dcd7a9 f01dfb45 97ee2e1a a9963f55 5edaca3e 04b32368 b4c1911c 034485e1\n");

  int size_in = 0;
  byte hmacKey[128];
  byte encIdentity[128];
  byte outerHmac[128];
  byte zero_iv[32];
  memset(zero_iv, 0, 32);

  byte in_buf[4096];
  memcpy(in_buf, seed_buf, seed_size);
  size_in += seed_size;
  memcpy(&in_buf[size_in], (byte*)"IDENTITY", strlen("IDENTITY") + 1);
  size_in += strlen("IDENTITY") + 1;
  HMAC_CTX hctx;

  // Secret= E(protector_key, seed || "IDENTITY")
  byte encrypted_secret[4096];
  int encrypted_secret_size = RSA_public_encrypt(size_in, in_buf, encrypted_secret,
                                                  p_key, RSA_PKCS1_OAEP_PADDING);

  printf("\n\nencrypted_secret_size: %d\n", encrypted_secret_size);
  printf("Encrypted secret: ");
  PrintBytes(encrypted_secret_size, encrypted_secret); printf("\n");
  
  string key;
  key.assign((const char*)seed_buf, seed_size);
  printf("\nseed: ");
  PrintBytes(key.size(), (byte*)key.data());
  printf("\n");
  printf("name: ");
  PrintBytes(name.size(), (byte*)name.data());
  printf("\n");

  // symKey= KDFa(hash, seed, "STORAGE", name, nullptr, 128);
  byte symKey[128];
  memset(symKey, 0, 128);
  label = "STORAGE";
  key.assign((const char*)seed_buf, seed_size);
  contextV.clear();
  if (!KDFa(TPM_ALG_SHA1, key, label, name, contextV, 128, 32, symKey)) {
    printf("Can't KDFa symKey\n");
  }
  printf("symKey: "); PrintBytes(16, symKey); printf("\n");
  printf("marshaled_credential: ");
  PrintBytes(unmarshaled_credential.size + sizeof(uint16_t),
             (byte*)&marshaled_credential);
  printf("\n");

  // encIdentity = CFBEncrypt(symKey, marshaled_credential, out)
  // We need to encrypt the entire marshaled_credential
  int size_encIdentity = 128;
  if (!AesCFBEncrypt(symKey, unmarshaled_credential.size + sizeof(uint16_t),
                     (byte*)&marshaled_credential,
                     16, zero_iv,
                     &size_encIdentity, encIdentity)) {
    printf("Can't AesCFBEncrypt\n");
  }
  printf("\n");
  printf("size_encIdentity: %d\n", size_encIdentity);
  test_size = 4096;
  if (!AesCFBDecrypt(symKey, size_encIdentity,
                     (byte*)encIdentity, 16, zero_iv,
                     &test_size, test_buf)) {
    printf("Can't AesCFBDecrypt\n");
  }
  printf("\nencIdentity (%d): ", size_encIdentity);
  PrintBytes(size_encIdentity, encIdentity); printf("\n");
  printf("Decrypted secret (%d): ", test_size);
  PrintBytes(test_size, test_buf); printf("\n");

 // hmacKey= KDFa(TPM_ALG_SHA1, seed, "INTEGRITY", nullptr, nullptr, 8*hashsize);
  label = "INTEGRITY";
  if (!KDFa(TPM_ALG_SHA1, key, label, contextV,
            contextV, 8 * 20, 32, hmacKey)) {
    printf("Can't KDFa hmacKey\n");
  }
  printf("\nhmacKey: ");
  PrintBytes(20, hmacKey); printf("\n");

  // outerMac = HMAC(hmacKey, encIdentity || name);
  TPM_ALG_ID hash_alg_id = TPM_ALG_SHA1;
  HMAC_CTX_init(&hctx);
  if (hash_alg_id == TPM_ALG_SHA1) {
    HMAC_Init_ex(&hctx, hmacKey, size_hmacKey, EVP_sha1(), nullptr);
  } else {
    HMAC_Init_ex(&hctx, hmacKey, size_hmacKey, EVP_sha256(), nullptr);
  }
  HMAC_Update(&hctx, (const byte*)encIdentity, size_encIdentity);
  HMAC_Update(&hctx, (const byte*)name.data(), name.size());
  HMAC_Final(&hctx, outerHmac, (uint32_t*)&size_hmacKey);
  HMAC_CTX_cleanup(&hctx);
  printf("\nouterHmac: ");
  PrintBytes(20, outerHmac); printf("\n");

printf("\n\n*** \n paultest done\n\n");
  return;
}

