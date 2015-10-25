#ifdef DEBUG
  string k;
  string kname;
  string nullstr;
  label = "INTEGRITY";
  k.assign((const char*)zero_iv, 16);
  KDFa(TPM_ALG_SHA256, k, label, nullstr, nullstr, 128, 32, test_buf);
  printf("\n\nKDFa(TPM_ALG_SHA256, 0, null, null, 128): ");
  PrintBytes(16, test_buf);
  printf("\n\n");
  label.clear();
  k.clear();

{
  byte seed[]= {
    0x67, 0x9a, 0xea, 0x85, 0x81, 0x24, 0x6d, 0x18,
    0x69, 0x3f, 0xcf, 0x7a, 0x00, 0xa2, 0x00, 0x94
  };
  k.assign((const char*)seed, 16);
  byte keyName[] = {
    0x00, 0x04, 0x6b, 0x6b, 0x64, 0x9d, 0x49, 0x1e,
    0x24, 0xdf, 0x83, 0x0a, 0xfa, 0xdc, 0xe7, 0x07,
    0x1a, 0xa9, 0x97, 0x7c, 0x14, 0x66
  };
  byte sKey[32];
  kname.assign((const char*)keyName, 22);
  string label("STORAGE");
  printf("symKey: 00a805738b152182c740c4dbb59a47f1\n");
  KDFa(TPM_ALG_SHA1, k, label, kname, nullstr, 128, 32, sKey);
  printf("Calculated symKey: ");
  PrintBytes(16, sKey);
  printf("\n");
  byte lSecret[] = {
    0x00, 0x14, 0xda, 0xfa, 0x96, 0x3d, 0x3e, 0xa6,
    0xf9, 0x19, 0x47, 0x02, 0x86, 0x4a, 0x30, 0x9c, 
    0xb4, 0x17, 0x1b, 0xfe, 0xc6, 0x71
  };
  printf("\n");
  byte EI[128];
  int iEI = 128;
  if (!AesCFBEncrypt(sKey, 22, (byte*)lSecret, 16, zero_iv,
                     &iEI, EI)) {
    printf("AesCFBEncrypt failed\n");
  }
  printf("\n");
  printf("encIdentity: c371176fdd19f4cc3a67eaea031f3ec7c0f5c66c4306\n");
  printf("Calculated encidentity: ");
  PrintBytes(iEI, EI);
  printf("\n");
  printf("hmacKey: 1642143537aa04a0fad52b78bc1bd2496a4192ef\n");
  byte hMK[64];
  label.clear();
  label = "INTEGRITY";
  KDFa(TPM_ALG_SHA1, k, label, nullstr, nullstr,
       160, 32, hMK);
  printf("calculated hMacKey: ");
  PrintBytes(20, hMK);
  printf("\n");
  byte toHash[128];
  memset(toHash, 0, 128);
  memcpy(toHash, EI, iEI);
  memcpy(&toHash[iEI], keyName, 22);
  int hashSize = iEI + 22;
  printf("Tomac: ");
  PrintBytes(hashSize, toHash);
  printf("\n");
  HMAC_CTX_init(&hctx);
  HMAC_Init_ex(&hctx, hMK, 20, EVP_sha1(), nullptr);
  HMAC_Update(&hctx, (const byte*)EI, iEI);
  HMAC_Update(&hctx, keyName, 22);
  HMAC_Final(&hctx, test_buf, (uint32_t*)&test_size);
  HMAC_CTX_cleanup(&hctx);
  printf("\n");
  printf("integrity: ");
  PrintBytes(test_size, test_buf);
  printf("\n");
  printf("outerHmac: 80a0516b8881db9076756a8be3ec4f2b90af0370\n");
  printf("\n");
  printf("Blob: 001480a0516b8881db9076756a8be3ec4f2b90af0370c371176fdd19f4cc3a67eaea031f3ec7c0f5c66c4306\n");
}
#endif
