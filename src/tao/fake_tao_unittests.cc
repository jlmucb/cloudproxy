#include "tao/fake_tao.h"
#include "gtest/gtest.h"

using tao::FakeTao;

class FakeTaoTest : public ::testing::Test {
protected:
  virtual void SetUp() {
    ASSERT_TRUE(tao_.Init());
  }

  FakeTao tao_;
};

TEST_F(FakeTaoTest, RandomBytesTest) {
  string bytes;

  EXPECT_TRUE(tao_.GetRandomBytes(10, &bytes));
  EXPECT_TRUE(tao_.GetRandomBytes(0, &bytes));
}

TEST_F(FakeTaoTest, SealTest) {
  string bytes;
  EXPECT_TRUE(tao_.GetRandomBytes(128, &bytes));
  string sealed;
  EXPECT_TRUE(tao_.Seal(bytes, &sealed));
}

TEST_F(FakeTaoTest, UnsealTest) {
  string bytes;
  EXPECT_TRUE(tao_.GetRandomBytes(128, &bytes));
  string sealed;
  EXPECT_TRUE(tao_.Seal(bytes, &sealed));

  string unsealed;
  EXPECT_TRUE(tao_.Unseal(sealed, &unsealed));

  EXPECT_EQ(bytes, unsealed);
}  

TEST_F(FakeTaoTest, AttestTest) {
  string bytes;
  EXPECT_TRUE(tao_.GetRandomBytes(128, &bytes));
  
  string attestation;
  EXPECT_TRUE(tao_.Attest(bytes, &attestation));
}

TEST_F(FakeTaoTest, VerifyAttestTest) {
  string bytes;
  EXPECT_TRUE(tao_.GetRandomBytes(128, &bytes));
  
  string attestation;
  EXPECT_TRUE(tao_.Attest(bytes, &attestation));

  string data;
  EXPECT_TRUE(tao_.VerifyAttestation(attestation, &data));

  EXPECT_EQ(data, bytes);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
