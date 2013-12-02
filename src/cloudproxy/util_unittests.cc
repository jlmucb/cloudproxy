#include <gtest/gtest.h>

#include "cloudproxy/util.h"

TEST(DummyTest, dummy) {
  printf("The test succeeded\n");
  EXPECT_TRUE(true);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
