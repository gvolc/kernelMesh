// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026,
//           gvolc <https://github.com/gvolc> 2026,
//           gvolc team <https://github.com/gvolc> 2026.
//
// The code is distributed under the Mozilla Public License Version 2.0 license
// (you can find the license file in the root folder).

// @file ml_kem_test.cpp
// @brief Unit tests for hardened ML-KEM key generation.

// #include "../crypto/ml_kem.hpp"
#include "../future/crypto/ml_kem.hpp"

#include <gtest/gtest.h>

#include <array>
#include <vector>

namespace kernelmesh {
namespace crypto {
namespace {

TEST(MlKemTest, GenerateKeyPair768Success) {
  alignas(MlCryptoAlignment) std::array<std::byte, MlKem768PublicKeySize> pub;
  alignas(MlCryptoAlignment) std::array<std::byte, MlKem768SecretKeySize> sec;

  CryptoStatus status = GenerateKeyPair(pub, sec);

  EXPECT_EQ(status, CryptoStatus::kSuccess);
  EXPECT_FALSE(IsCryptoFailed(status));

  bool all_zeros = true;
  for (std::byte b : pub) {
    if (b != std::byte{0}) {
      all_zeros = false;
      break;
    }
  }
  EXPECT_FALSE(all_zeros);
}

TEST(MlKemTest, GenerateKeyPairExAllVariantsSuccess) {
  // ML-KEM-512
  {
    alignas(MlCryptoAlignment) std::array<std::byte, MlKem512PublicKeySize> pub;
    alignas(MlCryptoAlignment) std::array<std::byte, MlKem512SecretKeySize> sec;
    EXPECT_EQ(GenerateKeyPairEx(MlKemVariant::kMlKem512, pub, sec),
              CryptoStatus::kSuccess);
  }
  // ML-KEM-1024
  {
    alignas(MlCryptoAlignment) std::array<std::byte, MlKem1024PublicKeySize>
        pub;
    alignas(MlCryptoAlignment) std::array<std::byte, MlKem1024SecretKeySize>
        sec;
    EXPECT_EQ(GenerateKeyPairEx(MlKemVariant::kMlKem1024, pub, sec),
              CryptoStatus::kSuccess);
  }
}

TEST(MlKemTest, RejectsMisalignedBuffers) {
  alignas(MlCryptoAlignment) std::array<std::byte, MlKem768PublicKeySize + 1>
      raw_pub;
  alignas(MlCryptoAlignment) std::array<std::byte, MlKem768SecretKeySize + 1>
      raw_sec;

  std::span<std::byte> misaligned_pub(raw_pub.data() + 1,
                                      MlKem768PublicKeySize);
  std::span<std::byte> misaligned_sec(raw_sec.data() + 1,
                                      MlKem768SecretKeySize);

  CryptoStatus status = GenerateKeyPairEx(MlKemVariant::kMlKem768,
                                          misaligned_pub, misaligned_sec);
  EXPECT_EQ(status, CryptoStatus::kBufferNotAligned);
}

TEST(MlKemTest, RejectsInvalidBufferSizes) {
  alignas(MlCryptoAlignment) std::array<std::byte, MlKem768PublicKeySize - 1>
      small_pub;
  alignas(MlCryptoAlignment) std::array<std::byte, MlKem768SecretKeySize>
      correct_sec;

  CryptoStatus status =
      GenerateKeyPairEx(MlKemVariant::kMlKem768, small_pub, correct_sec);
  EXPECT_EQ(status, CryptoStatus::kInvalidBufferSize);
}

TEST(MlKemTest, FullKemCycle768Success) {
  alignas(MlCryptoAlignment) std::array<std::byte, MlKem768PublicKeySize> pub;
  alignas(MlCryptoAlignment) std::array<std::byte, MlKem768SecretKeySize> sec;
  
  ASSERT_EQ(GenerateKeyPair(pub, sec), CryptoStatus::kSuccess);

  alignas(MlCryptoAlignment) std::array<std::byte, MlKem768CiphertextSize> ciphertext;
  alignas(MlCryptoAlignment) std::array<std::byte, MlKemSharedSecretSize> alice_secret;
  alignas(MlCryptoAlignment) std::array<std::byte, MlKemSharedSecretSize> bob_secret;

  EXPECT_EQ(Encapsulate(pub, ciphertext, alice_secret), CryptoStatus::kSuccess);
  EXPECT_EQ(Decapsulate(sec, ciphertext, bob_secret), CryptoStatus::kSuccess);

  EXPECT_EQ(alice_secret, bob_secret);
}


}  // namespace
}  // namespace crypto
}  // namespace kernelmesh
