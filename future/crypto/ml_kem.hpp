// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026,
//           gvolc <https://github.com/gvolc> 2026,
//           gvolc team <https://github.com/gvolc> 2026.
//
// The code is distributed under the Mozilla Public License Version 2.0 license
// (you can find the license file in the root folder).

// @file ml_kem.hpp
// @brief Declaration of the ML-KEM post-quantum encryption algorithm interface.

#ifndef KERNELMESH_CRYPTO_ML_KEM_HPP_
#define KERNELMESH_CRYPTO_ML_KEM_HPP_

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace kernelmesh {
namespace crypto {

// Hardened memory alignment to eliminate hardware-level timing leaks (AVX-512)
inline constexpr size_t MlCryptoAlignment = 64;

// --- NIST FIPS 203 ML-KEM Constant Parameters ---

inline constexpr size_t MlKem512PublicKeySize = 800;
inline constexpr size_t MlKem512SecretKeySize = 1632;
inline constexpr size_t MlKem512CiphertextSize = 768;

inline constexpr size_t MlKem768PublicKeySize = 1184;
inline constexpr size_t MlKem768SecretKeySize = 2400;
inline constexpr size_t MlKem768CiphertextSize = 1088;

inline constexpr size_t MlKem1024PublicKeySize = 1568;
inline constexpr size_t MlKem1024SecretKeySize = 3168;
inline constexpr size_t MlKem1024CiphertextSize = 1568;

inline constexpr size_t MlKemSharedSecretSize = 32;

enum class MlKemVariant : uint8_t {
  kMlKem512 = 0,
  kMlKem768 = 1,
  kMlKem1024 = 2
};

// --- Hardened Error Handling ---

enum class CryptoStatus : uint32_t {
  kSuccess = 0,
  kInvalidArgument = 1,
  kBufferNotAligned = 2,
  kInvalidBufferSize = 3,
  kContextCreationFailed = 4,
  kKeyGenerationFailed = 5,
  kDecapsulationFailed = 6,
  kExportFailed = 7
};

[[nodiscard]] inline constexpr bool IsCryptoFailed(
    CryptoStatus status) noexcept {
  return status != CryptoStatus::kSuccess;
}

[[nodiscard]] inline constexpr std::string_view CryptoStatusToString(
    CryptoStatus status) noexcept {
  switch (status) {
    case CryptoStatus::kSuccess:
      return "Success";
    case CryptoStatus::kInvalidArgument:
      return "Invalid argument: nullptr pointer or invalid variant detected";
    case CryptoStatus::kBufferNotAligned:
      return "Cryptographic buffer misaligned (Must be 64-byte boundary)";
    case CryptoStatus::kInvalidBufferSize:
      return "Buffer sizing conflict against FIPS 203 constraint mapping";
    case CryptoStatus::kContextCreationFailed:
      return "OpenSSL EVP state context initialization failure";
    case CryptoStatus::kKeyGenerationFailed:
      return "Cryptographic hardware or TRNG key derivation failure";
    case CryptoStatus::kDecapsulationFailed:
      return "OpenSSL EVP decapsulate initialization or processing failure";
    case CryptoStatus::kExportFailed:
      return "Serialization from OpenSSL internal key material failed";
    default:
      return "Fatal: Untracked internal cryptographic anomaly";
  }
}

// --- Memory Boundary Verification Functions ---

[[nodiscard]] inline bool IsMemoryAligned(const void* ptr) noexcept {
  return reinterpret_cast<uintptr_t>(ptr) % MlCryptoAlignment == 0;
}

// --- Main Cryptographic API ---

[[nodiscard]] CryptoStatus GenerateKeyPairEx(
    MlKemVariant variant, std::span<std::byte> public_key,
    std::span<std::byte> secret_key) noexcept;

[[nodiscard]] inline CryptoStatus GenerateKeyPair(
    std::span<std::byte, MlKem768PublicKeySize> public_key,
    std::span<std::byte, MlKem768SecretKeySize> secret_key) noexcept {
  return GenerateKeyPairEx(MlKemVariant::kMlKem768, public_key, secret_key);
}

// --- Advanced KEM API: Encapsulation and Decapsulation ---

[[nodiscard]] CryptoStatus EncapsulateEx(
    MlKemVariant variant, std::span<const std::byte> public_key,
    std::span<std::byte> ciphertext,
    std::span<std::byte> shared_secret) noexcept;

[[nodiscard]] CryptoStatus DecapsulateEx(
    MlKemVariant variant, std::span<const std::byte> secret_key,
    std::span<const std::byte> ciphertext,
    std::span<std::byte> shared_secret) noexcept;

// --- High-Performance ML-KEM-768 Inline Helpers ---

[[nodiscard]] inline CryptoStatus Encapsulate(
    std::span<const std::byte, MlKem768PublicKeySize> public_key,
    std::span<std::byte, MlKem768CiphertextSize> ciphertext,
    std::span<std::byte, MlKemSharedSecretSize> shared_secret) noexcept {
  return EncapsulateEx(MlKemVariant::kMlKem768, public_key, ciphertext,
                       shared_secret);
}

[[nodiscard]] inline CryptoStatus Decapsulate(
    std::span<const std::byte, MlKem768SecretKeySize> secret_key,
    std::span<const std::byte, MlKem768CiphertextSize> ciphertext,
    std::span<std::byte, MlKemSharedSecretSize> shared_secret) noexcept {
  return DecapsulateEx(MlKemVariant::kMlKem768, secret_key, ciphertext,
                       shared_secret);
}

}  // namespace crypto
}  // namespace kernelmesh

#endif  // KERNELMESH_CRYPTO_ML_KEM_HPP_