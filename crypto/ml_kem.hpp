// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026,
//           gvolc <https://github.com/gvolc> 2026,
//           gvolc team <https://github.com/gvolc> 2026.
//
// The code is distributed under the Mozilla Public License Version 2.0 license
// (you can find the license file in the root folder).

// @file ml_kem.hpp
// @brief Declaration of the ML-KEM post-quantum encryption algorithm interface.
//
// This file contains declarations of the Key Encapsulation Mechanism (KEM)
// functions, standardized by NIST (FIPS 203) to protect against threats from
// quantum computers. The interface architecture is optimized for use in
// high-load system components of the kernelMesh project.
//
// Architectural principles:
// * Coding standard: Code conforms to Google C++ Style.
// * Cryptographic backend: The implementation is based on OpenSSL.
// * Zero-copy: Data is passed via std::span or raw pointers.
// * Exceptions: Functions do not throw exceptions (noexcept), returning error
// codes.
// * Thread safety: Constant operations are thread-safe.
//
// Parameter specification (ML-KEM-768 by default):
// * Public Key size: 1184 bytes.
// * Secret Key size: 2400 bytes.
// * Ciphertext size: 1088 bytes.
// * Shared Secret size: 32 bytes.

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

// ML-KEM-512 Parameters
inline constexpr size_t MlKem512PublicKeySize = 800;
inline constexpr size_t MlKem512SecretKeySize = 1632;
inline constexpr size_t MlKem512CiphertextSize = 768;

// ML-KEM-768 Parameters (Default High-Load Component Standard)
inline constexpr size_t MlKem768PublicKeySize = 1184;
inline constexpr size_t MlKem768SecretKeySize = 2400;
inline constexpr size_t MlKem768CiphertextSize = 1088;

// ML-KEM-1024 Parameters
inline constexpr size_t MlKem1024PublicKeySize = 1568;
inline constexpr size_t MlKem1024SecretKeySize = 3168;
inline constexpr size_t MlKem1024CiphertextSize = 1568;

// Shared Secret Size (Identical across all FIPS 203 parameters)
inline constexpr size_t MlKemSharedSecretSize = 32;

// Supported Key Sizes Enum Group
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
  kExportFailed = 6
};

// @brief Evaluates whether the crypto status indicates a failure state.
[[nodiscard]] inline constexpr bool IsCryptoFailed(
    CryptoStatus status) noexcept {
  return status != CryptoStatus::kSuccess;
}

// @brief Resolves error code into a constant human-readable string.
[[nodiscard]] inline constexpr std::string_view CryptoStatusToString(
    CryptoStatus status) noexcept {
  switch (status) {
    case CryptoStatus::kSuccess:
      return "Success";
    case CryptoStatus::kInvalidArgument:
      return "Invalid argument: nullptr pointer detected";
    case CryptoStatus::kBufferNotAligned:
      return "Cryptographic buffer misaligned (Must be 64-byte boundary)";
    case CryptoStatus::kInvalidBufferSize:
      return "Buffer sizing conflict against FIPS 203 constraint mapping";
    case CryptoStatus::kContextCreationFailed:
      return "OpenSSL EVP state context initialization failure";
    case CryptoStatus::kKeyGenerationFailed:
      return "Cryptographic hardware or TRNG key derivation failure";
    case CryptoStatus::kExportFailed:
      return "Serialization from OpenSSL internal key material failed";
    default:
      return "Fatal: Untracked internal cryptographic anomaly";
  }
}

// --- Memory Boundary Verification Functions ---

// @brief Runtime verification of strict memory line alignment.
[[nodiscard]] inline bool IsMemoryAligned(const void* ptr) noexcept {
  return reinterpret_cast<uintptr_t>(ptr) % MlCryptoAlignment == 0;
}

// --- Main Cryptographic API ---

// @brief Core extensible key generation logic with robust parameter protection.
// @param variant Algorithm strength selector (512, 768, or 1024).
// @param[out] public_key Aligned destination buffer for encapsulation key (ek).
// @param[out] secret_key Aligned destination buffer for decapsulation key (dk).
[[nodiscard]] CryptoStatus GenerateKeyPairEx(
    MlKemVariant variant, std::span<std::byte> public_key,
    std::span<std::byte> secret_key) noexcept;

// @brief High-performance static interface strictly locked to ML-KEM-768
// limits.
[[nodiscard]] inline CryptoStatus GenerateKeyPair(
    std::span<std::byte, MlKem768PublicKeySize> public_key,
    std::span<std::byte, MlKem768SecretKeySize> secret_key) noexcept {
  return GenerateKeyPairEx(MlKemVariant::kMlKem768, public_key, secret_key);
}

}  // namespace crypto
}  // namespace kernelmesh

#endif  // KERNELMESH_CRYPTO_ML_KEM_HPP_
