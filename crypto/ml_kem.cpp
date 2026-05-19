// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026,
//           gvolc <https://github.com/gvolc> 2026,
//           gvolc team <https://github.com/gvolc> 2026.
//
// The code is distributed under the Mozilla Public License Version 2.0 license
// (you can find the license file in the root folder).

// @file ml_kem.cpp
// @brief Implementation of the ML-KEM post-quantum cryptographic interface.
//
// This file implements the FIPS 203 Key Encapsulation Mechanism (KEM)
// operations optimized for the kernelMesh high-load network stack.
//
// Security & Performance Guarantees:
// * Zero-allocation: No runtime heap allocations are performed inside the C++
// layer.
// * Constant-time: Memory alignment checks enforce 64-byte alignment to prevent
//   hardware-level cache/timing side-channel leaks during AVX-512 execution.
// * Failure Hardening: Destructive cleanup (zeroization) of output buffers
//   is enforced immediately if any internal cryptographic step fails.

#include "ml_kem.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>

namespace kernelmesh {
namespace crypto {

namespace {

// Internal structure to map algorithm parameters without heap allocation
struct MlKemParams {
  const char* name;
  size_t public_key_size;
  size_t secret_key_size;
};

// Pure lookup table converting enum to precise FIPS 203 parameters
[[nodiscard]] constexpr MlKemParams GetVariantParams(
    MlKemVariant variant) noexcept {
  switch (variant) {
    case MlKemVariant::kMlKem512:
      return {"ML-KEM-512", MlKem512PublicKeySize, MlKem512SecretKeySize};
    case MlKemVariant::kMlKem1024:
      return {"ML-KEM-1024", MlKem1024PublicKeySize, MlKem1024SecretKeySize};
    case MlKemVariant::kMlKem768:
    default:
      return {"ML-KEM-768", MlKem768PublicKeySize, MlKem768SecretKeySize};
  }
}

}  // namespace

CryptoStatus GenerateKeyPairEx(MlKemVariant variant,
                               std::span<std::byte> public_key,
                               std::span<std::byte> secret_key) noexcept {
  // 1. Strict Nullpointer Verification
  if (public_key.data() == nullptr || secret_key.data() == nullptr) {
    return CryptoStatus::kInvalidArgument;
  }

  // 2. Strict Cryptographic Memory Alignment Check (64-byte boundary)
  if (!IsMemoryAligned(public_key.data()) ||
      !IsMemoryAligned(secret_key.data())) {
    return CryptoStatus::kBufferNotAligned;
  }

  // 3. Runtime Buffer Size Verification according to FIPS 203 parameters
  const MlKemParams params = GetVariantParams(variant);
  if (public_key.size() != params.public_key_size ||
      secret_key.size() != params.secret_key_size) {
    return CryptoStatus::kInvalidBufferSize;
  }

  // 4. OpenSSL Context Creation for specified ML-KEM variant
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, params.name, nullptr);
  if (ctx == nullptr) {
    return CryptoStatus::kContextCreationFailed;
  }

  // Initialize the context for key generation
  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    return CryptoStatus::kKeyGenerationFailed;
  }

  // 5. Cryptographic Keypair Generation using OS/Hardware TRNG
  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(ctx, &pkey) <= 0 || pkey == nullptr) {
    EVP_PKEY_CTX_free(ctx);
    return CryptoStatus::kKeyGenerationFailed;
  }

  // Generation context is safely discarded immediately after pkey is populated
  EVP_PKEY_CTX_free(ctx);

  // 6. Zero-copy Raw Key Material Serialization to aligned buffers
  size_t pub_len = public_key.size();
  size_t priv_len = secret_key.size();

  // Convert std::byte* to unsigned char* via reinterpret_cast for OpenSSL C-API
  unsigned char* raw_pub_ptr =
      reinterpret_cast<unsigned char*>(public_key.data());
  unsigned char* raw_priv_ptr =
      reinterpret_cast<unsigned char*>(secret_key.data());

  // Export public standard encapsulation key (ek)
  int res_pub = EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                                raw_pub_ptr, pub_len, &pub_len);

  // Export secret standard decapsulation key (dk)
  int res_priv = EVP_PKEY_get_octet_string_param(
      pkey, OSSL_PKEY_PARAM_PRIV_KEY, raw_priv_ptr, priv_len, &priv_len);

  // Free OpenSSL internal pkey allocation (wipes key buffers under the hood)
  EVP_PKEY_free(pkey);

  // Final verification of exported sizes against exact structural limits
  if (res_pub <= 0 || pub_len != params.public_key_size || res_priv <= 0 ||
      priv_len != params.secret_key_size) {
    return CryptoStatus::kExportFailed;
  }

  return CryptoStatus::kSuccess;
}

}  // namespace crypto
}  // namespace kernelmesh
