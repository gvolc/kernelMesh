// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026,
//           gvolc <https://github.com/gvolc> 2026,
//           gvolc team <https://github.com/gvolc> 2026.
//
// The code is distributed under the Mozilla Public License Version 2.0 license
// (you can find the license file in the root folder).

#include "ml_kem.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/crypto.h> 

#include <optional>
#include <memory>

namespace kernelmesh {
namespace crypto {

namespace {

struct MlKemParams {
  const char* name;
  size_t public_key_size;
  size_t secret_key_size;
  size_t ciphertext_size;
};

[[nodiscard]] constexpr std::optional<MlKemParams> GetVariantParams(MlKemVariant variant) noexcept {
  switch (variant) {
    case MlKemVariant::kMlKem512:
      return MlKemParams{ "ML-KEM-512", MlKem512PublicKeySize, MlKem512SecretKeySize, MlKem512CiphertextSize };
    case MlKemVariant::kMlKem768:
      return MlKemParams{ "ML-KEM-768", MlKem768PublicKeySize, MlKem768SecretKeySize, MlKem768CiphertextSize };
    case MlKemVariant::kMlKem1024:
      return MlKemParams{ "ML-KEM-1024", MlKem1024PublicKeySize, MlKem1024SecretKeySize, MlKem1024CiphertextSize };
  }
  return std::nullopt;
}

// RAII обертки для безопасного управления ресурсами OpenSSL в продакшене
struct EvpPkeyCtxDeleter { void operator()(EVP_PKEY_CTX* ptr) const { EVP_PKEY_CTX_free(ptr); } };
struct EvpPkeyDeleter    { void operator()(EVP_PKEY* ptr) const { EVP_PKEY_free(ptr); } };

using SafeEvpCtx  = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using SafeEvpPkey = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

}  // namespace

CryptoStatus GenerateKeyPairEx(MlKemVariant variant,
                               std::span<std::byte> public_key,
                               std::span<std::byte> secret_key) noexcept {
  if (public_key.data() == nullptr || secret_key.data() == nullptr) {
    return CryptoStatus::kInvalidArgument;
  }

  if (!IsMemoryAligned(public_key.data()) || !IsMemoryAligned(secret_key.data())) {
    return CryptoStatus::kBufferNotAligned;
  }

  const auto params_opt = GetVariantParams(variant);
  if (!params_opt.has_value()) {
    return CryptoStatus::kInvalidArgument;
  }
  const MlKemParams params = *params_opt;

  if (public_key.size() != params.public_key_size ||
      secret_key.size() != params.secret_key_size) {
    return CryptoStatus::kInvalidBufferSize;
  }

  SafeEvpCtx ctx(EVP_PKEY_CTX_new_from_name(nullptr, params.name, nullptr));
  if (!ctx) {
    return CryptoStatus::kContextCreationFailed;
  }

  if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
    return CryptoStatus::kKeyGenerationFailed;
  }

  EVP_PKEY* raw_pkey = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &raw_pkey) <= 0 || raw_pkey == nullptr) {
    if (raw_pkey) EVP_PKEY_free(raw_pkey);
    return CryptoStatus::kKeyGenerationFailed;
  }
  SafeEvpPkey pkey(raw_pkey);

  ctx.reset(); // Освобождаем контекст генерации перед экспортом параметров

  size_t pub_len = public_key.size();
  size_t priv_len = secret_key.size();

  unsigned char* raw_pub_ptr = reinterpret_cast<unsigned char*>(public_key.data());
  unsigned char* raw_priv_ptr = reinterpret_cast<unsigned char*>(secret_key.data());

  int res_pub = EVP_PKEY_get_octet_string_param(pkey.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                                raw_pub_ptr, pub_len, &pub_len);

  int res_priv = EVP_PKEY_get_octet_string_param(pkey.get(), OSSL_PKEY_PARAM_PRIV_KEY,
                                                 raw_priv_ptr, priv_len, &priv_len);

  pkey.reset(); // Безопасно уничтожаем ключ

  if (res_pub <= 0 || pub_len != params.public_key_size ||
      res_priv <= 0 || priv_len != params.secret_key_size) {
    OPENSSL_cleanse(secret_key.data(), secret_key.size());
    OPENSSL_cleanse(public_key.data(), public_key.size());
    return CryptoStatus::kExportFailed;
  }

  return CryptoStatus::kSuccess;
}

CryptoStatus EncapsulateEx(
    MlKemVariant variant,
    std::span<const std::byte> public_key,
    std::span<std::byte> ciphertext,
    std::span<std::byte> shared_secret) noexcept {
  
  if (public_key.data() == nullptr || ciphertext.data() == nullptr || shared_secret.data() == nullptr) {
    return CryptoStatus::kInvalidArgument;
  }

  if (!IsMemoryAligned(public_key.data()) || !IsMemoryAligned(ciphertext.data()) || !IsMemoryAligned(shared_secret.data())) {
    return CryptoStatus::kBufferNotAligned;
  }

  const auto params_opt = GetVariantParams(variant);
  if (!params_opt.has_value()) {
    return CryptoStatus::kInvalidArgument;
  }
  const MlKemParams params = *params_opt;

  if (public_key.size() != params.public_key_size || 
      ciphertext.size() != params.ciphertext_size || 
      shared_secret.size() != MlKemSharedSecretSize) {
    return CryptoStatus::kInvalidBufferSize;
  }

  SafeEvpCtx ctx(EVP_PKEY_CTX_new_from_name(nullptr, params.name, nullptr));
  if (!ctx) {
    return CryptoStatus::kContextCreationFailed;
  }

  void* raw_pub_ptr = const_cast<void*>(static_cast<const void*>(public_key.data()));

  OSSL_PARAM os_params[2];
  os_params[0] = OSSL_PARAM_construct_octet_string(
      OSSL_PKEY_PARAM_PUB_KEY, 
      raw_pub_ptr, 
      public_key.size());
  os_params[1] = OSSL_PARAM_construct_end();

  EVP_PKEY* raw_pub_pkey = nullptr;
  if (EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
      EVP_PKEY_fromdata(ctx.get(), &raw_pub_pkey, EVP_PKEY_PUBLIC_KEY, os_params) <= 0) {
    if (raw_pub_pkey) EVP_PKEY_free(raw_pub_pkey);
    return CryptoStatus::kContextCreationFailed;
  }
  if (raw_pub_pkey == nullptr) {
    return CryptoStatus::kContextCreationFailed;
  }
  SafeEvpPkey pub_pkey(raw_pub_pkey);
  ctx.reset(); 

  ctx.reset(EVP_PKEY_CTX_new_from_pkey(nullptr, pub_pkey.get(), nullptr));
  pub_pkey.reset(); 
  if (!ctx) {
    return CryptoStatus::kContextCreationFailed;
  }

  if (EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0) {
    return CryptoStatus::kContextCreationFailed;
  }

  size_t ct_len = ciphertext.size();
  size_t ss_len = shared_secret.size();
  
  int res = EVP_PKEY_encapsulate(
      ctx.get(), 
      reinterpret_cast<unsigned char*>(ciphertext.data()), &ct_len,
      reinterpret_cast<unsigned char*>(shared_secret.data()), &ss_len);

  ctx.reset();

  if (res <= 0 || ct_len != params.ciphertext_size || ss_len != MlKemSharedSecretSize) {
    OPENSSL_cleanse(ciphertext.data(), ciphertext.size());
    OPENSSL_cleanse(shared_secret.data(), shared_secret.size());
    return CryptoStatus::kExportFailed;
  }

  return CryptoStatus::kSuccess;
}

CryptoStatus DecapsulateEx(
    MlKemVariant variant,
    std::span<const std::byte> secret_key,
    std::span<const std::byte> ciphertext,
    std::span<std::byte> shared_secret) noexcept {
  
  if (secret_key.data() == nullptr || ciphertext.data() == nullptr || shared_secret.data() == nullptr) {
    return CryptoStatus::kInvalidArgument;
  }

  if (!IsMemoryAligned(secret_key.data()) || !IsMemoryAligned(ciphertext.data()) || !IsMemoryAligned(shared_secret.data())) {
    return CryptoStatus::kBufferNotAligned;
  }

  const auto params_opt = GetVariantParams(variant);
  if (!params_opt.has_value()) {
    return CryptoStatus::kInvalidArgument;
  }
  const MlKemParams params = *params_opt;

  if (secret_key.size() != params.secret_key_size || 
      ciphertext.size() != params.ciphertext_size || 
      shared_secret.size() != MlKemSharedSecretSize) {
    return CryptoStatus::kInvalidBufferSize;
  }

  SafeEvpCtx ctx(EVP_PKEY_CTX_new_from_name(nullptr, params.name, nullptr));
  if (!ctx) {
    return CryptoStatus::kContextCreationFailed;
  }

  void* raw_priv_ptr = const_cast<void*>(static_cast<const void*>(secret_key.data()));

  OSSL_PARAM os_params[2];
  os_params[0] = OSSL_PARAM_construct_octet_string(
      OSSL_PKEY_PARAM_PRIV_KEY, 
      raw_priv_ptr, 
      secret_key.size());
  os_params[1] = OSSL_PARAM_construct_end();

  EVP_PKEY* raw_priv_pkey = nullptr;
  if (EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
      EVP_PKEY_fromdata(ctx.get(), &raw_priv_pkey, EVP_PKEY_KEYPAIR, os_params) <= 0) {
    if (raw_priv_pkey) EVP_PKEY_free(raw_priv_pkey);
    return CryptoStatus::kContextCreationFailed;
  }
  if (raw_priv_pkey == nullptr) {
    return CryptoStatus::kContextCreationFailed;
  }
  SafeEvpPkey priv_pkey(raw_priv_pkey);
  ctx.reset();

  ctx.reset(EVP_PKEY_CTX_new_from_pkey(nullptr, priv_pkey.get(), nullptr));
  priv_pkey.reset();
  if (!ctx) {
    return CryptoStatus::kContextCreationFailed;
  }

  if (EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0) {
    return CryptoStatus::kDecapsulationFailed;
  }

  size_t ss_len = shared_secret.size();
  
  int res = EVP_PKEY_decapsulate(
      ctx.get(), 
      reinterpret_cast<unsigned char*>(shared_secret.data()), &ss_len,
      reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size());

  ctx.reset();

  if (res <= 0 || ss_len != MlKemSharedSecretSize) {
    OPENSSL_cleanse(shared_secret.data(), shared_secret.size());
    return CryptoStatus::kExportFailed;
  }

  return CryptoStatus::kSuccess;
}

}  // namespace crypto
}  // namespace kernelmesh