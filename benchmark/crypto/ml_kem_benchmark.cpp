// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026,
//           gvolc <https://github.com/gvolc> 2026,
//           gvolc team <https://github.com/gvolc> 2026.
//
// The code is distributed under the Mozilla Public License Version 2.0 license
// (you can find the license file in the root folder).

// @file ml_kem_benchmark.cpp
// @brief Microbenchmarks for ML-KEM key generation.

#include <benchmark/benchmark.h>

#include <array>

#include "../crypto/ml_kem.hpp"

namespace kernelmesh {
namespace crypto {
namespace {

static void BM_MlKem768_KeyGeneration(benchmark::State& state) {
  alignas(MlCryptoAlignment) std::array<std::byte, MlKem768PublicKeySize> pub;
  alignas(MlCryptoAlignment) std::array<std::byte, MlKem768SecretKeySize> sec;

  for (auto _ : state) {
    CryptoStatus status = GenerateKeyPair(pub, sec);

    if (IsCryptoFailed(status)) {
      state.SkipWithError("Crypto keygen failed inside benchmark loop");
      break;
    }

    benchmark::DoNotOptimize(pub);
    benchmark::DoNotOptimize(sec);
  }
}
BENCHMARK(BM_MlKem768_KeyGeneration);

static void BM_MlKem_Variants_KeyGeneration(benchmark::State& state) {
  MlKemVariant variant = static_cast<MlKemVariant>(state.range(0));
  
  alignas(MlCryptoAlignment) std::array<std::byte, MlKem1024PublicKeySize> pub;
  alignas(MlCryptoAlignment) std::array<std::byte, MlKem1024SecretKeySize> sec;

  size_t pub_size = (variant == MlKemVariant::kMlKem512) ? MlKem512PublicKeySize :
                    (variant == MlKemVariant::kMlKem768) ? MlKem768PublicKeySize : MlKem1024PublicKeySize;
  size_t sec_size = (variant == MlKemVariant::kMlKem512) ? MlKem512SecretKeySize :
                    (variant == MlKemVariant::kMlKem768) ? MlKem768SecretKeySize : MlKem1024SecretKeySize;

  std::span<std::byte> dynamic_pub(pub.data(), pub_size);
  std::span<std::byte> dynamic_sec(sec.data(), sec_size);

  for (auto _ : state) {
    CryptoStatus status = GenerateKeyPairEx(variant, dynamic_pub, dynamic_sec);
    
    if (IsCryptoFailed(status)) {
      state.SkipWithError("Crypto keygen failed inside benchmark loop");
      break;
    }

    benchmark::DoNotOptimize(pub);
    benchmark::DoNotOptimize(sec);
  }
}
BENCHMARK(BM_MlKem_Variants_KeyGeneration)->Arg(0)->Arg(1)->Arg(2);

}  // namespace
}  // namespace crypto
}  // namespace kernelmesh

BENCHMARK_MAIN();
