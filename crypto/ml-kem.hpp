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
// * Memory: No heap allocations at runtime (zero-allocation).
//
// Parameter specification (ML-KEM-768 by default):
// * Public Key size: 1184 bytes.
// * Secret Key size: 2400 bytes.
// * Ciphertext size: 1088 bytes.
// * Shared Secret size: 32 bytes.

#pragma once