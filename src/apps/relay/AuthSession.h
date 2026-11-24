#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

struct AuthSession {

  static constexpr size_t kChallengeSize = 22;

  std::array<char, kChallengeSize> challenge{};
  std::string pubkey; // NIP-37: a connection stores and reads as a single pubkey, empty until AUTH

  AuthSession(std::string_view token) {
    if (token.size() != kChallengeSize)
      throw herr("challenge size not ", kChallengeSize, " bytes");
    ::memcpy(challenge.data(), token.data(), kChallengeSize);
  }

  bool isAuthed() const { return !pubkey.empty(); }

  std::string_view challengeSv() const {
    return std::string_view(challenge.data(), challenge.size());
  }
};
