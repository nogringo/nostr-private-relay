#pragma once

#include <algorithm>
#include <string>
#include <string_view>


// Keeps only the host (and port), lower-cased: "wss://Relay.example.com/" -> "relay.example.com"
inline std::string normalizeRelayUrl(std::string_view url) {
    auto pos = url.find("://");
    if (pos != std::string_view::npos) url.remove_prefix(pos + 3);
    pos = url.find_first_of("/?#");
    if (pos != std::string_view::npos) url = url.substr(0, pos);
    std::string result(url);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c){ return std::tolower(c); });
    return result;
}
