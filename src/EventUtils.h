#pragma once

#include <string_view>
#include <string>
#include <tuple>

#include "golpe.h"
#include "PackedEvent.h"


inline bool isReplaceableKind(uint64_t kind) {
    return (
        kind == 0 ||
        kind == 3 ||
        kind == 41 ||
        (kind >= 10'000 && kind < 20'000)
    );
}

inline bool isParamReplaceableKind(uint64_t kind) {
    return (
        (kind >= 30'000 && kind < 40'000)
    );
}

inline bool isEphemeralKind(uint64_t kind) {
    return (
        (kind >= 20'000 && kind < 30'000)
    );
}

inline bool isGiftWrapKind(uint64_t kind) {
    return kind == 1059 || kind == 21059;
}

// An event belongs to its author, except NIP-59 gift wraps: their signing key is thrown away,
// so a wrap belongs to the single recipient in its p-tag, never to its signer.
// Empty for a wrap that doesn't have exactly one p-tag
inline std::string_view ownerOf(const PackedEventView &packed) {
    if (!isGiftWrapKind(packed.kind())) return packed.pubkey();

    std::string_view recipient;
    size_t numRecipients = 0;

    packed.foreachTag([&](char tagName, std::string_view tagVal) {
        if (tagName == 'p') {
            recipient = tagVal;
            numRecipients++;
        }
        return true;
    });

    return numRecipients == 1 ? recipient : std::string_view();
}


inline std::tuple<uint64_t, std::string, std::string> parseATag(std::string_view input) {
    size_t firstColon = input.find(':');
    if (firstColon == std::string::npos) throw herr("parse error");

    std::string_view kindStr = input.substr(0, firstColon);
    size_t pos;
    uint64_t kind = std::stoull(std::string(kindStr), &pos);
    if (pos != kindStr.size()) throw herr("parse error");

    size_t secondColon = input.find(':', firstColon + 1);
    if (secondColon == std::string::npos) throw herr("parse error");

    std::string_view pubkeyStr = input.substr(firstColon + 1, secondColon - firstColon - 1);
    if (pubkeyStr.size() != 64) throw herr("parse error");

    std::string dTag = std::string(input.substr(secondColon + 1));

    return {kind, hoytech::from_hex(pubkeyStr), std::move(dTag)};
}
