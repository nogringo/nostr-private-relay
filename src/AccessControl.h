#pragma once

#include <string>
#include <string_view>
#include <vector>

#include <hoytech/hex.h>

#include "golpe.h"
#include "Bech32Utils.h"


// NIP-86 lists live in the DB, so every relay process sharing it applies them
namespace AccessControl {

enum PubkeyStatus : uint64_t {
    Allowed = 1,
    Banned = 2,
};

// Accepts an npub or 64 hex digits, returns the 32 raw bytes
inline std::string parsePubkey(std::string_view input) {
    std::string pubkey;

    try {
        pubkey = input.starts_with("npub1") ? decodeBech32Simple(input) : hoytech::from_hex(input);
    } catch (...) {
    }

    if (pubkey.size() != 32) throw herr("invalid pubkey: ", input);
    return pubkey;
}

// Items separated by commas or whitespace
inline std::vector<std::string_view> splitList(std::string_view list) {
    std::vector<std::string_view> items;

    while (list.size()) {
        auto pos = list.find_first_of(", \t\n");
        if (pos != 0) items.push_back(list.substr(0, pos));
        if (pos == std::string_view::npos) break;
        list.remove_prefix(pos + 1);
    }

    return items;
}

inline const flat_hash_set<std::string> &adminPubkeys() {
    thread_local bool loaded = false;
    thread_local uint64_t configVer = 0;
    thread_local flat_hash_set<std::string> pubkeys;

    if (!loaded || configVer != cfg().version()) {
        pubkeys.clear();

        for (auto item : splitList(cfg().relay__admin__pubkeys)) {
            try {
                pubkeys.insert(parsePubkey(item));
            } catch (...) {
            }
        }

        loaded = true;
        configVer = cfg().version();
    }

    return pubkeys;
}

inline bool isAdmin(std::string_view pubkey) {
    return adminPubkeys().contains(std::string(pubkey));
}

inline bool hasAllowList(lmdb::txn &txn) {
    bool found = false;

    env.foreachDup_PubkeyAccess__status(txn, Allowed, [&](auto &){
        found = true;
        return false;
    });

    return found;
}

// Why this pubkey can't use the relay, or an empty string when it can
inline std::string refusal(lmdb::txn &txn, std::string_view pubkey) {
    auto entry = env.lookup_PubkeyAccess__pubkey(txn, pubkey);

    if (entry && entry->status() == Banned) return "this pubkey is banned from this relay";
    if ((entry && entry->status() == Allowed) || isAdmin(pubkey) || !hasAllowList(txn)) return "";

    return "this relay only accepts allowed pubkeys";
}

inline bool isIpBlocked(lmdb::txn &txn, std::string_view ipBytes) {
    return ipBytes.size() && env.lookup_BlockedIp__ip(txn, ipBytes).has_value();
}

inline std::string relaySetting(lmdb::txn &txn, std::string_view name, std::string_view fallback) {
    auto entry = env.lookup_RelaySetting__name(txn, name);
    return std::string(entry ? entry->value() : fallback);
}

}
