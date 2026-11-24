#pragma once

#include <string_view>
#include <vector>

#include "Bytes32.h"


// NIP-42: a connection may AUTH as several pubkeys, and all of them count as authenticated.
struct AuthedPubkeys {
    std::vector<Bytes32> pubkeys;

    bool empty() const { return pubkeys.empty(); }
    size_t size() const { return pubkeys.size(); }

    bool contains(std::string_view pubkey) const {
        if (pubkey.size() != 32) return false;
        for (const auto &p : pubkeys) {
            if (p.sv() == pubkey) return true;
        }
        return false;
    }

    void add(const Bytes32 &pubkey) {
        if (!contains(pubkey.sv())) pubkeys.push_back(pubkey);
    }
};
