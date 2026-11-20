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

struct AuthedPubkeysByConn {
    flat_hash_map<uint64_t, AuthedPubkeys> conns;

    const AuthedPubkeys &get(uint64_t connId) const {
        static const AuthedPubkeys none;
        auto it = conns.find(connId);
        return it == conns.end() ? none : it->second;
    }

    void add(uint64_t connId, const Bytes32 &pubkey) {
        conns[connId].add(pubkey);
    }

    void erase(uint64_t connId) {
        conns.erase(connId);
    }
};
