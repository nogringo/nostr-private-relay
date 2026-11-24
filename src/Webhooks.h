#pragma once

#include <algorithm>
#include <memory>
#include <string>
#include <string_view>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <curl/curl.h>

#include "golpe.h"

#include "events.h"
#include "filters.h"
#include "RelayUrl.h"


// NIP-9a: a kind 30390 event asks the relay to POST the events matching its filters to its callback URL
namespace Webhooks {

const uint64_t subscriptionKind = 30390;

inline bool active() {
    return cfg().relay__webhooks__enabled && cfg().relay__auth__serviceUrl.size();
}

// Like welshman's normalizeRelayUrl, which clients compare relay URLs with: "wss://Relay.example.com" -> "wss://relay.example.com/"
inline std::string relayUrl() {
    std::string url = cfg().relay__auth__serviceUrl;
    std::transform(url.begin(), url.end(), url.begin(), [](unsigned char c){ return std::tolower(c); });

    url = url.substr(0, url.find('#'));
    while (url.ends_with('/')) url.pop_back();

    auto hostStart = url.find("://");
    hostStart = hostStart == std::string::npos ? 0 : hostStart + 3;
    if (url.find('/', hostStart) == std::string::npos) url += '/';

    return url;
}

inline bool isPublicIpv4(const uint8_t *b) {
    uint32_t a = (uint32_t(b[0]) << 24) | (uint32_t(b[1]) << 16) | (uint32_t(b[2]) << 8) | b[3];
    auto in = [&](uint32_t net, int bits){ return (a >> (32 - bits)) == (net >> (32 - bits)); };

    return !(in(0x00000000, 8) || in(0x0A000000, 8) || in(0x64400000, 10) || in(0x7F000000, 8)
          || in(0xA9FE0000, 16) || in(0xAC100000, 12) || in(0xC0000000, 24) || in(0xC0A80000, 16)
          || in(0xC6120000, 15) || in(0xE0000000, 3));
}

// False for loopback, private, link-local, shared, multicast and reserved addresses, so a callback can't reach the relay's network
inline bool isPublicAddress(const sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return isPublicIpv4(reinterpret_cast<const uint8_t *>(&reinterpret_cast<const sockaddr_in *>(sa)->sin_addr));
    }

    if (sa->sa_family != AF_INET6) return false;

    const uint8_t *b = reinterpret_cast<const sockaddr_in6 *>(sa)->sin6_addr.s6_addr;
    auto zeros = [&](size_t from, size_t to){
        for (size_t i = from; i < to; i++) if (b[i]) return false;
        return true;
    };

    if (zeros(0, 10) && b[10] == 0xFF && b[11] == 0xFF) return isPublicIpv4(b + 12); // ::ffff:a.b.c.d
    if (zeros(0, 12)) return false; // ::, ::1 and the deprecated ::a.b.c.d
    if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B && zeros(4, 12)) return isPublicIpv4(b + 12); // NAT64
    if (b[0] == 0x20 && b[1] == 0x02) return isPublicIpv4(b + 2); // 6to4
    if ((b[0] & 0xFE) == 0xFC) return false; // unique local
    if (b[0] == 0xFE && (b[1] & 0xC0) >= 0x80) return false; // link-local and site-local
    if (b[0] == 0xFF) return false; // multicast

    return true;
}

inline bool isPrivateHost(std::string host) {
    while (host.ends_with('.')) host.pop_back();
    if (host == "localhost" || host.ends_with(".localhost")) return true;

    if (host.starts_with('[') && host.ends_with(']')) host = host.substr(1, host.size() - 2);

    sockaddr_in v4{};
    if (inet_pton(AF_INET, host.c_str(), &v4.sin_addr) == 1) {
        v4.sin_family = AF_INET;
        return !isPublicAddress(reinterpret_cast<sockaddr *>(&v4));
    }

    sockaddr_in6 v6{};
    if (inet_pton(AF_INET6, host.c_str(), &v6.sin6_addr) == 1) {
        v6.sin6_family = AF_INET6;
        return !isPublicAddress(reinterpret_cast<sockaddr *>(&v6));
    }

    return false; // a name: checked once it resolves, before connecting
}

inline void checkCallbackUrl(const std::string &url) {
    std::unique_ptr<CURLU, decltype(&curl_url_cleanup)> u(curl_url(), curl_url_cleanup);
    if (!u || curl_url_set(u.get(), CURLUPART_URL, url.c_str(), 0) != CURLUE_OK) throw herr("callback is not a valid URL");

    auto part = [&](CURLUPart what){
        char *p = nullptr;
        std::string out;
        if (curl_url_get(u.get(), what, &p, 0) == CURLUE_OK && p) out = p;
        curl_free(p);
        return out;
    };

    auto scheme = part(CURLUPART_SCHEME);
    if (scheme != "https" && !(scheme == "http" && cfg().relay__webhooks__allowHttp)) throw herr("callback must be an https:// URL");

    auto host = part(CURLUPART_HOST);
    if (host.empty()) throw herr("callback has no host");
    if (!cfg().relay__webhooks__allowPrivateAddresses && isPrivateHost(host)) throw herr("callback must not point to a private address");
}

// NIP-9a: the callback must echo this challenge before its subscription is stored. Empty on failure.
inline std::string challengeUrl(const std::string &callback, const std::string &challenge) {
    std::unique_ptr<CURLU, decltype(&curl_url_cleanup)> u(curl_url(), curl_url_cleanup);
    auto param = "challenge=" + challenge;
    char *url = nullptr;
    std::string out;

    if (u && curl_url_set(u.get(), CURLUPART_URL, callback.c_str(), 0) == CURLUE_OK
          && curl_url_set(u.get(), CURLUPART_QUERY, param.c_str(), CURLU_APPENDQUERY) == CURLUE_OK
          && curl_url_get(u.get(), CURLUPART_URL, &url, 0) == CURLUE_OK) {
        out = url;
    }

    curl_free(url);
    return out;
}

// For logs: callback URLs act as secrets, so only their host is shown
inline std::string callbackHost(std::string_view url) {
    auto host = normalizeRelayUrl(url);
    auto at = host.rfind('@');
    return at == std::string::npos ? host : host.substr(at + 1);
}

inline std::string_view dTag(const PackedEventView &packed) {
    std::string_view d;

    packed.foreachTag([&](char tagName, std::string_view tagVal){
        if (tagName != 'd') return true;
        d = tagVal;
        return false;
    });

    return d;
}

// The pubkey's subscriptions that a new version of this one wouldn't replace
inline uint64_t countOtherSubscriptions(lmdb::txn &txn, const PackedEventView &packed) {
    auto ownD = dTag(packed);
    uint64_t count = 0;

    env.generic_foreachFull(txn, env.dbi_Event__pubkeyKind, makeKey_StringUint64Uint64(packed.pubkey(), subscriptionKind, 0), lmdb::to_sv<uint64_t>(0), [&](auto k, auto v){
        ParsedKey_StringUint64Uint64 parsedKey(k);
        if (parsedKey.s != packed.pubkey() || parsedKey.n1 != subscriptionKind) return false;
        if (dTag(PackedEventView(lookupEventByLevId(txn, lmdb::from_sv<uint64_t>(v)).buf)) != ownD) count++;
        return true;
    });

    return count;
}

struct Subscription {
    std::string pubkey;
    std::string callback;
    bool includeEvent = false;
    NostrFilterGroup filters;
    NostrFilterGroup ignore;
};

// Throws with the reason the relay won't fulfill the subscription
inline Subscription parse(const tao::json::value &evJson) {
    Subscription sub;
    sub.pubkey = from_hex(evJson.at("pubkey").get_string());

    auto ownHost = normalizeRelayUrl(cfg().relay__auth__serviceUrl);
    bool forThisRelay = false;
    size_t numFilters = 0, numFilterTags = 0, numCallbacks = 0;

    auto addFilter = [&](NostrFilterGroup &group, const std::string &name, const std::string &value){
        if (++numFilters > cfg().relay__maxReqFilterSize) throw herr("too many filter and ignore tags");

        tao::json::value filter;

        try {
            filter = tao::json::from_string(value);
        } catch (std::exception &) {
            throw herr(name, " tag is not JSON");
        }

        try {
            group.addFilter(filter);
        } catch (std::exception &e) {
            throw herr("bad ", name, " tag: ", e.what());
        }
    };

    for (const auto &tagj : evJson.at("tags").get_array()) {
        const auto &tag = tagj.get_array();
        if (tag.empty()) continue;

        const auto &name = tag[0].get_string();

        if (name == "include_event") {
            sub.includeEvent = true;
            continue;
        }

        if (tag.size() < 2) continue;
        const auto &value = tag[1].get_string();

        if (name == "relay") {
            if (normalizeRelayUrl(value) == ownHost) forThisRelay = true;
        } else if (name == "filter") {
            numFilterTags++;
            addFilter(sub.filters, name, value);
        } else if (name == "ignore") {
            addFilter(sub.ignore, name, value);
        } else if (name == "callback") {
            numCallbacks++;
            sub.callback = value;
        }
    }

    if (!forThisRelay) throw herr("relay tag must be ", relayUrl());
    if (numFilterTags == 0) throw herr("missing filter tag");
    if (numCallbacks != 1) throw herr("needs exactly one callback tag");

    checkCallbackUrl(sub.callback);

    return sub;
}

}
