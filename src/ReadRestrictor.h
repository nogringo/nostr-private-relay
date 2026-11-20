#pragma once

#include <span>
#include <string_view>

#include "PackedEvent.h"
#include "config.h"
#include "filters.h"
#include "AuthedPubkeys.h"

#include "golpe.h"

struct ReadRestrictor {
private:
    // thread_local: every relay thread reloads its own copy when the config changes
    inline static thread_local bool loaded = false;
    inline static thread_local uint64_t configVer = 0;
    inline static thread_local flat_hash_set<uint64_t> restrictedKinds_;

public:
    static void init(){
        restrictedKinds_.clear();
        parseCommaSeparatedKinds(cfg().relay__auth__restrictedReadKinds, restrictedKinds_);
    }

    static flat_hash_set<uint64_t>& restrictedKinds() {
        if (!loaded || configVer != cfg().version()) {
            init();
            loaded = true;
            configVer = cfg().version();
        }
        return restrictedKinds_;
    }

    // NIP-37 private storage: every event is only served to its owner
    static bool authorOnly() {
        return cfg().relay__auth__authorOnlyReads;
    }

    static bool isGiftWrapKind(uint64_t kind) {
        return kind == 1059 || kind == 21059;
    }

    // An event belongs to its author, except NIP-59 gift wraps: their signing key is thrown away,
    // so a wrap belongs to the single recipient in its p-tag, never to its signer.
    // Returns a null Bytes32 when no authenticated pubkey owns the event
    static Bytes32 authedOwner(const PackedEventView &packed, const AuthedPubkeys &authed) {
        if (!isGiftWrapKind(packed.kind())) {
            return authed.contains(packed.pubkey()) ? Bytes32(packed.pubkey()) : Bytes32();
        }

        std::string_view recipient;
        size_t numRecipients = 0;

        packed.foreachTag([&](char tagName, std::string_view tagVal) {
            if (tagName == 'p') {
                recipient = tagVal;
                numRecipients++;
            }
            return true;
        });

        if (numRecipients != 1 || !authed.contains(recipient)) return Bytes32();
        return Bytes32(recipient);
    }

    static bool isOwnedBy(const PackedEventView &packed, const AuthedPubkeys &authed) {
        return !authedOwner(packed, authed).isNull();
    }

    static bool mayRestrict(uint64_t kind) {
        return authorOnly() || restrictedKinds().contains(kind);
    }

    // Rewrites a filter so it only matches events owned by the authenticated pubkeys: its authors
    // are intersected with them, and gift wraps addressed to them get a filter of their own.
    // Pushes 0, 1 or 2 filters. The filter must have been validated by parsing it as a NostrFilter.
    static void narrowFilter(const tao::json::value &filter, const AuthedPubkeys &authed, std::vector<tao::json::value> &out) {
        const auto &obj = filter.get_object();

        auto field = [&](const char *name) -> const tao::json::value* {
            auto it = obj.find(name);
            return it == obj.end() ? nullptr : &it->second;
        };

        auto authedSubset = [&](const tao::json::value *requested) {
            tao::json::value output = tao::json::empty_array;

            if (!requested) {
                for (const auto &p : authed.pubkeys) output.emplace_back(to_hex(p.sv()));
            } else {
                for (const auto &v : requested->get_array()) {
                    if (authed.contains(from_hex(v.get_string(), false))) output.emplace_back(v);
                }
            }

            return output;
        };

        auto authors = authedSubset(field("authors"));
        if (authors.get_array().size()) {
            tao::json::value f = filter;
            f["authors"] = std::move(authors);
            out.push_back(std::move(f));
        }

        // Gift wraps only carry a p-tag, so a filter on any other tag can't match one
        for (const auto &[k, v] : obj) {
            if (k.starts_with('#') && k != "#p") return;
        }

        // Wrap signers are throwaway keys: naming authors only means wraps when their kind is asked for
        if (field("authors") && !field("kinds")) return;

        tao::json::value wrapKinds = tao::json::empty_array;
        if (auto *kinds = field("kinds")) {
            for (const auto &k : kinds->get_array()) {
                if (isGiftWrapKind(k.get_unsigned())) wrapKinds.emplace_back(k);
            }
        } else {
            wrapKinds.emplace_back(uint64_t(1059));
            wrapKinds.emplace_back(uint64_t(21059));
        }
        if (wrapKinds.get_array().empty()) return;

        auto recipients = authedSubset(field("#p"));
        if (recipients.get_array().empty()) return;

        tao::json::value f = filter;
        f["kinds"] = std::move(wrapKinds);
        f["#p"] = std::move(recipients);
        out.push_back(std::move(f));
    }

    // outRestricted is set when the client asked for something, but only for other users' events
    static NostrFilterGroup narrowFilters(std::span<const tao::json::value> filters, const AuthedPubkeys &authed, uint64_t maxFilterLimit, bool &outRestricted) {
        NostrFilterGroup fg;
        bool anyMatchable = false;

        for (const auto &filter : filters) {
            if (NostrFilter(filter, maxFilterLimit).neverMatch) continue;
            anyMatchable = true;

            std::vector<tao::json::value> narrowed;
            narrowFilter(filter, authed, narrowed);
            for (const auto &f : narrowed) fg.addFilter(f, maxFilterLimit);
        }

        outRestricted = anyMatchable && fg.size() == 0;
        return fg;
    }

    static bool isFilterGroupFullyRestricted(const NostrFilterGroup &fg) {
        if (restrictedKinds().empty() || fg.filters.empty()) return false;
        for (const auto& f : fg.filters) {
            if (!isFilterFullyRestricted(f)) return false;
        }
        return true;
    }

    static bool isFilterFullyRestricted(const NostrFilter &filter) {
        if (!filter.kinds) return false;

        for (size_t i = 0; i < filter.kinds->size(); ++i) {
            uint64_t kind = filter.kinds->at(i);

            if (!restrictedKinds().contains(kind)) {
                return false;
            }
        }
        return true;
    }

    static bool isFilterAllowedToCount(const NostrFilterGroup &fg, const AuthedPubkeys &authed) {
        if (restrictedKinds().empty()) return true;

        for (const auto &f: fg.filters) {
            if (!f.kinds) continue;
            bool hasSomeRestrictedKind = false;
            for (size_t i = 0; i < f.kinds->size(); ++i) {
                uint64_t kind = f.kinds->at(i);
                if (restrictedKinds().contains(kind)) {
                    hasSomeRestrictedKind = true;
                    break;
                }
            }
            if (hasSomeRestrictedKind) {
                if (authed.empty()) {
                    return false;
                }
                if (!cfg().relay__auth__restrictReadToInvolvedPubkey) {
                    continue;
                }
                bool authorScoped = f.authors && allPubkeysMatch(*f.authors, authed);
                bool pScoped = false;
                if (auto it = f.tags.find('p'); it != f.tags.end()) {
                    pScoped = allPubkeysMatch(it->second, authed);
                }
                if (!authorScoped && !pScoped) return false;
            }
        }
        return true;
    }

    static bool allPubkeysMatch(const FilterSetBytes& set, const AuthedPubkeys &authed) {
        if (set.size() == 0) return false;

        for (size_t i = 0; i < set.size(); ++i) {
            if (!authed.contains(set.at(i))) return false;
        }
        return true;
    }

    // Returns true if the event should be sent to the subscriber
    static bool shouldSendToSubscriber(const PackedEventView &packed, const AuthedPubkeys &authed) {
        if (authorOnly()) return isOwnedBy(packed, authed);

        if (!restrictedKinds().contains(packed.kind())) {
            return true;
        }

        if (authed.empty()) {
            return false;
        }

        if(!cfg().relay__auth__restrictReadToInvolvedPubkey) return true;

        bool involved = authed.contains(packed.pubkey());

        packed.foreachTag([&](char tagName, std::string_view tagVal) {
            if (tagName == 'p' && authed.contains(tagVal)) {
                involved = true;
                return false;
            }

            return true;
        });

        return involved;
    }
};
