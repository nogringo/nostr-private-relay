#pragma once

#include <string>
#include <string_view>

#include "golpe.h"
#include "PackedEvent.h"


// Upload (one pubkey storing one event)
//   0: uploader (32)
//  32: levId (8)
//  40: created_at (8)
//  48: kind (8)
//  56: pubkey (32)
//  88: tags[] (variable, encoded as in PackedEvent)
//
// It copies the event fields its indices need, since an index can only read its own record

struct UploadView {
    std::string_view buf;

    UploadView(std::string_view sv) : buf(sv) {
        if (buf.size() < 88) throw hoytech::error("UploadView too short");
    }

    std::string_view uploader() const {
        return buf.substr(0, 32);
    }

    uint64_t levId() const {
        return lmdb::from_sv<uint64_t>(buf.substr(32, 8));
    }

    uint64_t created_at() const {
        return lmdb::from_sv<uint64_t>(buf.substr(40, 8));
    }

    uint64_t kind() const {
        return lmdb::from_sv<uint64_t>(buf.substr(48, 8));
    }

    std::string_view pubkey() const {
        return buf.substr(56, 32);
    }

    void foreachTag(const std::function<bool(char, std::string_view)> &cb) const {
        foreachPackedTag(buf.substr(88), cb);
    }

    std::string uploaderLevIdKey() const {
        return std::string(buf.substr(0, 40));
    }

    static std::string key(std::string_view uploader, uint64_t levId) {
        return std::string(uploader) + std::string(lmdb::to_sv<uint64_t>(levId));
    }

    static std::string build(std::string_view uploader, uint64_t levId, const PackedEventView &packed) {
        if (uploader.size() != 32) throw hoytech::error("unexpected uploader size");

        std::string out = key(uploader, levId);
        out += lmdb::to_sv<uint64_t>(packed.created_at());
        out += lmdb::to_sv<uint64_t>(packed.kind());
        out += packed.pubkey();
        out += packed.tags();
        return out;
    }
};
