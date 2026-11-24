#pragma once

#include <string>
#include <string_view>

#include "golpe.h"


// Upload (one pubkey storing one event)
//   0: uploader (32)
//  32: levId (8)
//  40: created_at (8)
//  48: kind (8)

struct UploadView {
    std::string_view buf;

    UploadView(std::string_view sv) : buf(sv) {
        if (buf.size() != 56) throw hoytech::error("UploadView has the wrong size");
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

    std::string uploaderLevIdKey() const {
        return std::string(buf.substr(0, 40));
    }

    static std::string key(std::string_view uploader, uint64_t levId) {
        return std::string(uploader) + std::string(lmdb::to_sv<uint64_t>(levId));
    }

    static std::string build(std::string_view uploader, uint64_t levId, uint64_t created_at, uint64_t kind) {
        if (uploader.size() != 32) throw hoytech::error("unexpected uploader size");

        std::string out = key(uploader, levId);
        out += lmdb::to_sv<uint64_t>(created_at);
        out += lmdb::to_sv<uint64_t>(kind);
        return out;
    }
};
