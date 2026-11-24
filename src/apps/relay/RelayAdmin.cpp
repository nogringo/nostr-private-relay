#include <cstdlib>
#include <ctime>
#include <sys/stat.h>

#include "RelayServer.h"
#include "RelayUrl.h"
#include "ReadRestrictor.h"
#include "AccessControl.h"
#include "app_git_version.h"


namespace {

struct Unauthorized : std::runtime_error {
    using std::runtime_error::runtime_error;
};

std::string base64Decode(std::string_view in) {
    static const auto table = []{
        std::array<int8_t, 256> t;
        t.fill(-1);
        const char *chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; i++) t[(uint8_t)chars[i]] = i;
        return t;
    }();

    while (in.size() && in.back() == '=') in.remove_suffix(1);

    std::string out;
    uint32_t acc = 0;
    int bits = 0;

    for (unsigned char c : in) {
        if (table[c] < 0) throw herr("invalid base64");
        acc = (acc << 6) | table[c];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += char((acc >> bits) & 0xFF);
        }
    }

    return out;
}

// NIP-98, with the payload tag that NIP-86 requires. Returns the admin pubkey
std::string verifyAdmin(secp256k1_context *secpCtx, std::string_view authorization, std::string_view body) {
    if (cfg().relay__auth__serviceUrl.empty()) throw Unauthorized("relay.auth.serviceUrl must be set to use the management API");
    if (!authorization.starts_with("Nostr ")) throw Unauthorized("missing NIP-98 Authorization header");

    tao::json::value eventJson;
    std::string packedStr, jsonStr;

    try {
        eventJson = tao::json::from_string(base64Decode(authorization.substr(6)));
        parseAndVerifyEvent(eventJson, secpCtx, true, false, packedStr, jsonStr);
    } catch (std::exception &e) {
        throw Unauthorized(std::string("invalid NIP-98 event: ") + e.what());
    }

    PackedEventView packed(packedStr);

    if (packed.kind() != 27235) throw Unauthorized("NIP-98 event must be kind 27235");

    uint64_t now = hoytech::curr_time_s();
    if (packed.created_at() + 60 < now || packed.created_at() > now + 60) throw Unauthorized("NIP-98 event must be created within 60 seconds of the request");

    // Behind a reverse proxy the request URL is unknown, so the u tag is checked like a NIP-42 relay tag
    auto relayHost = normalizeRelayUrl(cfg().relay__auth__serviceUrl);
    auto bodyHash = to_hex(sha256(body).sv());
    bool urlOk = false, methodOk = false, payloadOk = false;

    for (const auto &tagj : eventJson.at("tags").get_array()) {
        const auto &tag = tagj.get_array();
        if (tag.size() < 2) continue;
        const auto &name = tag[0].get_string();
        const auto &value = tag[1].get_string();

        if (name == "u") urlOk = normalizeRelayUrl(value) == relayHost;
        else if (name == "method") methodOk = value == "POST";
        else if (name == "payload") payloadOk = value == bodyHash;
    }

    if (!urlOk) throw Unauthorized("NIP-98 u tag must be this relay: " + cfg().relay__auth__serviceUrl);
    if (!methodOk) throw Unauthorized("NIP-98 method tag must be POST");
    if (!payloadOk) throw Unauthorized("NIP-98 payload tag must be the SHA-256 of the request body");

    std::string pubkey(packed.pubkey());
    if (!AccessControl::isAdmin(pubkey)) throw Unauthorized("this pubkey is not an admin of this relay");

    return pubkey;
}

tao::json::value listPubkeys(lmdb::txn &txn, uint64_t status) {
    tao::json::value out = tao::json::empty_array;

    env.foreachDup_PubkeyAccess__status(txn, status, [&](auto &v){
        tao::json::value item = tao::json::value({ { "pubkey", to_hex(v.pubkey()) } });
        if (v.reason().size()) item["reason"] = std::string(v.reason());
        out.push_back(std::move(item));
        return true;
    });

    return out;
}

void setPubkeyStatus(std::string_view pubkey, uint64_t status, std::string_view reason) {
    auto txn = env.txn_rw();
    if (auto v = env.lookup_PubkeyAccess__pubkey(txn, pubkey)) env.delete_PubkeyAccess(txn, v->primaryKeyId);
    env.insert_PubkeyAccess(txn, pubkey, status, reason);
    txn.commit();
}

void clearPubkeyStatus(std::string_view pubkey, uint64_t status) {
    auto txn = env.txn_rw();
    auto v = env.lookup_PubkeyAccess__pubkey(txn, pubkey);
    if (v && v->status() == status) env.delete_PubkeyAccess(txn, v->primaryKeyId);
    txn.commit();
}

void setRelaySetting(std::string_view name, std::string_view value) {
    auto txn = env.txn_rw();
    if (auto v = env.lookup_RelaySetting__name(txn, name)) env.delete_RelaySetting(txn, v->primaryKeyId);
    if (value.size()) env.insert_RelaySetting(txn, name, value);
    txn.commit();
}

// Scans every event, so it costs one pass over the DB
tao::json::value stats(lmdb::txn &txn, uint64_t startTime, uint64_t limit) {
    struct Usage {
        uint64_t events = 0;
        uint64_t bytes = 0;
        uint64_t lastCreatedAt = 0;
    };

    flat_hash_map<std::string, Usage> usageByOwner;
    uint64_t totalEvents = 0, totalBytes = 0;

    env.foreach_Event(txn, [&](auto &ev){
        PackedEventView packed(ev.buf);

        auto owner = ReadRestrictor::ownerOf(packed);
        if (owner.empty()) owner = packed.pubkey();

        std::string_view payload;
        uint64_t size = env.dbi_EventPayload.get(txn, lmdb::to_sv<uint64_t>(ev.primaryKeyId), payload) ? payload.size() : 0;

        auto &usage = usageByOwner[std::string(owner)];
        usage.events++;
        usage.bytes += size;
        usage.lastCreatedAt = std::max(usage.lastCreatedAt, packed.created_at());

        totalEvents++;
        totalBytes += size;
        return true;
    });

    std::vector<std::pair<std::string_view, const Usage *>> ranked;
    ranked.reserve(usageByOwner.size());
    for (const auto &[owner, usage] : usageByOwner) ranked.emplace_back(owner, &usage);

    auto top = std::min<size_t>(limit, ranked.size());
    std::partial_sort(ranked.begin(), ranked.begin() + top, ranked.end(), [](const auto &a, const auto &b){
        return a.second->bytes > b.second->bytes;
    });

    tao::json::value topUsers = tao::json::empty_array;

    for (size_t i = 0; i < top; i++) {
        const auto &[owner, usage] = ranked[i];

        tao::json::value item = tao::json::value({
            { "pubkey", to_hex(owner) },
            { "events", usage->events },
            { "bytes", usage->bytes },
            { "lastCreatedAt", usage->lastCreatedAt },
        });

        if (auto access = env.lookup_PubkeyAccess__pubkey(txn, owner)) {
            item["status"] = access->status() == AccessControl::Banned ? "banned" : "allowed";
        }

        topUsers.push_back(std::move(item));
    }

    MDB_envinfo envInfo;
    MDB_stat envStat;
    lmdb::env_info(env.lmdb_env.handle(), &envInfo);
    lmdb::env_stat(env.lmdb_env.handle(), &envStat);

    return tao::json::value({
        { "version", APP_GIT_VERSION },
        { "uptime", hoytech::curr_time_s() - startTime },
        { "connections", PrometheusMetrics::getInstance().activeConnections.get() },
        { "events", totalEvents },
        { "storage", totalBytes },
        { "dbSize", (uint64_t)(envInfo.me_last_pgno + 1) * envStat.ms_psize },
        { "users", usageByOwner.size() },
        { "allowList", AccessControl::hasAllowList(txn) },
        { "topUsers", std::move(topUsers) },
    });
}

std::string backupFilename() {
    std::string name;
    for (char c : normalizeRelayUrl(cfg().relay__auth__serviceUrl)) name += isalnum((unsigned char)c) || c == '.' || c == '-' ? c : '_';

    char date[32];
    time_t now = ::time(nullptr);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(date, sizeof(date), "-%Y%m%d-%H%M%S.mdb", &tm);

    return name + date;
}

// Same compacted copy as `strfry compact`, consistent while the relay keeps writing
BackupFile snapshotDb() {
    std::string path = cfg().db;
    if (path.empty() || path.back() != '/') path += '/';
    path += ".backup-XXXXXX";

    BackupFile file;
    file.fd = ::mkstemp(path.data());
    if (file.fd < 0) throw herr("unable to create a backup file in ", cfg().db, ": ", strerror(errno));
    ::unlink(path.c_str());

    env.copy_fd(file.fd);

    struct stat st;
    if (::fstat(file.fd, &st)) throw herr("unable to read the backup file size: ", strerror(errno));
    file.size = st.st_size;
    file.filename = backupFilename();

    return file;
}

// Stores the events of these JSONL lines under the same access lists as publishing them
tao::json::value importLines(secp256k1_context *secpCtx, std::string_view body) {
    const size_t maxErrors = 5;

    std::vector<EventToWrite> events;
    uint64_t lines = 0, refused = 0, invalid = 0;
    tao::json::value errors = tao::json::empty_array;

    auto addError = [&](std::string_view error){
        if (errors.get_array().size() < maxErrors) errors.push_back(tao::json::value({ { "line", lines }, { "error", std::string(error) } }));
    };

    {
        auto txn = env.txn_ro();

        while (body.size()) {
            auto end = body.find('\n');
            auto line = body.substr(0, end);
            body.remove_prefix(end == std::string_view::npos ? body.size() : end + 1);
            lines++;

            if (line.find_first_not_of(" \t\r") == std::string_view::npos) continue;

            std::string packedStr, jsonStr;
            bool isVanishRequest = false;

            try {
                auto json = tao::json::from_string(line);
                parseAndVerifyEvent(json, secpCtx, true, false, packedStr, jsonStr);
                isVanishRequest = isVanishRequestForThisRelay(json);
            } catch (std::exception &e) {
                invalid++;
                addError(e.what());
                continue;
            }

            PackedEventView packed(packedStr);
            auto owner = ReadRestrictor::ownerOf(packed);
            std::string refusal;

            if (owner.empty() && (cfg().relay__auth__authorOnlyWrites || ReadRestrictor::authorOnly())) refusal = "this relay only stores gift wraps with a single p tag";
            else if (!isVanishRequest) refusal = AccessControl::refusal(txn, owner.size() ? owner : packed.pubkey());

            if (refusal.size()) {
                refused++;
                addError(refusal);
                continue;
            }

            events.emplace_back(std::move(packedStr), std::move(jsonStr));
        }
    }

    uint64_t added = 0;

    if (events.size()) {
        auto txn = env.txn_rw();
        NegentropyFilterCache neFilterCache;
        writeEvents(txn, neFilterCache, events);
        txn.commit();

        for (const auto &ev : events) {
            if (ev.status == EventWriteStatus::Written) added++;
        }
    }

    uint64_t skipped = events.size() - added;
    LI << "Import of " << lines << " lines: " << added << " added, " << skipped << " skipped, " << refused << " refused, " << invalid << " invalid";

    return tao::json::value({
        { "lines", lines },
        { "added", added },
        { "skipped", skipped },
        { "refused", refused },
        { "invalid", invalid },
        { "errors", std::move(errors) },
    });
}

std::string importReply(secp256k1_context *secpCtx, std::string_view body) {
    try {
        return tao::json::to_string(tao::json::value({ { "result", importLines(secpCtx, body) } }));
    } catch (std::exception &e) {
        LE << "Import failed: " << e.what();
        return tao::json::to_string(tao::json::value({ { "result", tao::json::null }, { "error", e.what() } }));
    }
}

const std::vector<std::string> supportedMethods = {
    "supportedmethods",
    "banpubkey", "unbanpubkey", "listbannedpubkeys",
    "allowpubkey", "unallowpubkey", "listallowedpubkeys",
    "blockip", "unblockip", "listblockedips",
    "changerelayname", "changerelaydescription", "changerelayicon",
    "stats", "erasepubkey", "backup", "import",
};

}


static tao::json::value handleMethod(RelayServer &server, const std::string &method, const std::vector<tao::json::value> &params) {
    auto param = [&](size_t i) -> const std::string & {
        if (i >= params.size()) throw herr("missing parameter ", i + 1);
        return jsonGetString(params[i], "parameters must be strings");
    };

    auto optionalParam = [&](size_t i) -> std::string {
        return i < params.size() ? param(i) : "";
    };

    if (method == "supportedmethods") {
        tao::json::value out = tao::json::empty_array;
        for (const auto &m : supportedMethods) out.push_back(m);
        return out;
    } else if (method == "banpubkey") {
        setPubkeyStatus(AccessControl::parsePubkey(param(0)), AccessControl::Banned, optionalParam(1));
        return true;
    } else if (method == "unbanpubkey") {
        clearPubkeyStatus(AccessControl::parsePubkey(param(0)), AccessControl::Banned);
        return true;
    } else if (method == "listbannedpubkeys") {
        auto txn = env.txn_ro();
        return listPubkeys(txn, AccessControl::Banned);
    } else if (method == "allowpubkey") {
        setPubkeyStatus(AccessControl::parsePubkey(param(0)), AccessControl::Allowed, optionalParam(1));
        return true;
    } else if (method == "unallowpubkey") {
        clearPubkeyStatus(AccessControl::parsePubkey(param(0)), AccessControl::Allowed);
        return true;
    } else if (method == "listallowedpubkeys") {
        auto txn = env.txn_ro();
        return listPubkeys(txn, AccessControl::Allowed);
    } else if (method == "blockip") {
        auto ip = parseIP(param(0));
        if (ip.empty()) throw herr("invalid IP address: ", param(0));

        {
            auto txn = env.txn_rw();
            if (auto v = env.lookup_BlockedIp__ip(txn, ip)) env.delete_BlockedIp(txn, v->primaryKeyId);
            env.insert_BlockedIp(txn, ip, optionalParam(1));
            txn.commit();
        }

        server.dropConnectionsFromIp(ip);
        return true;
    } else if (method == "unblockip") {
        auto ip = parseIP(param(0));
        if (ip.empty()) throw herr("invalid IP address: ", param(0));

        auto txn = env.txn_rw();
        if (auto v = env.lookup_BlockedIp__ip(txn, ip)) env.delete_BlockedIp(txn, v->primaryKeyId);
        txn.commit();
        return true;
    } else if (method == "listblockedips") {
        auto txn = env.txn_ro();
        tao::json::value out = tao::json::empty_array;

        env.foreach_BlockedIp(txn, [&](auto &v){
            tao::json::value item = tao::json::value({ { "ip", renderIP(v.ip()) } });
            if (v.reason().size()) item["reason"] = std::string(v.reason());
            out.push_back(std::move(item));
            return true;
        });

        return out;
    } else if (method == "changerelayname") {
        setRelaySetting("name", param(0));
        return true;
    } else if (method == "changerelaydescription") {
        setRelaySetting("description", param(0));
        return true;
    } else if (method == "changerelayicon") {
        setRelaySetting("icon", param(0));
        return true;
    } else if (method == "stats") {
        uint64_t limit = params.size() ? jsonGetUnsigned(params[0], "limit must be a number") : 100;
        auto txn = env.txn_ro();
        return stats(txn, server.startTime, std::min<uint64_t>(limit, 1000));
    } else if (method == "erasepubkey") {
        auto pubkey = AccessControl::parsePubkey(param(0));

        auto txn = env.txn_rw();
        std::vector<uint64_t> levIds;
        collectOwnedEvents(txn, pubkey, MAX_U64, levIds);
        NegentropyFilterCache neFilterCache;
        uint64_t deleted = deleteEvents(txn, neFilterCache, levIds);
        txn.commit();

        return deleted;
    } else if (method == "backup") {
        auto file = snapshotDb();
        auto token = randomToken();

        LI << "Backup of " << renderSize(file.size) << " ready for download";
        server.offerBackup(token, std::move(file));

        return token;
    } else if (method == "import") {
        auto token = randomToken();
        server.offerImport(token);
        return token;
    }

    throw herr("unsupported method: ", method);
}


void RelayServer::runAdmin(ThreadPool<MsgAdmin>::Thread &thr) {
    secp256k1_context *secpCtx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    while (1) {
        auto newMsgs = thr.inbox.pop_all();

        for (auto &newMsg : newMsgs) {
            if (auto lines = std::get_if<MsgAdmin::ImportLines>(&newMsg.msg)) {
                sendHttpReply(lines->requestId, 200, importReply(secpCtx, lines->body));
                continue;
            }

            auto &req = std::get<MsgAdmin::Request>(newMsg.msg);

            int status = 200;
            tao::json::value reply;

            try {
                auto admin = verifyAdmin(secpCtx, req.authorization, req.body);

                auto body = tao::json::from_string(req.body);
                const auto &method = jsonGetString(body.at("method"), "method must be a string");

                tao::json::value params = tao::json::empty_array;
                if (auto *p = body.find("params")) {
                    jsonGetArray(*p, "params must be an array");
                    params = *p;
                }

                LI << "NIP-86 " << method << " " << tao::json::to_string(params) << " by " << to_hex(admin);

                reply = tao::json::value({ { "result", handleMethod(*this, method, params.get_array()) } });
            } catch (Unauthorized &e) {
                status = 401;
                reply = tao::json::value({ { "error", e.what() } });
            } catch (std::exception &e) {
                reply = tao::json::value({ { "result", tao::json::null }, { "error", e.what() } });
            }

            sendHttpReply(req.requestId, status, tao::json::to_string(reply));
        }
    }
}
