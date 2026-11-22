#include "RelayServer.h"

#include "StrfryTemplates.h"
#include "app_git_version.h"
#include "Favicon.h"
#include "Bech32Utils.h"
#include "PrometheusMetrics.h"
#include "AccessControl.h"
#include "AdminPage.h"
#include "Webhooks.h"



static std::string_view httpStatusLine(int status) {
    switch (status) {
        case 200: return "200 OK";
        case 204: return "204 No Content";
        case 401: return "401 Unauthorized";
        case 404: return "404 Not Found";
        case 413: return "413 Payload Too Large";
        default: return "500 Internal Server Error";
    }
}

static std::string httpHead(int status, const std::string &contentType, uint64_t contentLength, const std::string &extraHeaders = "") {
    std::string output = "HTTP/1.1 ";
    output += httpStatusLine(status);
    output += "\r\n";
    output += std::string("Content-Type: ") + contentType + "\r\n";
    output += "Access-Control-Allow-Origin: *\r\n";
    output += "Connection: keep-alive\r\n";
    output += "Server: strfry\r\n";
    output += std::string("Content-Length: ") + std::to_string(contentLength) + "\r\n";
    output += extraHeaders;
    output += "\r\n";
    return output;
}

static std::string preGenerateHttpResponse(const std::string &contentType, const std::string &content, const std::string &extraHeaders = "", int status = 200) {
    return httpHead(status, contentType, content.size(), extraHeaders) + content;
};

static std::string_view queryParam(std::string_view url, std::string_view name) {
    auto pos = url.find('?');
    if (pos == std::string_view::npos) return "";

    for (auto params = url.substr(pos + 1); params.size(); ) {
        auto param = params.substr(0, params.find('&'));
        if (param.size() > name.size() && param.starts_with(name) && param[name.size()] == '=') return param.substr(name.size() + 1);
        if (param.size() == params.size()) break;
        params.remove_prefix(param.size() + 1);
    }

    return "";
}

// A backup sent in chunks, each one written once the socket has drained the previous one
struct BackupDownload {
    RelayServer *server;
    uint64_t requestId;
    uWS::HttpResponse *res;
    BackupFile file;
    uint64_t offset = 0;
    bool writing = false;
    bool sentWhileWriting = false;
};

static void onBackupChunkSent(void *, void *data, bool cancelled, void *) {
    if (cancelled) return; // the connection closed, and onCancelledHttpRequest frees the download

    auto *download = static_cast<BackupDownload *>(data);
    if (download->writing) download->sentWhileWriting = true;
    else download->server->continueBackup(download->requestId);
}

static const uint64_t backupLinkLifetimeSeconds = 60;
static const size_t backupChunkSize = 1 << 20;

// An import token lasts this long after its last slice was imported
static const uint64_t importTokenLifetimeSeconds = 60;
static const size_t maxImportBodySize = 1 << 20;



void RelayServer::runWebsocket(ThreadPool<MsgWebsocket>::Thread &thr) {
    struct Connection {
        uWS::WebSocket<uWS::SERVER> *websocket;
        uint64_t connId;
        uint64_t connectedTimestamp;
        std::string ipAddr;
        struct Stats {
            uint64_t bytesUp = 0;
            uint64_t bytesUpCompressed = 0;
            uint64_t bytesDown = 0;
            uint64_t bytesDownCompressed = 0;
            // Application bytes handed to uWS that have not yet been fully drained
            // to the kernel (either still queued in uWS or in-flight in a partial
            // send). Useful for diagnosing slow or stalled clients.
            uint64_t pendingOutbound = 0;
        } stats;

        Connection(uWS::WebSocket<uWS::SERVER> *p, uint64_t connId_)
            : websocket(p), connId(connId_), connectedTimestamp(hoytech::curr_time_us()) { }
        Connection(const Connection &) = delete;
        Connection(Connection &&) = delete;
    };

    uWS::Hub hub;
    uWS::Group<uWS::SERVER> *hubGroup = nullptr;
    flat_hash_map<uint64_t, Connection*> connIdToConnection;
    uint64_t nextConnectionId = 1;
    bool gracefulShutdown = false;

    // NIP-86 requests and import slices, from their first byte until the admin thread replies
    struct PendingRequest {
        uWS::HttpResponse *res;
        std::string authorization;
        std::string body;
        std::string importToken;
    };

    flat_hash_map<uint64_t, PendingRequest> pendingRequests;
    uint64_t nextRequestId = 1;
    const size_t maxRequestBodySize = 65536;

    struct OfferedBackup {
        BackupFile file;
        uint64_t expiresAt;
    };

    flat_hash_map<std::string, OfferedBackup> offeredBackups; // by one-time token
    flat_hash_map<uint64_t, std::unique_ptr<BackupDownload>> backupDownloads; // by requestId
    std::string backupChunk;

    flat_hash_map<std::string, uint64_t> importTokens; // expiry by token

    std::function<void()> expireTokens = [&]{
        auto now = hoytech::curr_time_s();
        std::vector<std::string> expiredBackups, expiredImports;

        for (const auto &[token, offer] : offeredBackups) {
            if (offer.expiresAt <= now) expiredBackups.push_back(token);
        }

        for (const auto &[token, expiresAt] : importTokens) {
            if (expiresAt <= now) expiredImports.push_back(token);
        }

        for (const auto &token : expiredBackups) offeredBackups.erase(token);
        for (const auto &token : expiredImports) importTokens.erase(token);
    };

    auto pumpBackup = [&](BackupDownload &download){
        while (download.offset < download.file.size) {
            size_t length = std::min<uint64_t>(backupChunkSize, download.file.size - download.offset);
            backupChunk.resize(length);
            ssize_t n = ::pread(download.file.fd, backupChunk.data(), length, download.offset);

            if (n <= 0) {
                LE << "Backup download failed: " << (n < 0 ? strerror(errno) : "file is shorter than expected");
                download.res->getHttpSocket()->terminate(); // runs onCancelledHttpRequest, which frees download
                return;
            }

            download.offset += n;
            download.writing = true;
            download.sentWhileWriting = false;
            download.res->write(backupChunk.data(), n, onBackupChunkSent, &download);
            download.writing = false;

            if (!download.sentWhileWriting) return;
        }

        LI << "Backup download complete: " << renderSize(download.file.size);
        backupDownloads.erase(download.requestId);
    };

    std::string tempBuf;
    tempBuf.reserve(cfg().events__maxEventSize + MAX_SUBID_SIZE + 100);


    auto supportedNips = []{
        tao::json::value output = tao::json::value::array({ 1, 2, 4, 9, 11, 28, 40, 59, 62, 70 });

        if (cfg().relay__auth__enabled && cfg().relay__auth__serviceUrl.size() > 0) output.push_back(42);
        if (cfg().relay__auth__authorOnlyReads) output.push_back(37);
        if (AccessControl::adminPubkeys().size()) output.push_back(86);
        if (cfg().relay__maxFilterLimitCount > 0) output.push_back(45);
        if (cfg().relay__negentropy__enabled) output.push_back(77);

        std::sort(output.get_array().begin(), output.get_array().end());

        if (Webhooks::active()) output.push_back("9a");

        if (cfg().relay__info__nips.size() == 0) return output;

        try {
            auto parsed = tao::json::from_string(cfg().relay__info__nips);
            if (!parsed.is_array()) throw herr("not an array");
            output = parsed;
        } catch (std::exception &e) {
            LE << "Unable to parse config param relay.info.nips, using default: " << e.what();
        }

        return output;
    };

    struct RelayInfo {
        std::string name;
        std::string description;
        std::string icon;
        bool allowList = false;

        bool operator==(const RelayInfo &) const = default;
    };

    auto loadRelayInfo = []{
        auto txn = env.txn_ro();

        return RelayInfo{
            AccessControl::relaySetting(txn, "name", cfg().relay__info__name),
            AccessControl::relaySetting(txn, "description", cfg().relay__info__description),
            AccessControl::relaySetting(txn, "icon", cfg().relay__info__icon),
            AccessControl::hasAllowList(txn),
        };
    };

    auto getServerInfoHttpResponse = [&supportedNips, &loadRelayInfo, ver = uint64_t(0), info = RelayInfo(), rendered = std::string("")]() mutable {
        auto currInfo = loadRelayInfo();

        if (ver != cfg().version() || currInfo != info) {
            info = std::move(currInfo);

            auto maybeNpub = [](std::string_view sv){
                if (sv.starts_with("npub1")) {
                    return to_hex(decodeBech32Simple(sv));
                } else {
                    return std::string(sv);
                }
            };

            tao::json::value nip11 = tao::json::value({
                { "supported_nips", supportedNips() },
                { "software", "git+https://github.com/nogringo/nostr-private-relay.git" },
                { "version", APP_GIT_VERSION },
                { "negentropy", negentropy::PROTOCOL_VERSION - 0x60 },
                { "limitation", tao::json::value({
                    { "max_message_length", cfg().relay__maxWebsocketPayloadSize },
                    { "max_subscriptions", cfg().relay__maxSubsPerConnection },
                    { "max_limit", cfg().relay__maxFilterLimit },
                    { "max_event_tags", cfg().events__maxNumTags },
                    { "auth_required", cfg().relay__auth__authorOnlyReads && cfg().relay__auth__authorOnlyWrites },
                    { "restricted_writes", cfg().relay__auth__authorOnlyWrites || cfg().relay__writePolicy__plugin.size() > 0 || info.allowList },
                }) },
            });

            if (info.name.size()) nip11["name"] = info.name;
            if (info.description.size()) nip11["description"] = info.description;
            if (cfg().relay__info__contact.size()) nip11["contact"] = cfg().relay__info__contact;
            if (cfg().relay__info__pubkey.size()) nip11["pubkey"] = maybeNpub(cfg().relay__info__pubkey);
            if (info.icon.size()) nip11["icon"] = info.icon;
            if (cfg().relay__info__banner.size()) nip11["banner"] = cfg().relay__info__banner;
            if (cfg().relay__info__self.size()) nip11["self"] = maybeNpub(cfg().relay__info__self);
            if (cfg().relay__info__privacy.size()) nip11["privacy_policy"] = cfg().relay__info__privacy;
            if (cfg().relay__info__terms.size()) nip11["terms_of_service"] = cfg().relay__info__terms;

            rendered = preGenerateHttpResponse("application/json", tao::json::to_string(nip11));
            ver = cfg().version();
        }

        return std::string_view(rendered); // memory only valid until next call
    };

    auto getLandingPageHttpResponse = [this, &supportedNips, &loadRelayInfo, ver = uint64_t(0), info = RelayInfo(), lastUpdate = uint64_t(0), rendered = std::string("")]() mutable {
        auto currInfo = loadRelayInfo();

        if (ver != cfg().version() || currInfo != info || (uint64_t)::time(nullptr) - lastUpdate > 3600) {
            info = std::move(currInfo);

            auto maybeUrl = [](std::string_view inp){
                if (inp.starts_with("http://") || inp.starts_with("https://")) {
                    std::string output = "<a href=\"";
                    output += templarInternal::htmlEscape(inp, true);
                    output += "\">";
                    output += templarInternal::htmlEscape(inp, false);
                    output += "</a>";
                    return output;
                }
                return templarInternal::htmlEscape(inp, false);
            };

            auto maybeNpub = [](std::string_view inp){
                try {
                    if (inp.size() != 64) throw herr("invalid length for pubkey");
                    return encodeBech32Simple("npub", hoytech::from_hex(inp));
                } catch(...) {
                }

                return std::string(inp);
            };

            struct {
                std::string supportedNips;
                std::string version;
                uint64_t negentropy;
                std::function<std::string(std::string_view)> maybeUrl;
                std::function<std::string(std::string_view)> maybeNpub;
                uint64_t uptime;
                std::string name;
                std::string description;
                std::string icon;
            } ctx = { tao::json::to_string(supportedNips()), APP_GIT_VERSION, negentropy::PROTOCOL_VERSION - 0x60, maybeUrl, maybeNpub, (uint64_t)::time(nullptr) - startTime, info.name, info.description, info.icon };

            rendered = preGenerateHttpResponse("text/html", ::strfrytmpl::landing(ctx).str);
            ver = cfg().version();
            lastUpdate = ::time(nullptr);
        }

        return std::string_view(rendered); // memory only valid until next call
    };

    auto getNodeInfoHttpResponse = [ver = uint64_t(0), rendered = std::string("")](std::string host) mutable {
        if (ver != cfg().version()) {
            tao::json::value nodeinfo = tao::json::value({
                { "links", tao::json::value::array({
                    tao::json::value({
                        { "rel", "http://nodeinfo.diaspora.software/ns/schema/2.1" },
                        { "href", "https://" + host + "/nodeinfo/2.1" },
                    }),
                }) },
            });

            rendered = preGenerateHttpResponse("application/json", tao::json::to_string(nodeinfo));
            ver = cfg().version();
        }

        return std::string_view(rendered); // memory only valid until next call
    };

    auto getNodeInfo21HttpResponse = [ver = uint64_t(0), rendered = std::string("")]() mutable {
        if (ver != cfg().version()) {
            // https://github.com/jhass/nodeinfo/blob/main/schemas/2.1/schema.json
            tao::json::value nodeinfo = tao::json::value({
                { "version", "2.1" },
                { "software", tao::json::value({
                    { "name", "strfry" },
                    { "version", APP_GIT_VERSION },
                    { "repository", "https://github.com/hoytech/strfry"},
                    { "homepage", "https://github.com/hoytech/strfry"},
                }) },
                { "protocols", tao::json::value::array({
                    "nostr",
                }) },
                { "services", tao::json::value({
                    { "inbound", tao::json::value::array({}) },
                    { "outbound", tao::json::value::array({}) },
                }) },
                { "openRegistrations", false },
                { "usage", tao::json::value({
                    { "users", tao::json::value({}) },
                }) },
                { "metadata", tao::json::value({
                    { "features", tao::json::value::array({
                        "nostr_relay",
                    }) },
                }) },
            });

            rendered = preGenerateHttpResponse("application/json", tao::json::to_string(nodeinfo));
            ver = cfg().version();
        }

        return std::string_view(rendered); // memory only valid until next call
    };

    std::string faviconResponse = preGenerateHttpResponse("image/x-icon", favicon(), "Cache-Control: public, max-age=31536000\r\n");

    std::string adminPageResponse = preGenerateHttpResponse("text/html; charset=utf-8", adminPageHtml,
        "Cache-Control: no-store\r\n"
        "Content-Security-Policy: frame-ancestors 'none'; base-uri 'none'; form-action 'none'\r\n"
        "X-Frame-Options: DENY\r\n"
        "Referrer-Policy: no-referrer\r\n");

    // NIP-86 clients in a browser send Authorization and Content-Type, which need a CORS preflight
    std::string corsPreflightResponse = preGenerateHttpResponse("text/plain", "",
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Authorization, Content-Type, Accept\r\n"
        "Access-Control-Max-Age: 86400\r\n", 204);

    auto dispatchAdminRequest = [&](uint64_t requestId){
        auto &pending = pendingRequests.at(requestId);

        if (pending.importToken.size()) tpAdmin.dispatch(0, MsgAdmin{MsgAdmin::ImportLines{requestId, std::move(pending.body)}});
        else tpAdmin.dispatch(0, MsgAdmin{MsgAdmin::Request{requestId, std::move(pending.authorization), std::move(pending.body)}});
    };


    {
        int extensionOptions = 0;

        if (cfg().relay__compression__enabled) extensionOptions |= uWS::PERMESSAGE_DEFLATE;
        if (cfg().relay__compression__slidingWindow) extensionOptions |= uWS::SLIDING_DEFLATE_WINDOW;

        hubGroup = hub.createGroup<uWS::SERVER>(extensionOptions, cfg().relay__maxWebsocketPayloadSize);
    }

    if (cfg().relay__autoPingSeconds) hubGroup->startAutoPing(cfg().relay__autoPingSeconds * 1'000);

    hubGroup->onHttpRequest([&](uWS::HttpResponse *res, uWS::HttpRequest req, char *data, size_t length, size_t remainingBytes){
        LI << "HTTP request for [" << req.getUrl().toString() << "]";

        std::string host = req.getHeader("host").toString();
        std::string url = req.getUrl().toString();
        std::string_view path = std::string_view(url).substr(0, url.find('?'));
        auto method = req.getMethod();

        if (method == uWS::METHOD_OPTIONS) {
            res->write(corsPreflightResponse.data(), corsPreflightResponse.size());
            return;
        }

        if (method == uWS::METHOD_POST && path == "/admin/import") {
            uint64_t requestId = nextRequestId++;
            res->setUserData((void*)(uintptr_t)requestId);

            expireTokens();
            std::string token(queryParam(url, "token"));

            if (!importTokens.contains(token)) {
                auto response = preGenerateHttpResponse("application/json", "{\"error\":\"this import link has expired\"}", "Cache-Control: no-store\r\n", 404);
                res->write(response.data(), response.size());
                return;
            }

            if (length + remainingBytes > maxImportBodySize) {
                auto response = preGenerateHttpResponse("application/json", "{\"error\":\"request too large\"}", "", 413);
                res->write(response.data(), response.size());
                return;
            }

            auto &pending = pendingRequests[requestId];
            pending.res = res;
            pending.importToken = std::move(token);
            if (length) pending.body.assign(data, length);

            if (remainingBytes == 0) dispatchAdminRequest(requestId);
            return;
        }

        if (method == uWS::METHOD_POST && req.getHeader("content-type").toStringView().starts_with("application/nostr+json+rpc")) {
            uint64_t requestId = nextRequestId++;
            res->setUserData((void*)(uintptr_t)requestId);

            if (length + remainingBytes > maxRequestBodySize) {
                auto response = preGenerateHttpResponse("application/nostr+json+rpc", "{\"error\":\"request too large\"}", "", 413);
                res->write(response.data(), response.size());
                return;
            }

            auto authorization = req.getHeader("authorization");
            auto &pending = pendingRequests[requestId];
            pending.res = res;
            if (authorization) pending.authorization = authorization.toString();
            if (length) pending.body.assign(data, length);

            if (remainingBytes == 0) dispatchAdminRequest(requestId);
            return;
        }

        if (url == "/metrics") {
            auto metrics = PrometheusMetrics::getInstance().render();
            auto response = preGenerateHttpResponse("text/plain; version=0.0.4", metrics);
            res->write(response.data(), response.size());
        } else if (url == "/.well-known/nodeinfo") {
            auto nodeInfo = getNodeInfoHttpResponse(host);
            res->write(nodeInfo.data(), nodeInfo.size());
        } else if (url == "/nodeinfo/2.1") {
            auto nodeInfo = getNodeInfo21HttpResponse();
            res->write(nodeInfo.data(), nodeInfo.size());
        } else if (url == "/favicon.ico") {
            res->write(faviconResponse.data(), faviconResponse.size());
        } else if (path == "/admin/backup" && method == uWS::METHOD_GET) {
            expireTokens();
            auto offer = offeredBackups.find(std::string(queryParam(url, "token")));

            if (offer == offeredBackups.end()) {
                auto response = preGenerateHttpResponse("text/plain; charset=utf-8", "This backup link has expired or was already used.\n", "Cache-Control: no-store\r\n", 404);
                res->write(response.data(), response.size());
                return;
            }

            uint64_t requestId = nextRequestId++;
            res->setUserData((void*)(uintptr_t)requestId);

            auto download = std::make_unique<BackupDownload>(BackupDownload{this, requestId, res, std::move(offer->second.file)});
            offeredBackups.erase(offer);

            auto head = httpHead(200, "application/octet-stream", download->file.size,
                "Content-Disposition: attachment; filename=\"" + download->file.filename + "\"\r\n"
                "Cache-Control: no-store\r\n");
            res->write(head.data(), head.size());

            LI << "Backup download started: " << renderSize(download->file.size);
            backupDownloads.emplace(requestId, std::move(download));
            continueBackup(requestId);
        } else if (path == "/admin") {
            res->write(adminPageResponse.data(), adminPageResponse.size());
        } else if (req.getHeader("accept").toStringView() == "application/nostr+json") {
            auto info = getServerInfoHttpResponse();
            res->write(info.data(), info.size());
        } else {
            auto landing = getLandingPageHttpResponse();
            res->write(landing.data(), landing.size());
        }
    });

    hubGroup->onHttpData([&](uWS::HttpResponse *res, char *data, size_t length, size_t remainingBytes){
        auto it = pendingRequests.find((uint64_t)(uintptr_t)res->getUserData());
        if (it == pendingRequests.end()) return;

        it->second.body.append(data, length);
        if (remainingBytes == 0) dispatchAdminRequest(it->first);
    });

    hubGroup->onCancelledHttpRequest([&](uWS::HttpResponse *res){
        auto requestId = (uint64_t)(uintptr_t)res->getUserData();
        pendingRequests.erase(requestId);
        backupDownloads.erase(requestId);
    });

    hubGroup->onConnection([&](uWS::WebSocket<uWS::SERVER> *ws, uWS::HttpRequest req) {
        uint64_t connId = nextConnectionId++;

        Connection *c = new Connection(ws, connId);

        if (cfg().relay__realIpHeader.size()) {
            auto header = req.getHeader(cfg().relay__realIpHeader.c_str()).toString(); // not string_view: parseIP needs trailing 0 byte

            c->ipAddr = parseIP(header);
            if (c->ipAddr.size() == 0) LW << "Couldn't parse IP from header " << cfg().relay__realIpHeader << ": " << header;
        }

        if (c->ipAddr.size() == 0) c->ipAddr = ws->getAddressBytes();

        ws->setUserData((void*)c);
        connIdToConnection.emplace(connId, c);

        bool compEnabled, compSlidingWindow;
        ws->getCompressionState(compEnabled, compSlidingWindow);
        LI << "[" << connId << "] Connect from " << renderIP(c->ipAddr)
           << " compression=" << (compEnabled ? 'Y' : 'N')
           << " sliding=" << (compSlidingWindow ? 'Y' : 'N')
        ;

        PrometheusMetrics::getInstance().activeConnections.inc();

        tpIngester.dispatch(connId, MsgIngester{MsgIngester::NewConn{connId}});

        if (cfg().relay__enableTcpKeepalive) {
            int optval = 1;
            if (setsockopt(ws->getFd(), SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval))) {
                LW << "Failed to enable TCP keepalive: " << strerror(errno);
            }
        }

        bool blocked;
        {
            auto txn = env.txn_ro();
            blocked = AccessControl::isIpBlocked(txn, c->ipAddr);
        }

        if (blocked) {
            LI << "[" << connId << "] Blocked IP " << renderIP(c->ipAddr) << ", closing";
            // close() runs onDisconnection right away, which deletes c
            ws->close(1008, "blocked", 7);
        }
    });

    hubGroup->onDisconnection([&](uWS::WebSocket<uWS::SERVER> *ws, int code, char *message, size_t length) {
        auto *c = (Connection*)ws->getUserData();
        uint64_t connId = c->connId;

        auto upComp = renderPercent(1.0 - (double)c->stats.bytesUpCompressed / c->stats.bytesUp);
        auto downComp = renderPercent(1.0 - (double)c->stats.bytesDownCompressed / c->stats.bytesDown);

        LI << "[" << connId << "] Disconnect from " << renderIP(c->ipAddr)
           << " (" << code << "/" << (message ? std::string_view(message, length) : "-") << ")"
           << " UP: " << renderSize(c->stats.bytesUp) << " (" << upComp << " compressed)"
           << " DN: " << renderSize(c->stats.bytesDown) << " (" << downComp << " compressed)"
           << " Pending: " << renderSize(c->stats.pendingOutbound)
        ;

        tpIngester.dispatch(connId, MsgIngester{MsgIngester::CloseConn{connId}});

        connIdToConnection.erase(connId);
        delete c;

        PrometheusMetrics::getInstance().activeConnections.dec();

        if (gracefulShutdown) {
            LI << "Graceful shutdown in progress: " << connIdToConnection.size() << " connections remaining";
            if (connIdToConnection.size() == 0) {
                LW << "All connections closed, shutting down";
                ::exit(0);
            }
        }
    });

    hubGroup->onMessage2([&](uWS::WebSocket<uWS::SERVER> *ws, char *message, size_t length, uWS::OpCode opCode, size_t compressedSize) {
        auto &c = *(Connection*)ws->getUserData();

        c.stats.bytesDown += length;
        c.stats.bytesDownCompressed += compressedSize;

        tpIngester.dispatch(c.connId, MsgIngester{MsgIngester::ClientMessage{c.connId, c.ipAddr, std::string(message, length)}});
    });


    std::function<void()> asyncCb = [&]{
        auto newMsgs = thr.inbox.pop_all_no_wait();

        auto doSend = [&](uint64_t connId, std::string_view payload, uWS::OpCode opCode){
            auto it = connIdToConnection.find(connId);
            if (it == connIdToConnection.end()) return;
            auto &c = *it->second;

            // Track bytes still inside uWS's outbound path (either queued or
            // partially sent). Increment before send(), decrement in the
            // completion callback. The payload size is smuggled through the
            // callback's user-data pointer so the callback captures nothing and
            // decays to a plain function pointer.
            const size_t payloadSize = payload.size();
            c.stats.pendingOutbound += payloadSize;

            size_t compressedSize;

            auto cb = [](uWS::WebSocket<uWS::SERVER> *ws, void *data, bool /*cancelled*/, void * /*reserved*/){
                // uWS invokes this exactly once per send() on every path:
                //   - immediate send success          (ws != nullptr, cancelled=false)
                //   - immediate send failure          (ws != nullptr, cancelled=true)
                //   - queued drain success            (ws != nullptr, cancelled=false)
                //   - socket teardown (onEnd flush)   (ws == nullptr, cancelled=true)
                // The teardown path runs after our onDisconnection handler has
                // already logged and deleted the Connection, so we must not
                // dereference anything via ws in that case. Gate on ws.
                if (!ws) return;
                auto *conn = static_cast<Connection*>(ws->getUserData());
                if (!conn) return;
                conn->stats.pendingOutbound -= reinterpret_cast<uintptr_t>(data);
            };
            c.websocket->send(payload.data(), payloadSize, opCode, cb,
                              reinterpret_cast<void*>(static_cast<uintptr_t>(payloadSize)),
                              true, &compressedSize);
            c.stats.bytesUp += payloadSize;
            c.stats.bytesUpCompressed += compressedSize;

            // Back-pressure: if a client is too slow to read and the outbound
            // backlog inside uWS exceeds the configured cap, drop the connection
            // to bound memory. terminate() synchronously invokes our
            // onDisconnection (which logs and deletes the Connection) and then
            // drains the queued sends with cancellation callbacks, so no queue
            // entries leak. c is dangling after terminate(), so we must return.
            const uint64_t maxPending = cfg().relay__maxPendingOutboundBytes;
            if (maxPending > 0 && c.stats.pendingOutbound > maxPending) {
                LW << "[" << c.connId << "] Slow client: pendingOutbound "
                   << renderSize(c.stats.pendingOutbound)
                   << " exceeds relay.maxPendingOutboundBytes "
                   << renderSize(maxPending) << ", terminating";
                PrometheusMetrics::getInstance().slowClientTerminations.inc();
                c.websocket->terminate();
                return;
            }
        };

        for (auto &newMsg : newMsgs) {
            if (auto msg = std::get_if<MsgWebsocket::Send>(&newMsg.msg)) {
                doSend(msg->connId, msg->payload, uWS::OpCode::TEXT);
            } else if (auto msg = std::get_if<MsgWebsocket::SendBinary>(&newMsg.msg)) {
                doSend(msg->connId, msg->payload, uWS::OpCode::BINARY);
            } else if (auto msg = std::get_if<MsgWebsocket::SendEventToBatch>(&newMsg.msg)) {
                tempBuf.reserve(13 + MAX_SUBID_SIZE + msg->evJson.size());
                tempBuf.resize(10 + MAX_SUBID_SIZE);
                tempBuf += "\",";
                tempBuf += msg->evJson;
                tempBuf += "]";

                for (auto &item : msg->list) {
                    PROM_INC_RELAY_MSG("EVENT");
                    auto subIdSv = item.subId.sv();
                    auto *p = tempBuf.data() + MAX_SUBID_SIZE - subIdSv.size();
                    memcpy(p, "[\"EVENT\",\"", 10);
                    memcpy(p + 10, subIdSv.data(), subIdSv.size());
                    doSend(item.connId, std::string_view(p, 13 + subIdSv.size() + msg->evJson.size()), uWS::OpCode::TEXT);
                }
            } else if (auto msg = std::get_if<MsgWebsocket::HttpReply>(&newMsg.msg)) {
                auto it = pendingRequests.find(msg->requestId);

                if (it != pendingRequests.end()) {
                    const auto &importToken = it->second.importToken;
                    auto response = preGenerateHttpResponse(importToken.size() ? "application/json" : "application/nostr+json+rpc", msg->body, "", msg->status);
                    it->second.res->write(response.data(), response.size());

                    if (auto token = importTokens.find(importToken); token != importTokens.end()) {
                        token->second = hoytech::curr_time_s() + importTokenLifetimeSeconds;
                    }

                    pendingRequests.erase(it);
                }
            } else if (auto msg = std::get_if<MsgWebsocket::DropIp>(&newMsg.msg)) {
                std::vector<uWS::WebSocket<uWS::SERVER>*> blocked;

                for (auto &[connId, c] : connIdToConnection) {
                    if (c->ipAddr == msg->ipAddr) blocked.push_back(c->websocket);
                }

                // terminate() runs onDisconnection, which erases from connIdToConnection
                for (auto *ws : blocked) ws->terminate();

                if (blocked.size()) LI << "Dropped " << blocked.size() << " connections from blocked IP " << renderIP(msg->ipAddr);
            } else if (auto msg = std::get_if<MsgWebsocket::OfferBackup>(&newMsg.msg)) {
                offeredBackups[msg->token] = OfferedBackup{std::move(msg->file), hoytech::curr_time_s() + backupLinkLifetimeSeconds};
            } else if (auto msg = std::get_if<MsgWebsocket::ContinueBackup>(&newMsg.msg)) {
                auto it = backupDownloads.find(msg->requestId);
                if (it != backupDownloads.end()) pumpBackup(*it->second);
            } else if (auto msg = std::get_if<MsgWebsocket::OfferImport>(&newMsg.msg)) {
                importTokens[msg->token] = hoytech::curr_time_s() + importTokenLifetimeSeconds;
            } else if (std::get_if<MsgWebsocket::GracefulShutdown>(&newMsg.msg)) {
                LW << "Initiating graceful shutdown: " << connIdToConnection.size() << " connections remaining";
                gracefulShutdown = true;
                hubGroup->stopListening();
            }
        }
    };

    hubTrigger = new uS::Async(hub.getLoop());
    hubTrigger->setData(&asyncCb);

    hubTrigger->start([](uS::Async *a){
        auto *r = static_cast<std::function<void()> *>(a->getData());
        (*r)();
    });

    // Frees the disk space of backups nobody downloaded
    auto *tokenExpiryTimer = new uS::Timer(hub.getLoop());
    tokenExpiryTimer->setData(&expireTokens);
    tokenExpiryTimer->start([](uS::Timer *t){
        (*static_cast<std::function<void()> *>(t->getData()))();
    }, 15'000, 15'000);



    int port = cfg().relay__port;

    std::string bindHost = cfg().relay__bind;

    if (!hub.listen(bindHost.c_str(), port, nullptr, uS::REUSE_PORT, hubGroup)) throw herr("unable to listen on port ", port);

    LI << "Started websocket server on " << bindHost << ":" << port;

    hub.run();
}
