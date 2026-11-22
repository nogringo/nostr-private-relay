#pragma once

#include <iostream>
#include <memory>
#include <algorithm>
#include <utility>
#include <unistd.h>

#include <hoytech/time.h>
#include <hoytech/hex.h>
#include <hoytech/file_change_monitor.h>
#include <SessionToken.h>
#include <uWebSockets/src/uWS.h>
#include <tao/json.hpp>

#include "golpe.h"

#include "Subscription.h"
#include "ThreadPool.h"
#include "events.h"
#include "filters.h"
#include "jsonParseUtils.h"
#include "Decompressor.h"
#include "PrometheusMetrics.h"
#include "AuthSession.h"




// A compacted copy of the DB in an unlinked file, so the disk space comes back once fd is closed
struct BackupFile {
    int fd = -1;
    uint64_t size = 0;
    std::string filename;

    BackupFile() = default;
    BackupFile(BackupFile &&other) noexcept : fd(std::exchange(other.fd, -1)), size(other.size), filename(std::move(other.filename)) {}

    BackupFile &operator=(BackupFile &&other) noexcept {
        if (this != &other) {
            if (fd >= 0) ::close(fd);
            fd = std::exchange(other.fd, -1);
            size = other.size;
            filename = std::move(other.filename);
        }
        return *this;
    }

    ~BackupFile() {
        if (fd >= 0) ::close(fd);
    }
};

struct MsgWebsocket : NonCopyable {
    struct Send {
        uint64_t connId;
        std::string payload;
    };

    struct SendBinary {
        uint64_t connId;
        std::string payload;
    };

    struct SendEventToBatch {
        RecipientList list;
        std::string evJson;
    };

    struct GracefulShutdown {
    };

    struct HttpReply {
        uint64_t requestId;
        int status;
        std::string body;
    };

    struct DropIp {
        std::string ipAddr;
    };

    struct OfferBackup {
        std::string token;
        BackupFile file;
    };

    struct ContinueBackup {
        uint64_t requestId;
    };

    struct OfferImport {
        std::string token;
    };

    using Var = std::variant<Send, SendBinary, SendEventToBatch, GracefulShutdown, HttpReply, DropIp, OfferBackup, ContinueBackup, OfferImport>;
    Var msg;
    MsgWebsocket(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgIngester : NonCopyable {
    struct NewConn {
        uint64_t connId;
    };

    struct ClientMessage {
        uint64_t connId;
        std::string ipAddr;
        std::string payload;
    };

    struct CloseConn {
        uint64_t connId;
    };

    using Var = std::variant<NewConn, ClientMessage, CloseConn>;
    Var msg;
    MsgIngester(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgWriter : NonCopyable {
    struct AddEvent {
        uint64_t connId;
        std::string ipAddr;
        std::string packedStr;
        std::string jsonStr;
        Bytes32 authed;
    };

    struct CloseConn {
        uint64_t connId;
    };

    using Var = std::variant<AddEvent, CloseConn>;
    Var msg;
    MsgWriter(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgReqWorker : NonCopyable {
    struct NewSub {
        Subscription sub;
    };

    struct AddAuth {
        uint64_t connId;
        Bytes32 pubkey;
    };

    struct RemoveSub {
        uint64_t connId;
        SubId subId;
    };

    struct CloseConn {
        uint64_t connId;
    };

    using Var = std::variant<NewSub, AddAuth, RemoveSub, CloseConn>;
    Var msg;
    MsgReqWorker(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgReqMonitor : NonCopyable {
    struct NewSub {
        Subscription sub;
    };

    struct AddAuth {
        uint64_t connId;
        Bytes32 pubkey;
    };

    struct RemoveSub {
        uint64_t connId;
        SubId subId;
    };

    struct CloseConn {
        uint64_t connId;
    };

    struct DBChange {
    };

    using Var = std::variant<NewSub, AddAuth, RemoveSub, CloseConn, DBChange>;
    Var msg;
    MsgReqMonitor(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgNegentropy : NonCopyable {
    struct NegOpen {
        Subscription sub;
        std::string filterStr;
        std::string negPayload;
    };

    struct NegMsg {
        uint64_t connId;
        SubId subId;
        std::string negPayload;
    };

    struct AddAuth {
        uint64_t connId;
        Bytes32 pubkey;
    };

    struct NegClose {
        uint64_t connId;
        SubId subId;
    };

    struct CloseConn {
        uint64_t connId;
    };

    using Var = std::variant<NegOpen, AddAuth, NegMsg, NegClose, CloseConn>;
    Var msg;
    MsgNegentropy(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgAdmin : NonCopyable {
    // NIP-86 request, with its NIP-98 Authorization header
    struct Request {
        uint64_t requestId;
        std::string authorization;
        std::string body;
    };

    // JSONL lines posted with an import token, which the websocket thread already checked
    struct ImportLines {
        uint64_t requestId;
        std::string body;
    };

    using Var = std::variant<Request, ImportLines>;
    Var msg;
    MsgAdmin(Var &&msg_) : msg(std::move(msg_)) {}
};

struct RelayServerCtx {
    secp256k1_context *secpCtx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    FilterValidator filterValidator;
    SessionToken::Generator challengeGenerator;
    flat_hash_map<uint64_t, AuthSession> connIdToAuthSession;
};

struct RelayServer {
    uS::Async *hubTrigger = nullptr;
    uint64_t startTime = ::time(nullptr);

    // Thread Pools

    ThreadPool<MsgWebsocket> tpWebsocket;
    ThreadPool<MsgIngester> tpIngester;
    ThreadPool<MsgWriter> tpWriter;
    ThreadPool<MsgReqWorker> tpReqWorker;
    ThreadPool<MsgReqMonitor> tpReqMonitor;
    ThreadPool<MsgNegentropy> tpNegentropy;
    ThreadPool<MsgAdmin> tpAdmin;
    std::thread cronThread;
    std::thread webhooksThread;
    std::thread signalHandlerThread;

    void run();

    void runWebsocket(ThreadPool<MsgWebsocket>::Thread &thr);

    void runIngester(ThreadPool<MsgIngester>::Thread &thr);
    void ingesterProcessEvent(lmdb::txn &txn, uint64_t connId, flat_hash_map<uint64_t, AuthSession*> &connIdToAuthStatus, std::string ipAddr, secp256k1_context *secpCtx, const tao::json::value &origJson, std::vector<MsgWriter> &output);
    void ingesterProcessEvent(lmdb::txn &txn, RelayServerCtx &rsctx, uint64_t connId, std::string ipAddr, const tao::json::value &origJson, std::vector<MsgWriter> &output);
    void ingesterProcessReq(lmdb::txn &txn, RelayServerCtx &rsctx, uint64_t connId, const tao::json::value &arr, bool countOnly, std::string &outSubIdStr);
    void ingesterProcessClose(lmdb::txn &txn, uint64_t connId, const tao::json::value &arr);
    void ingesterProcessAuth(lmdb::txn &txn, RelayServerCtx &rsctx, uint64_t connId, const tao::json::value &eventJson);
    std::string ingesterChallenge(RelayServerCtx &rsctx, uint64_t connId);
    void ingesterProcessNegentropy(lmdb::txn &txn, RelayServerCtx &rsctx, uint64_t connId, const tao::json::value &origJson);

    void runWriter(ThreadPool<MsgWriter>::Thread &thr);

    void runReqWorker(ThreadPool<MsgReqWorker>::Thread &thr);

    void runReqMonitor(ThreadPool<MsgReqMonitor>::Thread &thr);

    void runNegentropy(ThreadPool<MsgNegentropy>::Thread &thr);

    void runAdmin(ThreadPool<MsgAdmin>::Thread &thr);

    void runCron();

    void runWebhooks();

    void runSignalHandler();

    // Utils (can be called by any thread)

    void sendToConn(uint64_t connId, std::string &&payload) {
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::Send{connId, std::move(payload)}});
        hubTrigger->send();
    }

    void sendToConnBinary(uint64_t connId, std::string &&payload) {
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::SendBinary{connId, std::move(payload)}});
        hubTrigger->send();
    }

    void sendEvent(uint64_t connId, const SubId &subId, std::string_view evJson) {
        PROM_INC_RELAY_MSG("EVENT");
        auto subIdSv = subId.sv();

        std::string reply;
        reply.reserve(13 + subIdSv.size() + evJson.size());

        reply += "[\"EVENT\",\"";
        reply += subIdSv;
        reply += "\",";
        reply += evJson;
        reply += "]";

        sendToConn(connId, std::move(reply));
    }

    void sendEventToBatch(RecipientList &&list, std::string &&evJson) {
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::SendEventToBatch{std::move(list), std::move(evJson)}});
        hubTrigger->send();
    }

    void sendNoticeError(uint64_t connId, std::string &&payload) {
        PROM_INC_RELAY_MSG("NOTICE");
        LI << "sending error to [" << connId << "]: " << payload;
        auto reply = tao::json::value::array({ "NOTICE", std::string("ERROR: ") + payload });
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::Send{connId, std::move(tao::json::to_string(reply))}});
        hubTrigger->send();
    }

    void sendClosedError(uint64_t connId, const std::string &subId, std::string &&payload) {
        PROM_INC_RELAY_MSG("CLOSED");
        LI << "sending closed to [" << connId << "]: " << payload;
        auto reply = tao::json::value::array({ "CLOSED", subId, payload });
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::Send{connId, std::move(tao::json::to_string(reply))}});
        hubTrigger->send();
    }

    void sendOKResponse(uint64_t connId, std::string_view eventIdHex, bool written, std::string_view message) {
        PROM_INC_RELAY_MSG("OK");
        auto reply = tao::json::value::array({ "OK", eventIdHex, written, message });
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::Send{connId, std::move(tao::json::to_string(reply))}});
        hubTrigger->send();
    }

    void sendHttpReply(uint64_t requestId, int status, std::string &&body) {
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::HttpReply{requestId, status, std::move(body)}});
        hubTrigger->send();
    }

    void dropConnectionsFromIp(std::string ipAddr) {
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::DropIp{std::move(ipAddr)}});
        hubTrigger->send();
    }

    void offerBackup(std::string token, BackupFile &&file) {
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::OfferBackup{std::move(token), std::move(file)}});
        hubTrigger->send();
    }

    void offerImport(std::string token) {
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::OfferImport{std::move(token)}});
        hubTrigger->send();
    }

    // Also called from the websocket thread, so a download never runs inside a uWS write callback
    void continueBackup(uint64_t requestId) {
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::ContinueBackup{requestId}});
        hubTrigger->send();
    }

    void sendAuthChallenge(uint64_t connId, std::string_view challenge) {
        PROM_INC_RELAY_MSG("AUTH");
        PrometheusMetrics::getInstance().authChallengesSentTotal.inc();
        auto reply = tao::json::value::array({ "AUTH", challenge });
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::Send{connId, std::move(tao::json::to_string(reply))}});
        hubTrigger->send();
    }
};
