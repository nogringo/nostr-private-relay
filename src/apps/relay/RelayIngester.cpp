#include "RelayServer.h"
#include "RelayUrl.h"
#include "jsonParseUtils.h"
#include "AccessControl.h"
#include "Webhooks.h"


static std::string sessionPubkey(const RelayServerCtx &rsctx, uint64_t connId) {
    auto it = rsctx.connIdToAuthSession.find(connId);
    return it == rsctx.connIdToAuthSession.end() ? "" : it->second.pubkey;
}


void RelayServer::runIngester(ThreadPool<MsgIngester>::Thread &thr) {
    RelayServerCtx rsctx;

    while(1) {
        auto newMsgs = thr.inbox.pop_all();

        auto txn = env.txn_ro();

        std::vector<MsgWriter> writerMsgs;

        for (auto &newMsg : newMsgs) {
            if (auto msg = std::get_if<MsgIngester::NewConn>(&newMsg.msg)) {
                // Nothing works here without AUTH, so let clients sign in before their first request
                if (cfg().relay__auth__serviceUrl.size()) {
                    sendAuthChallenge(msg->connId, ingesterChallenge(rsctx, msg->connId));
                }
            } else if (auto msg = std::get_if<MsgIngester::ClientMessage>(&newMsg.msg)) {
                try {
                    if (msg->payload.starts_with('[')) {
                        auto payload = tao::json::from_string(msg->payload);

                        if (cfg().relay__logging__dumpInAll) LI << "[" << msg->connId << "] dumpInAll: " << msg->payload;

                        auto &arr = jsonGetArray(payload, "message is not an array");
                        if (arr.size() < 2) throw herr("too few array elements");

                        auto &cmd = jsonGetString(arr[0], "first element not a command like REQ");

                        if (cmd == "EVENT") {
                            PROM_INC_CLIENT_MSG(cmd);
                            if (cfg().relay__logging__dumpInEvents) LI << "[" << msg->connId << "] dumpInEvent: " << msg->payload;

                            try {
                                ingesterProcessEvent(txn, rsctx, msg->connId, msg->ipAddr, arr[1], writerMsgs);
                            } catch (std::exception &e) {
                                sendOKResponse(msg->connId, arr[1].is_object() && arr[1].at("id").is_string() ? arr[1].at("id").get_string() : "?",
                                               false, std::string("invalid: ") + e.what());
                                if (cfg().relay__logging__invalidEvents) LI << "Rejected invalid event: " << e.what();
                            }
                        } else if (cmd == "AUTH") {
                            PROM_INC_CLIENT_MSG(cmd);
                            if (cfg().relay__logging__dumpInAll) LI << "[" << msg->connId << "] dumpInAuth: " << msg->payload;

                            try {
                                ingesterProcessAuth(txn, rsctx, msg->connId, arr[1]);
                            } catch (std::exception &e) {
                                PrometheusMetrics::getInstance().authFailureTotal.inc();
                                sendOKResponse(msg->connId, arr[1].is_object() && arr[1].at("id").is_string() ? arr[1].at("id").get_string() : "?",
                                               false, std::string("error: ") + e.what());
                            }
                        } else if (cmd == "REQ" || cmd == "COUNT") {
                            PROM_INC_CLIENT_MSG(cmd);
                            if (cfg().relay__logging__dumpInReqs) LI << "[" << msg->connId << "] dumpInReq: " << msg->payload;

                            std::string subIdStr;

                            try {
                                ingesterProcessReq(txn, rsctx, msg->connId, arr, cmd == "COUNT", subIdStr);
                            } catch (std::exception &e) {
                                if (subIdStr.size()) sendClosedError(msg->connId, subIdStr, std::string("error: bad req: ") + e.what());
                                else sendNoticeError(msg->connId, std::string("bad req: ") + e.what());
                            }
                        } else if (cmd == "CLOSE") {
                            PROM_INC_CLIENT_MSG(cmd);
                            if (cfg().relay__logging__dumpInReqs) LI << "[" << msg->connId << "] dumpInReq: " << msg->payload;

                            try {
                                ingesterProcessClose(txn, msg->connId, arr);
                            } catch (std::exception &e) {
                                sendNoticeError(msg->connId, std::string("bad close: ") + e.what());
                            }
                        } else if (cmd == "NEG-OPEN" || cmd == "NEG-MSG" || cmd == "NEG-CLOSE") {
                            PROM_INC_CLIENT_MSG(cmd);
                            if (!cfg().relay__negentropy__enabled) throw herr("negentropy disabled");

                            try {
                                ingesterProcessNegentropy(txn, rsctx, msg->connId, arr);
                            } catch (std::exception &e) {
                                sendNoticeError(msg->connId, std::string("negentropy error: ") + e.what());
                            }
                        } else {
                            throw herr("unknown cmd");
                        }
                    } else if (msg->payload == "\n") {
                        // Do nothing.
                        // This is for when someone is just sending newlines on websocat for debugging purposes.
                    } else {
                        throw herr("unparseable message");
                    }
                } catch (std::exception &e) {
                    sendNoticeError(msg->connId, std::string("bad msg: ") + e.what());
                }
            } else if (auto msg = std::get_if<MsgIngester::CloseConn>(&newMsg.msg)) {
                auto connId = msg->connId;

                if (sessionPubkey(rsctx, connId).size()) PrometheusMetrics::getInstance().authenticatedConnections.dec();
                rsctx.connIdToAuthSession.erase(connId);

                tpWriter.dispatch(connId, MsgWriter{MsgWriter::CloseConn{connId}});
                tpReqWorker.dispatch(connId, MsgReqWorker{MsgReqWorker::CloseConn{connId}});
                tpNegentropy.dispatch(connId, MsgNegentropy{MsgNegentropy::CloseConn{connId}});
            }
        }

        if (writerMsgs.size()) {
            tpWriter.dispatchMulti(0, writerMsgs);
        }
    }
}

std::string RelayServer::ingesterChallenge(RelayServerCtx &rsctx, uint64_t connId) {
    auto it = rsctx.connIdToAuthSession.find(connId);

    if (it == rsctx.connIdToAuthSession.end()) {
        it = rsctx.connIdToAuthSession.emplace(connId, rsctx.challengeGenerator.get()).first;
        LI << "[" << connId << "] Requesting initial AUTH";
    }

    return std::string(it->second.challengeSv());
}

void RelayServer::ingesterProcessEvent(lmdb::txn &txn, RelayServerCtx &rsctx, uint64_t connId, std::string ipAddr, const tao::json::value &origJson, std::vector<MsgWriter> &output) {
    std::string packedStr, jsonStr;

    parseAndVerifyEvent(origJson, rsctx.secpCtx, true, true, packedStr, jsonStr);

    PackedEventView packed(packedStr);
    bool isVanishRequest = isVanishRequestForThisRelay(origJson);
    // NIP-37: the pubkey the connection authenticated as stores the event, and only it can read it back
    std::string uploader = sessionPubkey(rsctx, connId);

    {
        // discard reposts that embed protected events
        if (packed.kind() == 6 || packed.kind() == 16) {
            if (origJson.at("content").get_string().find("[\"-\"]") != std::string::npos) {
                auto idHex = to_hex(packed.id());
                LI << "Repost embedded a protected event, blocking: " << idHex;
                sendOKResponse(connId, idHex, false, "blocked: reposts can't embed protected events");
                return;
            }
        }

        bool foundProtected = false;

        packed.foreachTag([&](char tagName, std::string_view){
            if (tagName == '-') {
                foundProtected = true;
                return false;
            }
            return true;
        });

        // NIP-62: a request to vanish is signed by the pubkey it erases, so it needs no AUTH
        if (foundProtected || !isVanishRequest) {
            // NIP-70 protected events must be rejected unless published by an authenticated public key
            // that matches the event author, so we do all the AUTH flow here

            auto idHex = to_hex(packed.id());

            if (cfg().relay__auth__serviceUrl.empty()) {
                LI << "[" << connId << "] Event needs AUTH and no serviceUrl configured, rejecting: " << idHex;
                sendOKResponse(connId, idHex, false, foundProtected ? "blocked: event marked as protected" : "blocked: this relay can't authenticate clients");
                return;
            }

            if (uploader.empty()) {
                LI << "[" << connId << "] Event needs AUTH, requesting it: " << idHex;
                sendAuthChallenge(connId, ingesterChallenge(rsctx, connId));
                sendOKResponse(connId, idHex, false, foundProtected ? "auth-required: event marked as protected" : "auth-required: this relay only stores events of authenticated users");
                return;
            }

            if (foundProtected && uploader != packed.pubkey()) {
                sendOKResponse(connId, idHex, false, "restricted: must be published by the author");
                return;
            }
        }
    }

    // Banned pubkeys can still vanish
    if (!isVanishRequest) {
        auto refusal = AccessControl::refusal(txn, uploader);

        if (refusal.size()) {
            sendOKResponse(connId, to_hex(packed.id()), false, "blocked: " + refusal);
            return;
        }
    }

    std::string webhookCallback;

    // NIP-9a: a subscription the relay won't fulfill is refused, with the reason
    if (packed.kind() == Webhooks::subscriptionKind) {
        if (!Webhooks::active()) {
            sendOKResponse(connId, to_hex(packed.id()), false, "blocked: this relay doesn't push events to webhooks");
            return;
        }

        // Its pushes go to its author, so nobody else may store it
        if (uploader != packed.pubkey()) {
            sendOKResponse(connId, to_hex(packed.id()), false, "restricted: a webhook subscription can only be stored by its author");
            return;
        }

        webhookCallback = Webhooks::parse(origJson).callback;

        if (Webhooks::countOtherSubscriptions(txn, packed) >= cfg().relay__webhooks__maxSubscriptionsPerPubkey) {
            sendOKResponse(connId, to_hex(packed.id()), false, "blocked: too many webhook subscriptions for this pubkey");
            return;
        }
    }

    {
        // An event another pubkey stored is still new to this one
        auto existing = lookupEventById(txn, packed.id());

        if (existing && lookupUpload(txn, uploader.size() ? uploader : defaultUploader(packed), existing->primaryKeyId)) {
            auto hexId = to_hex(packed.id());
            LI << "[" << connId << "] Duplicate event, skipping: " << hexId;
            sendOKResponse(connId, hexId, true, "duplicate: have this event");
            return;
        }
    }

    Bytes32 authedPubkey = uploader.size() ? Bytes32(uploader) : Bytes32();
    MsgWriter::AddEvent addEvent{connId, std::move(ipAddr), std::move(packedStr), std::move(jsonStr), authedPubkey, std::move(uploader)};

    if (webhookCallback.size()) {
        verifyWebhook(std::move(addEvent), std::move(webhookCallback));
        return;
    }

    output.emplace_back(MsgWriter{std::move(addEvent)});
}

void RelayServer::ingesterProcessReq(lmdb::txn &txn, RelayServerCtx &rsctx, uint64_t connId, const tao::json::value &arr, bool countOnly, std::string &outSubIdStr) {
    if (arr.get_array().size() < 2 + 1) throw herr("arr too small");
    outSubIdStr = jsonGetString(arr[1], "subscription id was not a string");
    if (arr.get_array().size() > 2 + cfg().relay__maxReqFilterSize) throw herr("arr too big");

    uint64_t maxFilterLimit;

    if (countOnly) {
        // + 1 so we can distinguish exact count versus limit exceeded
        maxFilterLimit = cfg().relay__maxFilterLimitCount + 1;
        if (maxFilterLimit == 1) throw herr("COUNT disabled");
    } else {
        maxFilterLimit = cfg().relay__maxFilterLimit;
    }

    NostrFilterGroup filterGroup = NostrFilterGroup::fromReq(arr, maxFilterLimit);

    try {
        rsctx.filterValidator.validate(filterGroup);
    } catch (std::exception &e) {
        throw herr("filter validation failed: ", e.what());
    }

    auto uploader = sessionPubkey(rsctx, connId);

    if (uploader.empty()) {
        sendAuthChallenge(connId, ingesterChallenge(rsctx, connId));
        sendClosedError(connId, outSubIdStr, "auth-required: this relay only serves events to the authenticated user who stored them");
        return;
    }

    // NIP-37: a subscription only ever sees what its connection's pubkey uploaded
    Subscription sub(connId, outSubIdStr, std::move(filterGroup), countOnly, std::move(uploader));
    tpReqWorker.dispatch(connId, MsgReqWorker{MsgReqWorker::NewSub{std::move(sub)}});
}

void RelayServer::ingesterProcessClose(lmdb::txn &txn, uint64_t connId, const tao::json::value &arr) {
    if (arr.get_array().size() != 2) throw herr("arr too small/big");

    tpReqWorker.dispatch(connId, MsgReqWorker{MsgReqWorker::RemoveSub{connId, SubId(jsonGetString(arr[1], "CLOSE subscription id was not a string"))}});
}

void RelayServer::ingesterProcessAuth(lmdb::txn &txn, RelayServerCtx &rsctx, uint64_t connId, const tao::json::value &eventJson) {
    if (cfg().relay__auth__serviceUrl.empty()) throw herr("relay needs serviceUrl to be configured before AUTH can work");

    std::string packedStr, jsonStr;
    // Note: kind 22242 is ephemeral, so parseAndVerifyEvent() also applies
    // the stricter ephemeral recency check here.
    parseAndVerifyEvent(eventJson, rsctx.secpCtx, true, true, packedStr, jsonStr);

    PackedEventView packed(packedStr);

    if (packed.kind() != 22242) throw herr("wrong event kind, expected 22242");

    auto it = rsctx.connIdToAuthSession.find(connId);
    if (it == rsctx.connIdToAuthSession.end()) throw herr("no auth status available for connection");

    auto &as = it->second;

    bool foundChallenge = false;
    bool foundCorrectRelayUrl = false;

    std::string normalizedServiceUrl = normalizeRelayUrl(cfg().relay__auth__serviceUrl);

    for (const auto &tagj : eventJson.at("tags").get_array()) {
        const auto &tag = tagj.get_array();
        if (tag.size() < 2) continue;
        const auto name = tag[0].as<std::string_view>();
        const auto value = tag[1].as<std::string_view>();
        if (name == "relay" && normalizeRelayUrl(value) == normalizedServiceUrl) {
            foundCorrectRelayUrl = true;
        } else if (name == "challenge" && value == as.challengeSv()) {
            foundChallenge = true;
        }
    }

    if (!foundChallenge) throw herr("challenge string mismatch");
    if (!foundCorrectRelayUrl) throw herr("incorrect or missing relay tag, expected: " + cfg().relay__auth__serviceUrl);

    auto idHex = to_hex(packed.id());

    if (as.pubkey == packed.pubkey()) {
        sendOKResponse(connId, idHex, true, "duplicate: already authenticated");
        return;
    }

    if (as.isAuthed()) {
        PrometheusMetrics::getInstance().authFailureTotal.inc();
        sendOKResponse(connId, idHex, false, "restricted: this connection is already authenticated as another pubkey");
        return;
    }

    if (auto refusal = AccessControl::refusal(txn, packed.pubkey()); refusal.size()) {
        PrometheusMetrics::getInstance().authFailureTotal.inc();
        sendOKResponse(connId, idHex, false, "restricted: " + refusal);
        return;
    }

    as.pubkey = std::string(packed.pubkey());

    PrometheusMetrics::getInstance().authSuccessTotal.inc();
    PrometheusMetrics::getInstance().authenticatedConnections.inc();

    LI << "[" << connId << "] AUTHed as " << to_hex(packed.pubkey());
    sendOKResponse(connId, idHex, true, "successfully authenticated");
}

void RelayServer::ingesterProcessNegentropy(lmdb::txn &txn, RelayServerCtx &rsctx, uint64_t connId, const tao::json::value &arr) {
    const auto &vals = arr.get_array();

    if (vals.size() < 2) throw herr("negentropy query missing elements");

    const auto &cmd = jsonGetString(vals[0], "negentropy command was not a string");
    const auto &subscriptionStr = jsonGetString(vals[1], "NEG subscription id was not a string");

    auto sendNegErr = [&](std::string_view reason){
        PROM_INC_RELAY_MSG("NEG-ERR");
        sendToConn(connId, tao::json::to_string(tao::json::value::array({
            "NEG-ERR",
            subscriptionStr,
            reason
        })));
    };

    if (cmd == "NEG-OPEN") {
        if (vals.size() < 4) throw herr("negentropy query missing elements");

        auto maxFilterLimit = cfg().relay__negentropy__maxSyncEvents + 1;

        const auto &filterJson = vals[2];
        if (!filterJson.is_object()) throw herr("negentropy filter must be an object");

        // validates the filter before anything else uses it
        NostrFilter requested(filterJson, maxFilterLimit);

        auto uploader = sessionPubkey(rsctx, connId);

        if (uploader.empty()) {
            sendAuthChallenge(connId, ingesterChallenge(rsctx, connId));
            sendNegErr("auth-required: this relay only serves events to the authenticated user who stored them");
            return;
        }

        NostrFilterGroup filterGroup;
        filterGroup.addFilter(filterJson, maxFilterLimit);

        Subscription sub(connId, subscriptionStr, std::move(filterGroup), false, std::move(uploader));

        std::string negPayload = from_hex(jsonGetString(vals[3], "negentropy payload not a string"));

        tpNegentropy.dispatch(connId, MsgNegentropy{MsgNegentropy::NegOpen{std::move(sub), std::move(negPayload)}});
    } else if (cmd == "NEG-MSG") {
        if (vals.size() < 3) throw herr("negentropy message missing elements");

        std::string negPayload = from_hex(jsonGetString(vals[2], "negentropy payload not a string"));
        tpNegentropy.dispatch(connId, MsgNegentropy{MsgNegentropy::NegMsg{connId, SubId(subscriptionStr), std::move(negPayload)}});
    } else if (cmd == "NEG-CLOSE") {
        tpNegentropy.dispatch(connId, MsgNegentropy{MsgNegentropy::NegClose{connId, SubId(subscriptionStr)}});
    } else {
        throw herr("unknown command");
    }
}
