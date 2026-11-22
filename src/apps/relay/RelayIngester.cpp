#include "RelayServer.h"
#include "RelayUrl.h"
#include "jsonParseUtils.h"
#include "ReadRestrictor.h"
#include "AccessControl.h"
#include "Webhooks.h"


static bool privateStorage() {
    return cfg().relay__auth__authorOnlyReads || cfg().relay__auth__authorOnlyWrites;
}

static const AuthedPubkeys &sessionPubkeys(const RelayServerCtx &rsctx, uint64_t connId) {
    static const AuthedPubkeys none;
    auto it = rsctx.connIdToAuthSession.find(connId);
    return it == rsctx.connIdToAuthSession.end() ? none : it->second.authed;
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
                if (privateStorage() && cfg().relay__auth__serviceUrl.size()) {
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

                if (sessionPubkeys(rsctx, connId).size()) PrometheusMetrics::getInstance().authenticatedConnections.dec();
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
    Bytes32 authedPubkey;
    bool isVanishRequest = isVanishRequestForThisRelay(origJson);

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
        bool ownerOnly = cfg().relay__auth__authorOnlyWrites && !isVanishRequest;

        if (foundProtected || ownerOnly) {
            // NIP-70 protected events must be rejected unless published by an authenticated public key
            // that matches the event author, so we do all the AUTH flow here

            auto idHex = to_hex(packed.id());

            if (foundProtected && !cfg().relay__auth__enabled) {
                LI << "[" << connId << "] Protected event and auth disabled, rejecting: " << idHex;
                sendOKResponse(connId, idHex, false, "blocked: event marked as protected");
                return;
            }

            if (cfg().relay__auth__serviceUrl.empty()) {
                LI << "[" << connId << "] Event needs AUTH and no serviceUrl configured, rejecting: " << idHex;
                sendOKResponse(connId, idHex, false, foundProtected ? "blocked: event marked as protected" : "blocked: this relay can't authenticate clients");
                return;
            }

            const auto &authed = sessionPubkeys(rsctx, connId);
            Bytes32 owner = ReadRestrictor::authedOwner(packed, authed);

            bool allowed = (!foundProtected || authed.contains(packed.pubkey())) && (!ownerOnly || !owner.isNull());

            if (!allowed) {
                if (authed.empty()) {
                    LI << "[" << connId << "] Event needs AUTH, requesting it: " << idHex;
                    sendAuthChallenge(connId, ingesterChallenge(rsctx, connId));
                    sendOKResponse(connId, idHex, false, foundProtected ? "auth-required: event marked as protected" : "auth-required: this relay only stores events of authenticated users");
                } else {
                    sendOKResponse(connId, idHex, false, foundProtected ? "restricted: must be published by the author" : "restricted: this relay only stores events from their author, or gift wraps with a single p tag from that recipient");
                }
                return;
            }

            // otherwise we proceed to accept the event
            authedPubkey = owner;
        }
    }

    // Banned pubkeys can still vanish
    if (!isVanishRequest) {
        auto owner = ReadRestrictor::ownerOf(packed);
        auto refusal = AccessControl::refusal(txn, owner.size() ? owner : packed.pubkey());

        if (refusal.size()) {
            sendOKResponse(connId, to_hex(packed.id()), false, "blocked: " + refusal);
            return;
        }
    }

    // NIP-9a: a subscription the relay won't fulfill is refused, with the reason
    if (packed.kind() == Webhooks::subscriptionKind) {
        if (!Webhooks::active()) {
            sendOKResponse(connId, to_hex(packed.id()), false, "blocked: this relay doesn't push events to webhooks");
            return;
        }

        Webhooks::parse(origJson);

        if (Webhooks::countOtherSubscriptions(txn, packed) >= cfg().relay__webhooks__maxSubscriptionsPerPubkey) {
            sendOKResponse(connId, to_hex(packed.id()), false, "blocked: too many webhook subscriptions for this pubkey");
            return;
        }
    }

    {
        auto existing = lookupEventById(txn, packed.id());
        if (existing) {
            auto hexId = to_hex(packed.id());
            LI << "[" << connId << "] Duplicate event, skipping: " << hexId;
            sendOKResponse(connId, hexId, true, "duplicate: have this event");
            return;
        }
    }

    output.emplace_back(MsgWriter{MsgWriter::AddEvent{connId, std::move(ipAddr), std::move(packedStr), std::move(jsonStr), authedPubkey}});
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

    const auto &authed = sessionPubkeys(rsctx, connId);

    if (ReadRestrictor::authorOnly()) {
        if (authed.empty()) {
            sendAuthChallenge(connId, ingesterChallenge(rsctx, connId));
            sendClosedError(connId, outSubIdStr, "auth-required: this relay only serves events to their authenticated author");
            return;
        }

        bool restricted = false;
        auto ownFilters = ReadRestrictor::narrowFilters(std::span<const tao::json::value>(arr.get_array()).subspan(2), authed, maxFilterLimit, restricted);

        if (restricted) {
            sendClosedError(connId, outSubIdStr, "restricted: this relay only serves events to their author");
            return;
        }

        Subscription sub(connId, outSubIdStr, std::move(ownFilters), countOnly);
        tpReqWorker.dispatch(connId, MsgReqWorker{MsgReqWorker::NewSub{std::move(sub)}});
        return;
    }

    bool shouldRejectReq = false;

    if (countOnly) {
        // COUNT can't be filtered per event, so a restricted-kind filter must be
        // scoped to the client's own pubkeys via authors/#p.
        shouldRejectReq = !ReadRestrictor::isFilterAllowedToCount(filterGroup, authed);
    } else {
        // if the filter group contains no filter that has a kind that is not restricted,
        // that means an unauthenticated client won't be able to see anything
        if (ReadRestrictor::isFilterGroupFullyRestricted(filterGroup)) {
            shouldRejectReq = authed.empty();
        }
    }

    if (shouldRejectReq) {
        if (countOnly && !authed.empty()) {
            sendClosedError(connId, outSubIdStr, "count-failed: can only count events you are involved in");
        } else {
            sendAuthChallenge(connId, ingesterChallenge(rsctx, connId));
            sendClosedError(connId, outSubIdStr, "auth-required: requested filter requires authentication");
        }
        return;
    }

    Subscription sub(connId, outSubIdStr, std::move(filterGroup), countOnly);

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

    if (as.authed.contains(packed.pubkey())) {
        sendOKResponse(connId, idHex, true, "duplicate: already authenticated");
        return;
    }

    if (as.authed.size() >= cfg().relay__auth__maxPubkeysPerConnection) {
        PrometheusMetrics::getInstance().authFailureTotal.inc();
        sendOKResponse(connId, idHex, false, "restricted: too many pubkeys authenticated on this connection");
        return;
    }

    if (auto refusal = AccessControl::refusal(txn, packed.pubkey()); refusal.size()) {
        PrometheusMetrics::getInstance().authFailureTotal.inc();
        sendOKResponse(connId, idHex, false, "restricted: " + refusal);
        return;
    }

    // NIP-42: every pubkey a client AUTHs as stays authenticated for the connection
    Bytes32 pubkey(packed.pubkey());
    bool firstPubkey = as.authed.empty();
    as.authed.add(pubkey);

    tpReqWorker.dispatch(connId, MsgReqWorker{MsgReqWorker::AddAuth{connId, pubkey}});
    tpReqMonitor.dispatch(connId, MsgReqMonitor{MsgReqMonitor::AddAuth{connId, pubkey}});
    tpNegentropy.dispatch(connId, MsgNegentropy{MsgNegentropy::AddAuth{connId, pubkey}});

    PrometheusMetrics::getInstance().authSuccessTotal.inc();
    if (firstPubkey) PrometheusMetrics::getInstance().authenticatedConnections.inc();

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

        const auto &authed = sessionPubkeys(rsctx, connId);
        std::vector<tao::json::value> filters;

        if (ReadRestrictor::authorOnly()) {
            if (authed.empty()) {
                sendAuthChallenge(connId, ingesterChallenge(rsctx, connId));
                sendNegErr("auth-required: this relay only serves events to their authenticated author");
                return;
            }

            if (requested.neverMatch) {
                filters.push_back(filterJson);
            } else {
                ReadRestrictor::narrowFilter(filterJson, authed, filters);

                if (filters.empty()) {
                    sendNegErr("restricted: this relay only serves events to their author");
                    return;
                }
            }
        } else {
            // if the filter group contains no filter that has a kind that is not restricted,
            // that means an unauthenticated client won't be able to see anything
            if (ReadRestrictor::isFilterGroupFullyRestricted(NostrFilterGroup(filterJson, maxFilterLimit)) && authed.empty()) {
                sendAuthChallenge(connId, ingesterChallenge(rsctx, connId));
                sendNegErr("auth-required: requested filter requires authentication");
                return;
            }

            filters.push_back(filterJson);
        }

        NostrFilterGroup filterGroup;
        for (const auto &f : filters) filterGroup.addFilter(f, maxFilterLimit);

        Subscription sub(connId, subscriptionStr, std::move(filterGroup));

        // A pre-computed negentropy tree stands for exactly one filter
        std::string filterStr;
        if (filters.size() == 1) {
            filters[0].get_object().erase("since");
            filters[0].get_object().erase("until");
            filterStr = tao::json::to_string(filters[0]);
        }

        std::string negPayload = from_hex(jsonGetString(vals[3], "negentropy payload not a string"));

        tpNegentropy.dispatch(connId, MsgNegentropy{MsgNegentropy::NegOpen{std::move(sub), std::move(filterStr), std::move(negPayload)}});
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
