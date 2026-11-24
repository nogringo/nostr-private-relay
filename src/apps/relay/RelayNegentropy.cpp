#include <negentropy.h>
#include <negentropy/storage/Vector.h>

#include "RelayServer.h"
#include "QueryScheduler.h"

// NIP-37: a session only covers what its uploader stored, so it never uses a pre-computed tree of every event
struct NegentropyViews {
    struct MemoryView {
        std::string initialMsg;
        negentropy::storage::Vector storageVector;
        std::vector<uint64_t> levIds;
        uint64_t startTime = hoytech::curr_time_us();
    };

    using ConnViews = flat_hash_map<SubId, MemoryView>;
    flat_hash_map<uint64_t, ConnViews> conns; // connId -> subId -> MemoryView

    bool addMemoryView(uint64_t connId, const SubId &subId, const std::string &initialMsg) {
        {
            auto *existing = findView(connId, subId);
            if (existing) removeView(connId, subId);
        }

        auto res = conns.try_emplace(connId);
        auto &connViews = res.first->second;

        if (connViews.size() >= cfg().relay__maxSubsPerConnection) {
            return false;
        }

        connViews.try_emplace(subId, MemoryView{ initialMsg, });

        return true;
    }

    MemoryView *findView(uint64_t connId, const SubId &subId) {
        auto f1 = conns.find(connId);
        if (f1 == conns.end()) return nullptr;

        auto f2 = f1->second.find(subId);
        if (f2 == f1->second.end()) return nullptr;

        return &f2->second;
    }

    void removeView(uint64_t connId, const SubId &subId) {
        auto *view = findView(connId, subId);
        if (!view) return;
        conns[connId].erase(subId);
        if (conns[connId].empty()) conns.erase(connId);
    }

    void closeConn(uint64_t connId) {
        auto f1 = conns.find(connId);
        if (f1 == conns.end()) return;

        conns.erase(connId);
    }
};


void RelayServer::runNegentropy(ThreadPool<MsgNegentropy>::Thread &thr) {
    QueryScheduler queries;
    NegentropyViews views;

    auto handleReconcile = [&](uint64_t connId, const SubId &subId, negentropy::StorageBase &storage, const std::string &msg) {
        std::string resp;

        try {
            Negentropy<negentropy::StorageBase> ne(storage, 500'000);
            resp = ne.reconcile(msg);
        } catch (std::exception &e) {
            LI << "[" << connId << "] Error parsing negentropy message: " << e.what();

            PROM_INC_RELAY_MSG("NEG-ERR");
            sendToConn(connId, tao::json::to_string(tao::json::value::array({
                "NEG-ERR",
                subId.str(),
                "PROTOCOL-ERROR"
            })));

            views.removeView(connId, subId);
            return;
        }

        LI << "[" << connId << "] negentropy SEND session=" << subId.sv() << " bytesOut=" << resp.size();

        PROM_INC_RELAY_MSG("NEG-MSG");
        sendToConn(connId, tao::json::to_string(tao::json::value::array({
            "NEG-MSG",
            subId.str(),
            to_hex(resp)
        })));
    };


    queries.ensureExists = false;

    queries.onEventBatch = [&](lmdb::txn &txn, const auto &sub, const std::vector<uint64_t> &levIds){
        auto *view = views.findView(sub.connId, sub.subId);
        if (!view) return;

        for (auto levId : levIds) {
            view->levIds.push_back(levId);
        }
    };

    queries.onComplete = [&](lmdb::txn &txn, Subscription &sub, uint64_t){
        auto *view = views.findView(sub.connId, sub.subId);
        if (!view) return;

        LI << "[" << sub.connId << "] negentropy QUERY matched " << view->levIds.size() << " events in "
           << (hoytech::curr_time_us() - view->startTime) << "us";

        if (view->levIds.size() > cfg().relay__negentropy__maxSyncEvents) {
            LI << "[" << sub.connId << "] negentropy QUERY size exceeded " << cfg().relay__negentropy__maxSyncEvents;

            PROM_INC_RELAY_MSG("NEG-ERR");
            sendToConn(sub.connId, tao::json::to_string(tao::json::value::array({
                "NEG-ERR",
                sub.subId.str(),
                "blocked: too many query results",
                cfg().relay__negentropy__maxSyncEvents
            })));

            views.removeView(sub.connId, sub.subId);
            return;
        }

        std::sort(view->levIds.begin(), view->levIds.end());

        for (auto levId : view->levIds) {
            try {
                PackedEventView packed(lookupEventByLevId(txn, levId).buf);
                view->storageVector.insert(packed.created_at(), packed.id());
            } catch (std::exception &) {
                // levId was deleted when query was paused
            }
        }

        view->levIds.clear();
        view->levIds.shrink_to_fit();

        view->storageVector.seal();

        handleReconcile(sub.connId, sub.subId, view->storageVector, view->initialMsg);

        view->initialMsg = "";
    };


    while(1) {
        auto newMsgs = queries.running.empty() ? thr.inbox.pop_all() : thr.inbox.pop_all_no_wait();

        auto txn = env.txn_ro();

        for (auto &newMsg : newMsgs) {
            if (auto msg = std::get_if<MsgNegentropy::NegOpen>(&newMsg.msg)) {
                auto connId = msg->sub.connId;
                auto subId = msg->sub.subId;

                queries.removeSub(connId, subId);
                views.removeView(connId, subId);

                LI << "[" << connId << "] negentropy NEW session=" << subId.sv() << " bytesIn=" << msg->negPayload.size();

                if (!queries.addSub(txn, std::move(msg->sub))) {
                    sendNoticeError(connId, std::string("too many concurrent REQs"));
                }

                if (!views.addMemoryView(connId, subId, msg->negPayload)) {
                    queries.removeSub(connId, subId);
                    sendNoticeError(connId, std::string("too many concurrent NEG requests"));
                }

                queries.process(txn);
            } else if (auto msg = std::get_if<MsgNegentropy::NegMsg>(&newMsg.msg)) {
                auto *view = views.findView(msg->connId, msg->subId);
                if (!view) {
                    PROM_INC_RELAY_MSG("NEG-ERR");
                    sendToConn(msg->connId, tao::json::to_string(tao::json::value::array({
                        "NEG-ERR",
                        msg->subId.str(),
                        "closed: unknown subscription handle"
                    })));

                    continue;
                }

                LI << "[" << msg->connId << "] negentropy RECV session=" << msg->subId.sv() << " bytesIn=" << msg->negPayload.size();

                if (!view->storageVector.sealed) {
                    sendNoticeError(msg->connId, "negentropy error: got NEG-MSG before NEG-OPEN complete");
                    continue;
                }

                handleReconcile(msg->connId, msg->subId, view->storageVector, msg->negPayload);
            } else if (auto msg = std::get_if<MsgNegentropy::NegClose>(&newMsg.msg)) {
                LI << "[" << msg->connId << "] negentropy CLOSE session=" << msg->subId.sv();

                queries.removeSub(msg->connId, msg->subId);
                views.removeView(msg->connId, msg->subId);
            } else if (auto msg = std::get_if<MsgNegentropy::CloseConn>(&newMsg.msg)) {
                queries.closeConn(msg->connId);
                views.closeConn(msg->connId);
            }
        }

        queries.process(txn);

        txn.abort();
    }
}
