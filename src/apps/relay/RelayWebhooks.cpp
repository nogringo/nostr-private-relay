#include <atomic>
#include <deque>

#include <curl/curl.h>

#include "RelayServer.h"
#include "Webhooks.h"
#include "AccessControl.h"
#include "app_git_version.h"


namespace {

const size_t maxConcurrentRequests = 64;
const size_t maxQueuedRequests = 10'000;

struct StoredSubscription {
    std::string eventId;
    std::string address; // pubkey + d tag
    uint64_t since; // only events stored after this levId are pushed
    bool gone = false; // its callback answered 404
    std::optional<Webhooks::Subscription> sub; // empty when the relay won't fulfill it
};

struct Delivery {
    uint64_t subLevId;
    std::string callback;
    std::string body;
};

struct Transfer {
    Delivery delivery;
    curl_slist *headers = nullptr;
    bool blockedAddress = false;

    ~Transfer() {
        curl_slist_free_all(headers);
    }
};

curl_socket_t openSocket(void *clientp, curlsocktype purpose, curl_sockaddr *address) {
    if (purpose == CURLSOCKTYPE_IPCXN && !cfg().relay__webhooks__allowPrivateAddresses && !Webhooks::isPublicAddress(&address->addr)) {
        static_cast<Transfer *>(clientp)->blockedAddress = true;
        return CURL_SOCKET_BAD;
    }

    return ::socket(address->family, address->socktype, address->protocol);
}

size_t discardBody(char *, size_t size, size_t nmemb, void *) {
    return size * nmemb;
}

}


void RelayServer::runWebhooks() {
    setThreadName("Webhooks");

    CURLM *multi = curl_multi_init();
    if (!multi) throw herr("curl_multi_init failed");
    uint64_t multiConfigVer = cfg().version();

    std::atomic<bool> dbChanged = true;

    auto dbChangeWatcher = hoytech::file_change_monitor(dbDir + "/data.mdb");
    dbChangeWatcher.setDebounce(100);
    dbChangeWatcher.run([&]{
        dbChanged = true;
    });

    Decompressor decomp;
    flat_hash_map<uint64_t, StoredSubscription> subs; // by levId
    flat_hash_map<std::string, std::vector<std::pair<uint64_t, StoredSubscription*>>> subsByOwner;
    std::vector<std::pair<uint64_t, std::string>> pendingDeletions; // levId, event id
    bool deletionsDue = false;
    std::deque<Delivery> queue;
    flat_hash_map<CURL*, std::unique_ptr<Transfer>> transfers;
    uint64_t currEventId = MAX_U64;
    uint64_t configVer = 0;
    std::string userAgent = std::string("nostr-private-relay/") + APP_GIT_VERSION;

    auto loadSubscription = [&](lmdb::txn &txn, uint64_t levId, StoredSubscription &stored){
        stored.sub.reset();

        try {
            stored.sub.emplace(Webhooks::parse(tao::json::from_string(getEventJson(txn, decomp, levId))));
        } catch (std::exception &e) {
            LI << "Ignoring webhook subscription " << to_hex(stored.eventId) << ": " << e.what();
        }
    };

    auto refreshSubscriptions = [&](lmdb::txn &txn){
        bool reparse = configVer != cfg().version();
        configVer = cfg().version();

        flat_hash_set<uint64_t> present;
        std::vector<uint64_t> added;

        env.generic_foreachFull(txn, env.dbi_Event__kind, makeKey_Uint64Uint64(Webhooks::subscriptionKind, 0), lmdb::to_sv<uint64_t>(0), [&](auto k, auto v){
            if (ParsedKey_Uint64Uint64(k).n1 != Webhooks::subscriptionKind) return false;
            uint64_t levId = lmdb::from_sv<uint64_t>(v);
            present.insert(levId);
            if (!subs.contains(levId)) added.push_back(levId);
            return true;
        });

        if (!reparse && added.empty() && present.size() == subs.size()) return;

        // A replaced subscription keeps receiving what was stored since its first version
        flat_hash_map<std::string, uint64_t> sinceByAddress;
        std::vector<uint64_t> removed;

        for (auto &[levId, stored] : subs) {
            if (present.contains(levId)) continue;
            sinceByAddress[stored.address] = stored.since;
            removed.push_back(levId);
        }

        for (auto levId : removed) subs.erase(levId);

        if (reparse) {
            for (auto &[levId, stored] : subs) loadSubscription(txn, levId, stored);
        }

        for (auto levId : added) {
            PackedEventView packed(lookupEventByLevId(txn, levId).buf);
            auto address = std::string(packed.pubkey()) + std::string(Webhooks::dTag(packed));
            auto since = sinceByAddress.find(address);

            auto &stored = subs.try_emplace(levId, StoredSubscription{
                std::string(packed.id()),
                address,
                since == sinceByAddress.end() ? levId : std::min(since->second, levId),
            }).first->second;

            loadSubscription(txn, levId, stored);
        }

        subsByOwner.clear();
        for (auto &[levId, stored] : subs) {
            if (stored.sub) subsByOwner[stored.sub->pubkey].emplace_back(levId, &stored);
        }
    };

    auto collectDeliveries = [&](lmdb::txn &txn, defaultDb::environment::View_Event &ev){
        PackedEventView packed(ev.buf);

        // NIP-9a: subscriptions are only served to their author, and their callbacks are secrets
        if (packed.kind() == Webhooks::subscriptionKind) return;

        auto owner = ReadRestrictor::ownerOf(packed);
        if (owner.empty()) return;

        auto found = subsByOwner.find(std::string(owner));
        if (found == subsByOwner.end()) return;

        std::optional<bool> ownerRefused;
        std::string eventIdJson;

        for (auto &[subLevId, stored] : found->second) {
            const auto &sub = *stored->sub;

            if (stored->gone || ev.primaryKeyId <= stored->since) continue;
            if (!sub.filters.doesMatch(packed) || sub.ignore.doesMatch(packed)) continue;

            if (!ownerRefused) ownerRefused = AccessControl::refusal(txn, owner).size() > 0;
            if (*ownerRefused) return;

            if (queue.size() >= maxQueuedRequests) {
                LW << "Webhook queue full, dropping a POST to " << Webhooks::callbackHost(sub.callback);
                continue;
            }

            if (eventIdJson.empty()) eventIdJson = to_hex(packed.id());

            std::string body = "{\"id\":\"" + eventIdJson + "\",\"relay\":" + tao::json::to_string(tao::json::value(Webhooks::relayUrl()));
            if (sub.includeEvent) {
                body += ",\"event\":";
                body += getEventJson(txn, decomp, ev.primaryKeyId);
            }
            body += "}";

            queue.push_back(Delivery{ subLevId, sub.callback, std::move(body) });
        }
    };

    // Deleting the most recent event would let the next one reuse its levId, which monitors would never see
    auto runPendingDeletions = [&]{
        auto txn = env.txn_rw();
        auto mostRecent = getMostRecentLevId(txn);
        std::vector<uint64_t> levIds;
        decltype(pendingDeletions) stillPending;

        for (auto &[levId, eventId] : pendingDeletions) {
            auto ev = env.lookup_Event(txn, levId);
            if (!ev || PackedEventView(ev->buf).id() != eventId) continue;

            if (levId == mostRecent) stillPending.emplace_back(levId, eventId);
            else levIds.push_back(levId);
        }

        if (levIds.size()) {
            NegentropyFilterCache neFilterCache;
            auto deleted = deleteEvents(txn, neFilterCache, levIds);
            txn.commit();
            LI << "Deleted " << deleted << " webhook subscriptions whose callback answered 404";
        }

        pendingDeletions = std::move(stillPending);
    };

    auto startTransfers = [&]{
        while (transfers.size() < maxConcurrentRequests && queue.size()) {
            auto transfer = std::make_unique<Transfer>();
            transfer->delivery = std::move(queue.front());
            queue.pop_front();

            auto stored = subs.find(transfer->delivery.subLevId);
            if (stored != subs.end() && stored->second.gone) continue;

            CURL *easy = curl_easy_init();
            if (!easy) {
                LE << "curl_easy_init failed";
                continue;
            }

            transfer->headers = curl_slist_append(transfer->headers, "Content-Type: application/json");
            transfer->headers = curl_slist_append(transfer->headers, "Expect:");

            curl_easy_setopt(easy, CURLOPT_URL, transfer->delivery.callback.c_str());
            curl_easy_setopt(easy, CURLOPT_POSTFIELDS, transfer->delivery.body.data());
            curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)transfer->delivery.body.size());
            curl_easy_setopt(easy, CURLOPT_HTTPHEADER, transfer->headers);
            curl_easy_setopt(easy, CURLOPT_USERAGENT, userAgent.c_str());
            curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, (long)cfg().relay__webhooks__timeoutSeconds * 1000);
            curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
            curl_easy_setopt(easy, CURLOPT_PROXY, ""); // a proxy would connect to private addresses for us
            curl_easy_setopt(easy, CURLOPT_OPENSOCKETFUNCTION, openSocket);
            curl_easy_setopt(easy, CURLOPT_OPENSOCKETDATA, transfer.get());
            curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, discardBody);

            curl_multi_add_handle(multi, easy);
            transfers.emplace(easy, std::move(transfer));
        }
    };

    auto finishTransfers = [&]{
        int remaining;

        while (CURLMsg *msg = curl_multi_info_read(multi, &remaining)) {
            if (msg->msg != CURLMSG_DONE) continue;

            CURL *easy = msg->easy_handle;
            auto result = msg->data.result;
            long status = 0;
            curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &status);

            curl_multi_remove_handle(multi, easy);
            curl_easy_cleanup(easy);

            auto found = transfers.find(easy);
            auto transferOwner = std::move(found->second);
            transfers.erase(found);

            auto &transfer = *transferOwner;
            auto host = Webhooks::callbackHost(transfer.delivery.callback);

            if (result != CURLE_OK) {
                LI << "Webhook POST to " << host << " failed: " << (transfer.blockedAddress ? "callback resolves to a private address" : curl_easy_strerror(result));
            } else if (status == 404) {
                // NIP-9a: the push server no longer knows this subscription
                auto stored = subs.find(transfer.delivery.subLevId);

                if (stored != subs.end() && !stored->second.gone) {
                    stored->second.gone = true;
                    pendingDeletions.emplace_back(stored->first, stored->second.eventId);
                    deletionsDue = true;
                }
            } else if (status < 200 || status >= 300) {
                LI << "Webhook POST to " << host << " answered " << status;
            }
        }
    };

    while (1) {
        if (dbChanged.exchange(false)) {
            deletionsDue = pendingDeletions.size() > 0;

            try {
                auto txn = env.txn_ro();
                uint64_t latestEventId = getMostRecentLevId(txn);
                if (currEventId > latestEventId) currEventId = latestEventId;

                if (Webhooks::active()) {
                    refreshSubscriptions(txn);

                    if (subsByOwner.size()) {
                        env.foreach_Event(txn, [&](auto &ev){
                            collectDeliveries(txn, ev);
                            return true;
                        }, false, currEventId + 1);
                    }
                }

                currEventId = latestEventId;
            } catch (std::exception &e) {
                LE << "Webhooks: " << e.what();
            }
        }

        // Pooled connections skip openSocket, so they are dropped once a new config may forbid their address
        bool configChanged = multiConfigVer != cfg().version();

        if (configChanged && transfers.empty()) {
            curl_multi_cleanup(multi);
            multi = curl_multi_init();
            if (!multi) throw herr("curl_multi_init failed");
            multiConfigVer = cfg().version();
            configChanged = false;
        }

        if (!configChanged) startTransfers();

        int running;
        curl_multi_perform(multi, &running);
        finishTransfers();
        if (!configChanged) startTransfers();

        if (deletionsDue) {
            deletionsDue = false;

            try {
                runPendingDeletions();
            } catch (std::exception &e) {
                LE << "Webhooks: unable to delete subscriptions: " << e.what();
            }
        }

        curl_multi_poll(multi, nullptr, 0, 100, nullptr);
    }
}
