#include "RelayServer.h"

#include "ActiveMonitors.h"



// NIP-37: every subscription is scoped to its uploader, so it follows uploads rather than events
void RelayServer::runReqMonitor(ThreadPool<MsgReqMonitor>::Thread &thr) {
    auto dbChangeWatcher = hoytech::file_change_monitor(dbDir + "/data.mdb");

    dbChangeWatcher.setDebounce(100);

    dbChangeWatcher.run([&](){
        tpReqMonitor.dispatchToAll([]{ return MsgReqMonitor{MsgReqMonitor::DBChange{}}; });
    });


    Decompressor decomp;
    ActiveMonitors monitors;
    uint64_t currUploadId = MAX_U64;

    while (1) {
        auto newMsgs = thr.inbox.pop_all();

        auto txn = env.txn_ro();

        uint64_t latestUploadId = getMostRecentUploadId(txn);
        if (currUploadId > latestUploadId) currUploadId = latestUploadId;

        auto foreachUploadAfter = [&](uint64_t uploadId, const std::function<void(uint64_t, const UploadView &, defaultDb::environment::View_Event &)> &cb){
            env.foreach_Upload(txn, [&](auto &upload){
                UploadView view(upload.buf);
                if (auto ev = env.lookup_Event(txn, view.levId())) cb(upload.primaryKeyId, view, *ev);
                return true;
            }, false, uploadId + 1);
        };

        for (auto &newMsg : newMsgs) {
            if (auto msg = std::get_if<MsgReqMonitor::NewSub>(&newMsg.msg)) {
                auto connId = msg->sub.connId;

                foreachUploadAfter(msg->sub.latestEventId, [&](uint64_t, const UploadView &upload, auto &ev){
                    if (msg->sub.uploader == upload.uploader() && msg->sub.filterGroup.doesMatch(PackedEventView(ev.buf))) {
                        sendEvent(connId, msg->sub.subId, getEventJson(txn, decomp, ev.primaryKeyId));
                    }
                });

                msg->sub.latestEventId = latestUploadId;

                if (!monitors.addSub(txn, std::move(msg->sub), latestUploadId)) {
                    sendNoticeError(connId, std::string("too many concurrent REQs"));
                }
            } else if (auto msg = std::get_if<MsgReqMonitor::RemoveSub>(&newMsg.msg)) {
                monitors.removeSub(msg->connId, msg->subId);
            } else if (auto msg = std::get_if<MsgReqMonitor::CloseConn>(&newMsg.msg)) {
                monitors.closeConn(msg->connId);
            } else if (std::get_if<MsgReqMonitor::DBChange>(&newMsg.msg)) {
                foreachUploadAfter(currUploadId, [&](uint64_t uploadId, const UploadView &upload, auto &ev){
                    monitors.process(txn, ev, uploadId, upload.uploader(), [&](RecipientList &&recipients, uint64_t levId){
                        sendEventToBatch(std::move(recipients), std::string(getEventJson(txn, decomp, levId)));
                    });
                });

                currUploadId = latestUploadId;
            }
        }
    }
}
