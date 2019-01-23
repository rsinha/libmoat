//
// Created by sivanarayana gaddam on 1/22/19.
//

#ifndef LEDGER_NATIVE_CLIENT_LEDGERCLIENT_H
#define LEDGER_NATIVE_CLIENT_LEDGERCLIENT_H


#include <google/protobuf/service.h>
#include <iostream>
#include <grpcpp/grpcpp.h>
#include "luciditee/ledgerentry.grpc.pb.h"

using namespace std;
using namespace luciditee;
using namespace google::protobuf;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;


class LedgerClient {
public:
    LedgerClient(std::shared_ptr<Channel> channel)
            : stub_(LedgerService::NewStub(channel)) {}
    LedgerEntryResponse entry(LedgerEntry& entry);
    LedgerQueryResponse query(LedgerQueryRequest& queryRequest);
    BlockchainInfoResponse info(BlockchainInfoRequest& blockchainInfoRequest);
private:
    std::unique_ptr<LedgerService::Stub> stub_;
};


#endif //LEDGER_NATIVE_CLIENT_LEDGERCLIENT_H
