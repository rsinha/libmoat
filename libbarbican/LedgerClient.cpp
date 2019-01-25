//
// Created by sivanarayana gaddam on 1/22/19.
//

#include "LedgerClient.h"

LedgerEntryResponse LedgerClient::entry(LedgerEntry &entry) {
    ClientContext context;
    LedgerEntryResponse response;
    Status status = stub_->entry(&context, entry, &response);
    if (status.ok()) {
        return response;
    } else {
        cout << status.error_code() << ":" << status.error_message();
    }

}


LedgerQueryResponse LedgerClient::query(LedgerQueryRequest &queryRequest) {
    ClientContext context;
    LedgerQueryResponse response;
    Status status = stub_->query(&context, queryRequest, &response);
    if (status.ok()) {
        return response;
    } else {
        cout << status.error_code() << ": " << status.error_message();
    }
}

BlockchainInfoResponse LedgerClient::info(BlockchainInfoRequest &blockchainInfoRequest) {
    ClientContext context;
    BlockchainInfoResponse response;
    Status status = stub_->info(&context, blockchainInfoRequest, &response);
    if (status.ok()) {
        return response;
    } else {
        cout << status.error_code() << ":" << status.error_message();
    }

}
