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

    LedgerQueryResponse query(LedgerQueryRequest& queryRequest) {
        ClientContext context;

        LedgerQueryResponse response;

        Status status = stub_->query(&context, queryRequest, &response);

        if(status.ok()) {
            return response;
        } else {
            cout << status.error_code() << ": " << status.error_message();
        }
    }

    BlockchainInfoResponse info(BlockchainInfoRequest& blockchainInfoRequest) {
        ClientContext context;
        BlockchainInfoResponse response;
        Status status = stub_->info(&context, blockchainInfoRequest, &response);
        if(status.ok()) {
            return response;
        } else {
            cout << status.error_code() << ":" << status.error_message();
        }
    }

    LedgerEntryResponse entry(LedgerEntry& entry) {
        ClientContext context;
        LedgerEntryResponse response;
        Status status = stub_->entry(&context, entry, &response);
        if(status.ok()) {
            return response;
        } else {
            cout << status.error_code() << ":" << status.error_message();
        }
    }

private:
    std::unique_ptr<LedgerService::Stub> stub_;
};

//luciditee::LedgerEntry& create_policy(::google::protobuf::uint64 value) {
//
//    return ledger_entry;
//}

int main(int argc, char *argv[])
{

    LedgerClient client(grpc::CreateChannel(
            "localhost:8080", grpc::InsecureChannelCredentials()));

    // Create Policy
    luciditee::LedgerEntry ledger_entry;
    ledger_entry.set_type(luciditee::LedgerEntry_EntryType_CREATE);
    luciditee::Specification *spec = ledger_entry.mutable_spec();

    spec->set_id(38);
    luciditee::Specification_InputDescription *mint_input = spec->add_inputs();
    mint_input->set_input_name("mint_input");
    mint_input->set_type(luciditee::Specification_Type_KVS);
    luciditee::Specification_InputDescription *bank_input = spec->add_inputs();
    bank_input->set_input_name("bank_input");
    bank_input->set_type(luciditee::Specification_Type_FILE);
    luciditee::Specification_OutputDescription *fin_output = spec->add_outputs();
    fin_output->set_output_name("fin_output");
    fin_output->set_type(luciditee::Specification_Type_FILE);
    luciditee::Specification_StateDescription *fin_state = spec->add_statevars();
    fin_state->set_state_name("fin_state");
    fin_state->set_type(luciditee::Specification_Type_FILE);

    LedgerEntryResponse entryResponse = client.entry(ledger_entry);
    entryResponse.PrintDebugString();

    // Query
    LedgerQueryRequest request;
    request.set_entryid(38);
    request.set_type(LedgerEntry_EntryType::LedgerEntry_EntryType_CREATE);

    LedgerQueryResponse response = client.query(request);
    response.PrintDebugString();

    // Blockchain Info
    BlockchainInfoRequest blockchainInfoRequest;
    blockchainInfoRequest.set_chaincode("luciditee");

    BlockchainInfoResponse resp = client.info(blockchainInfoRequest);
    resp.PrintDebugString();


}

