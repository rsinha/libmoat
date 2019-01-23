#include <google/protobuf/service.h>
#include <iostream>
#include <grpcpp/grpcpp.h>
#include "luciditee/ledgerentry.grpc.pb.h"
#include "LedgerClient.h"

using namespace std;
using namespace luciditee;
using namespace google::protobuf;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;


int main(int argc, char *argv[])
{

    LedgerClient client(grpc::CreateChannel(
            "localhost:8080", grpc::InsecureChannelCredentials()));

    // Create Policy
    luciditee::LedgerEntry ledger_entry;
    ledger_entry.set_type(luciditee::LedgerEntry_EntryType_CREATE);
    luciditee::Specification *spec = ledger_entry.mutable_spec();

    spec->set_id(39);
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
    request.set_entryid(39);
    request.set_type(LedgerEntry_EntryType::LedgerEntry_EntryType_CREATE);

    LedgerQueryResponse response = client.query(request);
    response.PrintDebugString();

    // Blockchain Info
    BlockchainInfoRequest blockchainInfoRequest;
    blockchainInfoRequest.set_chaincode("luciditee");

    BlockchainInfoResponse resp = client.info(blockchainInfoRequest);
    resp.PrintDebugString();


}

