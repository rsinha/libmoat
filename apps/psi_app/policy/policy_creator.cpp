#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <unistd.h>
#include <string>
#include <fstream>
#include <iostream>

#include "cxxopts.hpp"

#include "ledgerentry.pb.h"
#include "specification.pb.h"
#include "Ledger.pb.h"

#define LEDGER "/tmp/luciditee.ledger"

#include "LedgerClient.h"

using namespace std;
using namespace luciditee;

#define LEDGER_URL "localhost:8080"
#define CHAINCODE_NAME  "luciditee"

int main(int argc, char *argv[])
{
  try {
    cxxopts::Options options("fair exchange policy creation", 
                             "Fair Exchange between Irene and Sherlock");

    options
      .show_positional_help()
      .add_options()
        ("help", "Print help")
        ("s,spec", "Computation's specification", cxxopts::value<uint64_t>())
      ;

    auto result = options.parse(argc, argv);

    if (!result.count("s") || result.count("help")) {
      std::cout << options.help({"", "Group"}) << std::endl;
      exit(0);
    }

    uint64_t spec_id = result["s"].as<uint64_t>();

    GOOGLE_PROTOBUF_VERIFY_VERSION;

    luciditee::LedgerEntry ledger_entry;
    ledger_entry.set_type(luciditee::LedgerEntry_EntryType_CREATE);
    luciditee::Specification *spec = ledger_entry.mutable_spec();

    spec->set_id(spec_id);
    luciditee::Specification_InputDescription *h_a_input = spec->add_inputs();
    h_a_input->set_input_name("hospital_a_input");
    h_a_input->set_type(luciditee::Specification_Type_FILE);

    luciditee::Specification_InputDescription *h_b_input = spec->add_inputs();
    h_b_input->set_input_name("hospital_b_input");
    h_b_input->set_type(luciditee::Specification_Type_FILE);

    luciditee::Specification_OutputDescription *psi_output = spec->add_outputs();
    psi_output->set_output_name("psi_output");
    psi_output->set_type(luciditee::Specification_Type_FILE);

    LedgerClient client(grpc::CreateChannel(
            LEDGER_URL, grpc::InsecureChannelCredentials()));

    LedgerEntryResponse entryResponse = client.entry(ledger_entry);
    entryResponse.PrintDebugString();



  } catch (const cxxopts::OptionException& e) {
    std::cout << "error parsing options: " << e.what() << std::endl;
    exit(1);
  }

}
