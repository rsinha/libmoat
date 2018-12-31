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

using namespace std;

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
    luciditee::Specification_InputDescription *irene_input = spec->add_inputs();
    irene_input->set_input_name("irene_input");
    irene_input->set_type(luciditee::Specification_Type_FILE);

    std::string content;
    if (!ledger_entry.SerializeToString(&content)) {
      cerr << "Failed to write policy." << endl;
      return -1;
    }


    barbican::Ledger ledger;
    std::fstream input(LEDGER, std::ios::binary | std::ios::in);
    if (!input) {
      std::cout << LEDGER << ": File not found.  Creating a new file." << std::endl;
    } else if (!ledger.ParseFromIstream(&input)) {
      std::cerr << "Failed to parse " << LEDGER << std::endl;
      return -1;
    }

    barbican::Ledger_Block *block = ledger.add_blocks();
    block->set_content(content);
    block->set_height(ledger.blocks_size());

    // Write the new address book back to disk.
    std::fstream output(LEDGER, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!ledger.SerializeToOstream(&output)) {
      std::cerr << "Failed to write " << LEDGER<< std::endl;
      return -1;
    }

  } catch (const cxxopts::OptionException& e) {
    std::cout << "error parsing options: " << e.what() << std::endl;
    exit(1);
  }

}

