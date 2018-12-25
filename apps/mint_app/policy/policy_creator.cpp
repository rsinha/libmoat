#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <unistd.h>
#include <string>
#include <fstream>
#include <iostream>

#include "ledgerentry.pb.h"
#include "specification.pb.h"
#include "Ledger.pb.h"

#define LEDGER "/tmp/luciditee.ledger"

using namespace std;

int main(int argc, char *argv[])
{
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  luciditee::LedgerEntry ledger_entry;
  ledger_entry.set_type(luciditee::LedgerEntry_EntryType_CREATE);
  luciditee::Specification *spec = ledger_entry.mutable_spec();

  spec->set_id(43);
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

}

