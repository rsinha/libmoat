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

  spec->set_id(55);
  luciditee::Specification_InputDescription *h_a_input = spec->add_inputs();
  h_a_input->set_input_name("hospital_a_input");
  h_a_input->set_type(luciditee::Specification_Type_FILE);

  luciditee::Specification_InputDescription *h_b_input = spec->add_inputs();
  h_b_input->set_input_name("hospital_b_input");
  h_b_input->set_type(luciditee::Specification_Type_FILE);

  luciditee::Specification_OutputDescription *psi_output = spec->add_outputs();
  psi_output->set_output_name("psi_output");
  psi_output->set_type(luciditee::Specification_Type_FILE);

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

