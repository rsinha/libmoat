#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <unistd.h>
#include <string>
#include <fstream>
#include <iostream>

#include "computation.pb.h"

using namespace std;

int main(int argc, char *argv[])
{
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  luciditee_guess_app::Computation spec;
  spec.set_id(42);
  luciditee_guess_app::Computation_InputDescription *irene_input = spec.add_inputs();
  irene_input->set_input_name("irene_input");
  luciditee_guess_app::Computation_InputDescription *sherlock_input = spec.add_inputs();
  sherlock_input->set_input_name("sherlock_input");
  luciditee_guess_app::Computation_OutputDescription *pwdchkr_output = spec.add_outputs();
  pwdchkr_output->set_output_name("pwdchkr_output");
  luciditee_guess_app::Computation_StateDescription *state = spec.add_statevars();
  state->set_state_name("pwdchkr_state");

  // Write the new address book back to disk.
  fstream output("pwdchkr.spec", ios::out | ios::trunc | ios::binary);
  if (!spec.SerializeToOstream(&output)) {
    cerr << "Failed to write policy." << endl;
    return -1;
  }
}

