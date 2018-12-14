#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"

#include "sgx_dh.h"
#include "sgx_trts.h"

#include "computation.pb-c.h"


uint64_t f(bool); /* user-defined function */


void print_digest(const char *name, int64_t fd)
{
    sgx_sha256_hash_t hash;
    int64_t result = _moat_fs_get_digest(fd, &hash);
    if (result != 0) { return; }
    _moat_print_debug("%s digest: 0x", name); 
    for (size_t i = 0; i < sizeof(hash); i++) { 
        _moat_print_debug("%02x", ((uint8_t *) hash)[i]); 
    }
    _moat_print_debug("\n");
}

void record_computation(uint8_t *spec_buf, size_t spec_buf_len)
{   
    LuciditeeGuessApp__Computation *spec;
    spec = luciditee_guess_app__computation__unpack(NULL, spec_buf_len, spec_buf);
    assert(spec != NULL);

    //print id
    _moat_print_debug("----------------------------\n");
    _moat_print_debug("record computation:\n");
    _moat_print_debug("spec has id: %" PRIu64 "\n", spec->id);
    //print inputs
    for (size_t i = 0; i < spec->n_inputs; i++) {
        LuciditeeGuessApp__Computation__InputDescription *input = spec->inputs[i];
        int64_t fd = _moat_fs_open(input->input_name, 0, NULL);
        print_digest(input->input_name, fd);
    }
    //print outputs
    for (size_t i = 0; i < spec->n_outputs; i++) {
        LuciditeeGuessApp__Computation__OutputDescription *output = spec->outputs[i];
        //_moat_print_debug("spec has output: %s\n", output->output_name);
        int64_t fd = _moat_fs_open(output->output_name, 0, NULL);
        print_digest(output->output_name, fd);
    }
    //print state
    for (size_t i = 0; i < spec->n_statevars; i++) {
        LuciditeeGuessApp__Computation__StateDescription *statevar = spec->statevars[i];
        //_moat_print_debug("spec has state var: %s\n", statevar->state_name);
        int64_t fd = _moat_fs_open(statevar->state_name, 0, NULL);
        print_digest(statevar->state_name, fd);
    }
    _moat_print_debug("----------------------------\n");

    luciditee_guess_app__computation__free_unpacked(spec, NULL);
}

void open_files(uint8_t *spec_buf, size_t spec_buf_len, bool init)
{   
    LuciditeeGuessApp__Computation *spec;
    spec = luciditee_guess_app__computation__unpack(NULL, spec_buf_len, spec_buf);
    assert(spec != NULL);

    //open inputs
    sgx_aes_gcm_128bit_key_t encr_key;

    for (size_t i = 0; i < spec->n_inputs; i++) {
        LuciditeeGuessApp__Computation__InputDescription *input = spec->inputs[i];
        memset(&encr_key, 0, sizeof(encr_key));
        int64_t fd = _moat_fs_open(input->input_name, O_RDONLY, &encr_key);
        assert(fd != -1);
    }
    //print outputs
    for (size_t i = 0; i < spec->n_outputs; i++) {
        LuciditeeGuessApp__Computation__OutputDescription *output = spec->outputs[i];
        memset(&encr_key, 0, sizeof(encr_key));
        int64_t fd = _moat_fs_open(output->output_name, O_RDWR | O_CREAT, &encr_key);
        assert(fd != -1);
    }
    //print state
    for (size_t i = 0; i < spec->n_statevars; i++) {
        LuciditeeGuessApp__Computation__StateDescription *statevar = spec->statevars[i];
        memset(&encr_key, 0, sizeof(encr_key));
        int64_t fd = _moat_fs_open(statevar->state_name, init ? O_RDWR | O_CREAT : O_RDWR, &encr_key);
        print_digest(statevar->state_name, fd);
    }

    luciditee_guess_app__computation__free_unpacked(spec, NULL);
}

/* TODO: eventually init arg will go away in lieu of a ledger */
uint64_t invoke_enclave_computation(uint8_t *spec_buf, size_t spec_buf_len, bool init)
{
    /* initialize libmoat */
    _moat_debug_module_init();
    _moat_fs_module_init();

    /* open all the input, output, and state structures */
    open_files(spec_buf, spec_buf_len, init);

    /* use the ledger to decide whether we are creating initial state, and let f know that */
    uint64_t result = f(init);

    /* generate the on-ledger record */
    record_computation(spec_buf, spec_buf_len);

    return result;
}