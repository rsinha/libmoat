#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"

#include "sgx_dh.h"
#include "sgx_trts.h"

#include "computation.pb-c.h"
#include "attempt.pb-c.h"
#include "secret.pb-c.h"

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

uint64_t f_init()
{
    int64_t sherlock_fd = _moat_fs_open("sherlock_input", 0, NULL);
    int64_t irene_fd = _moat_fs_open("irene_input", 0, NULL);
    int64_t state_fd = _moat_fs_open("pwdchkr_state", 0, NULL);
    int64_t output_fd = _moat_fs_open("pwdchkr_output", 0, NULL);

    size_t irene_buf_len = (size_t) _moat_fs_file_size(irene_fd);
    uint8_t *irene_buf = (uint8_t *) malloc(irene_buf_len);
    int64_t api_result = _moat_fs_read(irene_fd, irene_buf, irene_buf_len);
    assert(api_result == irene_buf_len);
    
    LuciditeeGuessApp__Secret *secret;
    secret = luciditee_guess_app__secret__unpack(NULL, irene_buf_len, irene_buf);
    assert(secret != NULL);
    _moat_print_debug("parsing proto from enclave...got secret value %" 
        PRIu64 ", with max guesses %" PRIu64 "\n", secret->password, secret->guesses);

    api_result = _moat_fs_write(state_fd, irene_buf, irene_buf_len);
    assert(api_result == irene_buf_len);
    api_result = _moat_fs_save(state_fd);
    assert(api_result == 0);

    const char *output = "initialized";
    api_result = _moat_fs_write(output_fd, (void *) output, strlen(output) + 1);
    assert(api_result == strlen(output) + 1);
    api_result = _moat_fs_save(output_fd);
    assert(api_result == 0);

    return 0;
}

uint64_t f_next()
{
    int64_t sherlock_fd = _moat_fs_open("sherlock_input", 0, NULL);
    int64_t irene_fd = _moat_fs_open("irene_input", 0, NULL);
    int64_t state_fd = _moat_fs_open("pwdchkr_state", 0, NULL);
    int64_t output_fd = _moat_fs_open("pwdchkr_output", 0, NULL);

    size_t state_buf_len = (size_t) _moat_fs_file_size(state_fd);
    size_t sherlock_buf_len = (size_t) _moat_fs_file_size(sherlock_fd);

    uint8_t *state_buf = (uint8_t *) malloc(state_buf_len); assert(state_buf != NULL);
    uint8_t *sherlock_buf = (uint8_t *) malloc(sherlock_buf_len); assert(sherlock_buf != NULL);

    int64_t api_result = _moat_fs_read(state_fd, state_buf, state_buf_len);
    assert(api_result == state_buf_len);
    api_result = _moat_fs_read(sherlock_fd, sherlock_buf, sherlock_buf_len);
    assert(api_result == sherlock_buf_len);
    
    LuciditeeGuessApp__Secret *state;
    state = luciditee_guess_app__secret__unpack(NULL, state_buf_len, state_buf);
    assert(state != NULL);
    _moat_print_debug("parsing state within enclave...got secret password %" 
        PRIu64 ", with remaining guesses %" PRIu64 "\n", state->password, state->guesses);

    LuciditeeGuessApp__Attempt *attempt;
    attempt = luciditee_guess_app__attempt__unpack(NULL, sherlock_buf_len, sherlock_buf);
    assert(attempt != NULL);
    _moat_print_debug("parsing Sherlock's input from enclave...got guess value %" PRIu64 "\n", attempt->guess);

    assert (state->guesses > 0); //should have been caught in policy checking phase

    char *output;
    if (attempt->guess == state->password) {
        output = "success"; //write success message
        state->guesses = 0; //set guesses to 0 to terminate the game
    } else {
        output = "failure"; //write failure message
        state->guesses = state->guesses - 1; //decrement guesses by 1
    }

    _moat_print_debug("enclave result: %s\n", output);
    _moat_print_debug("updated state->guesses = %" PRIu64 "\n", state->guesses);

    //serialize state to state_buf
    assert(state_buf_len == luciditee_guess_app__secret__get_packed_size(state));
    assert (luciditee_guess_app__secret__pack(state, state_buf) == state_buf_len);
    //write to fd
    api_result = _moat_fs_write(state_fd, state_buf, state_buf_len);
    assert(api_result == state_buf_len);
    api_result = _moat_fs_save(state_fd);
    assert(api_result == 0);

    api_result = _moat_fs_write(output_fd, output, strlen(output) + 1);
    assert(api_result == strlen(output) + 1);
    api_result = _moat_fs_save(output_fd);
    assert(api_result == 0);

    luciditee_guess_app__secret__free_unpacked(state, NULL);
    luciditee_guess_app__attempt__free_unpacked(attempt, NULL);

    return 0;
}

uint64_t f(bool init)
{
    return init ? f_init() : f_next();
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
}