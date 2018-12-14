#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"

#include "sgx_dh.h"
#include "sgx_trts.h"

#include "attempt.pb-c.h"
#include "secret.pb-c.h"

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