#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"

#include "sgx_dh.h"
#include "sgx_trts.h"

#include "statement.pb-c.h"

bool phi(bool init) {
    if (init) { return true; }
    /*
    //TODO: scaffolding will take care of this later
    sgx_aes_gcm_128bit_key_t encr_key;
    memset(&encr_key, 0, sizeof(encr_key));

    int64_t state_fd = _moat_fs_open("fin_state", O_RDWR, &encr_key);
    size_t state_buf_len = (size_t) _moat_fs_file_size(state_fd);

    uint8_t *state_buf = (uint8_t *) malloc(state_buf_len); 
    assert(state_buf != NULL);

    int64_t api_result = _moat_fs_read(state_fd, state_buf, state_buf_len);
    assert(api_result == state_buf_len);
    
    LuciditeeGuessApp__Secret *state;
    state = luciditee_guess_app__secret__unpack(NULL, state_buf_len, state_buf);
    assert(state != NULL);
    _moat_print_debug("parsing state within enclave...got secret password %" 
        PRIu64 ", with remaining guesses %" PRIu64 "\n", state->password, state->guesses);

    if (state->guesses == 0) { return false; }
    */
    return true;
}

uint64_t f_init()
{
    int64_t bank_fd = _moat_fs_open("bank_input", 0, NULL); assert(bank_fd != -1);
    int64_t mint_fd = _moat_kvs_open("mint_input", 0, NULL); assert(mint_fd != -1);
    int64_t state_fd = _moat_fs_open("fin_state", 0, NULL); assert(state_fd != -1);
    int64_t output_fd = _moat_fs_open("fin_output", 0, NULL); assert(output_fd != -1);

    uint64_t timestamp = 0;
    int64_t api_result = _moat_fs_write(state_fd, &timestamp, sizeof(timestamp));
    assert(api_result == sizeof(timestamp));
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
    int64_t bank_fd = _moat_fs_open("bank_input", 0, NULL); assert(bank_fd != -1);
    int64_t mint_fd = _moat_kvs_open("mint_input", 0, NULL); assert(mint_fd != -1);
    int64_t state_fd = _moat_fs_open("fin_state", 0, NULL); assert(state_fd != -1);
    int64_t output_fd = _moat_fs_open("fin_output", 0, NULL); assert(output_fd != -1);

    size_t state_buf_len = (size_t) _moat_fs_file_size(state_fd);
    size_t bank_buf_len = (size_t) _moat_fs_file_size(bank_fd);

    uint8_t *state_buf = (uint8_t *) malloc(state_buf_len); assert(state_buf != NULL);
    uint8_t *bank_buf = (uint8_t *) malloc(bank_buf_len); assert(bank_buf != NULL);

    int64_t api_result = _moat_fs_read(bank_fd, bank_buf, bank_buf_len);
    assert(api_result == bank_buf_len);
    api_result = _moat_fs_read(state_fd, state_buf, state_buf_len);
    assert(api_result == state_buf_len);

    LuciditeeMintApp__Statement *stmt;
    stmt = luciditee_mint_app__statement__unpack(NULL, bank_buf_len, bank_buf);
    assert(stmt != NULL);
    _moat_print_debug("enclave: parsing proto...got %" PRIu64 " transactions\n", stmt->n_txs);

    uint64_t output[2];
    for (int i = 0; i < 2; i++) { output[i] = 0; }

    for (size_t i = 0; i < stmt->n_txs; i++) {
        LuciditeeMintApp__Statement__Transaction *tx = stmt->txs[i];
        uint64_t gmr = tx->gmr;
        uint64_t amt = tx->amount;
        uint64_t cat;
        int64_t api_result = _moat_kvs_get(mint_fd, &gmr, sizeof(gmr), 0, &cat, sizeof(cat));
        assert(api_result == sizeof(cat));
        output[cat] += amt;
    }

    _moat_print_debug("enclave result: %s\n", output);
    _moat_print_debug("enclave result: [1] = %" PRIu64 ", [2] = %" PRIu64 "\n", output[0], output[1]);

    //write to fd
    api_result = _moat_fs_write(output_fd, &output, sizeof(output));
    assert(api_result == sizeof(output));
    api_result = _moat_fs_save(output_fd);
    assert(api_result == 0);

    luciditee_mint_app__statement__free_unpacked(stmt, NULL);

    return 0;
}

uint64_t f(bool init)
{
    return init ? f_init() : f_next();
}