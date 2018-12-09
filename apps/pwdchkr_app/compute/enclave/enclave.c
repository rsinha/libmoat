#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"

#include "sgx_dh.h"
#include "sgx_trts.h"
#include "attempt.pb-c.h"
#include "secret.pb-c.h"

int64_t get_file_size(int64_t fd)
{
    int64_t result = _moat_fs_lseek(fd, 0, SEEK_END);
    assert(result != -1);
    int64_t end = _moat_fs_tell(fd);
    result = _moat_fs_lseek(fd, 0, SEEK_SET);
    assert(result != -1);
    return end;
}

uint64_t enclave_init()
{
    _moat_debug_module_init();
    _moat_fs_module_init();

    sgx_aes_gcm_128bit_key_t irene_encr_key, state_encr_key;
    memset(&irene_encr_key, 0, sizeof(irene_encr_key));
    memset(&state_encr_key, 0, sizeof(state_encr_key));

    int64_t irene_fd = _moat_fs_open("irene_input", O_RDONLY, &irene_encr_key);
    assert(irene_fd != -1);

    size_t irene_buf_len = (size_t) get_file_size(irene_fd);
    _moat_print_debug("Irene's input has size %" PRIu64 "\n", irene_buf_len);
    uint8_t *irene_buf = (uint8_t *) malloc(irene_buf_len);
    int64_t api_result = _moat_fs_read(irene_fd, irene_buf, irene_buf_len);
    assert(api_result == irene_buf_len);
    
    LuciditeeGuessApp__Secret *secret;
    secret = luciditee_guess_app__secret__unpack(NULL, irene_buf_len, irene_buf);
    assert(secret != NULL);
    _moat_print_debug("parsing proto from enclave...got secret value %" 
        PRIu64 ", with max guesses %" PRIu64 "\n", secret->password, secret->guesses);

    int64_t state_fd = _moat_fs_open("pwdchkr_state", O_RDWR | O_CREAT, &state_encr_key);
    assert(state_fd != -1);

    api_result = _moat_fs_write(state_fd, irene_buf, irene_buf_len);
    assert(api_result == irene_buf_len);

    api_result = _moat_fs_save(state_fd);
    assert(api_result == 0);

    return 0;
}

uint64_t enclave_transition()
{
    _moat_debug_module_init();
    _moat_fs_module_init();

    sgx_aes_gcm_128bit_key_t irene_encr_key, sherlock_encr_key;
    memset(&irene_encr_key, 0, sizeof(irene_encr_key));
    memset(&sherlock_encr_key, 0, sizeof(sherlock_encr_key));

    int64_t irene_fd = _moat_fs_open("irene_input", O_RDONLY, &irene_encr_key);
    assert(irene_fd != -1);
    int64_t sherlock_fd = _moat_fs_open("sherlock_input", O_RDONLY, &sherlock_encr_key);
    assert(sherlock_fd != -1);

    size_t irene_buf_len = (size_t) get_file_size(irene_fd);
    _moat_print_debug("Irene's input has size %" PRIu64 "\n", irene_buf_len);
    size_t sherlock_buf_len = (size_t) get_file_size(sherlock_fd);
    _moat_print_debug("Sherlock's input has size %" PRIu64 "\n", sherlock_buf_len);

    uint8_t *irene_buf = (uint8_t *) malloc(irene_buf_len);
    uint8_t *sherlock_buf = (uint8_t *) malloc(sherlock_buf_len);

    int64_t api_result = _moat_fs_read(irene_fd, irene_buf, irene_buf_len);
    assert(api_result == irene_buf_len);
    api_result = _moat_fs_read(sherlock_fd, sherlock_buf, sherlock_buf_len);
    assert(api_result == sherlock_buf_len);

    
    
    LuciditeeGuessApp__Secret *secret;
    secret = luciditee_guess_app__secret__unpack(NULL, irene_buf_len, irene_buf);
    assert(secret != NULL);
    _moat_print_debug("parsing proto from enclave...got secret value %" 
        PRIu64 ", with max guesses %" PRIu64 "\n", secret->password, secret->guesses);

    LuciditeeGuessApp__Attempt *attempt;
    attempt = luciditee_guess_app__attempt__unpack(NULL, sherlock_buf_len, sherlock_buf);
    assert(attempt != NULL);
    _moat_print_debug("parsing proto from enclave...got attempt value %" PRIu64 "\n", attempt->guess);



    if (attempt->guess == secret->password) {

    }

    luciditee_guess_app__secret__free_unpacked(secret, NULL);
    luciditee_guess_app__attempt__free_unpacked(attempt, NULL);


    return 0;
}

