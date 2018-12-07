#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"

#include "sgx_dh.h"
#include "sgx_trts.h"
#include "secret.pb-c.h"

uint64_t enclave_test(uint8_t *buf, size_t size)
{
    _moat_debug_module_init();
    _moat_fs_module_init();

    _moat_print_debug("enclave: buf: %p, size: %zu\n", buf, size);

    LuciditeeGuessApp__Secret *secret;
    secret = luciditee_guess_app__secret__unpack(NULL, size, buf);
    assert(secret != NULL);

    _moat_print_debug("parsing proto from enclave...got secret value %" 
        PRIu64 ", with max guesses %" PRIu64 "\n", secret->password, secret->guesses);

    luciditee_guess_app__secret__free_unpacked(secret, NULL);

    //first copy the proto buffer internally
    uint8_t *internal_buf = (uint8_t *) malloc(size);
    _moat_print_debug("malloc \n");
    assert(internal_buf != NULL);
    memcpy(internal_buf, buf, size);

    //create a file out of this protobuf message
    //first create the key
    sgx_aes_gcm_128bit_key_t fs_encr_key;
    memset(&fs_encr_key, 0, sizeof(fs_encr_key)); //TODO: this is zeroed out now

    //open the file
    int64_t fd = _moat_fs_open("irene_input", O_WRONLY | O_CREAT, &fs_encr_key);
    assert(fd != -1);
    int64_t api_result = _moat_fs_write(fd, buf, size);
    assert(api_result == size);
    api_result = _moat_fs_save(fd);
    assert(api_result == 0);

    return 0;
}

