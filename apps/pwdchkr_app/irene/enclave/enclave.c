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
    //uint8_t *internal_buf = (uint8_t *) malloc(size);
    //_moat_print_debug("malloc \n");
    //assert(!internal_buf);

    LuciditeeGuessApp__Secret *secret;
    secret = luciditee_guess_app__secret__unpack(NULL, size, buf);
    assert(secret != NULL);

    _moat_print_debug("parsing proto from enclave...got secret value %" 
        PRIu64 ", with max guesses %" PRIu64 "\n", secret->value, secret->guesses);

    luciditee_guess_app__secret__free_unpacked(secret, NULL);
    return 0;
}

