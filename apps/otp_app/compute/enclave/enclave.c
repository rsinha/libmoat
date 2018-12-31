#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"

#include "sgx_dh.h"
#include "sgx_trts.h"

#include "content.pb-c.h"

bool phi(bool init) {
    return init;
}

uint64_t f(bool init)
{
    if (!init) { return -1; } //should not happen because of phi

    int64_t irene_fd = _moat_fs_open("irene_input", 0, NULL); 
    assert(irene_fd != -1);
    size_t irene_buf_len = (size_t) _moat_fs_file_size(irene_fd); 
    assert(irene_buf_len != -1);
    uint8_t *irene_buf = (uint8_t *) malloc(irene_buf_len); 
    assert(irene_buf != NULL);

    int64_t api_result = _moat_fs_read(irene_fd, irene_buf, irene_buf_len);
    assert(api_result == irene_buf_len);
    
    LuciditeeOtpApp__Content *content;
    content = luciditee_otp_app__content__unpack(NULL, irene_buf_len, irene_buf);
    assert(content != NULL);
    _moat_print_debug("parsing content...got value %" PRIu64 "\n", content->value);

    luciditee_otp_app__content__free_unpacked(content, NULL);

    return 0;
}