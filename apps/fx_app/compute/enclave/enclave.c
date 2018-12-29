#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"

#include "sgx_dh.h"
#include "sgx_trts.h"

#include "secret.pb-c.h"

bool phi(bool init) {
    return true;
}

uint64_t f(bool init)
{
    int64_t sherlock_fd = _moat_fs_open("sherlock_input", 0, NULL); assert(sherlock_fd != -1);
    int64_t irene_fd = _moat_fs_open("irene_input", 0, NULL); assert(irene_fd != -1);
    int64_t sherlock_output_fd = _moat_fs_open("sherlock_output", 0, NULL); assert(sherlock_output_fd != -1);
    int64_t irene_output_fd = _moat_fs_open("irene_output", 0, NULL); assert(irene_output_fd != -1);

    size_t irene_buf_len = (size_t) _moat_fs_file_size(irene_fd);
    size_t sherlock_buf_len = (size_t) _moat_fs_file_size(sherlock_fd);

    uint8_t *irene_buf = (uint8_t *) malloc(irene_buf_len); assert(irene_buf != NULL);
    uint8_t *sherlock_buf = (uint8_t *) malloc(sherlock_buf_len); assert(sherlock_buf != NULL);

    int64_t api_result = _moat_fs_read(irene_fd, irene_buf, irene_buf_len);
    assert(api_result == irene_buf_len);
    api_result = _moat_fs_read(sherlock_fd, sherlock_buf, sherlock_buf_len);
    assert(api_result == sherlock_buf_len);
    
    LuciditeeFxApp__Secret *irene_secret;
    irene_secret = luciditee_fx_app__secret__unpack(NULL, irene_buf_len, irene_buf);
    assert(irene_secret != NULL);
    _moat_print_debug("parsing irene's secret...got value %" PRIu64 "\n", irene_secret->value);

    LuciditeeFxApp__Secret *sherlock_secret;
    sherlock_secret = luciditee_fx_app__secret__unpack(NULL, sherlock_buf_len, sherlock_buf);
    assert(sherlock_secret != NULL);
    _moat_print_debug("parsing sherlock's secret...got value %" PRIu64 "\n", sherlock_secret->value);

    api_result = _moat_fs_write(sherlock_output_fd, irene_buf, irene_buf_len);
    assert(api_result == irene_buf_len);
    api_result = _moat_fs_write(irene_output_fd, sherlock_buf, sherlock_buf_len);
    assert(api_result == sherlock_buf_len);

    api_result = _moat_fs_save(sherlock_output_fd);
    assert(api_result == 0);
    api_result = _moat_fs_save(irene_output_fd);
    assert(api_result == 0);

    luciditee_fx_app__secret__free_unpacked(sherlock_secret, NULL);
    luciditee_fx_app__secret__free_unpacked(irene_secret, NULL);

    return 0;
}