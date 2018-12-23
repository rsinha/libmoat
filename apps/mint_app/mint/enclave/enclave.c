#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"

#include "sgx_dh.h"
#include "sgx_trts.h"

static int64_t fd;

uint64_t enclave_init()
{
    _moat_debug_module_init();
    _moat_kvs_module_init();

    sgx_aes_gcm_128bit_key_t fs_encr_key;
    memset(&fs_encr_key, 0, sizeof(fs_encr_key)); //TODO: this is zeroed out now

    fd = _moat_kvs_open("mint_input", O_RDWR | O_CREAT, &fs_encr_key);
    assert(fd != -1);
    
    return 0;
}

uint64_t enclave_finish()
{
    int64_t api_result = _moat_kvs_save(fd);
    assert(api_result == 0);

    return 0;
}

uint64_t enclave_add_data(uint8_t *key_buf, size_t key_buf_size, uint8_t *val_buf, size_t val_buf_size)
{
    //open the file
    int64_t api_result = _moat_kvs_set(fd, key_buf, key_buf_size, val_buf, val_buf_size);
    assert(api_result == val_buf_size);

    return 0;
}

