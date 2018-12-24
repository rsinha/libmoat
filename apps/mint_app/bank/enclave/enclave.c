#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"

#include "sgx_dh.h"
#include "sgx_trts.h"

uint64_t enclave_encrypt_data(void *buf, size_t size)
{
    _moat_debug_module_init();
    _moat_fs_module_init();

    sgx_aes_gcm_128bit_key_t fs_encr_key;
    memset(&fs_encr_key, 0, sizeof(fs_encr_key)); //TODO: this is zeroed out now

    int64_t fd = _moat_fs_open("bank_input", O_RDWR | O_CREAT, &fs_encr_key);
    assert(fd != -1);


    size_t internal_buf_size = size;
    //first copy the proto buffer internally
    uint8_t *internal_buf = (uint8_t *) malloc(internal_buf_size);
    assert(internal_buf != NULL);
    memcpy(internal_buf, buf, internal_buf_size);

    int64_t api_result = _moat_fs_write(fd, internal_buf, internal_buf_size);
    assert(api_result == internal_buf_size);


    //save the file
    api_result = _moat_fs_save(fd);
    assert(api_result == 0);

    return 0;
}
