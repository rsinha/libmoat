#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"

#include "sgx_dh.h"
#include "sgx_trts.h"

int64_t fd;
uint8_t *internal_buf;
size_t internal_buf_size;

void file_write_and_seek(int64_t fd, void *buf, size_t size)
{
    int64_t api_result = _moat_fs_write(fd, buf, size);
    assert(api_result == size);
    api_result = _moat_fs_lseek(fd, (int64_t) size, SEEK_CUR);
    assert(api_result == _moat_fs_file_size(fd));
}

uint64_t enclave_init()
{
    _moat_debug_module_init();
    _moat_fs_module_init();

    sgx_aes_gcm_128bit_key_t fs_encr_key;
    memset(&fs_encr_key, 0, sizeof(fs_encr_key)); //TODO: this is zeroed out now

    fd = _moat_fs_open("hospital_input", O_RDWR | O_CREAT, &fs_encr_key);
    assert(fd != -1);

    internal_buf = NULL;
    internal_buf_size = 0;
}

uint64_t enclave_encrypt_data(void *buf, size_t size)
{
    if (size == 0) { return -1; }

    if (size > internal_buf_size) {
        if (internal_buf != NULL) { free(internal_buf); }
        internal_buf = (uint8_t *) malloc(size);
        assert(internal_buf != NULL);
	internal_buf_size = size;
    }

    memcpy(internal_buf, buf, size);

    file_write_and_seek(fd, &size, sizeof(size));
    file_write_and_seek(fd, internal_buf, size);

    return 0;
}

uint64_t enclave_finish()
{
    //save the file
    int64_t api_result = _moat_fs_save(fd);
    assert(api_result == 0);
    return 0;
}
