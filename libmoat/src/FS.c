#include <stddef.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "../api/libmoat.h"
#include "../api/libmoat_untrusted.h"

//this module implements journaling: mapping files to blocks

fs_handle_t *_moat_fs_open(char *name)
{
    return NULL;
}

size_t _moat_fs_read(fs_handle_t *handle, size_t offset, void* buf, size_t len)
{
    return 0;
}

size_t _moat_fs_write(fs_handle_t *handle, size_t offset, void* buf, size_t len)
{
    return 0;
}

void _moat_fs_close(fs_handle_t *handle)
{
    return;
}

