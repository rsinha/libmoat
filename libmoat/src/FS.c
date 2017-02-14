#include <stddef.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "../api/libmoat.h"
#include "../api/libmoat_untrusted.h"
#include "utils/api/Utils.h"

//this module implements journaling: mapping files to blocks

/***************************************************
 DEFINITIONS FOR INTERNAL USE
 ***************************************************/

typedef struct
{
    size_t addr; //which block holds the data?
    size_t len;  //how many bytes are in this block? max B i.e. 4096 bytes
} fs_block_t;

typedef struct
{
    char **filename;
    fs_block_t *head_block;
} fs_file_t;

/***************************************************
 INTERNAL STATE
 ***************************************************/

static ll_t *g_files = NULL; //list of files

/***************************************************
 PRIVATE METHODS
 ***************************************************/



/***************************************************
 PUBLIC API IMPLEMENTATION
 ***************************************************/

void _moat_fs_module_init()
{
    return;
}

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

