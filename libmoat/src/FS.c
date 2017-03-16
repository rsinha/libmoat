#include <stddef.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "../api/libmoat.h"
#include "../api/libmoat_untrusted.h"
#include "utils/api/Utils.h"
#include "storage/api/BlockStorage.h"

//this module implements journaling: mapping files to blocks

/***************************************************
 DEFINITIONS FOR INTERNAL USE
 ***************************************************/

#define MAX_FILE_COUNT 16

typedef struct
{
    size_t    addr; //which block holds the data?
    size_t    len;  //how many bytes are in this block? max B i.e. 4096 bytes
} fs_block_t;

typedef struct
{
    char      *filename; //use a constant string here
    size_t    file_descriptor; //integer file id
    ll_t      *blocks;   //head of the linked list of blocks for this file
} fs_file_t;

/***************************************************
 INTERNAL STATE
 ***************************************************/

static ll_t *g_files; //list of fs_file_t

/***************************************************
 PRIVATE METHODS
 ***************************************************/

size_t generate_unique_file_descriptor(size_t *result)
{
    if(!result) { return -1; }
    
    bool occupied[MAX_FILE_COUNT];
    for (int i = 0; i < MAX_FILE_COUNT; i++)
    {
        occupied[i] = false;
    }
    
    ll_iterator_t *iter = list_create_iterator(g_files);
    while (list_has_next(iter))
    {
        fs_file_t *current_file = (fs_file_t *) list_get_next(iter);
        //file descriptors start at 1
        occupied[current_file->file_descriptor - 1] = true;
    }
    list_destroy_iterator(iter);
    
    for (int i = 0; i < MAX_FILE_COUNT; i++) {
        if (occupied[i] == false) {
            *result = i + 1; //session ids start at 1
            return 0;
        }
    }
    
    return -1;
}

size_t generate_unique_block_id(size_t *result)
{
    if(!result) { return -1; }
    
    bool occupied[NUM_BLOCKS];
    for (int i = 0; i < NUM_BLOCKS; i++)
    {
        occupied[i] = false;
    }
    
    ll_iterator_t *file_iter = list_create_iterator(g_files);
    while (list_has_next(file_iter))
    {
        fs_file_t *current_file = (fs_file_t *) list_get_next(file_iter);
        ll_iterator_t *block_iter = list_create_iterator(current_file->blocks);

        while (list_has_next(block_iter))
        {
            fs_block_t *current_block = (fs_block_t *) list_get_next(block_iter);
            //file descriptors start at 1
            occupied[current_block->addr - 1] = true;
        }

        list_destroy_iterator(block_iter);
    }
    list_destroy_iterator(file_iter);
    
    for (int i = 0; i < NUM_BLOCKS; i++) {
        if (occupied[i] == false) {
            *result = i + 1; //block ids start at 1
            return 0;
        }
    }
    
    return -1;
}

fs_file_t *find_file_by_descriptor(size_t file_descriptor)
{
    ll_iterator_t *iter = list_create_iterator(g_files);
    fs_file_t *fd = NULL;
    while (list_has_next(iter)) //search for the file descriptor within g_files
    {
        fd = (fs_file_t *) list_get_next(iter);
        if (fd->file_descriptor == file_descriptor)
        {
            list_destroy_iterator(iter);
            return fd;
        }
    }
    list_destroy_iterator(iter);

    return NULL; //didn't find anything
}

fs_file_t *find_file_by_name(char *name)
{
    ll_iterator_t *iter = list_create_iterator(g_files);
    fs_file_t *fd = NULL;
    while (list_has_next(iter)) //search for the file descriptor within g_files
    {
        fd = (fs_file_t *) list_get_next(iter);
        if (strcmp(name, fd->filename) == 0) {
            list_destroy_iterator(iter);
            return fd;
        }
    }
    list_destroy_iterator(iter);
    
    return NULL; //didn't find anything
}

/***************************************************
 PUBLIC API IMPLEMENTATION
 ***************************************************/

void _moat_fs_module_init()
{
    g_files = malloc(sizeof(ll_t));
    assert(g_files != NULL);
    g_files->head = NULL;

    block_storage_module_init();
}

fs_handle_t *_moat_fs_open(char *name)
{
    fs_file_t *fd = find_file_by_name(name);
    
    if (fd == NULL) //else file already exists by that name
    {
        fd = (fs_file_t *) malloc(sizeof(fs_file_t));
        assert(fd != NULL);
        fd->blocks = malloc(sizeof(ll_t));
        assert(fd->blocks != NULL);
        fd->blocks->head = NULL;
        fd->filename = name;
        size_t success = generate_unique_file_descriptor(&(fd->file_descriptor));
        assert(success == 0);

        list_insert_value(g_files, fd);
    }
    
    //allocate memory for the context
    fs_handle_t *handle = (fs_handle_t *) malloc(sizeof(fs_handle_t));
    assert(handle != NULL);
    handle->file_descriptor = fd->file_descriptor;
    return handle;
}

size_t _moat_fs_read(fs_handle_t *handle, size_t offset, void* buf, size_t len)
{
    //error-checking
    if (offset + len < offset) { return -1; } //can't have a file larger than 2^64
    if (offset + BLOCK_SIZE < offset) { return -1; } //this will prevent overflows in the code
    
    fs_file_t *fd = find_file_by_descriptor(handle->file_descriptor);
    if (fd == NULL) { return -1; } //this needs an error code
    
    //we need to iterate through all blocks that hold the requested data
    size_t offset_reached = 0, len_completed = 0;
    block_t block_data; //stack allocated buffer populated by the storage api
    
    ll_iterator_t *iter = list_create_iterator(fd->blocks);
    while (list_has_next(iter))
    {
        fs_block_t *block = (fs_block_t *) list_get_next(iter);

        //should we grab some bytes from this block?
        if ((offset_reached + block->len - 1) >= offset)
        {
            //once we find the first block, we can read from offset 0 in the second block, and so on.
            size_t offset_within_block = (offset_reached < offset) ? offset - offset_reached : 0;
            //we either copy enough bytes to fulfill len, or enough available bytes after the offset_within_block
            size_t num_bytes_to_copy = min(len - len_completed, block->len - offset_within_block);
            
            size_t status = block_storage_access(READ, block->addr, block_data);
            assert(status == 0);
            
            memcpy(((uint8_t *) buf) + len_completed, ((uint8_t *) block_data) + offset_within_block, num_bytes_to_copy);
            len_completed += num_bytes_to_copy;
        }
        
        offset_reached += block->len;
        
        if (len_completed == len) { break; }
    }
    list_destroy_iterator(iter);
    
    return (len_completed == len) ? 0 : -1;
}

size_t _moat_fs_write(fs_handle_t *handle, size_t offset, void* buf, size_t len)
{
    size_t status;
    //error-checking
    if (offset + len < offset) { return -1; } //can't have a file larger than 2^64
    if (offset + BLOCK_SIZE < offset) { return -1; } //this will prevent overflows in the code
    
    fs_file_t *fd = find_file_by_descriptor(handle->file_descriptor);
    if (fd == NULL) { return -1; } //this needs an error code
    
    //we need to iterate through all blocks that hold the requested data
    size_t offset_reached = 0, len_completed = 0;
    block_t block_data; //stack allocated buffer populated by the storage api
    
    ll_iterator_t *iter = list_create_iterator(fd->blocks);
    while (list_has_next(iter))
    {
        fs_block_t *block = (fs_block_t *) list_get_next(iter);
        //invariant maintained by _moat_fs_write
        assert(block->len <= BLOCK_SIZE);
        //only last block is allowed to be less than BLOCK_SIZE: block->len != BLOCK_SIZE ==> !list_has_next(iter)
        assert(block->len == BLOCK_SIZE || !list_has_next(iter));
        
        //should we grab some bytes from this block?
        if ((offset_reached + BLOCK_SIZE - 1) >= offset)
        {
            //once we find the first block, we can read from offset 0 in the second block, and so on.
            size_t offset_within_block = (offset_reached < offset) ? offset - offset_reached : 0;
            //we either copy enough bytes to fulfill len, or enough available bytes after the offset_within_block
            size_t num_bytes_to_copy = min(len - len_completed, BLOCK_SIZE - offset_within_block);
            
            //if we are going to overwrite the entire block, then no point reading
            //read either if block has bytes after or before the written region
            if (num_bytes_to_copy < block->len || offset_within_block > 0)
            {
                status = block_storage_access(READ, block->addr, block_data); //read old data
                assert(status == 0);
            }
            
            //overwrite parts of old data with new data
            memcpy(((uint8_t *) block_data) + offset_within_block, ((uint8_t *) buf) + len_completed, num_bytes_to_copy);
            
            //write the entire block back to untrusted storage
            status = block_storage_access(WRITE, block->addr, block_data);
            assert(status == 0);
            
            block->len = max(block->len, num_bytes_to_copy + offset_within_block);
            len_completed += num_bytes_to_copy;
        }
        
        offset_reached += block->len;
        
        if (len_completed == len) { break; }
    }
    list_destroy_iterator(iter);

    //we ran out of existing blocks to place the new data. Let's allocate some new blocks.
    while (len_completed < len)
    {
        size_t num_bytes_to_copy = min(len - len_completed, BLOCK_SIZE);

        fs_block_t *block = (fs_block_t *) malloc(sizeof(fs_block_t));
        size_t success = generate_unique_block_id(&(block->addr));
        assert(success == 0);
        block->len = num_bytes_to_copy;
        list_insert_value(fd->blocks, block);

        memcpy(((uint8_t *) block_data), ((uint8_t *) buf) + len_completed, num_bytes_to_copy);
        
        //write the entire block back to untrusted storage
        size_t status = block_storage_access(WRITE, block->addr, block_data);
        assert(status == 0);

        len_completed += block->len;
    }
    
    return 0;
}

size_t _moat_fs_close(fs_handle_t *handle)
{
    free(handle);
    return 0;
}

size_t _moat_fs_delete(fs_handle_t *handle)
{
    fs_file_t *fd = find_file_by_descriptor(handle->file_descriptor);
    if (fd == NULL) { return -1; } //this needs an error code

    ll_iterator_t *block_iter = list_create_iterator(fd->blocks);
    while (list_has_next(block_iter))
    {
        fs_block_t *current_block = (fs_block_t *) list_get_next(block_iter);
        bool deleted_successfully = list_delete_value(fd->blocks, current_block);
        assert(deleted_successfully);
        free(current_block);
    }
    list_destroy_iterator(block_iter);

    free(fd->blocks);
    bool deleted_successfully = list_delete_value(g_files, fd);
    assert(deleted_successfully);
    free(fd);
    return 0;
}

