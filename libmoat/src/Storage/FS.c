#include <stddef.h>
#include <sys/types.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "../../api/libmoat.h"
#include "../../api/libbarbican.h"
#include "../Utils/api/Utils.h"
#include "BlockStorage/api/BlockStorage.h"
#include "ChunkyStorage/api/ChunkyStorage.h"

//this module implements journaling: mapping files to blocks

/***************************************************
 DEFINITIONS FOR INTERNAL USE
 ***************************************************/

/* don't see why an enclave would access more than 16 files */
#define MAX_FILE_COUNT 16

/* for now, we will let FS be at most 1 MB */
//#define MAX_BLOCKS 256

#define MAX_FILE_NAME_LEN 64
#define MAX_FILE_LEN UINT32_MAX

#define o_rdonly(oflag) ((O_RDONLY & oflag) != 0)
#define o_wronly(oflag) ((O_WRONLY & oflag) != 0)
#define o_rdwr(oflag) ((O_RDWR & oflag) != 0)
#define o_creat(oflag) ((O_CREAT & (oflag)) != 0)
#define o_tmpfile(oflag) ((O_TMPFILE & (oflag)) != 0)

typedef struct
{
    int64_t   addr; //which block holds the data?
    int64_t   len;  //how many bytes are in this block? max B i.e. 4096 bytes
} fs_block_t;

typedef struct
{
    cipher_ctx_t cipher_ctx;
    char         file_name[MAX_FILE_NAME_LEN]; //use a constant string here
    int64_t      file_descriptor; //integer file id
    int64_t      offset; //current offset in the file
    int64_t      length; //number of bytes written to this file
    int64_t      num_blocks; //number of blocks in this file
    int64_t      oflag;
    ll_t         *blocks;   //head of the linked list of blocks for this file
} fs_file_t;

/***************************************************
 INTERNAL STATE
 ***************************************************/

static ll_t *g_files; //list of fs_file_t

/***************************************************
 PRIVATE METHODS
 ***************************************************/

/* -1 on error, >= 0 on success */
int64_t generate_unique_file_descriptor()
{   
    bool occupied[MAX_FILE_COUNT];
    for (int64_t i = 0; i < MAX_FILE_COUNT; i++)
    {
        occupied[i] = false;
    }
    
    ll_iterator_t *iter = list_create_iterator(g_files);
    while (list_has_next(iter))
    {
        fs_file_t *current_file = (fs_file_t *) list_get_next(iter);
        //file descriptors start at 1
        occupied[current_file->file_descriptor] = true;
    }
    list_destroy_iterator(iter);
    
    for (int64_t i = 0; i < MAX_FILE_COUNT; i++) {
        if (occupied[i] == false) {
            return i;
        }
    }
    
    return -1;
}

/* -1 on error, >= 0 on success */
/*
int64_t generate_unique_block_id()
{    
    bool occupied[MAX_BLOCKS];
    for (int64_t i = 0; i < MAX_BLOCKS; i++)
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
            occupied[current_block->addr] = true;
        }

        list_destroy_iterator(block_iter);
    }
    list_destroy_iterator(file_iter);
    
    for (int64_t i = 0; i < MAX_BLOCKS; i++) {
        if (occupied[i] == false) {
            return i;
        }
    }
    
    return -1;
}
*/

fs_file_t *find_file_by_descriptor(int64_t file_descriptor)
{
    ll_iterator_t *iter = list_create_iterator(g_files);
    fs_file_t *current_file = NULL;
    while (list_has_next(iter)) //search for the file descriptor within g_files
    {
        current_file = (fs_file_t *) list_get_next(iter);
        if (current_file->file_descriptor == file_descriptor)
        {
            list_destroy_iterator(iter);
            return current_file;
        }
    }
    list_destroy_iterator(iter);

    return NULL; //didn't find anything
}

fs_file_t *find_file_by_name(char *name)
{
    ll_iterator_t *iter = list_create_iterator(g_files);
    fs_file_t *current_file = NULL;
    while (list_has_next(iter)) //search for the file descriptor within g_files
    {
        current_file = (fs_file_t *) list_get_next(iter);
        if (strcmp(name, current_file->file_name) == 0) {
            list_destroy_iterator(iter);
            return current_file;
        }
    }
    list_destroy_iterator(iter);
    
    return NULL; //didn't find anything
}

bool is_file_temporary(fs_file_t *file_md)
{
    return o_tmpfile(file_md->oflag);
}


/***************************************************
 PUBLIC API IMPLEMENTATION
 ***************************************************/

void _moat_fs_module_init()
{
    g_files = list_create();
    block_storage_module_init();
}

/*
 oflag is one or more of O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_LOAD
 */
int64_t _moat_fs_open(char *name, int64_t oflag, sgx_aes_gcm_128bit_key_t *key)
{
    fs_file_t *file_md = find_file_by_name(name);
    assert(key != NULL);

    if (file_md == NULL) //else file already exists by that name
    {
        if (strlen(name) >= MAX_FILE_NAME_LEN) { return -1; }
        int64_t fd = generate_unique_file_descriptor();
        if (fd == -1) { return -1; } //we didn't get an available fd
        //check that only one of O_RDONLY, O_WRONLY, O_RDWR are set
        if (o_rdonly(oflag)) { if (o_wronly(oflag) || o_rdwr(oflag)) { return -1; } }
        if (o_wronly(oflag)) { if (o_rdonly(oflag) || o_rdwr(oflag)) { return -1; } }
        if (o_rdwr(oflag)) { if (o_rdonly(oflag) || o_wronly(oflag)) { return -1; } }

        size_t retstatus;
        sgx_status_t status;
        if (o_creat(oflag)) {
            status = fs_create_ocall(&retstatus, fd, name);
        } else {
            //ask host to load db with specified name if it knows about it, and bind it to fd
            status = fs_load_ocall(&retstatus, fd, name);
        }
        assert(status == SGX_SUCCESS && retstatus == 0);

        file_md = (fs_file_t *) malloc(sizeof(fs_file_t)); assert(file_md != NULL);

        strcpy(file_md->file_name, name);
        file_md->file_descriptor = fd;
        file_md->offset = 0;
        file_md->length = 0;
        file_md->num_blocks = 0;
        file_md->oflag = oflag;
        file_md->cipher_ctx.counter = 0;
        memcpy((uint8_t *) &(file_md->cipher_ctx.key), key, sizeof(sgx_aes_gcm_128bit_key_t));
        file_md->blocks = list_create();

        list_insert_value(g_files, file_md);
    }

    return file_md->file_descriptor;
}

/*
reposition the current offset
base refers to the position from which the bytes will be offset, and it is either 
SEEK_SET (beginning of file) or SEEK_CUR (current value of offset) or SEEK_END (end of file)
offset refers to the number of bytes to be offset with respect to base
e.g. _moat_fs_lseek(fd, 4, SEEK_CUR) skips 4 bytes, and _moat_fs_lseek(fd, 0, SEEK_SET) sets to the start of the file
returns -1 on error, else the resulting offset location as measured in bytes from the beginning of the file
 */
int64_t _moat_fs_lseek(int64_t fd, int64_t offset, int base)
{
    fs_file_t *file_md = find_file_by_descriptor(fd);
    if (file_md == NULL) { return -1; } //this needs an error code

    int64_t old_offset = file_md->offset;

    switch (base) {
        case SEEK_SET:
            file_md->offset = offset;
            break;
        case SEEK_CUR:
            file_md->offset = file_md->offset + offset;
            break;
        case SEEK_END:
            file_md->offset = file_md->length + offset;
            break;
    }

    /* maintain invariant that offset is between 0 and length */
    if (file_md->offset < 0 || file_md->offset > file_md->length) { 
        file_md->offset = old_offset;
        return -1; 
    }

    return file_md->offset;
}

/* returns the current value of the position indicator of file
   To get the size of a file f:
     _moat_fs_lseek(f, 0, SEEK_END); // seek to end of file
     size = _moat_fs_tell(f); // get current file pointer
     _moat_fs_lseek(f, 0, SEEK_SET); // seek back to beginning of file
 */
int64_t _moat_fs_tell(int64_t fd)
{
    fs_file_t *file_md = find_file_by_descriptor(fd);
    if (file_md == NULL) { return -1; } //this needs an error code

    return file_md->offset;
}

/* read len bytes from the file into buf, starting from the current offset
   returns the number of bytes that the api was able to read before SEEK_END
 */
int64_t _moat_fs_read(int64_t fd, void* buf, int64_t len)
{    
    fs_file_t *file_md = find_file_by_descriptor(fd);
    if (file_md == NULL) { return -1; } //this needs an error code

    //error-checking
    if (len < 0 || len > MAX_FILE_LEN) { return -1; } //bad len argument
    if (! (o_rdonly(file_md->oflag) || o_rdwr(file_md->oflag))) { return -1; }

    //we need to iterate through all blocks that hold the requested data
    int64_t offset_reached = 0, len_completed = 0;
    block_data_t block_data; //stack allocated buffer populated by the storage api
    
    ll_iterator_t *iter = list_create_iterator(file_md->blocks);
    while (list_has_next(iter))
    {
        fs_block_t *block = (fs_block_t *) list_get_next(iter);

        //invariant maintained by _moat_fs_write
        assert(block->len <= BLOCK_SIZE);
        //only last block is allowed to be less than BLOCK_SIZE: block->len != BLOCK_SIZE ==> !list_has_next(iter)
        assert(block->len == BLOCK_SIZE || !list_has_next(iter));

        //should we grab some bytes from this block?
        if ((offset_reached + block->len - 1) >= file_md->offset)
        {
            //once we find the first block, we can read from offset 0 in the second block, and so on.
            size_t offset_within_block = (offset_reached < file_md->offset) ? file_md->offset - offset_reached : 0;
            //we either copy enough bytes to fulfill len, or enough available bytes after the offset_within_block
            size_t num_bytes_to_copy = min(len - len_completed, block->len - offset_within_block);
            
            size_t status = block_storage_read(file_md->file_descriptor,
                &(file_md->cipher_ctx), block->addr, block_data);
            assert(status == 0);
            
            memcpy(((uint8_t *) buf) + len_completed, ((uint8_t *) block_data) + offset_within_block, num_bytes_to_copy);
            len_completed += num_bytes_to_copy;
        }
        
        offset_reached += block->len;
        
        if (len_completed == len) { break; }
    }
    list_destroy_iterator(iter);
    
    return len_completed;
}

/* write len bytes from buf into the file, starting from the current offset
   should return len, or -1 during exceptions
 */
int64_t _moat_fs_write(int64_t fd, void* buf, int64_t len)
{
    size_t status;
    
    fs_file_t *file_md = find_file_by_descriptor(fd);
    if (file_md == NULL) { return -1; } //this needs an error code

    //error-checking
    if (len < 0 || len > MAX_FILE_LEN) { return -1; } //bad len argument
    if ((MAX_FILE_LEN - file_md->offset) < len) { return -1; } //writing len bytes will exceed max len
    if (! (o_wronly(file_md->oflag) || o_rdwr(file_md->oflag))) { return -1; }

    //we need to iterate through all blocks that hold the requested data
    int64_t offset_reached = 0, len_completed = 0;
    block_data_t block_data; //stack allocated buffer populated by the storage api
    
    ll_iterator_t *iter = list_create_iterator(file_md->blocks);
    while (list_has_next(iter))
    {
        fs_block_t *block = (fs_block_t *) list_get_next(iter);
        //invariant maintained by _moat_fs_write
        assert(block->len <= BLOCK_SIZE);
        //only last block is allowed to be less than BLOCK_SIZE: block->len != BLOCK_SIZE ==> !list_has_next(iter)
        assert(block->len == BLOCK_SIZE || !list_has_next(iter));
        
        //should we grab some bytes from this block?
        if ((offset_reached + BLOCK_SIZE - 1) >= file_md->offset)
        {
            //once we find the first block, we can read from offset 0 in the second block, and so on.
            size_t offset_within_block = (offset_reached < file_md->offset) ? file_md->offset - offset_reached : 0;
            //we either copy enough bytes to fulfill len, or enough available bytes after the offset_within_block
            size_t num_bytes_to_copy = min(len - len_completed, BLOCK_SIZE - offset_within_block);
            
            //if we are going to overwrite the entire block, then no point reading
            //read either if block has bytes after or before the written region
            if (num_bytes_to_copy < block->len || offset_within_block > 0)
            {
                status = block_storage_read(file_md->file_descriptor,
                    &(file_md->cipher_ctx), block->addr, block_data); //read old data
                assert(status == 0);
            }
            
            //overwrite parts of old data with new data
            memcpy(((uint8_t *) block_data) + offset_within_block, ((uint8_t *) buf) + len_completed, num_bytes_to_copy);
            
            //write the entire block back to untrusted storage
            status = block_storage_write(file_md->file_descriptor,
                &(file_md->cipher_ctx), block->addr, block_data);
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

        //int64_t blk_uniq_id = generate_unique_block_id();
        //if (blk_uniq_id == -1) { break; } //ran out of space...no more blocks

        fs_block_t *block = (fs_block_t *) malloc(sizeof(fs_block_t));
        assert(block != NULL);

        block->addr = file_md->num_blocks;
        block->len = num_bytes_to_copy;
        list_insert_value(file_md->blocks, block);

        file_md->num_blocks += 1;

        memcpy(((uint8_t *) block_data), ((uint8_t *) buf) + len_completed, num_bytes_to_copy);
        
        //write the entire block back to untrusted storage
        size_t status = block_storage_write(file_md->file_descriptor, 
            &(file_md->cipher_ctx), block->addr, block_data);
        assert(status == 0);

        len_completed += block->len; //which is also num_bytes_to_copy
    }
    
    file_md->length = max(file_md->length, file_md->offset + len_completed);
    return len_completed;
}

//TODO: only delete the file contents if the file is tmp
int64_t _moat_fs_close(int64_t fd)
{
    size_t retstatus;
    sgx_status_t status;

    fs_file_t *file_md = find_file_by_descriptor(fd);
    if (file_md == NULL) { return -1; } //this needs an error code

    ll_iterator_t *block_iter = list_create_iterator(file_md->blocks);
    while (list_has_next(block_iter))
    {
        fs_block_t *current_block = (fs_block_t *) list_get_next(block_iter);

        //delete blocks on disk since file was tmp
        if (is_file_temporary(file_md)) {
            status = fs_delete_block_ocall(&retstatus, fd, current_block->addr);
            assert(status == SGX_SUCCESS);
        }

        bool deleted_successfully = list_delete_value(file_md->blocks, current_block);
        assert(deleted_successfully);
        free(current_block);
    }
    list_destroy_iterator(block_iter);

    status = fs_destroy_ocall(&retstatus, fd, file_md->file_name);
    assert(status == SGX_SUCCESS && retstatus == 0);

    free(file_md->blocks);
    bool deleted_successfully = list_delete_value(g_files, file_md);
    assert(deleted_successfully);
    free(file_md);
    return 0;
}

