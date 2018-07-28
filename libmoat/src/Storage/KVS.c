#include <stddef.h>
#include <sys/types.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "../../api/libmoat.h"
#include "../../api/libmoat_untrusted.h"
#include "../Utils/api/Utils.h"

/***************************************************
 DEFINITIONS FOR INTERNAL USE
 ***************************************************/

/* don't see why an enclave would access more than 16 databases */
#define MAX_KVS_COUNT 16
#define MAX_KVS_NAME_LEN 64

#define TMP_NAME_PREFIX "tmp://"
#define INPUT_NAME_PREFIX "in://"
#define OUTPUT_NAME_PREFIX "out://"
#define INOUT_NAME_PREFIX "inout://"

#define o_rdonly(oflag) ((O_RDONLY & (oflag)) != 0)
#define o_wronly(oflag) ((O_WRONLY & (oflag)) != 0)
#define o_rdwr(oflag) ((O_RDWR & (oflag)) != 0)

#define aes_gcm_ciphertext_len(x) ((x) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE)

typedef struct
{
    uint64_t counter;
    sgx_aes_gcm_128bit_key_t key;
} cipher_ctx_t;

typedef struct
{
    cipher_ctx_t cipher_ctx;
    char         db_name[MAX_KVS_NAME_LEN];
    int64_t      db_descriptor; //integer id
    int64_t      size; //number of keys inserted
    bool         read_permission;
    bool         write_permission;
} kvs_db_t;

 //we store values as a collection of ordered chunks
#define MAX_CHUNK_SIZE 1024
//1 GB max value size
#define MAX_VALUE_SIZE 1073741824

typedef struct
{
    uint64_t untrusted_len;
    uint64_t num_chunks;
    uint64_t value_version;
} chunk_header_t;

/***************************************************
 INTERNAL STATE
 ***************************************************/

static ll_t         *g_dbs;  //list of kvs_db_t

/***************************************************
 PRIVATE METHODS
 ***************************************************/

/* -1 on error, >= 0 on success */
int64_t generate_unique_db_descriptor()
{   
    bool occupied[MAX_KVS_COUNT];
    for (int64_t i = 0; i < MAX_KVS_COUNT; i++)
    {
        occupied[i] = false;
    }
    
    ll_iterator_t *iter = list_create_iterator(g_dbs);
    while (list_has_next(iter))
    {
        kvs_db_t *current_db = (kvs_db_t *) list_get_next(iter);
        occupied[current_db->db_descriptor] = true;
    }
    list_destroy_iterator(iter);
    
    for (int64_t i = 0; i < MAX_KVS_COUNT; i++) {
        if (occupied[i] == false) {
            return i;
        }
    }
    
    return -1;
}

kvs_db_t *find_db_by_descriptor(int64_t db_descriptor)
{
    ll_iterator_t *iter = list_create_iterator(g_dbs);
    while (list_has_next(iter)) //search for the file descriptor within g_files
    {
        kvs_db_t *current_db = (kvs_db_t *) list_get_next(iter);
        if (current_db->db_descriptor == db_descriptor)
        {
            list_destroy_iterator(iter);
            return current_db;
        }
    }
    list_destroy_iterator(iter);

    return NULL; //didn't find anything
}

kvs_db_t *find_db_by_name(char *name)
{
    ll_iterator_t *iter = list_create_iterator(g_dbs);
    while (list_has_next(iter)) //search for the file descriptor within g_files
    {
        kvs_db_t *current_db = (kvs_db_t *) list_get_next(iter);
        if (strcmp(name, current_db->db_name) == 0) {
            list_destroy_iterator(iter);
            return current_db;
        }
    }
    list_destroy_iterator(iter);
    
    return NULL; //didn't find anything
}

/* size of 1 chunk */
uint64_t chunk_len(uint64_t len)
{
    /* each chunk is of the form chunk_size[64] || ciphertext[chunk_size] */
    return sizeof(uint64_t) + aes_gcm_ciphertext_len(len);
}

/* size of entire payload */
uint64_t payload_len(uint64_t len)
{
    /* payload is of the form header || chunk_1 || ... || chunk_n */
    uint64_t num_chunks = div_ceil(len, MAX_CHUNK_SIZE);
    uint64_t all_but_one_len = (num_chunks - 1) * chunk_len(MAX_CHUNK_SIZE);
    uint64_t last_chunk_len = chunk_len(len - MAX_CHUNK_SIZE * (num_chunks - 1));
    return sizeof(chunk_header_t) + all_but_one_len + last_chunk_len;
}

/* NOTE: it is upto caller to ensure that dst has enough space: chunk_len(src_len) 
         caller must also ensure that [src..src+src_len] is in enclave
         caller must also ensure that [dst..dst+chunk_len(src_len)+sizeof(chunk_header_t)] is outside enclave
 */
int64_t write_chunk(
    cipher_ctx_t *ctx,
    uint8_t *dst,
    uint8_t *src,
    uint64_t src_len,
    uint64_t value_version,
    uint8_t *aad,
    uint64_t aad_len)
{
    uint8_t *current_uptr = dst;

    /* chunk has the format chunk_size[64] || ciphertext[chunk_size] */
    *((uint64_t *) current_uptr) = aes_gcm_ciphertext_len(src_len); //number of bytes to follow
    current_uptr += sizeof(uint64_t);

    //BEWARE: We need to first allocate space rather than using space in dst, because dst in non-enc memory
    uint8_t iv[SGX_AESGCM_IV_SIZE];
    //nonce is the 64-bit counter followed by 32 bits of 0
    memcpy(iv, &(ctx->counter), sizeof(ctx->counter));
    memset(iv + sizeof(ctx->counter), 0, SGX_AESGCM_IV_SIZE - sizeof(ctx->counter));

    /* IV || MAC || encrypted_msg */
    sgx_status_t status = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *) &(ctx->key),
                                        src, /* input */
                                        src_len, /* input length */
                                        current_uptr + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, /* out */
                                        iv, /* IV */
                                        SGX_AESGCM_IV_SIZE, /* 12 bytes of IV */
                                        aad, /* additional data */
                                        aad_len,
                                        (sgx_aes_gcm_128bit_tag_t *) (current_uptr + SGX_AESGCM_IV_SIZE)); /* mac */
    assert(status == SGX_SUCCESS);

    memcpy(current_uptr, iv, SGX_AESGCM_IV_SIZE); //copy the IV to non-enc memory

    //update ctx to prevent reusing the IV
    ctx->counter = ctx->counter + 1;
    //TODO: if ctx->counter exceeds a certain value, we need to rotate the keys

    return (int64_t) src_len;
}

int64_t chunk_storage_write(
    cipher_ctx_t *ctx,
    uint8_t *dst,
    uint8_t *src,
    uint64_t src_len,
    uint64_t value_version,
    uint8_t *aad_prefix, /* supplied by caller */
    uint64_t aad_prefix_len)
{
    chunk_header_t header;
    header.untrusted_len = payload_len(src_len) - sizeof(chunk_header_t);
    header.num_chunks = div_ceil(src_len, MAX_CHUNK_SIZE);
    header.value_version = value_version;

    uint8_t *current_uptr = dst;

     /* first populate the header */
    memcpy(current_uptr, &(header), sizeof(chunk_header_t));
    current_uptr += sizeof(chunk_header_t);

    /* From here on, we write the chunk */

    //additional associated data: computes HMAC over caller's content || kv_header || chunk's offset
    uint64_t aad_len = aad_prefix_len + sizeof(chunk_header_t) + sizeof(uint64_t);
    uint8_t *aad = (uint8_t *) malloc(aad_len);
    assert(aad != NULL);
    memcpy(aad, aad_prefix, aad_prefix_len);
    memcpy(aad + aad_prefix_len, &header, sizeof(chunk_header_t));
    //we will apply the chunk's offset within the loop, as it will change for each chunk

    uint64_t offset = 0;
    uint8_t *current_tptr = src;
    while (offset < src_len) {
        //write offset
        memcpy(aad + aad_prefix_len + sizeof(chunk_header_t), &offset, sizeof(uint64_t));
        uint64_t ptxt_bytes_to_write = (src_len - offset) > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : (src_len - offset);
        int64_t result = write_chunk(ctx, current_uptr, current_tptr, ptxt_bytes_to_write, value_version, aad, aad_len);
        if (result != ptxt_bytes_to_write) { return -1; }
        offset += ptxt_bytes_to_write;
        current_tptr += ptxt_bytes_to_write;
        current_uptr += chunk_len(ptxt_bytes_to_write);
    }

    free(aad);
    return (int64_t) src_len;
}

int64_t chunk_storage_read(
    cipher_ctx_t *ctx,
    uint64_t offset, /* requesting len bytes starting from offset */
    uint8_t *buf, /* dst buf */
    uint64_t len, /* dst buf len */
    uint8_t *untrusted_buf, /* buf of unknown size in untrusted mem; holds the entire value starting at offset 0 */
    uint64_t value_version, /* expected value_version provided by caller */
    uint8_t *aad_prefix, /* supplied by caller */
    uint64_t aad_prefix_len)
{
    uint64_t untrusted_offset_reached = 0, trusted_offset_reached = 0;

    assert(sgx_is_outside_enclave(untrusted_buf, sizeof(chunk_header_t))); /* technically not needed, but good to have */
    chunk_header_t header;
    //we know at least chunk_header_t worth of bytes are there, let's pull them in
    memcpy(&header, untrusted_buf, sizeof(chunk_header_t));
    untrusted_offset_reached += sizeof(chunk_header_t);

    uint64_t untrusted_len = header.untrusted_len + sizeof(chunk_header_t);

    assert(addition_is_safe((uint64_t) untrusted_buf, untrusted_len)); /* do some sanity error checking */
    assert(sgx_is_outside_enclave(untrusted_buf, untrusted_len)); /* technically not needed, but good to have */

    //additional associated data: computes HMAC over caller's content || kv_header || chunk's offset
    uint64_t aad_len = aad_prefix_len + sizeof(chunk_header_t) + sizeof(uint64_t);
    uint8_t *aad = (uint8_t *) malloc(aad_len);
    assert(aad != NULL);
    memcpy(aad, aad_prefix, aad_prefix_len);
    memcpy(aad + aad_prefix_len, &header, sizeof(chunk_header_t));
    //we will apply the chunk's offset within the loop, as it will change for each chunk

    //TODO: as an optimization, no point copying and decrypting chunks if we are not going to read within them
    uint64_t chunk_ctr = 0;
    while ( (trusted_offset_reached < (offset + len)) && /* done reading requested content */
            (untrusted_offset_reached < untrusted_len) && /* ran out of bytes */
            (chunk_ctr < header.num_chunks) ) /* ran out of chunks */
    {
        uint64_t chunk_size;
        memcpy(&chunk_size, untrusted_buf + untrusted_offset_reached, sizeof(chunk_size));
        untrusted_offset_reached += sizeof(chunk_size);
        assert(chunk_size <= aes_gcm_ciphertext_len(MAX_CHUNK_SIZE));

        uint8_t ctxt_chunk[aes_gcm_ciphertext_len(MAX_CHUNK_SIZE)]; //stack allocated buffer populated by the storage api
        memcpy(ctxt_chunk, untrusted_buf + untrusted_offset_reached, chunk_size);
        untrusted_offset_reached += chunk_size;

        uint64_t ptxt_chunk_size = chunk_size - (SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
        //we don't always need to allocate worst case size, but this allows us to use static allocation
        uint8_t ptxt_chunk[MAX_CHUNK_SIZE];

        //additional associated data: computes HMAC over kv_key || kv_header || chunk's offset
        memcpy(aad + aad_prefix_len + sizeof(chunk_header_t), &trusted_offset_reached, sizeof(uint64_t));

        /* ciphertext: IV || MAC || encrypted */
        sgx_status_t status;
        status = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) &(ctx->key), //key
                                            ctxt_chunk + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, //src
                                            ptxt_chunk_size, //src_len
                                            ptxt_chunk, //dst
                                            ctxt_chunk, //iv
                                            SGX_AESGCM_IV_SIZE, //12 bytes
                                            aad, //aad
                                            aad_len, //AAD bytes
                                            (const sgx_aes_gcm_128bit_tag_t *) (ctxt_chunk + SGX_AESGCM_IV_SIZE)); //mac
        assert(status == SGX_SUCCESS);

        //should we grab some bytes from this block?
        if ((trusted_offset_reached + ptxt_chunk_size - 1) >= offset)
        {
            uint64_t len_completed = (trusted_offset_reached > offset) ? trusted_offset_reached - offset : 0;
            //once we find the first block, we can read from offset 0 in the second block, and so on.
            uint64_t offset_within_chunk = (trusted_offset_reached < offset) ? offset - trusted_offset_reached : 0;
            //we either copy enough bytes to fulfill len, or enough available bytes after the offset_within_block
            uint64_t num_bytes_to_copy = min(len - len_completed, ptxt_chunk_size - offset_within_chunk);
            
            memcpy((uint8_t *) buf + len_completed, ptxt_chunk + offset_within_chunk, num_bytes_to_copy);
        }

        trusted_offset_reached += ptxt_chunk_size;
        chunk_ctr += 1;
    }

    free(aad);
    return (trusted_offset_reached > offset) ? trusted_offset_reached - offset : 0;
}

/*
 * Retrieves value associated with the input key
 * The value format in the untrusted DB is untrusted_len[64] || num_chunks[64] || value_version[64] || content.
 * content is of the form chunk_1 || ... || chunk_n
 * chunk_i is of the form chunk_size[64] || ciphertext[chunk_size]
 */
int64_t kvs_write_helper(int64_t fd, kv_key_t *k, uint64_t offset, void *buf, uint64_t len, uint64_t value_version)
{   
    kvs_db_t *db_md = find_db_by_descriptor(fd);
    _moat_print_debug("writing to %s\n", db_md->db_name);
    if (db_md == NULL) { return -1; } //this needs an error code

    //error-checking
    if (!addition_is_safe(offset, len)) { return -1; } //offset + len causes integer overflow
    if (!addition_is_safe((uint64_t) buf, len)) { return -1; } //offset + len causes integer overflow
    if (offset + len > MAX_VALUE_SIZE) { return -1; } //offset + len is more than allowed size
    if (!db_md->write_permission) { return -1; } //need write permission for this DB

    assert (offset == 0); //TODO: handling the simple case for now

    uint8_t *untrusted_buf;
    uint64_t untrusted_len = payload_len(len);
    size_t retstatus;
    //request location of buffer in untrusted memory which is supposed to hold the value
    sgx_status_t status = malloc_ocall(&retstatus, untrusted_len, (void **) &untrusted_buf);
    assert(status == SGX_SUCCESS && retstatus == 0);

    assert(sgx_is_outside_enclave(untrusted_buf, untrusted_len));

    //additional associated data: computes HMAC over kv_key || kv_header || chunk's offset
    uint8_t aad_prefix[sizeof(kv_key_t)];
    memcpy(aad_prefix, k, sizeof(kv_key_t));

    int64_t result = chunk_storage_write(&(db_md->cipher_ctx), 
        untrusted_buf, buf, len,
        value_version,
        aad_prefix, sizeof(aad_prefix));

    status = kvs_set_ocall(&retstatus, fd, k, sizeof(kv_key_t), untrusted_buf, untrusted_len);
    assert(status == SGX_SUCCESS && retstatus == 0);

    /* TODO: invoke free_ocall */

    return result;
}

bool is_db_temporary(kvs_db_t *db_md)
{
    return strncmp(TMP_NAME_PREFIX, db_md->db_name, strlen(TMP_NAME_PREFIX)) == 0;
}

/***************************************************
 PUBLIC API IMPLEMENTATION
 ***************************************************/

void _moat_kvs_module_init()
{
    g_dbs = list_create();

    /* init external KVS */
    size_t retstatus;
    sgx_status_t status = kvs_init_service_ocall(&retstatus);
    assert(status == SGX_SUCCESS && retstatus == 0);
}

/*
 oflag is one or more of O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_LOAD
 */
int64_t _moat_kvs_open(char *name, int oflag)
{
    kvs_db_t *db_md = find_db_by_name(name);
    
    if (db_md == NULL) //else file already exists by that name
    {
        if (strlen(name) >= MAX_KVS_NAME_LEN) { return -1; }
        int64_t fd = generate_unique_db_descriptor();
        _moat_print_debug("creating new db with descriptor %ld\n", fd);
        if (fd == -1) { return -1; } //we didn't get an available fd
        //check that only one of O_RDONLY, O_WRONLY, O_RDWR are set
        if (o_rdonly(oflag)) { if (o_wronly(oflag) || o_rdwr(oflag)) { return -1; } }
        if (o_wronly(oflag)) { if (o_rdonly(oflag) || o_rdwr(oflag)) { return -1; } }
        if (o_rdwr(oflag)) { if (o_rdonly(oflag) || o_wronly(oflag)) { return -1; } }

        size_t retstatus;
        sgx_status_t status = kvs_create_ocall(&retstatus, fd, name);
        assert(status == SGX_SUCCESS && retstatus == 0);

        db_md = (kvs_db_t *) malloc(sizeof(kvs_db_t));
        assert(db_md != NULL);

        strcpy(db_md->db_name, name);
        db_md->db_descriptor = fd;
        db_md->size = 0;
        db_md->read_permission = o_rdonly(oflag) || o_rdwr(oflag);
        db_md->write_permission = o_wronly(oflag) || o_rdwr(oflag);
        db_md->cipher_ctx.counter = 0;
        status = sgx_read_rand((uint8_t *) &(db_md->cipher_ctx.key), sizeof(sgx_aes_gcm_128bit_key_t));
        assert(status == SGX_SUCCESS);

        list_insert_value(g_dbs, db_md);
    }

    return db_md->db_descriptor;
}

/*
 * Retrieves value associated with the input key
 * The value format in the untrusted DB is total_len[64] || num_chunks[64] || value_version[64] || content.
 * content is of the form chunk_1 || ... || chunk_n
 * chunk_i is of the form chunk_size[64] || ciphertext[chunk_size]
 */
int64_t _moat_kvs_get(int64_t fd, kv_key_t *k, uint64_t offset, void* buf, uint64_t len)
{
    kvs_db_t *db_md = find_db_by_descriptor(fd);
    _moat_print_debug("reading from %s\n", db_md->db_name);
    if (db_md == NULL) { return -1; } //this needs an error code

    //error-checking
    if (!addition_is_safe(offset,len)) { return -1; } //offset + len shouldn't cause integer overflow
    if (offset + len > MAX_VALUE_SIZE) { return -1; } //offset + len is more than allowed size
    if (!db_md->read_permission) { return -1; }

    uint8_t *untrusted_buf;
    //request untrusted database to populate a buffer in untrusted memory; ocall returns address of that buffer
    size_t retstatus;
    sgx_status_t status = kvs_get_ocall(&retstatus, fd, k, sizeof(kv_key_t), (void **) &untrusted_buf);
    assert(status == SGX_SUCCESS);
    if (retstatus != 0) { return -1; } //TODO: we should handle this more gracefully, as it means either db dropped k or we couldnt malloc

    int64_t result = chunk_storage_read(&(db_md->cipher_ctx), offset, buf, len, untrusted_buf, 0, (uint8_t *) k, sizeof(kv_key_t)); 

    //TODO: release untrusted_buf memory */
    return result;
}

int64_t _moat_kvs_set(int64_t fd, kv_key_t *k, uint64_t offset, void *buf, uint64_t len)
{
    //TODO: use the correct version once we use the Merkle tree
    return kvs_write_helper(fd, k, offset, buf, len, 0);
}

int64_t _moat_kvs_insert(int64_t fd, kv_key_t *k, uint64_t offset, void *buf, uint64_t len)
{
    return kvs_write_helper(fd, k, offset, buf, len, 0);
}

int64_t _moat_kvs_close(int64_t fd)
{
    kvs_db_t *db_md = find_db_by_descriptor(fd);
    if (db_md == NULL) { return -1; } //this needs an error code

    bool deleted_successfully = list_delete_value(g_dbs, db_md);
    assert(deleted_successfully);

    /* if this was a temporary file, request untrusted world to delete the DB (though it may never honor it) */
    if (is_db_temporary(db_md)) {
        size_t retstatus;
        sgx_status_t status = kvs_destroy_ocall(&retstatus, fd);
        assert(status == SGX_SUCCESS && retstatus == 0);
    }

    return 0;
}

