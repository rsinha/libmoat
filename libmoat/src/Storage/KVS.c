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

#define o_rdonly(oflag) ((O_RDONLY & oflag) != 0)
#define o_wronly(oflag) ((O_WRONLY & oflag) != 0)
#define o_rdwr(oflag) ((O_RDWR & oflag) != 0)

typedef struct
{
    char      db_name[MAX_KVS_NAME_LEN];
    int64_t   db_descriptor; //integer id
    int64_t   size; //number of keys inserted
    bool      read_permission;
    bool      write_permission;
} kvs_db_t;

#define MAX_CHUNK_SIZE 1024 //we store values as a collection of ordered chunks

typedef struct
{
    uint64_t untrusted_len;
    uint64_t num_chunks;
    uint64_t value_version;
} kvs_header_t;

/***************************************************
 INTERNAL STATE
 ***************************************************/

static sgx_aes_gcm_128bit_key_t  *g_key;  //key used to protect file contents
static ll_t                      *g_dbs;  //list of kvs_db_t
static uint64_t                   g_local_counter; //used as IV

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
        //file descriptors start at 1
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

/*
 * Retrieves value associated with the input key
 * The value format in the untrusted DB is num_chunks[32] || value_version[32] || content.
 * content is of the form chunk_1 || ... || chunk_n
 * chunk_i is of the form chunk_size[32] || ciphertext[chunk_size]
 */
int64_t kvs_write_helper(int64_t fd, kv_key_t *k, uint64_t offset, void *buf, uint64_t len, uint64_t value_version)
{   
    kvs_db_t *db_md = find_db_by_descriptor(fd);
    if (db_md == NULL) { return -1; } //this needs an error code

    //error-checking
    if (len < 0) { return -1; } //bad len argument
    if (!addition_is_safe(offset, len)) { return -1; }
    if (!db_md->write_permission) { return -1; }

    assert (offset == 0 && len <= MAX_CHUNK_SIZE); //TODO: handling the simple case for now

    uint8_t *untrusted_buf;
    size_t retstatus;
    //request location of buffer in untrusted memory which is supposed to hold the value
    uint64_t untrusted_len = sizeof(kvs_header_t) + sizeof(uint64_t) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + len;
    sgx_status_t status = malloc_ocall(&retstatus, untrusted_len, (void **) &untrusted_buf);
    assert(status == SGX_SUCCESS && retstatus == 0);

    uint8_t *current_uptr = untrusted_buf;

    ((kvs_header_t *) current_uptr)->untrusted_len = untrusted_len;
    ((kvs_header_t *) current_uptr)->num_chunks = 1;
    ((kvs_header_t *) current_uptr)->value_version = value_version;
    current_uptr += sizeof(kvs_header_t);

    /* From here on, we write the chunk */

    //size of chunk
    *((uint64_t *) current_uptr) = len + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;
    current_uptr += sizeof(uint64_t);

    //nonce is 32 bits of 0 followed by the message sequence number
    uint8_t iv[SGX_AESGCM_IV_SIZE];
    memcpy(iv, &g_local_counter, sizeof(g_local_counter));
    memset(iv + sizeof(g_local_counter), 0, SGX_AESGCM_IV_SIZE - sizeof(g_local_counter));

    //additional associated data: we effectively compute HMAC over the kv_key and version
    uint8_t aad[sizeof(kv_key_t) + sizeof(value_version) + sizeof(untrusted_len)];
    memcpy(aad, k, sizeof(kv_key_t));
    memcpy(aad + sizeof(kv_key_t), &value_version, sizeof(value_version));
    memcpy(aad + sizeof(kv_key_t) + + sizeof(value_version), &untrusted_len, sizeof(untrusted_len));

    /* IV || MAC || ciphertext */
    status = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *) g_key,
                                        buf, /* input */
                                        len, /* input length */
                                        current_uptr + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, /* out */
                                        iv, /* IV */
                                        SGX_AESGCM_IV_SIZE, /* 12 bytes of IV */
                                        aad, /* additional data */
                                        sizeof(aad),
                                        (sgx_aes_gcm_128bit_tag_t *) (current_uptr + SGX_AESGCM_IV_SIZE)); /* mac */
    assert(status == SGX_SUCCESS);

    //copy the IV
    memcpy(current_uptr, iv, SGX_AESGCM_IV_SIZE);

    current_uptr += SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + len;

    //so we don't reuse IVs
    g_local_counter = g_local_counter + 1;

    status = kvs_set_ocall(&retstatus, fd, k, sizeof(kv_key_t), untrusted_buf, untrusted_len);
    assert(status == SGX_SUCCESS && retstatus == 0);

    return len;
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
    g_dbs = malloc(sizeof(ll_t));
    assert(g_dbs != NULL);
    g_dbs->head = NULL;

    /* init external KVS */
    size_t retstatus;
    sgx_status_t status = kvs_init_service_ocall(&retstatus);
    assert(status == SGX_SUCCESS && retstatus == 0);

    /* initialize encryption key */
    status = sgx_read_rand((uint8_t *) g_key, sizeof(sgx_aes_gcm_128bit_key_t));
    assert(status == SGX_SUCCESS);

    /* we will use a counter as IV */
    g_local_counter = 0;
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
    if (db_md == NULL) { return -1; } //this needs an error code

    //error-checking
    if (len < 0) { return -1; } //bad len argument
    if (!addition_is_safe(offset,len)) { return -1; }
    if (!db_md->read_permission) { return -1; }

    uint8_t *untrusted_buf;
    uint8_t chunk[MAX_CHUNK_SIZE]; //stack allocated buffer populated by the storage api

    //request location of buffer in untrusted memory holding the value
    size_t retstatus;
    sgx_status_t status = kvs_get_ocall(&retstatus, fd, k, sizeof(kv_key_t), (void **) &untrusted_buf);
    assert(status == SGX_SUCCESS && retstatus == 0);

    uint64_t untrusted_offset_reached = 0, trusted_offset_reached = 0;

    //we know at least kvs_header_t worth of bytes are there, let's pull them in
    memcpy(chunk, untrusted_buf, sizeof(kvs_header_t));
    untrusted_offset_reached += sizeof(kvs_header_t);

    uint64_t untrusted_len = ((kvs_header_t *) chunk)->untrusted_len; /* total untrusted bytes including header */
    uint64_t num_chunks = ((kvs_header_t *) chunk)->num_chunks; /* number of chunks in untrusted */
    uint64_t value_version = ((kvs_header_t *) chunk)->value_version; /* incremented on each write */

    //do some sanity error checking
    assert(addition_is_safe((uint64_t) untrusted_buf, untrusted_len));
    //TODO: check that [untrusted_buf..untrusted_buf+untrusted_len] is within non-enclave memory

    uint64_t chunk_ctr = 0;

    while ( (trusted_offset_reached < (offset + len)) && /* done reading requested content */
            (untrusted_offset_reached < untrusted_len) && /* ran out of bytes */
            (chunk_ctr < num_chunks) ) /* ran out of chunks */
    {
        uint64_t chunk_size;
    
        memcpy(&chunk_size, untrusted_buf + untrusted_offset_reached, sizeof(chunk_size));
        untrusted_offset_reached += sizeof(chunk_size);
        assert(chunk_size <= MAX_CHUNK_SIZE);

        memcpy(chunk, untrusted_buf + untrusted_offset_reached, chunk_size);
        untrusted_offset_reached += chunk_size;

        uint64_t ptxt_chunk_size = chunk_size - (SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
        //we don't always need to allocate worst case size, but this allows us to use static allocation
        uint8_t ptxt_chunk[MAX_CHUNK_SIZE - (SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE)];

        //additional associated data: we effectively compute HMAC over the kv_key || version || untrusted_len
        uint8_t aad[sizeof(kv_key_t) + sizeof(value_version) + sizeof(untrusted_len)];
        memcpy(aad, k, sizeof(kv_key_t));
        memcpy(aad + sizeof(kv_key_t), &value_version, sizeof(value_version));
        memcpy(aad + sizeof(kv_key_t) + sizeof(value_version), &untrusted_len, sizeof(untrusted_len));

        /* ciphertext: IV || MAC || encrypted */
        status = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) g_key, //key
                                            chunk + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, //src
                                            ptxt_chunk_size, //src_len
                                            ptxt_chunk, //dst
                                            chunk, //iv
                                            SGX_AESGCM_IV_SIZE, //12 bytes
                                            aad, //aad
                                            sizeof(aad), //AAD bytes
                                            (const sgx_aes_gcm_128bit_tag_t *) (chunk + SGX_AESGCM_IV_SIZE)); //mac
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
    
    return (trusted_offset_reached > offset) ? trusted_offset_reached - offset : 0;
}

int64_t _moat_kvs_set(int64_t fd, kv_key_t *k, uint64_t offset, void *buf, uint64_t len)
{
    //TODO: use the correct version once we use the Merkle tree
    kvs_write_helper(fd, k, offset, buf, len, 0);
}

int64_t _moat_kvs_insert(int64_t fd, kv_key_t *k, uint64_t offset, void *buf, uint64_t len)
{
    kvs_write_helper(fd, k, offset, buf, len, 0);
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

