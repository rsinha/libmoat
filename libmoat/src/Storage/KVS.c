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
#include "ChunkyStorage/api/ChunkyStorage.h"

/***************************************************
 DEFINITIONS FOR INTERNAL USE
 ***************************************************/

/* don't see why an enclave would access more than 16 databases */
#define MAX_KVS_COUNT 16
#define MAX_KVS_NAME_LEN 64

#define o_rdonly(oflag) ((O_RDONLY & (oflag)) != 0)
#define o_wronly(oflag) ((O_WRONLY & (oflag)) != 0)
#define o_rdwr(oflag) ((O_RDWR & (oflag)) != 0)
#define o_creat(oflag) ((O_CREAT & (oflag)) != 0)
#define o_tmpfile(oflag) ((O_TMPFILE & (oflag)) != 0)

typedef struct
{
    cipher_ctx_t cipher_ctx;
    char         db_name[MAX_KVS_NAME_LEN];
    int64_t      db_descriptor; //integer id
    int64_t      size; //number of keys inserted
    int64_t      oflag;
} kvs_db_t;

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

/*
 * Retrieves value associated with the input key
 * The value format in the untrusted DB is untrusted_len[64] || num_chunks[64] || value_version[64] || content.
 * content is of the form chunk_1 || ... || chunk_n
 * chunk_i is of the form chunk_size[64] || ciphertext[chunk_size]
 */
int64_t kvs_write_helper(int64_t fd, void *k, uint64_t k_len, void *buf, uint64_t buf_len, uint64_t value_version)
{   
    kvs_db_t *db_md = find_db_by_descriptor(fd);
    _moat_print_debug("writing to %s\n", db_md->db_name);
    if (db_md == NULL) { return -1; } //this needs an error code

    //error-checking
    if (!addition_is_safe((uint64_t) buf, buf_len)) { return -1; } //buf + buf_len causes integer overflow
    if (! (o_wronly(db_md->oflag) || o_rdwr(db_md->oflag))) { return -1; } //need write permission for this DB

    uint8_t *untrusted_buf;
    uint64_t untrusted_len = chunk_storage_payload_len(buf_len); /* ask chunky storage module how much space it needs */
    size_t retstatus;
    //request location of buffer in untrusted memory which is supposed to hold the value
    sgx_status_t status = malloc_ocall(&retstatus, untrusted_len, (void **) &untrusted_buf);
    assert(status == SGX_SUCCESS && retstatus == 0);

    assert(sgx_is_outside_enclave(untrusted_buf, untrusted_len));

    //additional associated data: computes HMAC over at least the key, the chunky lib adds other fields
    uint8_t *aad_prefix = k;
    uint64_t aad_prefix_len = k_len;

    int64_t result = chunk_storage_write(&(db_md->cipher_ctx), 
        untrusted_buf, buf, buf_len,
        value_version,
        aad_prefix, aad_prefix_len);

    status = kvs_set_ocall(&retstatus, fd, k, k_len, untrusted_buf, untrusted_len);
    assert(status == SGX_SUCCESS && retstatus == 0);

    /* we can get rid of this buffer after the set operation terminated */
    status = free_ocall(&retstatus, untrusted_buf);
    assert(status == SGX_SUCCESS && retstatus == 0);

    return result;
}

bool is_db_temporary(kvs_db_t *db_md)
{
    return o_tmpfile(db_md->oflag);
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
 oflag is one or more of O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_TMPFILE
 */
int64_t _moat_kvs_open(char *name, int64_t oflag, sgx_aes_gcm_128bit_key_t *key)
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
        sgx_status_t status;

        db_md = (kvs_db_t *) malloc(sizeof(kvs_db_t));
        assert(db_md != NULL);

        strcpy(db_md->db_name, name);
        db_md->db_descriptor = fd;
        db_md->size = 0;
        db_md->oflag = oflag;
        db_md->cipher_ctx.counter = 0;

        if (o_creat(oflag)) {
            status = kvs_create_ocall(&retstatus, fd, name);
        } else {
            //ask host to load db with specified name if it knows about it, and bind it to fd
            status = kvs_load_ocall(&retstatus, fd, name);
        }

        assert(status == SGX_SUCCESS && retstatus == 0);
        assert(key != NULL);
        memcpy((uint8_t *) &(db_md->cipher_ctx.key), key, sizeof(sgx_aes_gcm_128bit_key_t));
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
int64_t _moat_kvs_get(int64_t fd, void *k, uint64_t k_len, uint64_t offset, void* buf, uint64_t buf_len)
{
    kvs_db_t *db_md = find_db_by_descriptor(fd);
    if (db_md == NULL) { return -1; } //this needs an error code
    _moat_print_debug("reading from %s\n", db_md->db_name);

    //error-checking
    if (!addition_is_safe(offset, buf_len)) { return -1; } //offset + len shouldn't cause integer overflow
    if (! (o_rdonly(db_md->oflag) || o_rdwr(db_md->oflag))) { return -1; }

    uint8_t *untrusted_buf;
    //request untrusted database to populate a buffer in untrusted memory; ocall returns address of that buffer
    size_t retstatus;
    sgx_status_t status = kvs_get_ocall(&retstatus, fd, k, k_len, (void **) &untrusted_buf);
    assert(status == SGX_SUCCESS);
    if (retstatus != 0) { return -1; } //TODO: we should handle this more gracefully, as it means either db dropped k or we couldnt malloc

    int64_t result = chunk_storage_read(&(db_md->cipher_ctx), offset, buf, buf_len, untrusted_buf, 0, k, k_len); 

    //TODO: release untrusted_buf memory */
    return result;
}

int64_t _moat_kvs_set(int64_t fd, void *k, uint64_t k_len, void *buf, uint64_t buf_len)
{
    //TODO: use the correct version once we use the Merkle tree
    return kvs_write_helper(fd, k, k_len, buf, buf_len, 0);
}

int64_t _moat_kvs_insert(int64_t fd, void *k, uint64_t k_len, void *buf, uint64_t buf_len)
{
    return kvs_write_helper(fd, k, k_len, buf, buf_len, 0);
}

int64_t _moat_kvs_delete(int64_t fd, void *k, uint64_t k_len)
{
    kvs_db_t *db_md = find_db_by_descriptor(fd);
    if (db_md == NULL) { return -1; }
    _moat_print_debug("deleting from %s\n", db_md->db_name);

    size_t retstatus;
    sgx_status_t status = kvs_delete_ocall(&retstatus, fd, k, k_len);
    assert(status == SGX_SUCCESS);
    if (retstatus != 0) { return -1; }

    return 0;
}

int64_t _moat_kvs_save(int64_t fd)
{
    kvs_db_t *db_md = find_db_by_descriptor(fd);
    if (db_md == NULL) { return -1; }
    if (o_tmpfile(db_md->oflag)) { return -1; } //tmp files cannot be saved

    size_t retstatus;
    /* giving both fd and db_name to help out barbican */
    sgx_status_t status = kvs_save_ocall(&retstatus, fd, db_md->db_name);
    assert(status == SGX_SUCCESS);
    if (retstatus != 0) { return -1; }

    return 0;
}

int64_t _moat_kvs_close(int64_t fd)
{
    size_t retstatus;
    sgx_status_t status;

    kvs_db_t *db_md = find_db_by_descriptor(fd);
    if (db_md == NULL) { return -1; } //this needs an error code

    /* if this was a temporary file, request untrusted world to delete the DB (though it may never honor it) */
    if (is_db_temporary(db_md)) {
        /* giving both fd and db_name to help out barbican */
        status = kvs_destroy_ocall(&retstatus, fd, db_md->db_name);
        assert(status == SGX_SUCCESS && retstatus == 0);
    }

    /* giving both fd and db_name to help out barbican */
    status = kvs_close_ocall(&retstatus, fd);
    assert(status == SGX_SUCCESS && retstatus == 0);

    bool deleted_successfully = list_delete_value(g_dbs, db_md);
    assert(deleted_successfully);

    return 0;
}

