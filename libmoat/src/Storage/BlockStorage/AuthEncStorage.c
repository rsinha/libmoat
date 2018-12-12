#include <stddef.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "../../../api/libmoat.h"
#include "../../../api/libbarbican.h"
#include "api/BlockStorage.h"
#include "../../Utils/api/Utils.h"

/***************************************************
 DEFINITIONS FOR INTERNAL USE
 ***************************************************/

typedef enum {
    RESET = 0,
    DESTROY = 1,
    APPLICATION_DATA = 2
} fs_ciphertext_type_t;

typedef struct
{
    size_t type;
    size_t length;
    size_t addr;
} fs_ciphertext_header_t;

#define ALPHABET_SIZE (2)

typedef struct _merkle_node {
    bool                    is_end_of_word; //is this leaf node
    sgx_sha256_hash_t       hash; //hash of block for leaves, hash of children otherwise
    struct _merkle_node     *children[ALPHABET_SIZE];
} merkle_node_t;

/***************************************************
 INTERNAL STATE
 ***************************************************/

static size_t          g_max_files;
static merkle_node_t **g_merkle_roots; //array of pointers to merkle roots

/***************************************************
 PRIVATE METHODS
 ***************************************************/

/*
void integrity_check_freshness(size_t addr, uint8_t *ciphertext, size_t len)
{
    sgx_sha256_hash_t computed_hash;

    sgx_status_t status = sgx_sha256_msg(ciphertext, len, &computed_hash);
    assert(status == SGX_SUCCESS);
    assert(memcmp(&(g_latest_hash[addr]), &computed_hash, sizeof(computed_hash)) == 0);
}

void integrity_record_freshness(size_t addr, uint8_t *ciphertext, size_t len)
{
    sgx_status_t status = sgx_sha256_msg(ciphertext, len, &(g_latest_hash[addr]));
    assert(status == SGX_SUCCESS);
}
*/

merkle_node_t *alloc_merkle_node() {
    merkle_node_t *n = (merkle_node_t *) malloc(sizeof(merkle_node_t));
    if (n) {
        n->is_end_of_word = false;
        for (int i = 0; i < ALPHABET_SIZE; i++) {
            n->children[i] = NULL;
        }
    }
    return n;
}

void recompute_merkle_hashes(merkle_node_t *node) {
    if (node->is_end_of_word) { return; } //recursion terminates here
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        if (node->children[i] != NULL) {
            recompute_merkle_hashes(node->children[i]);
        }
    }

    uint8_t buf[ALPHABET_SIZE * (sizeof(uint8_t) + sizeof(sgx_sha256_hash_t))];
    uint8_t *tmp = buf;
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        if (node->children[i] != NULL) {
            *tmp = (node->children[i] != NULL) ? 1 : 0;
            memcpy(tmp + 1, &(node->children[i]->hash), sizeof(sgx_sha256_hash_t));
        } else {
            memset(tmp, 0, (sizeof(uint8_t) + sizeof(sgx_sha256_hash_t)));
        }
        tmp += (sizeof(uint8_t) + sizeof(sgx_sha256_hash_t));
    }
    sgx_status_t status = sgx_sha256_msg(buf, sizeof(buf), &(node->hash));
    assert(status == SGX_SUCCESS);
}

bool insert_merkle_node(merkle_node_t *root, 
    uint8_t *key, size_t key_len, sgx_sha256_hash_t *hash) {
    merkle_node_t *crawl = root;
    
    for (size_t byte_idx = 0; byte_idx < key_len; byte_idx++) {
        for (size_t bit_idx = 0; bit_idx < 8; bit_idx++) {
            bool bit = ((key[byte_idx] >> bit_idx) & 0x01) != 0;
            size_t index = bit ? 1 : 0;
            if (crawl->children[index] == NULL) {
                crawl->children[index] = alloc_merkle_node();
                if (crawl->children[index] == NULL) { return false; }
            }
            crawl = crawl->children[index];
        }
    }
    memcpy(&(crawl->hash), hash, sizeof(sgx_sha256_hash_t));
    crawl->is_end_of_word = true; // mark last node as leaf

    recompute_merkle_hashes(root);

    return true;
}

bool get_merkle_leaf_hash(merkle_node_t *root, 
    uint8_t *key, size_t key_len,
    sgx_sha256_hash_t *hash)
{
    merkle_node_t *crawl = root;
    if (!crawl) { return false; }
    
    for (size_t byte_idx = 0; byte_idx < key_len; byte_idx++) {
        for (size_t bit_idx = 0; bit_idx < 8; bit_idx++) {
            bool bit = ((key[byte_idx] >> bit_idx) & 0x01) != 0;
            size_t index = bit ? 1 : 0;
            if (crawl->children[index] == NULL) { return false; }
            crawl = crawl->children[index];
        }
    }
    
    if (crawl != NULL && crawl->is_end_of_word) {
        memcpy(hash, &(crawl->hash), sizeof(sgx_sha256_hash_t));
        return true;
    } else {
        return false;
    }
}

void create_root_if_null(int64_t fd) {
    if (g_merkle_roots[fd] == NULL) {
        merkle_node_t *node = alloc_merkle_node();
        assert(node != NULL); //check that malloc suceeded
        g_merkle_roots[fd] = node;
    }
}

/***************************************************
 PUBLIC API
 ***************************************************/

void block_storage_module_init(size_t max_files)
{
    sgx_status_t status;
    size_t retstatus;

    status = fs_init_service_ocall(&retstatus);
    assert(status == SGX_SUCCESS && retstatus == 0);

    g_max_files = max_files;

    //set the array of merkle pointers to null
    g_merkle_roots = (merkle_node_t **) malloc(sizeof(merkle_node_t *) * max_files);
    assert(g_merkle_roots != NULL);

    for (int i = 0; i < max_files; i++) {
        g_merkle_roots[i] = NULL;
    }
}

size_t block_storage_get_digest(int64_t fd, sgx_sha256_hash_t *hash) {
    if(((size_t) fd) >= g_max_files) { return -1; }
    if(g_merkle_roots[fd] == NULL) { return -1; }
    memcpy(hash, &(g_merkle_roots[fd]->hash), sizeof(sgx_sha256_hash_t));
    return 0;
}

size_t block_storage_load(int64_t fd, size_t num_blocks) {
    sgx_status_t status;
    size_t retstatus;

    if(((size_t) fd) >= g_max_files) { return -1; }
    create_root_if_null(fd);
    merkle_node_t *root = g_merkle_roots[fd];

    //allocate memory for ciphertext
    uint8_t ciphertext[
        sizeof(fs_ciphertext_header_t) + 
        SGX_AESGCM_IV_SIZE + 
        SGX_AESGCM_MAC_SIZE + 
        sizeof(block_data_t)
        ];

    for (size_t i = 0; i < num_blocks; i++) {
        status = fs_read_block_ocall(&retstatus, fd, i, ciphertext, sizeof(ciphertext));
        assert(status == SGX_SUCCESS && retstatus == 0);
        
        assert(((fs_ciphertext_header_t *) ciphertext)->type == APPLICATION_DATA);
        assert(((fs_ciphertext_header_t *) ciphertext)->length == sizeof(block_data_t) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
        assert(((fs_ciphertext_header_t *) ciphertext)->addr == i);

        sgx_sha256_hash_t hash;
        sgx_status_t status = sgx_sha256_msg(ciphertext, sizeof(ciphertext), &hash);
        assert(status == SGX_SUCCESS);
        insert_merkle_node(root, (uint8_t *) &i, sizeof(size_t), &hash);
    }

    return 0;
}

//NOTE: addr ranges from 1 to g_num_blocks
size_t block_storage_read(int64_t fd, cipher_ctx_t *ctx, size_t addr, block_data_t data)
{
    sgx_status_t status;
    size_t retstatus;

    assert(((size_t) fd) < g_max_files);
    assert(g_merkle_roots[fd] != NULL);
    merkle_node_t *root = g_merkle_roots[fd];

    //allocate memory for ciphertext
    uint8_t ciphertext[
        sizeof(fs_ciphertext_header_t) + 
        SGX_AESGCM_IV_SIZE + 
        SGX_AESGCM_MAC_SIZE + 
        sizeof(block_data_t)
        ];
    
    status = fs_read_block_ocall(&retstatus, fd, addr, ciphertext, sizeof(ciphertext));
    assert(status == SGX_SUCCESS && retstatus == 0);
    
    assert(((fs_ciphertext_header_t *) ciphertext)->type == APPLICATION_DATA);
    assert(((fs_ciphertext_header_t *) ciphertext)->length == sizeof(block_data_t) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
    assert(((fs_ciphertext_header_t *) ciphertext)->addr == addr);
    
    uint8_t *payload = ciphertext + sizeof(fs_ciphertext_header_t);
    
    //preventing rollback attacks
    //integrity_check_freshness(addr, ciphertext, sizeof(ciphertext));
    sgx_sha256_hash_t hash_computed, hash_stored;
    status = sgx_sha256_msg(ciphertext, sizeof(ciphertext), &hash_computed);
    assert(status == SGX_SUCCESS);
    bool success = get_merkle_leaf_hash(root, (uint8_t *) &addr, sizeof(size_t), &hash_stored);
    assert(success);
    assert(memcmp(&hash_computed, &hash_stored, sizeof(sgx_sha256_hash_t)) == 0);
    
    /* ciphertext: header || IV || MAC || encrypted */
    status = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) &(ctx->key), //key
                                        payload + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, //src
                                        sizeof(block_data_t), //src_len
                                        data, //dst
                                        payload, //iv
                                        SGX_AESGCM_IV_SIZE, //12 bytes
                                        NULL, //aad
                                        0, //0 bytes of AAD
                                        (const sgx_aes_gcm_128bit_tag_t *) (payload + SGX_AESGCM_IV_SIZE)); //mac
    assert(status == SGX_SUCCESS);
    
    return 0;
}

//NOTE: addr ranges from 1 to g_num_blocks
//performs authenticated encryption of data, and writes it as a file
size_t block_storage_write(int64_t fd, cipher_ctx_t *ctx, size_t addr, block_data_t data)
{
    sgx_status_t status;
    size_t retstatus;

    assert(((size_t) fd) < g_max_files);
    create_root_if_null(fd);
    merkle_node_t *root = g_merkle_roots[fd];

    /* error checking */
    //if (addr >= g_num_blocks) { return -1; }

    size_t iv_counter = ctx->counter;
    //NIST guidelines for using AES-GCM
    if (iv_counter > ((uint32_t) -2)) { return -1; }

    //allocate memory for ciphertext
    uint8_t ciphertext[
        sizeof(fs_ciphertext_header_t) + 
        SGX_AESGCM_IV_SIZE + 
        SGX_AESGCM_MAC_SIZE + 
        sizeof(block_data_t)
        ];
    
    ((fs_ciphertext_header_t *) ciphertext)->type = APPLICATION_DATA;
    ((fs_ciphertext_header_t *) ciphertext)->length = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + sizeof(block_data_t);
    ((fs_ciphertext_header_t *) ciphertext)->addr = addr;
    
    uint8_t *payload = ciphertext + sizeof(fs_ciphertext_header_t);
    
    //nonce is 32 bits of 0 followed by the message sequence number
    memcpy(payload + 0, &iv_counter, sizeof(iv_counter));
    memset(payload + sizeof(iv_counter), 0, SGX_AESGCM_IV_SIZE - sizeof(iv_counter));
    
    /* ciphertext: IV || MAC || encrypted */
    status = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *) &(ctx->key),
                                        data, /* input */
                                        sizeof(block_data_t), /* input length */
                                        payload + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, /* out */
                                        payload + 0, /* IV */
                                        SGX_AESGCM_IV_SIZE, /* 12 bytes of IV */
                                        NULL, /* additional data */
                                        0, /* zero bytes of additional data */
                                        (sgx_aes_gcm_128bit_tag_t *) (payload + SGX_AESGCM_IV_SIZE)); /* mac */
    assert(status == SGX_SUCCESS);
    
    //saving SHA-256 hash for future freshness checks
    sgx_sha256_hash_t hash;
    status = sgx_sha256_msg(ciphertext, sizeof(ciphertext), &hash);
    assert(status == SGX_SUCCESS);
    bool success = insert_merkle_node(root, (uint8_t *) &addr, sizeof(size_t), &hash);
    assert(success);

    //so we don't reuse IVs
    ctx->counter = ctx->counter + 1;
    
    status = fs_write_block_ocall(&retstatus, fd, addr, ciphertext, sizeof(ciphertext));
    assert(status == SGX_SUCCESS && retstatus == 0);

    return 0;
}
