#include <stddef.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "../../../api/libmoat.h"
#include "../../../api/libmoat_untrusted.h"
#include "api/BlockStorage.h"

/***************************************************
 INTERNAL STATE
 ***************************************************/

#define L 2 //height of the binary tree
#define Z 4 //capacit of each bucket (in blocks)

typedef size_t block_addr_t;
typedef size_t bucket_addr_t;
typedef size_t leaf_node_id_t;
typedef size_t level_t;

typedef struct {
    block_addr_t addr;
    block_data_t data;
} oram_block_t;

typedef struct {
    uint8_t iv[SGX_AESGCM_IV_SIZE];
    uint8_t mac[SGX_AESGCM_MAC_SIZE];
    uint8_t ciphertext[sizeof(oram_block_t)]; //addr, data
} encrypted_oram_block_t;

typedef encrypted_oram_block_t bucket_t[Z];

/***************************************************
 INTERNAL STATE
 ***************************************************/

static uint64_t                   g_local_counter;  //used as IV
static sgx_aes_gcm_128bit_key_t  *g_key;            //key used to protect file contents
//static boom stash;
static size_t                    *g_position;       //addr -> leaf
static oram_block_t              *g_dummy_block;

/***************************************************
 PRIVATE API
 ***************************************************/

void read_bucket_from_server(size_t addr, encrypted_oram_block_t data)
{
    sgx_status_t status;
    size_t retstatus;

    //allocate memory for bucket
    uint8_t *bucket = (uint8_t *) malloc(sizeof(bucket_t));
    assert(bucket != NULL);
    
    status = read_oram_bucket_ocall(&retstatus, bucket, sizeof(bucket_t), addr);
    assert(status == SGX_SUCCESS && retstatus == 0);
}

void write_bucket_from_server(size_t addr)
{
    
}

bool is_dummy_block(oram_block_t *blk)
{
    return (blk->addr == 0);
}

oram_block_t *get_dummy_block()
{
    if (g_dummy_block == NULL) {
        g_dummy_block = malloc(sizeof(oram_block_t));
        assert(g_dummy_block != NULL);
        g_dummy_block->addr = 0;
        sgx_status_t status = sgx_read_rand((uint8_t *) g_dummy_block->data, sizeof(block_data_t));
        assert(status == SGX_SUCCESS);
    }
    
    return g_dummy_block;
}

//bucket at level l along the path P(x)
//where, P(x) is the path from leaf node x to the root
//NOTE: root is at level 0 and has bucket id 1
bucket_addr_t P(leaf_node_id_t x, level_t l)
{
    bucket_addr_t node = exp_of_2(L) + x;
    level_t level = L;
    while (level > l) {
        node = node >> 1;
        level = level - 1;
    }
    return node;
}

/***************************************************
 PUBLIC API
 ***************************************************/

void path_oram_storage_module_init()
{
    sgx_status_t status;
    size_t retstatus;
    
    g_key = malloc(sizeof(sgx_aes_gcm_128bit_key_t));
    assert(g_key != NULL);
    status = sgx_read_rand((uint8_t *) g_key, sizeof(sgx_aes_gcm_128bit_key_t));
    assert(status == SGX_SUCCESS);
    
    g_local_counter = 0;
}

size_t path_oram_storage_access(size_t op, size_t addr, block_data_t data)
{
    if (addr == 0 && addr >= NUM_BLOCKS) {
        return -1; //block id 0 not allowed, so we actually support NUM_BLOCKS - 1
    }
    
    if (op == READ) {
        return auth_enc_storage_read_access(addr, data);
    }
    else if (op == WRITE) {
        return auth_enc_storage_write_access(addr, data);
    }
    else {
        return -1;
    }
}
