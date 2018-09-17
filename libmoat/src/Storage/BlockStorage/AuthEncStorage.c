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

/***************************************************
 INTERNAL STATE
 ***************************************************/

static sgx_sha256_hash_t     *g_latest_hash;   //for freshness
static size_t                 g_num_blocks;

/***************************************************
 PRIVATE METHODS
 ***************************************************/

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

/***************************************************
 PUBLIC API
 ***************************************************/

//TODO: we need a better way for users to express space-time tradeoffs than "useMerkleTree"
void auth_enc_storage_module_init(size_t num_blocks)
{
    sgx_status_t status;
    size_t retstatus;

    g_num_blocks = num_blocks;

    g_latest_hash = malloc(sizeof(sgx_sha256_hash_t) * num_blocks);
    assert(g_latest_hash != NULL);
}

//NOTE: addr ranges from 1 to g_num_blocks
size_t auth_enc_storage_read(cipher_ctx_t *ctx, size_t addr, block_data_t data)
{
    sgx_status_t status;
    size_t retstatus;
    
    /* error checking */
    if (addr >= g_num_blocks) { return -1; }

    //allocate memory for ciphertext
    uint8_t ciphertext[sizeof(fs_ciphertext_header_t) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + sizeof(block_data_t)];
    assert(ciphertext != NULL);
    
    status = fs_read_block_ocall(&retstatus, addr, ciphertext, sizeof(ciphertext));
    assert(status == SGX_SUCCESS && retstatus == 0);
    
    assert(((fs_ciphertext_header_t *) ciphertext)->type == APPLICATION_DATA);
    assert(((fs_ciphertext_header_t *) ciphertext)->length == sizeof(block_data_t) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
    assert(((fs_ciphertext_header_t *) ciphertext)->addr == addr);
    
    uint8_t *payload = ciphertext + sizeof(fs_ciphertext_header_t);
    
    //preventing rollback attacks
    integrity_check_freshness(addr, ciphertext, sizeof(ciphertext));
    
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
size_t auth_enc_storage_write(cipher_ctx_t *ctx, size_t addr, block_data_t data)
{
    sgx_status_t status;
    size_t retstatus;

    /* error checking */
    if (addr >= g_num_blocks) { return -1; }

    size_t iv_counter = ctx->counter;
    //NIST guidelines for using AES-GCM
    if (iv_counter > ((uint32_t) -2)) { return -1; }

    //allocate memory for ciphertext
    uint8_t ciphertext[sizeof(fs_ciphertext_header_t) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + sizeof(block_data_t)];
    assert (ciphertext != NULL);
    
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
    integrity_record_freshness(addr, ciphertext, sizeof(ciphertext));
    
    //so we don't reuse IVs
    ctx->counter = ctx->counter + 1;
    
    status = fs_write_block_ocall(&retstatus, addr, ciphertext, sizeof(ciphertext));
    assert(status == SGX_SUCCESS && retstatus == 0);

    return 0;
}
