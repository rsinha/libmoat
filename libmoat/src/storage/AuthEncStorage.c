#include <stddef.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "../../api/libmoat.h"
#include "../../api/libmoat_untrusted.h"
#include "api/BlockStorage.h"
#include "../utils/api/Utils.h"

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

static uint64_t                   g_local_counter; //used as IV
static sgx_aes_gcm_128bit_key_t  *g_key;   //key used to protect file contents
static bool                       g_using_merkle_tree;
static sgx_sha256_hash_t         *g_latest_hash;   //for freshness

/***************************************************
 PRIVATE METHODS
 ***************************************************/

void integrity_check_freshness(size_t addr, uint8_t *ciphertext, size_t len)
{
    sgx_status_t status;
    size_t retstatus;

    if (g_using_merkle_tree) {
        sgx_sha256_hash_t *sibling_merkle_nodes = malloc(sizeof(sgx_sha256_hash_t) * log_base_2(NUM_BLOCKS));

        //ocall to read sibling nodes
        status = read_merkle_ocall(&retstatus, addr, sibling_merkle_nodes, log_base_2(NUM_BLOCKS));
        assert(status == SGX_SUCCESS && retstatus == 0);

        //start from height 0 and iterate till root to compute the hash
        sgx_sha256_hash_t computed_hash;
        status = sgx_sha256_msg(ciphertext, len, &computed_hash);
        assert(status == SGX_SUCCESS);

        uint8_t *to_hash = malloc(2 * sizeof(sgx_sha256_hash_t));
        assert(to_hash != NULL);

        size_t merkle_height = 0, width = 1;
        size_t left_low = addr, left_high = addr, right_low = addr, right_high = addr;
        while(merkle_height < log_base_2(NUM_BLOCKS))
        {
            size_t next_width = width * 2;
            size_t div = (addr - 1) / next_width;
            left_low = div * next_width + 1;
            left_high = div * next_width + width;
            right_low = div * next_width + width + 1;
            right_high = (div + 1) * next_width;

            //grab the sibling and use it as either left or right chunk of to_hash
            if (addr >= left_low && addr <= left_high) {
                memcpy(to_hash, &computed_hash, sizeof(sgx_sha256_hash_t));
                memcpy(to_hash + sizeof(sgx_sha256_hash_t), &(sibling_merkle_nodes[merkle_height]), sizeof(sgx_sha256_hash_t));
            }
            else {
                memcpy(to_hash, &(sibling_merkle_nodes[merkle_height]), sizeof(sgx_sha256_hash_t));
                memcpy(to_hash + sizeof(sgx_sha256_hash_t), &computed_hash, sizeof(sgx_sha256_hash_t));
            }

            status = sgx_sha256_msg(to_hash, 2 * sizeof(sgx_sha256_hash_t), &computed_hash);
            assert(status == SGX_SUCCESS);

            width = next_width;
            merkle_height = merkle_height + 1;
        }

        //computed_hash stores the computed root hash now
        assert(memcmp(g_latest_hash, &computed_hash, sizeof(sgx_sha256_hash_t)) == 0);

        //cleanup
        free(sibling_merkle_nodes);
        free(to_hash);
    }
    else {
        sgx_sha256_hash_t computed_hash;
        status = sgx_sha256_msg(ciphertext, len, &computed_hash);
        assert(status == SGX_SUCCESS);
        assert(memcmp(&(g_latest_hash[addr - 1]), &computed_hash, sizeof(computed_hash)) == 0);
    }
}

void integrity_record_freshness(size_t addr, uint8_t *ciphertext, size_t len)
{
    sgx_status_t status;
    size_t retstatus;

    if (g_using_merkle_tree) {
        sgx_sha256_hash_t *sibling_merkle_nodes = malloc(sizeof(sgx_sha256_hash_t) * log_base_2(NUM_BLOCKS));
        sgx_sha256_hash_t *written_merkle_nodes = malloc(sizeof(sgx_sha256_hash_t) * (log_base_2(NUM_BLOCKS) + 1));

        //ocall to read sibling nodes
        status = read_merkle_ocall(&retstatus, addr, sibling_merkle_nodes, log_base_2(NUM_BLOCKS));
        assert(status == SGX_SUCCESS && retstatus == 0);

        sgx_sha256_hash_t computed_hash;
        status = sgx_sha256_msg(ciphertext, len, &computed_hash);
        assert(status == SGX_SUCCESS);
        memcpy(&(written_merkle_nodes[0]), &computed_hash, sizeof(sgx_sha256_hash_t));

        uint8_t *to_hash = malloc(2 * sizeof(sgx_sha256_hash_t));
        assert(to_hash != NULL);

        size_t merkle_height = 0, width = 1;
        size_t left_low = addr, left_high = addr, right_low = addr, right_high = addr;

        while(merkle_height < log_base_2(NUM_BLOCKS))
        {
            size_t next_width = width * 2;
            size_t div = (addr - 1) / next_width;
            left_low = div * next_width + 1;
            left_high = div * next_width + width;
            right_low = div * next_width + width + 1;
            right_high = (div + 1) * next_width;

            //grab the sibling and use it as either left or right chunk of to_hash
            if (addr >= left_low && addr <= left_high) {
                memcpy(to_hash, &computed_hash, sizeof(sgx_sha256_hash_t));
                memcpy(to_hash + sizeof(sgx_sha256_hash_t), &(sibling_merkle_nodes[merkle_height]), sizeof(sgx_sha256_hash_t));
            }
            else {
                memcpy(to_hash, &(sibling_merkle_nodes[merkle_height]), sizeof(sgx_sha256_hash_t));
                memcpy(to_hash + sizeof(sgx_sha256_hash_t), &computed_hash, sizeof(sgx_sha256_hash_t));
            }

            status = sgx_sha256_msg(to_hash, 2 * sizeof(sgx_sha256_hash_t), &computed_hash);
            assert(status == SGX_SUCCESS);

            memcpy(&(written_merkle_nodes[merkle_height + 1]), &computed_hash, sizeof(sgx_sha256_hash_t));

            width = next_width;
            merkle_height = merkle_height + 1;
        }

        //save the new root
        memcpy(g_latest_hash, &computed_hash, sizeof(sgx_sha256_hash_t));

        //ocall to outsource written_merkle_nodes
        status = write_merkle_ocall(&retstatus, addr, written_merkle_nodes, log_base_2(NUM_BLOCKS) + 1);
        assert(status == SGX_SUCCESS && retstatus == 0);

        //cleanup
        free(sibling_merkle_nodes);
        free(written_merkle_nodes);
        free(to_hash);
    }
    else {
        status = sgx_sha256_msg(ciphertext, len, &(g_latest_hash[addr - 1]));
        assert(status == SGX_SUCCESS);
    }
}

//NOTE: addr ranges from 1 to NUM_BLOCKS
size_t auth_enc_storage_read_access(size_t addr, block_t data)
{
    sgx_status_t status;
    size_t retstatus;
    
    //NIST guidelines for using AES-GCM
    if (g_local_counter > ((uint32_t) -2)) { return -1; }
    
    size_t len = sizeof(fs_ciphertext_header_t) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + sizeof(block_t);
    //allocate memory for ciphertext
    uint8_t *ciphertext = (uint8_t *) malloc(len);
    assert(ciphertext != NULL);
    
    status = read_block_ocall(&retstatus, ciphertext, len, addr);
    assert(status == SGX_SUCCESS && retstatus == 0);
    
    assert(((fs_ciphertext_header_t *) ciphertext)->type == APPLICATION_DATA);
    assert(((fs_ciphertext_header_t *) ciphertext)->length == sizeof(block_t) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
    assert(((fs_ciphertext_header_t *) ciphertext)->addr == addr);
    
    uint8_t *payload = ciphertext + sizeof(fs_ciphertext_header_t);
    
    //preventing rollback attacks
    integrity_check_freshness(addr, ciphertext, len);
    
    /* ciphertext: header || IV || MAC || encrypted */
    status = sgx_rijndael128GCM_decrypt((const sgx_aes_gcm_128bit_key_t *) g_key, //key
                                        payload + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, //src
                                        sizeof(block_t), //src_len
                                        data, //dst
                                        payload, //iv
                                        SGX_AESGCM_IV_SIZE, //12 bytes
                                        NULL, //aad
                                        0, //0 bytes of AAD
                                        (const sgx_aes_gcm_128bit_tag_t *) (payload + SGX_AESGCM_IV_SIZE)); //mac
    assert(status == SGX_SUCCESS);
    
    free(ciphertext);
    return 0;
}

//NOTE: addr ranges from 1 to NUM_BLOCKS
//performs authenticated encryption of data, and writes it as a file
size_t auth_enc_storage_write_access(size_t addr, block_t data)
{
    sgx_status_t status;
    size_t retstatus;
    
    size_t len = sizeof(fs_ciphertext_header_t) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + sizeof(block_t);
    //allocate memory for ciphertext
    uint8_t *ciphertext = (uint8_t *) malloc(len);
    assert (ciphertext != NULL);
    
    ((fs_ciphertext_header_t *) ciphertext)->type = APPLICATION_DATA;
    ((fs_ciphertext_header_t *) ciphertext)->length = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + sizeof(block_t);
    ((fs_ciphertext_header_t *) ciphertext)->addr = addr;
    
    uint8_t *payload = ciphertext + sizeof(fs_ciphertext_header_t);
    
    //nonce is 32 bits of 0 followed by the message sequence number
    memcpy(payload + 0, &g_local_counter, sizeof(g_local_counter));
    memset(payload + sizeof(g_local_counter), 0, SGX_AESGCM_IV_SIZE - sizeof(g_local_counter));
    
    /* ciphertext: IV || MAC || encrypted */
    status = sgx_rijndael128GCM_encrypt((const sgx_aes_gcm_128bit_key_t *) g_key,
                                        data, /* input */
                                        sizeof(block_t), /* input length */
                                        payload + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, /* out */
                                        payload + 0, /* IV */
                                        SGX_AESGCM_IV_SIZE, /* 12 bytes of IV */
                                        NULL, /* additional data */
                                        0, /* zero bytes of additional data */
                                        (sgx_aes_gcm_128bit_tag_t *) (payload + SGX_AESGCM_IV_SIZE)); /* mac */
    assert(status == SGX_SUCCESS);
    
    //saving SHA-256 hash for future freshness checks
    integrity_record_freshness(addr, ciphertext, len);
    
    //so we don't reuse IVs
    g_local_counter = g_local_counter + 1;
    
    status = write_block_ocall(&retstatus, ciphertext, len, addr);
    assert(status == SGX_SUCCESS && retstatus == 0);
    
    free(ciphertext);
    return 0;
}

/***************************************************
 PUBLIC API
 ***************************************************/

//TODO: we need a better way for users to express space-time tradeoffs than "useMerkleTree"
void auth_enc_storage_module_init(bool useMerkleTree)
{
    sgx_status_t status;
    size_t retstatus;

    g_key = malloc(sizeof(sgx_aes_gcm_128bit_key_t));
    assert(g_key != NULL);
    status = sgx_read_rand((uint8_t *) g_key, sizeof(sgx_aes_gcm_128bit_key_t));
    assert(status == SGX_SUCCESS);

    g_using_merkle_tree = useMerkleTree;

    if (useMerkleTree) {
        g_latest_hash = malloc(sizeof(sgx_sha256_hash_t) * 1); //just the root
        assert(g_latest_hash != NULL);

        //this will be sent to the untrusted storage
        sgx_sha256_hash_t *outsourced_merkle_path = malloc(sizeof(sgx_sha256_hash_t) * (log_base_2(NUM_BLOCKS) + 1));

        //let's compute the height 0 hash of a zeroed block
        size_t to_hash_len = sizeof(fs_ciphertext_header_t) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + sizeof(block_t);
        uint8_t *to_hash = malloc(to_hash_len);
        assert(to_hash != NULL);
        memset(to_hash, 0, to_hash_len);

        size_t merkle_depth = log_base_2(NUM_BLOCKS);
        //merkle leaf is special as it only hashes the block
        status = sgx_sha256_msg(to_hash, to_hash_len, &(outsourced_merkle_path[merkle_depth]));
        assert(status == SGX_SUCCESS);

        while (merkle_depth > 0) {
            //left child and right child
            memcpy(to_hash, &(outsourced_merkle_path[merkle_depth]), sizeof(sgx_sha256_hash_t));
            memcpy(to_hash + sizeof(sgx_sha256_hash_t), &(outsourced_merkle_path[merkle_depth]), sizeof(sgx_sha256_hash_t));

            status = sgx_sha256_msg(to_hash, 2 * sizeof(sgx_sha256_hash_t), &(outsourced_merkle_path[merkle_depth - 1]));
            assert(status == SGX_SUCCESS);

            merkle_depth = merkle_depth - 1;
        }

        //ocall to create Merkle tree
        status = create_merkle_ocall(&retstatus, outsourced_merkle_path, log_base_2(NUM_BLOCKS) + 1, NUM_BLOCKS);
        assert(status == SGX_SUCCESS && retstatus == 0);

        free(outsourced_merkle_path);
        free(to_hash);
    }
    else {
        g_latest_hash = malloc(sizeof(sgx_sha256_hash_t) * NUM_BLOCKS);
        assert(g_latest_hash != NULL);
    }

    g_local_counter = 0;
}

size_t auth_enc_storage_access(size_t op, size_t addr, block_t data)
{
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
