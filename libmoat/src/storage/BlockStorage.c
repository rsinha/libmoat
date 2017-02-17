#include <stddef.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "../../api/libmoat.h"
#include "../../api/libmoat_untrusted.h"
#include "api/BlockStorage.h"

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
} fs_ciphertext_header_t;

/***************************************************
                INTERNAL STATE
 ***************************************************/

static size_t g_local_counter = 0;
static sgx_aes_gcm_128bit_key_t g_key;

/***************************************************
                PRIVATE METHODS
 ***************************************************/

size_t read_access(size_t addr, block_t data)
{
    sgx_status_t status;
    size_t retstatus;
    size_t actual_len; //how much data has the ocall given us?

    //allocate memory for ciphertext
    uint8_t *ciphertext = (uint8_t *) malloc(sizeof(fs_ciphertext_header_t) +
                                             SGX_AESGCM_IV_SIZE +
                                             SGX_AESGCM_MAC_SIZE +
                                             sizeof(block_t));
    assert(ciphertext != NULL);
    
    //fetch the ciphertext
    //status = read_file_ocall(&retstatus, ciphertext, header->length, &actual_len, ...);
    //assert(status == SGX_SUCCESS && retstatus == 0);
    assert(((fs_ciphertext_header_t *) ciphertext)->length ==
           sizeof(block_t) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
    
    uint8_t *payload = ciphertext + sizeof(fs_ciphertext_header_t);
    
    /* ciphertext: header || IV || MAC || encrypted */
    status = sgx_rijndael128GCM_decrypt(g_key, //key
                                        payload + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, //src
                                        sizeof(block_t), //src_len
                                        data, //dst
                                        payload, //iv
                                        SGX_AESGCM_IV_SIZE, //12 bytes
                                        NULL, //aad
                                        0, //0 bytes of AAD
                                        (const sgx_aes_gcm_128bit_tag_t *) (ciphertext + SGX_AESGCM_IV_SIZE)); //mac
    assert(status == SGX_SUCCESS);
    
    free(ciphertext);
    return 0;
}

//performs authenticated encryption of data, and writes it as a file
size_t write_access(size_t addr, block_t data)
{
    sgx_status_t status;
    size_t retstatus;
    
    //allocate memory for ciphertext
    uint8_t *ciphertext = (uint8_t *) malloc(sizeof(fs_ciphertext_header_t) +
                                             SGX_AESGCM_IV_SIZE +
                                             SGX_AESGCM_MAC_SIZE +
                                             sizeof(block_t));
    assert (ciphertext != NULL);
    
    ((fs_ciphertext_header_t *) ciphertext)->type = APPLICATION_DATA;
    ((fs_ciphertext_header_t *) ciphertext)->length = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + sizeof(block_t);
    
    uint8_t *payload = ciphertext + sizeof(fs_ciphertext_header_t);
    
    //nonce is 64 bits of 0 followed by the message sequence number
    memcpy(payload + 0, &g_local_counter, sizeof(g_local_counter));
    memset(payload + sizeof(g_local_counter), 0, SGX_AESGCM_IV_SIZE - sizeof(g_local_counter));
    
    /* ciphertext: IV || MAC || encrypted */
    status = sgx_rijndael128GCM_encrypt(g_key,
                                        data, /* input */
                                        sizeof(block_t), /* input length */
                                        payload + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, /* out */
                                        payload + 0, /* IV */
                                        SGX_AESGCM_IV_SIZE, /* 12 bytes of IV */
                                        NULL, /* additional data */
                                        0, /* zero bytes of additional data */
                                        (sgx_aes_gcm_128bit_tag_t *) (payload + SGX_AESGCM_IV_SIZE)); /* mac */
    assert(status == SGX_SUCCESS);
    
    //so we don't reuse IVs
    g_local_counter = g_local_counter + 1;
    
    //status = write_file_ocall(retstatus, ...);
    //assert(status == SGX_SUCCESS && retstatus == 0);
    
    free(ciphertext);
    return 0;
}

/***************************************************
                    PUBLIC API
 ***************************************************/

size_t access(size_t op, size_t addr, block_t data)
{
    if (op == READ) {
        return read_access(addr, data);
    } else if (op == WRITE) {
        return write_access(addr, data);
    } else {
        return 1;
    }
}
