#include <assert.h>
#include <string.h>

#include "sgx_trts.h"

 #include "../../../api/libmoat.h"
#include "../../../api/libmoat_untrusted.h"
#include "../../Utils/api/Utils.h"
#include "api/ChunkyStorage.h"

 /***************************************************
 DEFINITIONS FOR INTERNAL USE
 ***************************************************/
 
 //we store values as a collection of ordered chunks
#define MAX_CHUNK_SIZE 1024
//1 GB max value size
#define MAX_VALUE_SIZE 1073741824

//ciphertext expansion
#define aes_gcm_ciphertext_len(x) ((x) + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE)

typedef struct
{
    uint64_t untrusted_len;
    uint64_t num_chunks;
    uint64_t value_version;
} chunk_header_t;

/***************************************************
 PRIVATE METHODS
 ***************************************************/

/* size of 1 chunk */
uint64_t chunk_len(uint64_t len)
{
    /* each chunk is of the form chunk_size[64] || ciphertext[chunk_size] */
    return sizeof(uint64_t) + aes_gcm_ciphertext_len(len);
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

/***************************************************
 PUBLIC API IMPLEMENTATION
 ***************************************************/

/* size of entire payload */
uint64_t chunk_storage_payload_len(uint64_t len)
{
    /* payload is of the form header || chunk_1 || ... || chunk_n */
    uint64_t num_chunks = div_ceil(len, MAX_CHUNK_SIZE);
    uint64_t all_but_one_len = (num_chunks - 1) * chunk_len(MAX_CHUNK_SIZE);
    uint64_t last_chunk_len = chunk_len(len - MAX_CHUNK_SIZE * (num_chunks - 1));
    return sizeof(chunk_header_t) + all_but_one_len + last_chunk_len;
}

//TODO: allow for offsets
int64_t chunk_storage_write(
    cipher_ctx_t *ctx,
    uint8_t *dst,
    uint8_t *src,
    uint64_t src_len,
    uint64_t value_version,
    uint8_t *aad_prefix, /* supplied by caller */
    uint64_t aad_prefix_len)
{
    if (0 + src_len > MAX_VALUE_SIZE) { return -1; } //offset + len is more than allowed size

    chunk_header_t header;
    header.untrusted_len = chunk_storage_payload_len(src_len) - sizeof(chunk_header_t);
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
    if (offset + len > MAX_VALUE_SIZE) { return -1; } //offset + len is more than allowed size

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

        //should we grab some bytes from this block?
        if ((trusted_offset_reached + ptxt_chunk_size - 1) >= offset)
        {
            //additional associated data: computes HMAC over key || kv_header || chunk's offset
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