#include "sgx_tcrypto.h"
//#include "sgx_trts.h"

#include "api/Utils.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>

/***************************************************
        DEFINITIONS FOR INTERNAL USE
 ***************************************************/

#define SHA256_BLOCKSIZE 64

//sgx_status_t sgx_sha256_msg(const uint8_t *p_src, uint32_t src_len, sgx_sha256_hash_t *p_hash)

/***************************************************
                PRIVATE METHODS
 ***************************************************/


/***************************************************
            PUBLIC API IMPLEMENTATION
 ***************************************************/

//based on https://tools.ietf.org/html/rfc2104
//H(K XOR opad, H(K XOR ipad, text))
size_t hmac_sha256(uint8_t *key, size_t key_len, uint8_t *msg, size_t msg_len, sgx_sha256_hash_t *out)
{
    if (key_len > SHA256_BLOCKSIZE) { return -1; } //RFC doesn't cover this case
    
    uint8_t K[SHA256_BLOCKSIZE];
    size_t B = SHA256_BLOCKSIZE;
    uint8_t blk[SHA256_BLOCKSIZE];
    
    assert (K != NULL);
    
    //(1) append zeros to the end of K to create a B byte string
    //    (e.g., if K is of length 20 bytes and B=64, then K will be appended with 44 bytes of 0x00)
    memset(K, 0, B);
    memcpy(K, key, key_len);
    
    //(2) XOR (bitwise exclusive-OR) the B byte string computed in step (1) with ipad
    for (size_t i = 0; i < B; i++) { blk[i] = K[i] ^ 0x36; }
    
    //(3) append the stream of data 'text' to the B byte string resulting from step (2)
    uint8_t *i_key_pad_concat_msg = malloc(B + msg_len);
    assert(i_key_pad_concat_msg != NULL);
    memcpy(i_key_pad_concat_msg, blk, B);
    memcpy(i_key_pad_concat_msg + B, msg, msg_len);
    
    //(4) apply H to the stream generated in step (3)
    sgx_status_t status = sgx_sha256_msg(i_key_pad_concat_msg, B + msg_len, out);
    assert(status == SGX_SUCCESS);
    
    free(i_key_pad_concat_msg);
    
    //(5) XOR (bitwise exclusive-OR) the B byte string computed in step (1) with opad
    for (size_t i = 0; i < B; i++) { blk[i] = K[i] ^ 0x5c; }
    
    //(6) append the H result from step (4) to the B byte string resulting from step (5)
    uint8_t *o_key_pad_concat_hash = malloc(B + sizeof(sgx_sha256_hash_t));
    assert(o_key_pad_concat_hash != NULL);
    memcpy(o_key_pad_concat_hash, blk, B);
    memcpy(o_key_pad_concat_hash + B, out, sizeof(sgx_sha256_hash_t));
    
    //(7) apply H to the stream generated in step (6) and output the result
    status = sgx_sha256_msg(o_key_pad_concat_hash, B + sizeof(sgx_sha256_hash_t), out);
    assert(status == SGX_SUCCESS);
    
    free(o_key_pad_concat_hash);
    
    return 0;
}

//based on https://tools.ietf.org/html/rfc5869
size_t hkdf(uint8_t *ikm, size_t ikm_len, uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len)
{
    sgx_sha256_hash_t prk;
    
    //Input: optional salt value (a non-secret random value); if not provided, it is set to a string of HashLen zeros.
    //Input: input keying material
    //Output: a pseudorandom key (of HashLen octets)
    //PRK = HMAC-Hash(salt, IKM)
    size_t status = hmac_sha256("", 0, ikm, ikm_len, &prk);
    assert(status == 0);
    
    //Input: PRK, a pseudorandom key of at least HashLen octets (usually, the output from the extract step)
    //Input: info, an optional context and application specific information (can be a zero-length string)
    //Input: L, length of output keying material in octets (<= 255*HashLen)
    //N = ceil(L/HashLen)
    //T = T(1) | T(2) | T(3) | ... | T(N)
    //OKM = first L octets of T
    
    //where:
    //T(0) = empty string (zero length)
    //T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
    //T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
    //T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
    //...
    size_t L = okm_len;
    size_t N = L / sizeof(sgx_sha256_hash_t);
    if (L > N * sizeof(sgx_sha256_hash_t)) { N = N + 1; }
    assert(N <= 255);
    
    uint8_t *hash_msg = malloc(sizeof(sgx_sha256_hash_t) + info_len + 1);
    assert(hash_msg != NULL);
    
    sgx_sha256_hash_t T_i;
    //compute T(1), which is special because T(0) is an empty string
    //hash_msg = T(0) | info | 0x01
    memcpy(hash_msg, info, info_len);
    memset(hash_msg + info_len, 0x01, 1);
    //T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
    status = hmac_sha256((uint8_t *) &prk, sizeof(prk), hash_msg, info_len + 1, &T_i);
    assert(status == 0);
    
    memcpy(okm, &T_i, min(L, sizeof(T_i)));
    L = L - min(L, sizeof(T_i));
    
    size_t i = 1; //we already did T(1)
    while (i < N)
    {
        //hash_msg = T(i) | info | i+1
        memcpy(hash_msg, &T_i, sizeof(T_i));
        memcpy(hash_msg + sizeof(T_i), info, info_len);
        memset(hash_msg + sizeof(T_i) + info_len, (uint8_t) i + 1, 1);
        //T(i+1) = HMAC-Hash(PRK, T(i) | info | i+1)
        status = hmac_sha256((uint8_t *) &prk, sizeof(prk), hash_msg, sizeof(sgx_sha256_hash_t) + info_len + 1, &T_i);
        assert(status == 0);
        
        memcpy(okm + i * sizeof(T_i), &T_i, min(L, sizeof(T_i)));
        L = L - min(L, sizeof(T_i));
    }
    
    free(hash_msg);
    return 0;
}

