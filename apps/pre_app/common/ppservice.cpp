#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cassert>
#include <sys/time.h>

using namespace std;

#include "proxylib_api.h"
#include "proxylib.h"
#include "proxylib_pre1.h"
#include "proxylib_pre2.h"

#include "drng.h"

std::string status_msg(bool b)
{
    return b ?  " ... OK" : " ... FAILED";
}

void print_char_arr_to_hex_str(char *data, size_t len)
{
    for(int i=len-1; i >= 0; i--) {
        printf("%02x", (unsigned char) data[i]);
    }
}

void generate_random_key(char *key, size_t len)
{
    for (int i = 0; i < len; i++)
    {
        uint32_t r;
        while(rdrand_get_n_uints(1, &r) != 1) { }
        key[i] = (char) (r % 256);
    }
}

typedef enum {
    SUCCESS = 0,
    ERROR_INSUFFICIENT_MEMORY,
    ERROR_INIT_LIBRARY,
    ERROR_GENERATE_PARAMS,
    ERROR_SERIALIZE_PARAMS,
    ERROR_DESERIALIZE_PARAMS,
    ERROR_PKSK_KEYGEN,
    ERROR_RK_KEYGEN,
    ERROR_SERIALIZE_PK,
    ERROR_DESERIALIZE_PK,
    ERROR_SERIALIZE_SK,
    ERROR_DESERIALIZE_SK,
    ERROR_SERIALIZE_RK,
    ERROR_DESERIALIZE_RK,
    ERROR_ENCRYPTING,
    ERROR_REENCRYPTING,
    ERROR_SERIALIZE_CTXT,
    ERROR_DESERIALIZE_CTXT,
    ERROR_DECRYPTING,
    ERROR_SERIALIZE_MSG
} pureprivacy_result_t;


pureprivacy_result_t pureprivacy_generate_params(
    char *params_buf, int params_buf_len, int *params_buf_len_used)
{
    CurveParams gParams;

    if (!initLibrary()) { 
        return ERROR_INIT_LIBRARY;
    }

    if (!PRE2_generate_params(gParams)) { 
        return ERROR_GENERATE_PARAMS;
    }

    int requested_len = gParams.getSerializedSize(SERIALIZE_BINARY);
    if (requested_len > params_buf_len) { 
        return ERROR_INSUFFICIENT_MEMORY; 
    }

    int actual_len = gParams.serialize(SERIALIZE_BINARY, params_buf, requested_len);
    if (actual_len == 0) {
        return ERROR_SERIALIZE_PARAMS; 
    }

    *params_buf_len_used = actual_len;
    return SUCCESS;
}

pureprivacy_result_t pureprivacy_generate_keypair(
    char *params_buf, int params_buf_len, //input
    char *pk_buf, int pk_buf_len, int *pk_buf_len_used, //output
    char *sk_buf, int sk_buf_len, int *sk_buf_len_used) //output
{
    ProxyPK_PRE2 pk;
    ProxySK_PRE2 sk;

    CurveParams gParams;
    if (! gParams.deserialize(SERIALIZE_BINARY, params_buf, params_buf_len) ) { 
        return ERROR_DESERIALIZE_PARAMS; 
    }

    if (!PRE2_keygen(gParams, pk, sk)) { 
        return ERROR_PKSK_KEYGEN; 
    }
    
    //serialize pk
    if (pk.getSerializedSize(SERIALIZE_BINARY) > pk_buf_len) { 
        return ERROR_INSUFFICIENT_MEMORY;
    }
    int actual_len = pk.serialize(SERIALIZE_BINARY, pk_buf, pk_buf_len);
    if (actual_len == 0) { 
        return ERROR_SERIALIZE_PK;
    }
    *pk_buf_len_used = actual_len;

    //serialize sk
    if (sk.getSerializedSize(SERIALIZE_BINARY) > sk_buf_len) { 
        return ERROR_INSUFFICIENT_MEMORY;
    }
    actual_len = sk.serialize(SERIALIZE_BINARY, sk_buf, sk_buf_len);
    if (actual_len == 0) { return ERROR_SERIALIZE_SK; }
    *sk_buf_len_used = actual_len;

    return SUCCESS;
}

pureprivacy_result_t pureprivacy_generate_delegation_key(
    char *params_buf, int params_buf_len, //input
    char *pk_buf, int pk_buf_len, //input
    char *sk_buf, int sk_buf_len, //input
    char *rk_buf, int rk_buf_len, int *rk_buf_len_used) //output
{
    DelegationKey_PRE2 rk;
    ProxyPK_PRE2 pk;
    ProxySK_PRE2 sk;

    CurveParams gParams;
    if (! gParams.deserialize(SERIALIZE_BINARY, params_buf, params_buf_len) ) { 
        return ERROR_DESERIALIZE_PARAMS; 
    }

    //reconstruct pk
    if (!pk.deserialize(SERIALIZE_BINARY, pk_buf, pk_buf_len)) {
        return ERROR_DESERIALIZE_PK;
    }

    //reconstruct sk
    if (!sk.deserialize(SERIALIZE_BINARY, sk_buf, sk_buf_len)) {
        return ERROR_DESERIALIZE_PK;
    }

    if (!PRE2_delegate(gParams,pk, sk, rk)) {
        return ERROR_RK_KEYGEN;
    }

    int len = SerializeDelegationKey_PRE2(rk, SERIALIZE_BINARY, rk_buf, rk_buf_len);
    if (len > rk_buf_len || len == 0) {
        return ERROR_SERIALIZE_RK;
    }

    *rk_buf_len_used = len;
    return SUCCESS;
}

pureprivacy_result_t pureprivacy_encrypt(
    char *params_buf, int params_buf_len, //input
    char *pk_buf, int pk_buf_len, //input
    char *msg_buf, int msg_buf_len, //input
    char *ctxt_buf, int ctxt_buf_len, int *ctxt_buf_len_used) 
{
    CurveParams gParams;
    if (! gParams.deserialize(SERIALIZE_BINARY, params_buf, params_buf_len) ) { 
        return ERROR_DESERIALIZE_PARAMS; 
    }

    ProxyPK_PRE2 pk;
    //reconstruct pk
    if (!pk.deserialize(SERIALIZE_BINARY, pk_buf, pk_buf_len)) {
        return ERROR_DESERIALIZE_PK;
    }

    Big msg_as_big = from_binary(msg_buf_len, msg_buf);
    //cout << "msg_as_big: " << msg_as_big << endl;
    
    ProxyCiphertext_PRE2 ctxt;
    if(! PRE2_level2_encrypt(gParams, msg_as_big, pk, ctxt)) {
        return ERROR_ENCRYPTING;
    }

    int len = ctxt.serialize(SERIALIZE_BINARY, ctxt_buf, ctxt_buf_len);
    if (len > ctxt_buf_len || len == 0) {
        return ERROR_SERIALIZE_CTXT;
    }

    *ctxt_buf_len_used = len;
    return SUCCESS;
}

pureprivacy_result_t pureprivacy_reencrypt(
    char *params_buf, int params_buf_len, //input
    char *rk_buf, int rk_buf_len, //input
    char *in_ctxt_buf, int in_ctxt_buf_len, //input
    char *out_ctxt_buf, int out_ctxt_buf_len, int *out_ctxt_buf_len_used) //output
{
    CurveParams gParams;
    if (! gParams.deserialize(SERIALIZE_BINARY, params_buf, params_buf_len) ) { 
        return ERROR_DESERIALIZE_PARAMS; 
    }

    DelegationKey_PRE2 rk;
    if (! DeserializeDelegationKey_PRE2(rk, SERIALIZE_BINARY, rk_buf, rk_buf_len)) {
        return ERROR_DESERIALIZE_RK;
    }
    
    ProxyCiphertext_PRE2 in_ctxt, out_ctxt;
    if (!in_ctxt.deserialize(SERIALIZE_BINARY, in_ctxt_buf, in_ctxt_buf_len)) {
        return ERROR_DESERIALIZE_CTXT;
    }
    
    if (! PRE2_reencrypt(gParams, in_ctxt, rk, out_ctxt)) {
        return ERROR_REENCRYPTING;
    }

    int len = out_ctxt.serialize(SERIALIZE_BINARY, out_ctxt_buf, out_ctxt_buf_len);
    if (len > out_ctxt_buf_len || len == 0) {
        return ERROR_SERIALIZE_CTXT;
    }

    *out_ctxt_buf_len_used = len;
    return SUCCESS;
}

pureprivacy_result_t pureprivacy_decrypt(
    char *params_buf, int params_buf_len, //input
    char *sk_buf, int sk_buf_len, //input
    char *ctxt_buf, int ctxt_buf_len, //input
    char *msg_buf, int msg_buf_len, int *msg_buf_len_used) //output
{
    CurveParams gParams;
    if (! gParams.deserialize(SERIALIZE_BINARY, params_buf, params_buf_len) ) { 
        return ERROR_DESERIALIZE_PARAMS; 
    }

    ProxySK_PRE2 sk;
    //reconstruct sk
    if (!sk.deserialize(SERIALIZE_BINARY, sk_buf, sk_buf_len)) {
        return ERROR_DESERIALIZE_SK;
    }

    ProxyCiphertext_PRE2 ctxt;
    if (!ctxt.deserialize(SERIALIZE_BINARY, ctxt_buf, ctxt_buf_len)) {
        return ERROR_DESERIALIZE_CTXT;
    }

    Big msg_as_big;
    if(! PRE2_decrypt(gParams, ctxt, sk, msg_as_big)) {
        return ERROR_DECRYPTING;
    }
    //cout << "msg_as_big: " << msg_as_big << endl;

    int len = to_binary(msg_as_big, msg_buf_len, msg_buf, FALSE);    
    if (len != msg_buf_len) { return ERROR_SERIALIZE_MSG; }

    *msg_buf_len_used = len;
    return SUCCESS;
}

int test3()
{
    char pk_p[1000];
    char sk_p[1000];
    char pk_c[1000];
    char sk_c[1000];
    char rk_p_c[1000];
    char params[1000];

    pureprivacy_result_t result;
    
    int params_len;
    result = pureprivacy_generate_params(params, sizeof(params), &params_len);
    cout << ". Generated curve parameters" << status_msg(result == SUCCESS) << endl;
    //cout << "Got params len " << params_len << endl;

    int pk_p_len, sk_p_len;
    result = pureprivacy_generate_keypair(
        params, params_len,
        pk_p, sizeof(pk_p), &pk_p_len, 
        sk_p, sizeof(sk_p), &sk_p_len);
    cout << ". Generated producer's keys" << status_msg(result == SUCCESS) << endl;
    //cout << "Got pk len " << pk_p_len << " sk len " << sk_p_len << endl;

    int pk_c_len, sk_c_len;
    result = pureprivacy_generate_keypair(
        params, params_len,
        pk_c, sizeof(pk_c), &pk_c_len, 
        sk_c, sizeof(sk_c), &sk_c_len);
    cout << ". Generated consumer's keys" << status_msg(result == SUCCESS) << endl;
    //cout << "Got pk len " << pk_c_len << " sk len " << sk_c_len << endl;

    int rk_p_c_len;
    result = pureprivacy_generate_delegation_key(
        params, params_len,
        pk_c, pk_c_len, 
        sk_p, sk_p_len, 
        rk_p_c, sizeof(rk_p_c), &rk_p_c_len);
    cout << ". Generated re-encryption keys" << status_msg(result == SUCCESS) << endl;
    //cout << "Got rk len " << rk_p_c_len << endl;

    char kek[16];
    generate_random_key(kek, 16);
    cout << "choosing key "; print_char_arr_to_hex_str(kek, 16); cout << endl;

    char ctxt_p[1000];
    int ctxt_p_len;
    result = pureprivacy_encrypt(
        params, params_len,
        pk_p, pk_p_len, 
        kek, 16, 
        ctxt_p, sizeof(ctxt_p), &ctxt_p_len);
    cout << ". Encrypted plaintext at producer" << status_msg(result == SUCCESS) << endl;
    //cout << "Got ctxt len " << ctxt_p_len << endl;
    
    char ctxt_c[1000];
    int ctxt_c_len;
    result = pureprivacy_reencrypt(
        params, params_len,
        rk_p_c, rk_p_c_len, 
        ctxt_p, ctxt_p_len, 
        ctxt_c, sizeof(ctxt_c), &ctxt_c_len);
    cout << ". Reencrypted ciphertext at proxy" << status_msg(result == SUCCESS) << endl;
    //cout << "Got ctxt len " << ctxt_c_len << endl;

    char kek_decrypted[16];
    int kek_decrypted_len;
    result = pureprivacy_decrypt(
        params, params_len,
        sk_c, sk_c_len,
        ctxt_c, ctxt_c_len,
        kek_decrypted, sizeof(kek_decrypted), &kek_decrypted_len);
    cout << ". Decrypted ciphertext at consumer" << status_msg(result == SUCCESS) << endl;
    //cout << "Got msg len " << kek_decrypted_len << endl;
    cout << "got key "; print_char_arr_to_hex_str(kek_decrypted, 16); cout << endl;
}


void test1()
{
    cout << "----------------------------------------" << endl;
    cout << "Pure Privacy Proxy Re-encryption Service" << endl;
    cout << "----------------------------------------" << endl;

    cout << ". Initializing library";
    if (initLibrary() == FALSE)
    {
        cout << " ... FAILED" << endl;
        std::exit(1);
    }
    else
    {
        cout << " ... OK" << endl;
    }

    //
    // Parameter generation test
    //
    CurveParams gParams;
    cout << ". Generating curve parameters";
    bool success = PRE2_generate_params(gParams);
    cout << status_msg(success) << endl;

    //
    // Key generation tests
    //
    cout << ". Generating keypair 1";
    ProxyPK_PRE2 ppk1;
    ProxySK_PRE2 ssk1;
    success = PRE2_keygen(gParams, ppk1, ssk1);
    cout << status_msg(success) << endl;

    cout << ". Generating keypair 2";
    ProxyPK_PRE2 ppk2;
    ProxySK_PRE2 ssk2;
    success = PRE2_keygen(gParams, ppk2, ssk2);
    cout << status_msg(success) << endl;

    //
    // Re-encryption key generation test
    //
    ECn delKey;
    cout << ". Re-encryption key generation test ";
    // Generate a delegation key from user1->user2
    success = PRE2_delegate(gParams, ppk2, ssk1, delKey);
    cout << status_msg(success) << endl;

    //
    // First-level encryption/decryption test
    //
    cout << ". First-level encryption/decryption test ";
    Big original_msg = 100;
    Big decrypted_msg = 0;
    ProxyCiphertext_PRE2 producer_ciphertext;
    bool success1 = PRE2_level1_encrypt(gParams, original_msg, ppk1, producer_ciphertext);
    bool success2 = PRE2_decrypt(gParams, producer_ciphertext, ssk1, decrypted_msg);
    success = (original_msg == decrypted_msg) && success1 && success2;
    cout << status_msg(success) << endl;

    //
    // Second-level encryption/decryption test
    //
    cout << ". Second-level encryption/decryption test ";
    original_msg = 100;
    decrypted_msg = 0;
    success1 = PRE2_level2_encrypt(gParams, original_msg, ppk1, producer_ciphertext);
    success2 = PRE2_decrypt(gParams, producer_ciphertext, ssk1, decrypted_msg);
    success = (original_msg == decrypted_msg) && success1 && success2;
    cout << status_msg(success) << endl;

    //
    // Re-encryption test
    //
    ProxyCiphertext_PRE2 consumer_ciphertext;
    decrypted_msg = 0;
    cout << ". Re-encryption/decryption test ";
    // Re-encrypt ciphertext from user1->user2 using delKey
    success1 = PRE2_reencrypt(gParams, producer_ciphertext, delKey, consumer_ciphertext);
    success2 = PRE2_decrypt(gParams, consumer_ciphertext, ssk2, decrypted_msg);
    success = (original_msg == decrypted_msg) && success1 && success2;
    cout << status_msg(success) << endl;

    //
    // Proxy invisibility test
    //
    // We take the re-encrypted ciphertext from the previous test
    // and mark it as a first-level ciphertext.  Decryption
    // should still work just fine.
    //
    cout << ". Proxy invisibility test ";
    consumer_ciphertext.type = CIPH_FIRST_LEVEL;
    // Decrypt the ciphertext
    success1 = PRE2_decrypt(gParams, consumer_ciphertext, ssk2, decrypted_msg);
    success = (original_msg == decrypted_msg) && success1;
    cout << status_msg(success) << endl;

    //
    // Serialization/Deserialization test
    //
    char buffer[1000];
    bool serTestResult = TRUE;
    cout << ". Serialization/deserialization tests";

    int serialSize = SerializeDelegationKey_PRE2(delKey, SERIALIZE_BINARY, buffer, 1000);
    serTestResult = serTestResult && (serialSize != 0);
    DelegationKey_PRE2 rk;
    BOOL x = DeserializeDelegationKey_PRE2(rk, SERIALIZE_BINARY, buffer, serialSize);
    serTestResult = serTestResult && (x != 0) && (rk == delKey);

    // Serialize a public key
    serialSize = ppk1.serialize(SERIALIZE_BINARY, buffer, 1000);
    ProxyPK_PRE2 nnewpk;
    nnewpk.deserialize(SERIALIZE_BINARY, buffer, serialSize);
    serTestResult = serTestResult && (nnewpk == ppk1);

    // Serialize a secret key
    serialSize = ssk1.serialize(SERIALIZE_BINARY, buffer, 1000);
    ProxySK_PRE2 nnewsk1;
    nnewsk1.deserialize(SERIALIZE_BINARY, buffer, serialSize);
    serTestResult = serTestResult && (nnewsk1 == ssk1);

    // Serialize a ciphertext
    serialSize = consumer_ciphertext.serialize(SERIALIZE_BINARY, buffer, 1000);
    ProxyCiphertext_PRE2 nnewerCiphertext;
    nnewerCiphertext.deserialize(SERIALIZE_BINARY, buffer, serialSize);
    serTestResult = serTestResult && (nnewerCiphertext == consumer_ciphertext);

    // Searialize curve parameters
    serialSize = gParams.getSerializedSize(SERIALIZE_BINARY);
    char *params_buf = (char *) malloc(serialSize * sizeof(char));
    assert(params_buf != NULL);
    gParams.serialize(SERIALIZE_BINARY, params_buf, serialSize);
    CurveParams newParams;
    newParams.deserialize(SERIALIZE_BINARY, params_buf, serialSize);
    serTestResult = serTestResult && (newParams == gParams);

    cout << status_msg(serTestResult) << endl;

    cout << endl << "All tests complete." << endl;
}

int test2()
{
    cout << "----------------------------------------" << endl;
    cout << "Pure Privacy Proxy Re-encryption Service" << endl;
    cout << "----------------------------------------" << endl;

    cout << ". Initializing library";
    if (initLibrary() == FALSE)
    {
        cout << " ... FAILED" << endl;
        std::exit(1);
    }
    else
    {
        cout << " ... OK" << endl;
    }

    //
    // Parameter generation test
    //
    CurveParams gParams;
    cout << ". Generating curve parameters";
    bool success = PRE2_generate_params(gParams);
    cout << status_msg(success) << endl;

    cout << ". Generating KEK";
    char aes_key[16]; 
    Big aes_key_as_big;
    generate_random_key(aes_key, 16);
    //cout << "Random key: "; print_char_arr_to_hex_str(aes_key, 16); cout << endl;
    aes_key_as_big = from_binary(16, aes_key);
    char aes_key_again[16];
    int aes_key_again_len = to_binary(aes_key_as_big, 16, aes_key_again, TRUE);
    //cout << "Reconstructed key: "; print_char_arr_to_hex_str(aes_key_again, 16); cout << endl;

    cout << status_msg(memcmp(aes_key, aes_key_again, 16) == 0) << endl;

    cout << "choosing key "; print_char_arr_to_hex_str(aes_key, 16); cout << endl;

    //char aes_key_again[16];
    //int aes_key_again_len;
    //success = decodePlaintextFromBig(gParams, aes_key_again, 16, &aes_key_again_len, aes_key_as_big);
    //cout << "decoding key back, length " << aes_key_again_len << endl;
    //cout << status_msg(success) << endl;

    //
    // Key generation tests
    //
    cout << ". Generating keypair 1";
    ProxyPK_PRE2 ppk1;
    ProxySK_PRE2 ssk1;
    success = PRE2_keygen(gParams, ppk1, ssk1);
    cout << status_msg(success) << endl;

    cout << ". Generating keypair 2";
    ProxyPK_PRE2 ppk2;
    ProxySK_PRE2 ssk2;
    success = PRE2_keygen(gParams, ppk2, ssk2);
    cout << status_msg(success) << endl;

    //
    // Re-encryption key generation test
    //
    ECn delKey;
    cout << ". Re-encryption key generation test ";
    // Generate a delegation key from user1->user2
    success = PRE2_delegate(gParams, ppk2, ssk1, delKey);
    cout << status_msg(success) << endl;

    //
    // enceypt
    //
    Big original_msg = aes_key_as_big;
    Big decrypted_msg = 0;
    ProxyCiphertext_PRE2 producer_ciphertext;

    cout << ". Second-level encryption/decryption test ";
    bool success1 = PRE2_level2_encrypt(gParams, original_msg, ppk1, producer_ciphertext);
    bool success2 = PRE2_decrypt(gParams, producer_ciphertext, ssk1, decrypted_msg);
    success = (original_msg == decrypted_msg) && success1 && success2;
    cout << status_msg(success) << endl;

    //
    // Re-encryption
    //
    ProxyCiphertext_PRE2 consumer_ciphertext;
    decrypted_msg = 0;
    cout << ". Re-encryption/decryption test ";
    // Re-encrypt ciphertext from user1->user2 using delKey
    success1 = PRE2_reencrypt(gParams, producer_ciphertext, delKey, consumer_ciphertext);
    success2 = PRE2_decrypt(gParams, consumer_ciphertext, ssk2, decrypted_msg);
    success = (original_msg == decrypted_msg) && success1 && success2;
    cout << status_msg(success) << endl;

    char msg_buf[16]; memset(msg_buf, 0, 16);
    int len = to_binary(decrypted_msg, 16, msg_buf, TRUE);
    assert(memcmp(aes_key, msg_buf, 16) == 0);
    cout << "got key "; print_char_arr_to_hex_str(msg_buf, 16); cout << endl;

    //
    // Serialization/Deserialization test
    //
    char buffer[1000];
    bool serTestResult = TRUE;

    int serialSize = SerializeDelegationKey_PRE2(delKey, SERIALIZE_BINARY, buffer, 1000);
    serTestResult = serTestResult && (serialSize != 0);

    //cout << "delKey serialized to size " << serialSize << 
    //    " with contents ";
    //print_char_arr_to_hex_str(buffer, serialSize); cout << endl << endl;

    DelegationKey_PRE2 rk;
    BOOL x = DeserializeDelegationKey_PRE2(rk, SERIALIZE_BINARY, buffer, serialSize);
    serTestResult = serTestResult && (x != 0) && (rk == delKey);

    //serialSize = SerializeDelegationKey_PRE2(rk, SERIALIZE_BINARY, buffer, 1000);
    //cout << "rk serialized to size " << serialSize << 
    //    " with contents ";
    //print_char_arr_to_hex_str(buffer, serialSize); cout << endl << endl;

    // Serialize a public key
    serialSize = ppk1.serialize(SERIALIZE_BINARY, buffer, 1000);
    //cout << "public key serialized to size " << serialSize << 
    //    " with contents ";
    //print_char_arr_to_hex_str(buffer, serialSize); cout << endl << endl;
    ProxyPK_PRE2 nnewpk;
    nnewpk.deserialize(SERIALIZE_BINARY, buffer, serialSize);
    serTestResult = serTestResult && (nnewpk == ppk1);

    // Serialize a secret key
    serialSize = ssk1.serialize(SERIALIZE_BINARY, buffer, 1000);
    //cout << "secret key serialized to size " << serialSize << 
    //    " with contents ";
    //print_char_arr_to_hex_str(buffer, serialSize); cout << endl << endl;
    ProxySK_PRE2 nnewsk1;
    nnewsk1.deserialize(SERIALIZE_BINARY, buffer, serialSize);
    serTestResult = serTestResult && (nnewsk1 == ssk1);

    // Serialize a ciphertext
    serialSize = consumer_ciphertext.serialize(SERIALIZE_BINARY, buffer, 1000);
    //cout << "ciphertext serialized to size " << serialSize << 
    //    " with contents ";
    //print_char_arr_to_hex_str(buffer, serialSize); cout << endl << endl;
    ProxyCiphertext_PRE2 nnewerCiphertext;
    nnewerCiphertext.deserialize(SERIALIZE_BINARY, buffer, serialSize);
    serTestResult = serTestResult && (nnewerCiphertext == consumer_ciphertext);

    // Searialize curve parameters
    int serialSize_requested = gParams.getSerializedSize(SERIALIZE_BINARY);
    char *params_buf = (char *) malloc(serialSize_requested * sizeof(char));
    assert(params_buf != NULL);
    int serialSize_actual = gParams.serialize(SERIALIZE_BINARY, params_buf, serialSize_requested);
    
    //cout << "gParams serialized to size " << 
    //    serialSize_requested << "," << serialSize_actual <<
    //    " with contents ";
    //print_char_arr_to_hex_str(params_buf, serialSize_actual); cout << endl << endl;
    
    CurveParams newParams;
    newParams.deserialize(SERIALIZE_BINARY, params_buf, serialSize_actual);
    serTestResult = serTestResult && (newParams == gParams);

    serialSize_actual = newParams.serialize(SERIALIZE_BINARY, 
        params_buf, newParams.getSerializedSize(SERIALIZE_BINARY));
    //cout << "newParams serialized to size " << 
    //    newParams.getSerializedSize(SERIALIZE_BINARY) << "," << serialSize_actual <<
    //    " with contents ";
    //print_char_arr_to_hex_str(params_buf, serialSize_actual); cout << endl;

    cout << ". Serialization/deserialization tests";
    cout << status_msg(serTestResult) << endl;
}

int main(){
    test3();
}