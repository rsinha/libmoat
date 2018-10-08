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

    // Serialize a public key
    int serialSize = ppk1.serialize(SERIALIZE_BINARY, buffer, 1000);
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
    Big original_msg = 100;
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

    //
    // Serialization/Deserialization test
    //
    char buffer[1000];
    bool serTestResult = TRUE;

    // Serialize a public key
    int serialSize = ppk1.serialize(SERIALIZE_BINARY, buffer, 1000);
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


int main()
{
    test2();
}