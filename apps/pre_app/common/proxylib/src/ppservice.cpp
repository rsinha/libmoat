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

std::string status_msg(bool b)
{
    return b ?  " ... OK" : " ... FAILED";
}

void print_char_arr_to_hex_str(char *data, size_t len)
{
    for(int i=0; i < len; ++i) {
        printf("%02x", (unsigned char) data[i]);
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
    Big plaintext1 = 100;
    Big plaintext2 = 0;
    ProxyCiphertext_PRE2 cciphertext;
    bool success1 = PRE2_level1_encrypt(gParams, plaintext1, ppk1, cciphertext);
    bool success2 = PRE2_decrypt(gParams, cciphertext, ssk1, plaintext2);
    success = (plaintext1 == plaintext2) && success1 && success2;
    cout << status_msg(success) << endl;

    //
    // Second-level encryption/decryption test
    //
    cout << ". Second-level encryption/decryption test ";
    plaintext1 = 100;
    plaintext2 = 0;
    success1 = PRE2_level2_encrypt(gParams, plaintext1, ppk1, cciphertext);
    success2 = PRE2_decrypt(gParams, cciphertext, ssk1, plaintext2);
    success = (plaintext1 == plaintext2) && success1 && success2;
    cout << status_msg(success) << endl;

    //
    // Re-encryption test
    //
    ProxyCiphertext_PRE2 nnewCiphertext;
    plaintext2 = 0;
    cout << ". Re-encryption/decryption test ";
    // Re-encrypt ciphertext from user1->user2 using delKey
    success1 = PRE2_reencrypt(gParams, cciphertext, delKey, nnewCiphertext);
    success2 = PRE2_decrypt(gParams, nnewCiphertext, ssk2, plaintext2);
    success = (plaintext1 == plaintext2) && success1 && success2;
    cout << status_msg(success) << endl;

    //
    // Proxy invisibility test
    //
    // We take the re-encrypted ciphertext from the previous test
    // and mark it as a first-level ciphertext.  Decryption
    // should still work just fine.
    //
    cout << ". Proxy invisibility test ";
    nnewCiphertext.type = CIPH_FIRST_LEVEL;
    // Decrypt the ciphertext
    success1 = PRE2_decrypt(gParams, nnewCiphertext, ssk2, plaintext2);
    success = (plaintext1 == plaintext2) && success1;
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
    serialSize = nnewCiphertext.serialize(SERIALIZE_BINARY, buffer, 1000);
    ProxyCiphertext_PRE2 nnewerCiphertext;
    nnewerCiphertext.deserialize(SERIALIZE_BINARY, buffer, serialSize);
    serTestResult = serTestResult && (nnewerCiphertext == nnewCiphertext);

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

int main()
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
    // enceypt
    //
    cout << ". First-level encryption/decryption test ";
    Big plaintext1 = 100;
    Big plaintext2 = 0;
    ProxyCiphertext_PRE2 cciphertext;

    cout << ". Second-level encryption/decryption test ";
    plaintext1 = 100;
    plaintext2 = 0;
    bool success1 = PRE2_level2_encrypt(gParams, plaintext1, ppk1, cciphertext);
    bool success2 = PRE2_decrypt(gParams, cciphertext, ssk1, plaintext2);
    success = (plaintext1 == plaintext2) && success1 && success2;
    cout << status_msg(success) << endl;

    //
    // Re-encryption
    //
    ProxyCiphertext_PRE2 nnewCiphertext;
    plaintext2 = 0;
    cout << ". Re-encryption/decryption test ";
    // Re-encrypt ciphertext from user1->user2 using delKey
    success1 = PRE2_reencrypt(gParams, cciphertext, delKey, nnewCiphertext);
    success2 = PRE2_decrypt(gParams, nnewCiphertext, ssk2, plaintext2);
    success = (plaintext1 == plaintext2) && success1 && success2;
    cout << status_msg(success) << endl;

    //
    // Serialization/Deserialization test
    //
    char buffer[1000];
    bool serTestResult = TRUE;

    // Serialize a public key
    int serialSize = ppk1.serialize(SERIALIZE_BINARY, buffer, 1000);
    cout << "public key serialized to size " << serialSize << 
        " with contents ";
    print_char_arr_to_hex_str(buffer, serialSize); cout << endl << endl;
    ProxyPK_PRE2 nnewpk;
    nnewpk.deserialize(SERIALIZE_BINARY, buffer, serialSize);
    serTestResult = serTestResult && (nnewpk == ppk1);

    // Serialize a secret key
    serialSize = ssk1.serialize(SERIALIZE_BINARY, buffer, 1000);
    cout << "secret key serialized to size " << serialSize << 
        " with contents ";
    print_char_arr_to_hex_str(buffer, serialSize); cout << endl << endl;
    ProxySK_PRE2 nnewsk1;
    nnewsk1.deserialize(SERIALIZE_BINARY, buffer, serialSize);
    serTestResult = serTestResult && (nnewsk1 == ssk1);

    // Serialize a ciphertext
    serialSize = nnewCiphertext.serialize(SERIALIZE_BINARY, buffer, 1000);
    cout << "ciphertext serialized to size " << serialSize << 
        " with contents ";
    print_char_arr_to_hex_str(buffer, serialSize); cout << endl << endl;
    ProxyCiphertext_PRE2 nnewerCiphertext;
    nnewerCiphertext.deserialize(SERIALIZE_BINARY, buffer, serialSize);
    serTestResult = serTestResult && (nnewerCiphertext == nnewCiphertext);

    // Searialize curve parameters
    int serialSize_requested = gParams.getSerializedSize(SERIALIZE_BINARY);
    char *params_buf = (char *) malloc(serialSize_requested * sizeof(char));
    assert(params_buf != NULL);
    int serialSize_actual = gParams.serialize(SERIALIZE_BINARY, params_buf, serialSize_requested);
    
    cout << "gParams serialized to size " << 
        serialSize_requested << "," << serialSize_actual <<
        " with contents ";
    print_char_arr_to_hex_str(params_buf, serialSize_actual); cout << endl << endl;
    
    CurveParams newParams;
    newParams.deserialize(SERIALIZE_BINARY, params_buf, serialSize_actual);
    serTestResult = serTestResult && (newParams == gParams);
    /*
    int bits;
  Big p, q, qsquared;
  ECn P;  
  ZZn2 Z;
  ZZn2 Zprecomp;
  ZZn2 cube;
    */
    cout << "newParams.bits = gParams.bits? " << (newParams.bits == gParams.bits) << endl;
    cout << "newParams.p = gParams.p? " << (newParams.p == gParams.p) << endl;
    cout << "newParams.q = gParams.q? " << (newParams.q == gParams.q) << endl;
    cout << "newParams.qsquared = gParams.qsquared? " << (newParams.qsquared == gParams.qsquared) << endl;
    cout << "newParams.P = gParams.P? " << (newParams.P == gParams.P) << endl;
    cout << "newParams.Z = gParams.Z? " << (newParams.Z == gParams.Z) << endl;
    cout << "newParams.cube = gParams.cube? " << (newParams.cube == gParams.cube) << endl;

    serialSize_actual = newParams.serialize(SERIALIZE_BINARY, 
        params_buf, newParams.getSerializedSize(SERIALIZE_BINARY));
    cout << "newParams serialized to size " << 
        newParams.getSerializedSize(SERIALIZE_BINARY) << "," << serialSize_actual <<
        " with contents ";
    print_char_arr_to_hex_str(params_buf, serialSize_actual); cout << endl;

    cout << ". Serialization/deserialization tests";
    cout << status_msg(serTestResult) << endl;
}