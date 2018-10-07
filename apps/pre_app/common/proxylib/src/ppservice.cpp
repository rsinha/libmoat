#include <iostream>
#include <fstream>
#include <cstring>
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

    cout << status_msg(serTestResult) << endl;

    cout << endl << "All tests complete." << endl;
}
