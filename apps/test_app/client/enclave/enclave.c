#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"
#include "common.h"

#include "sgx_dh.h"
#include "sgx_trts.h"

uint64_t enclave_test()
{
    _moat_debug_module_init();
    _moat_scc_module_init();
    _moat_fs_module_init();
    _moat_kvs_module_init();

    blob_t blob1;
    //ideally some authority (e.g. CA) will tell us this
    sgx_measurement_t measurement = { .m = { 0x55,0xCF,0x87,0x7E,0xFF,0x2F,0xE4,0x09,
                                             0x6F,0x16,0x5B,0xC1,0x0D,0x06,0xCB,0x7A,
                                             0xAF,0x49,0xEF,0x4B,0xCE,0xBD,0xEA,0x90,
                                             0xD6,0x28,0x98,0xBC,0xBC,0x8F,0x50,0x36 } };
    int64_t session_id = _moat_scc_create("remote_server", &measurement);
    assert(session_id != -1);
    _moat_print_debug("ECDHE+AES-GCM-128 channel established with server...\n");

    /* Test 0 (SCC) sends two values to server and checks the result */
    blob1.x1 = 42;
    blob1.x2 = 44;
    uint64_t result;
    int64_t api_result;
    
    _moat_print_debug("Commencing checks...\n--------------------\n");

    api_result = _moat_scc_send(session_id, &(blob1.x1), sizeof(blob1.x1)); assert(api_result == 0);
    api_result = _moat_scc_send(session_id, &(blob1.x2), sizeof(blob1.x2)); assert(api_result == 0);
    api_result = _moat_scc_recv(session_id, &result, sizeof(result)); assert(api_result == 0);
    api_result = _moat_print_debug("result: %" PRIu64 "\n", result); assert(api_result == 0);
    api_result = _moat_scc_destroy(session_id); assert(api_result == 0);
    
    assert(result == 86); //using the server to add x1 to x2
    _moat_print_debug("SCC check 1 successful\n");

    sgx_aes_gcm_128bit_key_t fs_encr_key;
    sgx_status_t status = sgx_read_rand((uint8_t *) &(fs_encr_key), sizeof(sgx_aes_gcm_128bit_key_t));
    assert(status == SGX_SUCCESS);

    /* Test 1 (FS) just tries to open a tmpfile */
    int64_t fd = _moat_fs_open("tmp://file", O_RDWR | O_TMPFILE, &fs_encr_key);
    assert(fd != -1);
    _moat_print_debug("FS check 1 successful\n");

    /* Test 2 (FS) just writes 86 at current offset (which at this time is 0), and reads it back */
    api_result = _moat_fs_write(fd, &result, sizeof(result));
    assert(api_result == sizeof(result));
    uint64_t reload_result;
    api_result = _moat_fs_read(fd, &reload_result, sizeof(reload_result));
    assert(api_result == sizeof(reload_result));
    assert(reload_result == result);
    api_result = _moat_fs_read(fd, &reload_result, sizeof(reload_result) + 1);
    assert(api_result == sizeof(reload_result));
    assert(reload_result == result);
    _moat_print_debug("FS check 2 successful\n");

    /* Test 3 (FS) closes the file and checks that file operations do not succeed. Then, reopens it */
    api_result = _moat_fs_close(fd);
    assert(api_result == 0);
    api_result = _moat_fs_write(fd, &result, sizeof(result));
    assert(api_result != 0);
    fd = _moat_fs_open("tmp://file", O_RDWR | O_TMPFILE, &fs_encr_key);
    assert(fd != -1);
    _moat_print_debug("FS check 3 successful\n");

    /* Test 4 (FS) writes 20,000 bytes using combination of lseek and write, then reads a few bytes back */
    int64_t offset = 0;
    while (offset < 20000) {
        api_result = _moat_fs_write(fd, &measurement, sizeof(sgx_measurement_t));
        api_result = _moat_fs_lseek(fd, 32, SEEK_CUR);
        assert(api_result == offset + 32);
        offset += 32;
    }
    sgx_measurement_t reload_measurement;
    offset = 4224;
    api_result = _moat_fs_lseek(fd, 4224, SEEK_SET);
    assert(api_result == offset);
    api_result = _moat_fs_read(fd, &reload_measurement, sizeof(reload_measurement));
    assert(api_result == sizeof(reload_measurement));
    assert(memcmp(&reload_measurement, &measurement, sizeof(sgx_measurement_t)) == 0);
    _moat_print_debug("FS check 4 successful\n");

    /* Test 5 (FS) tests lseek with negative offset, and then reads the value */
    api_result = _moat_fs_lseek(fd, -4184, SEEK_CUR);
    assert(api_result == 40);
    api_result = _moat_fs_read(fd, &reload_measurement, sizeof(reload_measurement));
    assert(api_result == sizeof(reload_measurement));
    assert(memcmp(&reload_measurement, &measurement, sizeof(sgx_measurement_t)) != 0);
    _moat_print_debug("FS check 5 successful\n");

    /* Test 6 (FS) tests reading back all the 20000 bytes written in Test 4 */
    offset = 4224;
    while (offset < 20000) {
        api_result = _moat_fs_lseek(fd, offset, SEEK_SET);
        assert(api_result == offset);
        api_result = _moat_fs_read(fd, &reload_measurement, sizeof(reload_measurement));
        assert(api_result == sizeof(reload_measurement));
        assert(memcmp(&reload_measurement, &measurement, sizeof(sgx_measurement_t)) == 0);
        offset += 32;
    }
    _moat_print_debug("FS check 6 successful\n");

    sgx_aes_gcm_128bit_key_t db_encr_key;
    status = sgx_read_rand((uint8_t *) &(db_encr_key), sizeof(sgx_aes_gcm_128bit_key_t));
    assert(status == SGX_SUCCESS);

    /* Test 1 (KVS) just tries to open a temp DB */
    int64_t dbd = _moat_kvs_open("test_app_db", O_RDWR | O_CREAT, &db_encr_key);
    assert(dbd != -1);
    _moat_print_debug("KVS check 1 successful\n");

    /* Test 2 (KVS) writes values to temp DB */
    uint8_t k1[32], k2[48], k3[64];
    uint8_t v1[64], v2[32];
    uint8_t v1_get[64], v2_get[64], v3_get[32];
    memset(&k1, 1, sizeof(k1)); memset(v1, 255, sizeof(v1));
    memset(&k2, 2, sizeof(k2)); memset(v2, 254, sizeof(v2));
    api_result = _moat_kvs_get(dbd, &k1, sizeof(k1), 0, &v1_get, sizeof(v1_get));
    assert(api_result == -1);
    api_result = _moat_kvs_get(dbd, &k2, sizeof(k2), 0, &v2_get, sizeof(v2_get));
    assert(api_result == -1);
    api_result = _moat_kvs_set(dbd, &k1, sizeof(k1), &v1, sizeof(v1));
    assert(api_result == sizeof(v1));
    api_result = _moat_kvs_set(dbd, &k2, sizeof(k2), &v2, sizeof(v2));
    assert(api_result == sizeof(v2));
    _moat_print_debug("KVS check 2 successful\n");

    /* Test 3 (KVS) reads back values from temp DB; also checks that non-existent keys don't return values */
    memset(v1_get, 0, sizeof(v1_get));
    memset(v2_get, 0, sizeof(v2_get));
    api_result = _moat_kvs_get(dbd, &k1, sizeof(k1), 0, &v1_get, sizeof(v1_get));
    assert(api_result == sizeof(v1));
    api_result = _moat_kvs_get(dbd, &k2, sizeof(k2), 0, &v2_get, sizeof(v2_get));
    assert(api_result == sizeof(v2));
    assert(memcmp(v1, v1_get, sizeof(v1)) == 0);
    assert(memcmp(v2, v2_get, sizeof(v2)) == 0);
    assert(v1[33] == 255 && v1_get[33] == 255 && v2[21] == 254 && v2_get[21] == 254);
    memset(&k3, 3, sizeof(k3));
    api_result = _moat_kvs_get(dbd, &k3, sizeof(k3), 0, &v3_get, sizeof(v3_get));
    assert(api_result == -1);
    _moat_print_debug("KVS check 3 successful\n");

    uint8_t v4[2048]; uint8_t k4[32];
    memset(&k4, 4, sizeof(k4));
    memset(v4, 251, sizeof(v4)); 
    v4[4] = 4;
    api_result = _moat_kvs_set(dbd, &k4, sizeof(k4), &v4, sizeof(v4));
    assert(api_result = sizeof(v4));
    uint8_t v4_get[2048];
    api_result = _moat_kvs_get(dbd, &k4, sizeof(k4), 0, &v4_get, sizeof(v4_get));
    assert(api_result == sizeof(v4_get));
    assert(memcmp(v4, v4_get, sizeof(v4)) == 0); assert(v4_get[4] == 4);
    api_result = _moat_kvs_get(dbd, &k4, sizeof(k4), 2, &v4_get, sizeof(v4_get));
    assert(api_result == (sizeof(v4_get) - 2));
    assert(memcmp(v4 + 2, v4_get, sizeof(v4) - 2) == 0); assert(v4_get[2] == 4); assert(v4_get[3] == 251);
    _moat_print_debug("KVS check 4 successful\n");

    api_result = _moat_kvs_delete(dbd, &k1, sizeof(k1));
    assert(api_result == 0);
    api_result = _moat_kvs_get(dbd, &k1, sizeof(k1), 0, &v1_get, sizeof(v1_get));
    assert(api_result == -1);
    _moat_print_debug("KVS check 5 successful\n");

    //save db
    api_result = _moat_kvs_save(dbd);
    assert (api_result == 0);
    _moat_print_debug("KVS check 6 successful\n");
    api_result = _moat_kvs_close(dbd);
    assert(api_result != -1);
    _moat_print_debug("KVS check 7 successful\n");

    int64_t db2d = _moat_kvs_open("test_app_db2", O_RDWR, &db_encr_key);
    assert(db2d != -1);
    _moat_print_debug("KVS check 8 successful\n");
    api_result = _moat_kvs_get(db2d, &k2, sizeof(k2), 0, &v2_get, sizeof(v2_get));
    assert(api_result == sizeof(v2));
    assert(memcmp(v2, v2_get, sizeof(v2)) == 0);
    _moat_print_debug("KVS check 9 successful\n");


    _moat_print_debug("Finished checks...\n--------------------\n");

    _moat_generate_seal_key();

    return 0;
}

