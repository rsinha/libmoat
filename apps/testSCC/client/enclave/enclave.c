#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"
#include "common.h"

#include "sgx_dh.h"

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
    scc_attributes_t attr = { .record_size = 128, .side_channel_protection = 0 };
    scc_handle_t *handle = _moat_scc_create(false, &measurement, &attr);
    assert(handle != NULL);
    _moat_print_debug("ECDHE+AES-GCM-128 channel established with server...\n");

    /* Test 0 (SCC) sends two values to server and checks the result */
    blob1.x1 = 42;
    blob1.x2 = 44;
    uint64_t result;
    int64_t api_result;
    
    //api_result = _moat_scc_send(handle, &blob1, sizeof(blob1)); assert(api_result == 0);
    api_result = _moat_scc_send(handle, &(blob1.x1), sizeof(blob1.x1)); assert(api_result == 0);
    api_result = _moat_scc_send(handle, &(blob1.x2), sizeof(blob1.x2)); assert(api_result == 0);
    api_result = _moat_scc_recv(handle, &result, sizeof(result)); assert(api_result == 0);
    api_result = _moat_print_debug("result: %" PRIu64 "\n", result); assert(api_result == 0);
    api_result = _moat_scc_destroy(handle); assert(api_result == 0);
    
    assert(result == 86); //using the server to add x1 to x2
    _moat_print_debug("SCC check 0 successful\n");

    /* Test 1 (FS) just tries to open a tmpfile */
    int64_t fd = _moat_fs_open("tmp://file", O_RDWR);
    assert(fd != -1);
    _moat_print_debug("FS check 1 successful\n");

    /* Test 2 (FS) just writes 86 at current offset (which at this time is 0), and reads it back */
    api_result = _moat_fs_write(fd, &result, sizeof(result));
    assert(api_result == sizeof(result));
    uint64_t reload_result;
    api_result = _moat_fs_read(fd, &reload_result, sizeof(reload_result));
    assert(api_result == sizeof(reload_result));
    assert(reload_result == result);
    _moat_print_debug("FS check 2 successful\n");

    /* Test 3 (FS) closes the file and checks that file operations do not succeed. Then, reopens it */
    api_result = _moat_fs_close(fd);
    assert(api_result == 0);
    api_result = _moat_fs_write(fd, &result, sizeof(result));
    assert(api_result != 0);
    fd = _moat_fs_open("tmp://file", O_RDWR);
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

    /* Test 7 (KVS) just tries to open a temp DB */
    int64_t dbd = _moat_kvs_open("tmp://db", O_RDWR);
    assert(dbd != -1);
    _moat_print_debug("KVS check 7 successful\n");

    return 0;
}

