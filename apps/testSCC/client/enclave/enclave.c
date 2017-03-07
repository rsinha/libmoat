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

    blob_t blob1;
    //ideally some authority (e.g. CA) will tell us this
    sgx_measurement_t measurement = { .m = { 0x55,0xCF,0x87,0x7E,0xFF,0x2F,0xE4,0x09,
                                             0x6F,0x16,0x5B,0xC1,0x0D,0x06,0xCB,0x7A,
                                             0xAF,0x49,0xEF,0x4B,0xCE,0xBD,0xEA,0x90,
                                             0xD6,0x28,0x98,0xBC,0xBC,0x8F,0x50,0x36 } };
    scc_handle_t *handle = _moat_scc_create(false, &measurement); assert(handle != NULL);
     _moat_print_debug("ECDHE+AES-GCM-128 channel established with server...\n");

    blob1.x1 = 42;
    blob1.x2 = 44;
    uint64_t result;
    size_t api_result;
    
    api_result = _moat_scc_send(handle, &blob1, sizeof(blob1)); assert(api_result == 0);
    api_result = _moat_scc_recv(handle, &result, sizeof(result)); assert(api_result == 0);
    api_result = _moat_print_debug("result: %" PRIu64 "\n", result); assert(api_result == 0);
    api_result = _moat_scc_destroy(handle); assert(api_result == 0);

    //save result in a file
    fs_handle_t *fd = _moat_fs_open("tmpfile");
    api_result = _moat_fs_write(fd, 0, &result, sizeof(result));
    assert(api_result == 0);
    uint64_t reload_result;
    api_result = _moat_fs_read(fd, 0, &reload_result, sizeof(reload_result));
    assert(api_result == 0);

    assert(reload_result == result);
    _moat_print_debug("FS check 1 successful\n");

    size_t offset = 0;
    while (offset < 20000) {
        api_result = _moat_fs_write(fd, offset, &measurement, sizeof(sgx_measurement_t));
        assert(api_result == 0);
        offset += 32;
    }

    offset = 4224;
    sgx_measurement_t reload_measurement;
    api_result = _moat_fs_read(fd, offset, &reload_measurement, sizeof(reload_measurement));
    assert(api_result == 0);

    assert(memcmp(&reload_measurement, &measurement, sizeof(sgx_measurement_t)) == 0);
    _moat_print_debug("FS check 2 successful\n");

    offset = 4224;
    while (offset < 20000) {
        api_result = _moat_fs_read(fd, offset, &reload_measurement, sizeof(reload_measurement));
        assert(api_result == 0);
        assert(memcmp(&reload_measurement, &measurement, sizeof(sgx_measurement_t)) == 0);
        offset += 32;
    }
    _moat_print_debug("FS check 3 successful\n");

    return 0;
}

