#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"

#include "sgx_dh.h"
#include "sgx_trts.h"

#include "input.pb-c.h"
#include "hashtable.h"
#include "contracts.h"


/* TODO: make this a protobuf */
typedef struct {
    uint64_t ssn;
    uint64_t secret_A;
    uint64_t secret_B;
} output_record_t;


uint64_t f(bool init)
{
    int64_t hospital_a_fd = _moat_fs_open("hospital_a_input", 0, NULL); assert(hospital_a_fd != -1);
    int64_t hospital_b_fd = _moat_fs_open("hospital_b_input", 0, NULL); assert(hospital_b_fd != -1);
    int64_t output_fd = _moat_fs_open("psi_output", 0, NULL); assert(output_fd != -1);

    /* modeling computation */
    _moat_sleep(8.2 * 1000000);

    output_record_t rec;
    int64_t api_result = _moat_fs_write(output_fd, &rec, sizeof(rec));
    assert(api_result == sizeof(rec));

    //write to fd
    api_result = _moat_fs_save(output_fd);
    assert(api_result == 0);

    return 0;
}

bool phi(bool init) {
    return true;
}

