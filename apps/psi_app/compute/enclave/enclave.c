#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "libmoat.h"

#include "sgx_dh.h"
#include "sgx_trts.h"

#include "statement.pb-c.h"

bool phi(bool init) {
    if (init) { return true; }

    return true;
}

uint64_t f(bool init)
{
    int64_t hospital_a_fd = _moat_fs_open("hospital_a_input", 0, NULL); assert(hospital_a_fd != -1);
    int64_t hospital_b_fd = _moat_fs_open("hospital_b_input", 0, NULL); assert(hospital_b_fd != -1);
    int64_t output_fd = _moat_fs_open("psi_output", 0, NULL); assert(output_fd != -1);

    size_t hospital_a_buf_len = (size_t) _moat_fs_file_size(hospital_a_fd);
    size_t hospital_b_buf_len = (size_t) _moat_fs_file_size(hospital_b_fd);

    uint8_t *hospital_a_buf = (uint8_t *) malloc(hospital_a_buf_len); assert(hospital_a_buf != NULL);
    uint8_t *hospital_b_buf = (uint8_t *) malloc(hospital_b_buf_len); assert(hospital_b_buf != NULL);

    int64_t api_result = _moat_fs_read(hospital_a_fd, hospital_a_buf, hospital_a_buf_len); assert(api_result == hospital_a_buf_len);
    api_result = _moat_fs_read(hospital_b_fd, hospital_b_buf, hospital_b_buf_len); assert(api_result == hospital_b_buf_len);

    LuciditeePsiApp__HospitalDB *db_A = luciditee_psi_app__hospital_db__unpack(NULL, hospital_a_buf_len, hospital_a_buf); assert(db_A != NULL);
    _moat_print_debug("enclave: parsing proto...got %" PRIu64 " transactions\n", db_A->n_records);
    LuciditeePsiApp__HospitalDB *db_B = luciditee_psi_app__hospital_db__unpack(NULL, hospital_b_buf_len, hospital_b_buf); assert(db_B != NULL);
    _moat_print_debug("enclave: parsing proto...got %" PRIu64 " transactions\n", db_B->n_records);

    LuciditeePsiApp__HospitalDB db_out;
    luciditee_psi_app__hospital_db__init(&db_out);
    db_out.n_records = db_A->n_records + db_B->n_records;
    db_out.records = (LuciditeePsiApp__HospitalDB__PatientRecord **) malloc(sizeof(void *) * db_out.n_records); assert(db_out.records != NULL);
    size_t j = 0;
    for (size_t i = 0; i < db_A->n_records; i++) {
        LuciditeePsiApp__HospitalDB__PatientRecord *r = db_A->records[i];
        db_out.records[j] = r;
        j++;
    }
    for (size_t i = 0; i < db_B->n_records; i++) {
        LuciditeePsiApp__HospitalDB__PatientRecord *r = db_B->records[i];
        db_out.records[j] = r;
        j++;
    }

    size_t output_buf_len = luciditee_psi_app__hospital_db__get_packed_size(&db_out);
    uint8_t *output_buf = (uint8_t *) malloc(output_buf_len); 
    assert(output_buf != NULL);
    assert (luciditee_psi_app__hospital_db__pack(&db_out, output_buf) == output_buf_len);

    //write to fd
    api_result = _moat_fs_write(output_fd, output_buf, output_buf_len); assert(api_result == output_buf_len);
    api_result = _moat_fs_save(output_fd); assert(api_result == 0);

    //luciditee_psi_app__hospital_db__free_unpacked(&db_out, NULL); //db_out has pointers within db_A and db_B
    luciditee_psi_app__hospital_db__free_unpacked(db_A, NULL); //db_out has pointers within db_A
    luciditee_psi_app__hospital_db__free_unpacked(db_B, NULL); //db_out has pointers within db_B

    free(hospital_a_buf);
    free(hospital_b_buf);
    free(output_buf);
    free(db_out.records);

    return 0;
}