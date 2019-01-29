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


void *g_buf = NULL;
size_t g_buf_size = 0;
size_t g_buf_used = 0;

void file_write_and_seek(int64_t fd, void *buf, size_t size)
{
    int64_t api_result = _moat_fs_write(fd, buf, size);
    assert(api_result == size);
    api_result = _moat_fs_lseek(fd, (int64_t) size, SEEK_CUR);
    assert(api_result == _moat_fs_file_size(fd));
}

void enclave_encrypt_data(int64_t fd, void *buf, size_t size)
{
    if (g_buf == NULL) {
        g_buf = malloc(4044);
	assert(g_buf != NULL);
	g_buf_size = 4044;
	g_buf_used = 0;
    }

    if (g_buf_used + (size + sizeof(size)) > g_buf_size) {
        file_write_and_seek(fd, g_buf, g_buf_used);
	memset(g_buf, 0, g_buf_size);
	g_buf_used = 0;
    }

    memcpy(g_buf + g_buf_used, &size, sizeof(size));
    g_buf_used += sizeof(size);
    memcpy(g_buf + g_buf_used, buf, size);
    g_buf_used += size;
}

/* hash function */
/* uses pseudo-random number generation */
/* converted to use unsigned int in C */
int hash(ht_key s, int m)
{
    uint64_t ssn = *((uint64_t *) s);
    int h = ssn % m;
    if (h < 0) { h += m; }
    return h;
}

bool equal(ht_key k1, ht_key k2)
{
    return *((uint64_t *) k1) == *((uint64_t *) k2);
}

ht_key elem_key(ht_elem e)
{
    return &(((LuciditeePsiApp__PatientRecord *) e)->ssn);
}

uint64_t f(bool init)
{
    table hashTbl = table_new(1<<10, &elem_key, &equal, &hash);


    int64_t hospital_a_fd = _moat_fs_open("hospital_a_input", 0, NULL); assert(hospital_a_fd != -1);
    int64_t hospital_b_fd = _moat_fs_open("hospital_b_input", 0, NULL); assert(hospital_b_fd != -1);
    int64_t output_fd = _moat_fs_open("psi_output", 0, NULL); assert(output_fd != -1);

    size_t hospital_a_db_size = (size_t) _moat_fs_file_size(hospital_a_fd); //how many bytes is the entire db?
    uint8_t *hospital_a_buf = NULL; size_t hospital_a_buf_size = 0; //used to hold protobuf
    size_t hospital_a_db_ptr = 0; //offset within the hospital db

    while(hospital_a_db_ptr < hospital_a_db_size) { //until we run out of bytes
	size_t record_size;

        int64_t api_result = _moat_fs_read(hospital_a_fd, &record_size, sizeof(record_size));
	assert(api_result == sizeof(record_size));
	hospital_a_db_ptr += sizeof(record_size);

	api_result = _moat_fs_lseek(hospital_a_fd, sizeof(record_size), SEEK_CUR);
	assert(api_result == hospital_a_db_ptr);

	if (hospital_a_buf_size < record_size) {
            if (hospital_a_buf != NULL) { free(hospital_a_buf); }
            hospital_a_buf = (uint8_t *) malloc(record_size);
	    assert(hospital_a_buf != NULL);
	    hospital_a_buf_size = record_size;
	}

	api_result = _moat_fs_read(hospital_a_fd, hospital_a_buf, record_size);
	assert(api_result == record_size);
	hospital_a_db_ptr += record_size;

	api_result = _moat_fs_lseek(hospital_a_fd, record_size, SEEK_CUR);
	assert(api_result == hospital_a_db_ptr);

	LuciditeePsiApp__PatientRecord *record = luciditee_psi_app__patient_record__unpack(NULL, record_size, hospital_a_buf);
	table_insert(hashTbl, record);
	//_moat_print_debug("added patient with ssn %" PRIu64 "\n", record->ssn);

    }

    size_t hospital_b_db_size = (size_t) _moat_fs_file_size(hospital_b_fd); //how many bytes is the entire db?
    uint8_t *hospital_b_buf = NULL; size_t hospital_b_buf_size = 0; //used to hold protobuf
    size_t hospital_b_db_ptr = 0; //offset within the hospital db

    while(hospital_b_db_ptr < hospital_b_db_size) { //until we run out of bytes
	size_t record_size;

        int64_t api_result = _moat_fs_read(hospital_b_fd, &record_size, sizeof(record_size));
	assert(api_result == sizeof(record_size));
	hospital_b_db_ptr += sizeof(record_size);

	api_result = _moat_fs_lseek(hospital_b_fd, sizeof(record_size), SEEK_CUR);
	assert(api_result == hospital_b_db_ptr);

	if (hospital_b_buf_size < record_size) {
            if (hospital_b_buf != NULL) { free(hospital_b_buf); }
            hospital_b_buf = (uint8_t *) malloc(record_size);
	    assert(hospital_b_buf != NULL);
	    hospital_b_buf_size = record_size;
	}

	api_result = _moat_fs_read(hospital_b_fd, hospital_b_buf, record_size);
	assert(api_result == record_size);
	hospital_b_db_ptr += record_size;

	api_result = _moat_fs_lseek(hospital_b_fd, record_size, SEEK_CUR);
	assert(api_result == hospital_b_db_ptr);

	LuciditeePsiApp__PatientRecord *record_in_B = luciditee_psi_app__patient_record__unpack(NULL, record_size, hospital_b_buf);
	LuciditeePsiApp__PatientRecord *record_in_A = table_search(hashTbl, elem_key(record_in_B));
	if (record_in_A != NULL) {
            assert(record_in_A->ssn == record_in_B->ssn);
	    //add to output set
	    //_moat_print_debug("output patient with ssn %" PRIu64 "\n", record_in_A->ssn);
	    
	    output_record_t out_record;
	    out_record.ssn = record_in_B->ssn;
	    out_record.secret_A = record_in_A->secret;
	    out_record.secret_B = record_in_B->secret;
	    enclave_encrypt_data(output_fd, &out_record, sizeof(out_record));
	}
        luciditee_psi_app__patient_record__free_unpacked(record_in_B, NULL); //don't delete record_in_B as the hashtable still needs it
    }

    //write to fd
    int64_t api_result = _moat_fs_save(output_fd);
    assert(api_result == 0);

    return 0;
}

bool phi(bool init) {
    return true;
}

