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

bool phi(bool init) {
    return true;
}

/* hash function */
/* uses pseudo-random number generation */
/* converted to use unsigned int in C */
int hash(ht_key s, int m)
{ REQUIRES(m > 1);
  unsigned int a = 1664525;
  unsigned int b = 1013904223;	/* inlined random number generator */
  unsigned int r = 0xdeadbeef;	       /* initial seed */
  int len = strlen(s);		       /* different from C0! */
  int i; unsigned int h = 0;	       /* empty string maps to 0 */
  for (i = 0; i < len; i++)
    {
      h = r*h + ((char*)s)[i];	 /* mod 2^32 */
      r = r*a + b;	 /* mod 2^32, linear congruential random no */
    }
  h = h % m;			/* reduce to range */
  //@assert -m < (int)h && (int)h < m;
  int hx = (int)h;
  if (hx < 0) h += m;	/* make positive, if necessary */
  ENSURES(0 <= hx && hx < m);
  return hx;
}

bool equal(ht_key k1, ht_key k2)
{
    return *((uint64_t *) k1) == *((uint64_t *) k2);
}

ht_key elem_key(ht_elem e)
{
    return &((LuciditeePsiApp__PatientRecord *) e)->ssn;
}

uint64_t f(bool init)
{
    table hashTbl = table_new(1<<20, &elem_key, &equal, &hash);


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
    }

    //write to fd
    //api_result = _moat_fs_write(output_fd, output_buf, output_buf_len); assert(api_result == output_buf_len);
    //api_result = _moat_fs_save(output_fd); assert(api_result == 0);

    //luciditee_psi_app__hospital_db__free_unpacked(&db_out, NULL); //db_out has pointers within db_A and db_B
    //luciditee_psi_app__hospital_db__free_unpacked(db_A, NULL); //db_out has pointers within db_A
    //luciditee_psi_app__hospital_db__free_unpacked(db_B, NULL); //db_out has pointers within db_B

    //free(hospital_a_buf);
    //free(hospital_b_buf);
    //free(output_buf);
    //free(db_out.records);

    return 0;
}
