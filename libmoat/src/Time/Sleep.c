#include <stddef.h>
#include <assert.h>
#include <string.h>

#include "../../api/libmoat.h"
#include "../../api/libbarbican.h"


void _moat_print_time_of_day()
{
	size_t retstatus;
	sgx_status_t status = print_time_of_day_ocall(&retstatus);
	assert(retstatus == 0 && status == SGX_SUCCESS);
}
