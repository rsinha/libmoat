#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
#include <zmq.h>

#include "sgx_urts.h"
#include "host.h"
#include "interface_u.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

int enclave_computation(void)
{
  uint64_t pwerr;

  /* Setup enclave */
  sgx_status_t ret;
  sgx_launch_token_t token = { 0 };
     
  int token_updated = 0;

  ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &token_updated, &global_eid, NULL);
  if (ret != SGX_SUCCESS)
  {
    printf("sgx_create_enclave failed: %#x\n", ret);
    return 1;
  }
  printf("created enclave...\n");
 
  ret = enclave_test(global_eid, &pwerr);
  //printf("pw_check+ took %ums\n", GetTickCount() - time);
  if (ret != SGX_SUCCESS)
  {
    printf("test failed: %#x\n", ret);
    sgx_destroy_enclave(global_eid);
    return 1;
  }

  printf("test returned %" PRIu64 "\n", pwerr);
  
  /* Destroy enclave */  
  ret = sgx_destroy_enclave(global_eid);
  if (ret != SGX_SUCCESS)
  {
    printf("sgx_destroy_enclave failed: %#x\n", ret);
    return 1;
  }
  
  return 0;
}


int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    int r = enclave_computation();

    return r;
}

