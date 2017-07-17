#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <cstring>
#include <string>
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
#include <zmq.h>
#include <iostream>
#include "sgx_urts.h"
#include "host.h"
#include "interface_u.h"
using namespace std;
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
int enclave_computation(uint8_t control)
{
  uint64_t pwerr;

  /* Setup enclave */
  sgx_status_t ret;
  sgx_launch_token_t token = { 0 };
  int token_updated = 0;
  sgx_launch_token_t token2 = { 0 };
  ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &token_updated, &global_eid, NULL);
  if (ret != SGX_SUCCESS)
  {
    printf("sgx_create_enclave failed: %#x\n", ret);
    return 1;
  }
 pw_starter(global_eid, &pwerr);
 printf("done??\n");
}


int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    int q;
    q = 0;
    int r;
    r = enclave_computation(0);
    return r;
}

