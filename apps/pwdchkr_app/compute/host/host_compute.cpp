#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "interface_u.h"

#include <string>
#include <fstream>
#include <iostream>

void init_barbican(const std::string &json_str);

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

int enclave_computation()
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
 
  ret = enclave_test(global_eid, &pwerr);

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


int main(int argc, char *argv[])
{
  if (argc < 2) {
    std::cout << "Insufficient arguments: must pass a json config" << std::endl;
    exit(1);
  }

  std::ifstream f(argv[1]);
  std::string json_str((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  init_barbican(json_str);

  return enclave_computation();
}

