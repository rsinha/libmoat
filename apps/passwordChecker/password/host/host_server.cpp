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
  uint32_t pwerr;

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
  string username = "Vinay";
  string password = "alsovinay";
  string user2 = "ABC";
  string pass2 = "DEF";
  string passwrong = "JKL";
  string alt_pass = "GHI";
  uint8_t to_write[56];
  uint8_t to_write2[56];
  uint8_t to_write3[56];
  uint8_t to_write4[56];
  uint8_t to_read2[56];
  ret = pw_setup(global_eid, &pwerr, (const uint8_t*) password.c_str(), password.length(), to_write, 56);
  assert(ret == SGX_SUCCESS && pwerr == 1);
  FILE* write_to = fopen(username.c_str(), "w");
  fwrite(to_write, 56, 1, write_to);
  fclose(write_to);
  printf("file written\n");
  uint8_t to_read[56];
  FILE* read_from = fopen(username.c_str(), "r");
  fread(to_read, 56, 1, read_from);
  printf("file read\n");
  printf("entering enclave\n");
  std::cout.flush();
  ret = pw_check(global_eid, &pwerr, (const uint8_t*) password.c_str(), password.length(), to_read, 56);
  std::cout.flush();
  std::cerr.flush();
  //printf("pw_check+ took %ums\n", GetTickCount() - time);
  //Check if it verifies the correct password.
  assert(pwerr == 1);
  //Check that it rejects incorrect password
  ret = pw_check(global_eid, &pwerr, (const uint8_t*) pass2.c_str(), pass2.length(), to_read, 56);
  assert(pwerr == 0);
  //Change existing password
  ret = sgx_destroy_enclave(global_eid);
  sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &token_updated, &global_eid, NULL);
  pw_setup(global_eid, &pwerr, (const uint8_t*) pass2.c_str(), pass2.length(), to_write2, 56);
  assert(pwerr == 1);
  FILE* write_to2 = fopen(username.c_str(), "w");
  fwrite(to_write2, 56, 1, write_to2);
  fclose(write_to2);
  FILE* read_from2 = fopen(username.c_str(), "r");
  fread(to_read2, 56, 1, read_from2);
  pw_check(global_eid, &pwerr, (const uint8_t*) password.c_str(), password.length(), to_read2, 56);
  assert(pwerr == 0);
  pw_check(global_eid, &pwerr, (const uint8_t*) pass2.c_str(), pass2.length(), to_read2, 56);
  assert(pwerr == 1);
  //Ensure its possible to have concurrent accounts
  pw_setup(global_eid, &pwerr, (const uint8_t*) alt_pass.c_str(), alt_pass.length(), to_write3, 56);
  assert(pwerr == 1);
  FILE* write_to3 = fopen(user2.c_str(), "w");
  fwrite(to_write3, 56, 1, write_to3);
  fclose(write_to3);
  FILE* read_from3 = fopen(user2.c_str(), "r");
  uint8_t to_read3[56];
  fread(to_read3, 56, 1, read_from3);
  pw_check(global_eid, &pwerr, (const uint8_t*) alt_pass.c_str(), alt_pass.length(), to_read3, 56);
  assert(pwerr == 1);
  pw_check(global_eid, &pwerr, (const uint8_t*) pass2.c_str(), pass2.length(), to_read3, 56);
  assert(pwerr == 0);
  pw_check(global_eid, &pwerr, (const uint8_t*) alt_pass.c_str(), alt_pass.length(), to_read2, 56);
  assert(pwerr == 0);
  pw_check(global_eid, &pwerr, (const uint8_t*) pass2.c_str(), pass2.length(), to_read2, 56);
  assert(pwerr ==1);
  std::cout.flush();
  sgx_destroy_enclave(global_eid);
  if (ret != SGX_SUCCESS)
  {
    printf("fail 2\n");
    return 0;
  }
  printf("success\n");
  std::cout.flush();
  return 1;
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

