#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include <unistd.h>
#include <pwd.h>

#include "sgx_urts.h"
#include "interface_u.h"
#include "secret.pb.h"

#include <string>
#include <fstream>
#include <iostream>
#include <cxxopts.hpp>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

int enclave_computation(const char* file_name, uint8_t *buf, size_t buf_size)
{
  uint64_t pwerr;

  /* Setup enclave */
  sgx_status_t ret;
  sgx_launch_token_t token = { 0 };

  int token_updated = 0;

  ret = sgx_create_enclave(file_name, SGX_DEBUG_FLAG, &token, &token_updated, &global_eid, NULL);
  if (ret != SGX_SUCCESS)
  {
    printf("sgx_create_enclave failed: %#x\n", ret);
    return 1;
  }
 
  ret = enclave_test(global_eid, &pwerr, buf, buf_size);
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


int main(int argc, char *argv[])
{
  cxxopts::Options options("pwdchkr irene enclave", "Creates Irene's input");

  options
    .show_positional_help()
    .add_options()
      ("help", "Print help")
      ("p,password", "Password value", cxxopts::value<int>())
      ("n,num_guesses", "Number of allowed guesses", cxxopts::value<int>())
      ("c,config", "Json configuration", cxxopts::value<std::string>())
      ("e,enclave", "Location of Enclave Binary", cxxopts::value<std::string>())
    ;

  auto result = options.parse(argc, argv);

  if (!result.count("p") || !result.count("n") || !result.count("c") || result.count("help")) {
    std::cout << options.help({"", "Group"}) << std::endl;
    exit(0);
  }

  std::string json_file = result["c"].as<std::string>();
  std::string enclave_file = result["e"].as<std::string>();

  void init_barbican(const std::string &json_str);
  std::ifstream f(json_file);
  std::string json_str((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  init_barbican(json_str);

  GOOGLE_PROTOBUF_VERIFY_VERSION;

  luciditee_guess_app::Secret secret;
  secret.set_password((uint64_t) result["p"].as<int>());
  secret.set_guesses((uint64_t) result["n"].as<int>());

  size_t ptxt_buf_size = secret.ByteSize();
  //std::cout << "byte encoding has size " << ptxt_buf_size << std::endl;
  unsigned char *ptxt_buf = (unsigned char *) malloc(ptxt_buf_size);
  if(!ptxt_buf) { std::cout << "unable to malloc" << std::endl; exit(1); }
  //printf("host: buf: %p, size: %zu\n", ptxt_buf, ptxt_buf_size);
  if (!secret.SerializeToArray(ptxt_buf, ptxt_buf_size)) {
      std::cerr << "Failed to write tx" << std::endl;
      return -1;
  }

  return enclave_computation(enclave_file.c_str(), ptxt_buf, ptxt_buf_size);
}

