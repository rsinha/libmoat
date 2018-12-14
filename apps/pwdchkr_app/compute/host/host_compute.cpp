#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <unistd.h>
#include <pwd.h>
#include <string>
#include <fstream>
#include <iostream>

#include "sgx_urts.h"
#include "interface_u.h"

#include <cxxopts.hpp>

void read_all_bytes_in_file(const char *filename, uint8_t **buf, size_t *len)
{
    std::ifstream ifs(filename, std::ios::binary | std::ios::ate);
    std::ifstream::pos_type pos = ifs.tellg();

    *len = pos;
    *buf = (uint8_t *) malloc(*len);
    assert(*buf != NULL);

    ifs.seekg(0, std::ios::beg);
    ifs.read((char *) *buf, (std::streamsize) *len);
    ifs.close();
}

int enclave_computation(const char *spec_file, const char *enc_file, bool init)
{
  uint64_t pwerr;

  /* Setup enclave */
  sgx_status_t ret;
  sgx_launch_token_t token = { 0 };

  int token_updated = 0;
  sgx_enclave_id_t global_eid = 0;

  uint8_t *spec_buf; size_t spec_buf_len;
  read_all_bytes_in_file(spec_file, &spec_buf, &spec_buf_len);

  ret = sgx_create_enclave(enc_file, SGX_DEBUG_FLAG, &token, &token_updated, &global_eid, NULL);
  if (ret != SGX_SUCCESS)
  {
    printf("sgx_create_enclave failed: %#x\n", ret);
    return 1;
  }
 
  ret = invoke_enclave_computation(global_eid, &pwerr, spec_buf, spec_buf_len, init);

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
  try {
    cxxopts::Options options("pwdchkr compute enclave", 
                             "Checks if Sherlock's guess equals Irene's password");

    bool init = false;

    options
      .show_positional_help()
      .add_options()
        ("help", "Print help")
        ("i,init", "Create initial state", cxxopts::value<bool>(init))
        ("c,config", "Json configuration", cxxopts::value<std::string>())
        ("e,enclave", "Enclave binary", cxxopts::value<std::string>())
        ("s,spec", "Computation's specification", cxxopts::value<std::string>())
      ;

    auto result = options.parse(argc, argv);

    if (!result.count("s") || 
        !result.count("e") || 
        !result.count("c") || 
        result.count("help")) {
      std::cout << options.help({"", "Group"}) << std::endl;
      exit(0);
    }

    std::string json_file = result["c"].as<std::string>();
    std::string enclave_file = result["e"].as<std::string>();
    std::string spec_file = result["s"].as<std::string>();
  
    void init_barbican(const std::string &json_str);
    std::ifstream f(json_file);
    std::string json_str((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    init_barbican(json_str);

    return enclave_computation(spec_file.c_str(), enclave_file.c_str(), init);

  } catch (const cxxopts::OptionException& e) {
    std::cout << "error parsing options: " << e.what() << std::endl;
    exit(1);
  }
}

