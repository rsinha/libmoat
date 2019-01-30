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

void init_barbican(const std::string &json_file, const std::string &scratch_space_root);

/*
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
*/

int enclave_computation(uint64_t spec_id, const char *enc_file)
{
  uint64_t pwerr;

  /* Setup enclave */
  sgx_status_t ret;
  sgx_launch_token_t token = { 0 };

  int token_updated = 0;
  sgx_enclave_id_t global_eid = 0;

  ret = sgx_create_enclave(enc_file, SGX_DEBUG_FLAG, &token, &token_updated, &global_eid, NULL);
  if (ret != SGX_SUCCESS)
  {
    printf("sgx_create_enclave failed: %#x\n", ret);
    return 1;
  }
 
  ret = invoke_enclave_computation(global_eid, &pwerr, spec_id);

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

    //bool init = false;

    options
      .show_positional_help()
      .add_options()
        ("help", "Print help")
        ("c,config", "Json configuration", cxxopts::value<std::string>())
        ("e,enclave", "Enclave binary", cxxopts::value<std::string>())
        ("s,spec", "Computation's specification", cxxopts::value<uint64_t>())
        ("l,location", "Directory to use as scratch space", cxxopts::value<std::string>())
      ;

    auto result = options.parse(argc, argv);

    if (!result.count("s") || 
        !result.count("e") || 
        !result.count("c") || 
        !result.count("l") || 
        result.count("help")) {
      std::cout << options.help({"", "Group"}) << std::endl;
      exit(0);
    }

    std::string json_file = result["c"].as<std::string>();
    std::string scratch_space_root = result["l"].as<std::string>();
    std::string enclave_file = result["e"].as<std::string>();
    uint64_t spec_id = result["s"].as<uint64_t>();
  
    init_barbican(json_file, scratch_space_root);

    return enclave_computation(spec_id, enclave_file.c_str());

  } catch (const cxxopts::OptionException& e) {
    std::cout << "error parsing options: " << e.what() << std::endl;
    exit(1);
  }
}

