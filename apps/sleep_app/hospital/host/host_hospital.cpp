#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include <unistd.h>
#include <pwd.h>

#include "sgx_urts.h"
#include "interface_u.h"
#include "csv.h"

#include "input.pb.h"

#include <string>
#include <fstream>
#include <iostream>
#include <cxxopts.hpp>

sgx_enclave_id_t global_eid = 0;
void init_barbican(const std::string &json_file, const std::string &scratch_space_root);

void launch_enclave(std::string &enclave_file)
{
  uint64_t pwerr;
  sgx_launch_token_t token = { 0 };
  int token_updated = 0;

  sgx_status_t ret = sgx_create_enclave(enclave_file.c_str(), 
    SGX_DEBUG_FLAG, &token, &token_updated, &global_eid, NULL);

  if (ret != SGX_SUCCESS)
  {
    printf("sgx_create_enclave failed: %#x\n", ret);
    exit(1);
  }
}

void destroy_enclave()
{
  /* Destroy enclave */  
  sgx_status_t ret = sgx_destroy_enclave(global_eid);
  if (ret != SGX_SUCCESS)
  {
    printf("sgx_destroy_enclave failed: %#x\n", ret);
    exit(1);
  }
}

int main(int argc, char *argv[])
{
  cxxopts::Options options("pwdchkr irene enclave", "Creates Irene's input");

  options
    .show_positional_help()
    .add_options()
      ("help", "Print help")
      ("c,config", "Json configuration", cxxopts::value<std::string>())
      ("d,data", "CSV database", cxxopts::value<std::string>())
      ("e,enclave", "Location of Enclave Binary", cxxopts::value<std::string>())
      ("l,location", "Directory to use as scratch space", cxxopts::value<std::string>())
    ;

  auto result = options.parse(argc, argv);

  if (!result.count("d") || !result.count("l") || !result.count("c") || result.count("help")) {
    std::cout << options.help({"", "Group"}) << std::endl;
    exit(0);
  }

  std::string json_file = result["c"].as<std::string>();
  std::string scratch_space_root = result["l"].as<std::string>();
  std::string data_file = result["d"].as<std::string>();
  std::string enclave_file = result["e"].as<std::string>();

  io::CSVReader<2> in(data_file);

  init_barbican(json_file, scratch_space_root);

  launch_enclave(enclave_file);

  GOOGLE_PROTOBUF_VERIFY_VERSION;

  luciditee_psi_app::PatientRecord record;

  in.read_header(io::ignore_extra_column, "ssn", "secret");

  uint64_t ssn, secret;
  uint64_t pwerr;

  sgx_status_t ret = enclave_init(global_eid, &pwerr);
  if (ret != SGX_SUCCESS)
  {
    printf("enclave  failed: %#x\n", ret);
    return -1;
  }

  while(in.read_row(ssn, secret)) 
  {
    record.set_ssn(ssn);
    record.set_secret(secret);

    size_t ptxt_buf_size = record.ByteSize();
    unsigned char *ptxt_buf = (unsigned char *) malloc(ptxt_buf_size);
    if(!ptxt_buf) { std::cout << "unable to malloc" << std::endl; exit(1); }

    if (!record.SerializeToArray(ptxt_buf, ptxt_buf_size)) {
      std::cerr << "Failed to write tx" << std::endl;
      return -1;
    }
    std::cout << "added patient record " << ssn << "," << secret << std::endl;
    sgx_status_t ret = enclave_encrypt_data(global_eid, &pwerr, ptxt_buf, ptxt_buf_size);
    if (ret != SGX_SUCCESS)
    {
      printf("enclave  failed: %#x\n", ret);
      return -1;
    }
    
    free(ptxt_buf);
  }


  ret = enclave_finish(global_eid, &pwerr);
  if (ret != SGX_SUCCESS)
  {
    printf("enclave  failed: %#x\n", ret);
    return -1;
  }

  destroy_enclave();
  
  return 0;

}

