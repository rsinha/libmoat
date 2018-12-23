#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include <unistd.h>
#include <pwd.h>

#include "sgx_urts.h"
#include "interface_u.h"
#include "csv.h"

#include <string>
#include <fstream>
#include <iostream>
#include <cxxopts.hpp>

sgx_enclave_id_t global_eid = 0;

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
    ;

  auto result = options.parse(argc, argv);

  if (!result.count("d") || !result.count("c") || result.count("help")) {
    std::cout << options.help({"", "Group"}) << std::endl;
    exit(0);
  }

  std::string json_file = result["c"].as<std::string>();
  std::string data_file = result["d"].as<std::string>();
  std::string enclave_file = result["e"].as<std::string>();

  io::CSVReader<2> in(data_file);

  void init_barbican(const std::string &json_str);
  std::ifstream f(json_file);
  std::string json_str((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  init_barbican(json_str);

  launch_enclave(enclave_file);

  uint64_t pwerr;
  sgx_status_t ret = enclave_init(global_eid, &pwerr);
  if (ret != SGX_SUCCESS) { goto error; }

  //step 1: parse the csv file containing all transactions
  //step 2: put each element in the kvs
  in.read_header(io::ignore_extra_column, "gmr", "category");
  uint64_t gmr, category;
  while(in.read_row(gmr, category)) 
  {
    //std::cout << "gmr: " << gmr << ", ";
    //std::cout << "category: " << category << std::endl;
    ret = enclave_add_data(global_eid, &pwerr, &gmr, sizeof(gmr), &category, sizeof(category));
    if (ret != SGX_SUCCESS) { goto error; }
  }

  ret = enclave_finish(global_eid, &pwerr);
  if (ret != SGX_SUCCESS) { goto error; }

  destroy_enclave();
  
  return 0;

  error:
    {
      printf("enclave  failed: %#x\n", ret);
      sgx_destroy_enclave(global_eid);
      return 1;
    }

}

