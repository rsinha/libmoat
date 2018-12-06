#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>

#include <unistd.h>
#include <pwd.h>
#include "csv.h"

#include "tx.pb.h"

using namespace std;

int main(int argc, char *argv[])
{
  //step 1: parse the csv file containing all transactions
  //step 2: put each element in the kvs
  io::CSVReader<3> in("txs.csv");
  in.read_header(io::ignore_extra_column, "amount", "gmr", "timestamp");
  uint64_t amount, gmr, timestamp;
  while(in.read_row(amount, gmr, timestamp)) {
    std::cout << "amount: " << amount << ", ";
    std::cout << "gmr: " << gmr << ", ";
    std::cout << "timestamp: " << timestamp << endl;

    cctx::Transaction tx;
    tx.set_amount(amount);
    tx.set_gmr(gmr);
    tx.set_timestamp(timestamp);

    
  }

  return 0;
}

int sample(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    GOOGLE_PROTOBUF_VERIFY_VERSION;

    //int r = enclave_computation();
    cctx::Transaction tx;
    tx.set_amount(120);
    tx.set_gmr(35);
    tx.set_timestamp(3523524);

    size_t size = tx.ByteSize();
    std::cout << "byte encoding has size " << size << endl;
    void *buf1 = malloc(size);
    if(!buf1) { std::cout << "unable to malloc" << std::endl; exit(1); }
    if (!tx.SerializeToArray(buf1, size)) {
      std::cerr << "Failed to write tx" << std::endl;
      return -1;
    }

    void *buf2 = malloc(size);
    if(!buf2) { std::cout << "unable to malloc" << std::endl; exit(1); }
    memcpy(buf2, buf1, size);
    cctx::Transaction tx_parsed;
    if (!tx_parsed.ParseFromArray(buf2, size)) {
      std::cerr << "Failed to parse tx" << std::endl;
      return -1;
    }

    std::cout << "tx_parsed.amt: " << tx_parsed.amount() << std::endl;
    std::cout << "tx_parsed.gmr: " << tx_parsed.gmr() << std::endl;
    std::cout << "tx_parsed.time: " << tx_parsed.timestamp() << std::endl;

    // Optional:  Delete all global objects allocated by libprotobuf.
    google::protobuf::ShutdownProtobufLibrary();

    return 0;
}



