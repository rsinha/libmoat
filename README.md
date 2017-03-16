# libmoat
[![Build Status](https://travis-ci.com/rsinha/libmoat.svg?token=D2mdydEyqN9gqKmdCX5p&branch=master)](https://travis-ci.com/rsinha/libmoat)

Enclave Programming Library with APIs for secure communication and file storage
* `moat_create_channel` API to establish a TLS-like bi-directional channel between two enclaves. 
The channel provides confidentiality, integrity, authenticity, and freshness (replay protection) guarantees.
* `moat_channel_send`(buf) and `moat_channel_recv`(buf) APIs to send bytes over the created channel.
* `moat_file_create(name)` and `moat_file_delete(name)` APIs to create and delete files (which are stored in the untrusted disk or memory).
* `moat_file_read(buf, offset)` and `moat_file_write(buf, offset)` API to write bytes at the specified offset.

# Setup

libmoat requires the following dependencies:
* Ubuntu Linux Operating System. libmoat has been tested with 14.04 LTS 64-bit and 16.04 LTS 64-bit.
* Intel SGX Linux Driver: used to launch enclaves.
Follow instructions on https://github.com/01org/linux-sgx-driver
* Intel SGX SDK: provides several utilities for developing and signing enclave programs.
Follow instructions on https://github.com/01org/linux-sgx
* ZeroMQ: used in the untrusted code to send messages between different actors.
Follow instructions on http://zeromq.org/intro:get-the-software.
libmoat has been tested with v4.2.1.
* C bindings for ZeroMQ: used in the untrusted code to send messages between actors.
Follow instructions on http://czmq.zeromq.org/page:get-the-software. 
libmoat has been tested with v4.0.2.
* gcc compiler for compiling enclave programs. libmoat has been tested with version 4.8.
* g++ compiler for compiling the untrusted host application. libmoat has been tested with version 4.8.

Note that running SGX programs requires an Intel CPU with SGX instructions enabled.
If this is not available, you can install SGX driver in simulation mode.

To learn how to use libmoat, experiment with a sample application written using libmoat e.g. [client](apps/testSCC/client) and [server](apps/testSCC/client)

# Read more

* libmoat has been described extensively in a publication in [PLDI 2016](https://people.eecs.berkeley.edu/~rsinha/research/pubs/pldi2016.pdf)
* Related literature on provably safe (confidential) enclave programs appears in [CCS 2015](https://people.eecs.berkeley.edu/~rsinha/research/pubs/ccs2015.pdf)
