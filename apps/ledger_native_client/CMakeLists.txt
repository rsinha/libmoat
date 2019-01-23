cmake_minimum_required(VERSION 3.8)
project(ledger_native_client)

set(CMAKE_CXX_STANDARD 11)

include_directories(/usr/local/include/)

set(SOURCE_FILES
        ledger_client.cpp
        luciditee/ledgerentry.grpc.pb.h
        luciditee/ledgerentry.grpc.pb.cc
        luciditee/ledgerentry.pb.h
        luciditee/ledgerentry.pb.cc
        )
add_executable(ledger_native_client ${SOURCE_FILES})