######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk

######## Other Dependency Settings ########
HIREDIS_INC_PATH := /usr/local/include/hiredis
HIREDIS_LIB_PATH := /usr/local/lib
HIREDIS_LIB_NAME := libhiredis.a

CZMQ_INC_PATH := /usr/local/include
CZMQ_LIB_PATH := /usr/local/lib
CZMQ_LIB_NAME := libczmq.a

ZMQ_INC_PATH := /usr/local/include
ZMQ_LIB_PATH := /usr/local/lib
ZMQ_LIB_NAME := libzmq.a

PTHREAD_LIB_PATH := /usr/lib/x86_64-linux-gnu
PTHREAD_LIB_NAME := libpthread.a

#DEPENDENCIES := $(HIREDIS_LIB_PATH)/$(HIREDIS_LIB_NAME) $(ZMQ_LIB_PATH)/$(ZMQ_LIB_NAME) $(CZMQ_LIB_PATH)/$(CZMQ_LIB_NAME) $(PTHREAD_LIB_PATH)/$(PTHREAD_LIB_NAME)

######## Library Settings ########
Ledger_Client_Sources := ledgerentry.grpc.pb.cc ledgerentry.pb.cc LedgerClient.cpp

Lib_Name := libbarbican.a
#Lib_Cpp_Files := Ledger.pb.cc ledgerentry.pb.cc Barbican.cpp RocksDBInterface.cpp $(Ledger_Client_Sources)

######## App Settings ########

Lib_Include_Paths :=  -I$(SGX_SDK)/include -I$(HIREDIS_INC_PATH)
Protobuf_C_Flags := -D_THREAD_SAFE -I/usr/local/include
Lib_C_Flags := $(Protobuf_C_Flags) -fPIC -Wno-attributes $(Lib_Include_Paths)
Lib_Cpp_Flags := $(Lib_C_Flags) -std=c++11
Ledger_Client_Objects := ledgerentry.grpc.pb.o ledgerentry.pb.o LedgerClient.o
Lib_Cpp_Objects :=  $(Ledger_Client_Objects) Barbican.o RocksDBInterface.o

######## Enclave Settings ########

.PHONY: all

all: $(Lib_Name)
	@echo "The project has been built."

######## Library Objects ########

$(Lib_Name): $(Lib_Cpp_Objects) $(Lib_C_Objects)
	@echo "AR   =>  $@"
	@$(AR) rcs $@ $(DEPENDENCIES) $^
	ranlib $@

######## App Objects ########

ledgerentry.pb.cc: ledgerentry.proto
	@echo "GEN1 <= $<"
	@protoc --cpp_out=. $<

ledgerentry.grpc.pb.cc: ledgerentry.proto
	@echo "GEN2 <= $<"
	@protoc --cpp_out=. $<
	@protoc --grpc_out=. --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` $<

%.grpc.pb.o: %.grpc.pb.cc
	@echo "CXX   <=  $<"
	@$(CXX) $(Lib_Cpp_Flags) -c $< -o $@

%.pb.o: %.pb.cc
	@echo "CXX   <=  $<"
	@$(CXX) $(Lib_Cpp_Flags) -c $< -o $@

%.o: %.cpp
	@echo "CXX  <=  $<"
	@$(CXX) $(Lib_Cpp_Flags) -c $< -o $@

######## Enclave Objects ########

.PHONY: clean

clean:
	@rm -f $(Lib_Name)
	@rm -f *.o *.pb.cc
