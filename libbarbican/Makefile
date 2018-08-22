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

Lib_Name := libbarbican.a
Lib_Cpp_Files := Barbican.cpp RocksDBInterface.cpp

######## App Settings ########

Lib_Include_Paths :=  -I$(SGX_SDK)/include -I$(HIREDIS_INC_PATH)

Lib_C_Flags := -fPIC -Wno-attributes $(Lib_Include_Paths)
Lib_Cpp_Flags := $(Lib_C_Flags) -std=c++11
Lib_Cpp_Objects := $(Lib_Cpp_Files:.cpp=.o)

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

%.o: %.cpp
	@echo "CXX  <=  $<"
	@$(CXX) $(Lib_Cpp_Flags) -c $< -o $@

######## Enclave Objects ########

.PHONY: clean

clean:
	@rm -f $(Lib_Name)
	@rm -f *.o
