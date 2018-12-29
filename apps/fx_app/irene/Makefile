######## SGX SDK Settings ########

MAKE := make
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

######## Library Settings ########

Untrust_Lib_Path := ../../../libbarbican
Untrust_Lib_Name := libbarbican.a
Untrust_Lib := $(Untrust_Lib_Path)/$(Untrust_Lib_Name)
Trust_Lib_Path := ../../../libmoat
Trust_Lib_Name := libmoat.a
Trust_Lib := $(Trust_Lib_Path)/$(Trust_Lib_Name)

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

Host_Cpp_Files := host/secret.pb.cc host/host_irene.cpp
#Host_Include_Paths := -I../common -Ihost -I$(SGX_SDK)/include
Host_Include_Paths := -Ihost -I$(SGX_SDK)/include

Protobuf_C_Flags := -D_THREAD_SAFE -I/usr/local/include
Host_C_Flags := $(Protobuf_C_Flags) $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Host_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        Host_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        Host_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        Host_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

Host_Cpp_Flags := $(Host_C_Flags) -std=c++11
Protobuf_Link_Flags := -L/usr/local/lib -l:libprotobuf.a -D_THREAD_SAFE
RocksDB_Link_Flags := -lrocksdb -lpq -lz -lbz2 -llz4 -lzstd -lsnappy -l:libjemalloc.a -ldl
Host_Link_Flags := -std=c++11 $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) $(Protobuf_Link_Flags) -L/usr/local/lib -lzmq -lczmq -lhiredis $(RocksDB_Link_Flags) -lpthread

ifneq ($(SGX_MODE), HW)
	Host_Link_Flags += -lsgx_uae_service_sim
else
	Host_Link_Flags += -lsgx_uae_service
endif

Host_Cpp_Objects := host/secret.pb.o host/host_irene.o

Host_Name := irene.out

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_C_Files := enclave/protobuf-c.c enclave/secret.pb-c.c enclave/enclave.c
Protobuf_Include_Paths := -I/usr/local/include
#Enclave_Include_Paths := $(Protobuf_Include_Paths) -I../common -Ienclave -I$(Trust_Lib_Path)/api -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc
Enclave_Include_Paths := $(Protobuf_Include_Paths) -Ienclave -I$(Trust_Lib_Path)/api -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -std=gnu99 -Wno-unused-parameter -Wno-missing-field-initializers -nostdinc -fvisibility=hidden -fPIC $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(SGX_COMMON_CFLAGS) -std=c++03 -Wno-unused-parameter -Wno-missing-field-initializers -nostdinc++ -fvisibility=hidden -fPIC $(Enclave_Include_Paths)

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Protobuf_Enc_Link_Flags := -L/usr/local/lib -lprotobuf-c -D_THREAD_SAFE
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(Crypto_Library_Name) -L$(Trust_Lib_Path) -l:$(Trust_Lib_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=enclave/enclave.lds

Enclave_C_Objects := enclave/protobuf-c.o enclave/secret.pb-c.o enclave/enclave.o

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := enclave/enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(Host_Name) $(Signed_Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(Host_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(Host_Name) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@echo "RUN  =>  $(Host_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
	@$(CURDIR)/$(Host_Name) &
endif

######## Library Objects ########

$(Untrust_Lib): 
	@echo "MAKE   =>  $@"
	@$(MAKE) -C $(Untrust_Lib_Path)

$(Trust_Lib): 
	@echo "MAKE   =>  $@"
	@$(MAKE) -C $(Trust_Lib_Path)

######## App Objects ########

host/secret.pb.cc: ../common/secret.proto
	@echo "GEN  =>  $@"
	@protoc --proto_path=../common --cpp_out=host secret.proto

host/interface_u.c: $(SGX_EDGER8R) interface.edl
	@echo "GEN  =>  $@"
	@cd host && $(SGX_EDGER8R) --untrusted ../interface.edl --search-path ../enclave --search-path $(SGX_SDK)/include

host/secret.pb.o: host/secret.pb.cc
	@echo "CXX   <=  $<"
	@$(CXX) $(Host_Cpp_Flags) -c $< -o $@

host/interface_u.o: host/interface_u.c
	@echo "CXX   <=  $<"
	@$(CXX) $(Host_Cpp_Flags) -c $< -o $@

host/%.o: host/%.cpp
	@echo "CXX  <=  $<"
	@$(CXX) $(Host_Cpp_Flags) -c $< -o $@

$(Host_Name): host/interface_u.o $(Host_Cpp_Objects) $(Untrust_Lib)
	@echo "LINK =>  $@"
	@$(CXX) -o $@ $^ $(Host_Link_Flags)


######## Enclave Objects ########

enclave/secret.pb-c.c: ../common/secret.proto
	@echo "GEN  =>  $@"
	@protoc --proto_path=../common --c_out=enclave secret.proto

#enclave/secret.pb-c.o: enclave/secret.pb-c.c
#	@echo "CC   <=  $<"
#	@$(CC) $(Enclave_C_Flags) -c $< -o $@

enclave/interface_t.c: $(SGX_EDGER8R) interface.edl
	@echo "GEN  =>  $@"
	@cd enclave && $(SGX_EDGER8R) --trusted ../interface.edl --search-path ../enclave --search-path $(SGX_SDK)/include

enclave/interface_t.o: enclave/interface_t.c
	@echo "CC   <=  $<"
	@$(CC) $(Enclave_C_Flags) -c $< -o $@

enclave/%.o: enclave/%.c
	@echo "CC   <=  $<"
	@$(CC) $(Enclave_C_Flags) -c $< -o $@

$(Enclave_Name): $(Trust_Lib) $(Enclave_C_Objects) enclave/interface_t.o
	@echo "LINK =>  $@"
	@$(CXX) enclave/interface_t.o $(Enclave_C_Objects) -o $@ $(Enclave_Link_Flags)

$(Signed_Enclave_Name): $(Enclave_Name)
	@echo "SIGN =>  $@"
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)

.PHONY: clean

clean:
	@rm -f $(Host_Name) $(Enclave_Name) $(Signed_Enclave_Name)
	@rm -f host/interface_u.* host/*.pb.* enclave/interface_t.* host/*.o enclave/*.o enclave/secret.* host/secret.*
	@rm -f $(Trust_Lib) $(Untrust_Lib)
	@$(MAKE) -C $(Trust_Lib_Path) clean
	@$(MAKE) -C $(Untrust_Lib_Path) clean
