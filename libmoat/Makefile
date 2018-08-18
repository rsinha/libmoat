######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
LIBMOAT := .
LIBMOAT_NETWORK := $(LIBMOAT)/src/Network
LIBMOAT_UTILS := $(LIBMOAT)/src/Utils
LIBMOAT_LOG := $(LIBMOAT)/src/Log
LIBMOAT_STORAGE := $(LIBMOAT)/src/Storage
LIBMOAT_KEYMGMT := $(LIBMOAT)/src/KeyManagement

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

Trust_Lib_Name := libmoat.a
TrustLib_C_Files := $(wildcard src/Network/*.c) \
                    $(wildcard src/Network/RecordChannel/*.c) \
                    $(wildcard src/Storage/*.c) \
                    $(wildcard src/Storage/BlockStorage/*.c) \
                    $(wildcard src/Storage/ChunkyStorage/*.c) \
                    $(wildcard src/Log/*.c) \
                    $(wildcard src/KeyManagement/*.c) \
                    $(wildcard src/Utils/*.c)
TrustLib_Cpp_Files := 
TrustLib_C_Objects := $(TrustLib_C_Files:.c=.o)
TrustLib_Cpp_Objects := $(TrustLib_Cpp_Files:.cpp=.o)
TrustLib_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid -I./Include
TrustLib_Compile_C_Flags := $(SGX_COMMON_CFLAGS) -std=gnu99 -Wno-unused-parameter -Wno-missing-field-initializers -nostdinc -fPIC -fstack-protector $(TrustLib_Include_Paths)
TrustLib_Compile_Cxx_Flags := $(SGX_COMMON_CFLAGS) -std=c++03 -nostdinc++ -Wno-unused-parameter -Wno-missing-field-initializers -fPIC -fstack-protector $(TrustLib_Include_Paths)

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_C_Files := enclave/enclave.c
Enclave_Include_Paths := -I../common -Ienclave -I$(LIBMOAT)/api -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -std=gnu99 -Wno-unused-parameter -Wno-missing-field-initializers -nostdinc -fvisibility=hidden -fPIC $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(SGX_COMMON_CFLAGS) -std=c++03 -Wno-unused-parameter -Wno-missing-field-initializers -nostdinc++ -fvisibility=hidden -fPIC $(Enclave_Include_Paths)

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=enclave/enclave.lds

Enclave_C_Objects := $(Enclave_C_Files:.c=.o)

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
all: $(Trust_Lib_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(Host_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(Trust_Lib_Name)
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

######## Library Objects ########

$(LIBMOAT_LOG)/%.o: $(LIBMOAT_LOG)/%.c
	@echo "CC   <= $<"
	@$(CC) $(TrustLib_Compile_C_Flags) -c $< -o $@

$(LIBMOAT_KEYMGMT)/%.o: $(LIBMOAT_KEYMGMT)/%.c
	@echo "CC   <= $<"
	@$(CC) $(TrustLib_Compile_C_Flags) -c $< -o $@

$(LIBMOAT_UTILS)/%.o: $(LIBMOAT_UTILS)/%.c
	@echo "CC   <= $<"
	@$(CC) $(TrustLib_Compile_C_Flags) -c $< -o $@

$(LIBMOAT_STORAGE)/ChunkyStorage/%.o: $(LIBMOAT_STORAGE)/ChunkyStorage/%.c
	@echo "CC   <= $<"
	@$(CC) $(TrustLib_Compile_C_Flags) -c $< -o $@

$(LIBMOAT_STORAGE)/BlockStorage/%.o: $(LIBMOAT_STORAGE)/BlockStorage/%.c
	@echo "CC   <= $<"
	@$(CC) $(TrustLib_Compile_C_Flags) -c $< -o $@

$(LIBMOAT_STORAGE)/%.o: $(LIBMOAT_STORAGE)/%.c
	@echo "CC   <= $<"
	@$(CC) $(TrustLib_Compile_C_Flags) -c $< -o $@

$(LIBMOAT_NETWORK)/%.o: $(LIBMOAT_NETWORK)/%.c
	@echo "CC   <= $<"
	@$(CC) $(TrustLib_Compile_C_Flags) -c $< -o $@

$(LIBMOAT_NETWORK)/RecordChannel/%.o: $(LIBMOAT_NETWORK)/RecordChannel/%.c
	@echo "CC   <= $<"
	@$(CC) $(TrustLib_Compile_C_Flags) -c $< -o $@

$(Trust_Lib_Name): $(TrustLib_Cpp_Objects) $(TrustLib_C_Objects)
	@echo "AR   =>  $@"
	@$(AR) rcs $@ $^

.PHONY: clean

clean:
	@rm -f $(Trust_Lib_Name)
	@find . -name *.o | xargs -I {} rm -f {}
