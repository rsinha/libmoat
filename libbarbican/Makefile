######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk

######## Other Dependency Settings ########
HIREDIS_INC_PATH := /usr/local/include/hiredis
HIREDIS_LIB_PATH := /usr/local/lib

######## Library Settings ########

Lib_Name := libbarbican.a
Lib_Cpp_Files := barbican.cpp 

######## App Settings ########

Lib_Include_Paths :=  -I$(SGX_SDK)/include -I$(HIREDIS_INC_PATH)

Lib_C_Flags := -fPIC -Wno-attributes $(Lib_Include_Paths)
Lib_Cpp_Flags := $(Lib_C_Flags) -std=c++11
Lib_Link_Flags := -lpthread -lzmq -lczmq -L$(HIREDIS_LIB_PATH) -lhiredis

Lib_Cpp_Objects := $(Lib_Cpp_Files:.cpp=.o)

######## Enclave Settings ########

.PHONY: all

all: $(Lib_Name)
	@echo "The project has been built."

######## Library Objects ########

$(Lib_Name): $(Lib_Cpp_Objects) $(Lib_C_Objects)
	@echo "AR   =>  $@"
	@$(AR) rcs $@ $^

######## App Objects ########

%.o: %.cpp
	@echo "CXX  <=  $<"
	@$(CXX) $(Lib_Cpp_Flags) -c $< -o $@

######## Enclave Objects ########

.PHONY: clean

clean:
	@rm -f $(Lib_Name)
	@rm -f *.o
