######## SGX SDK Settings ########

MAKE := make

######## Library Settings ########

######## App Settings ########

Host_Cpp_Files := computation.pb.cc policy_creator.cpp
Host_Include_Paths := -I.

Protobuf_C_Flags := -D_THREAD_SAFE -I/usr/local/include
Host_C_Flags := $(Protobuf_C_Flags) -fPIC -Wno-attributes $(Host_Include_Paths)
Host_Cpp_Flags := $(Host_C_Flags) -std=c++11
Protobuf_Link_Flags := -L/usr/local/lib -l:libprotobuf.a -D_THREAD_SAFE
Host_Link_Flags := -std=c++11 $(Protobuf_Link_Flags) -lpthread

Host_Cpp_Objects := computation.pb.o policy_creator.o

Host_Name := policy_checker.out

.PHONY: all run

all: $(Host_Name)

run: all

######## App Objects ########

computation.pb.cc: ../common/computation.proto
	@echo "GEN  =>  $@"
	@protoc --proto_path=../common --cpp_out=. computation.proto

computation.pb.o: computation.pb.cc
	@echo "CXX   <=  $<"
	@$(CXX) $(Host_Cpp_Flags) -c $< -o $@

%.o: %.cpp
	@echo "CXX  <=  $<"
	@$(CXX) $(Host_Cpp_Flags) -c $< -o $@

$(Host_Name): $(Host_Cpp_Objects)
	@echo "LINK =>  $@"
	@$(CXX) -o $@ $^ $(Host_Link_Flags)


.PHONY: clean

clean:
	@rm -f $(Host_Name) *.pb.* *.o
