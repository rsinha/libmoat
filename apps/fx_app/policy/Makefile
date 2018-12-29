######## SGX SDK Settings ########

MAKE := make

######## Library Settings ########

######## App Settings ########

Host_Cpp_Files := specification.pb.cc ledgerentry.pb.cc policy_creator.cpp
Host_Include_Paths := -I.

Protobuf_C_Flags := -D_THREAD_SAFE -I/usr/local/include
Host_C_Flags := $(Protobuf_C_Flags) -fPIC -Wno-attributes $(Host_Include_Paths)
Host_Cpp_Flags := $(Host_C_Flags) -std=c++11
Protobuf_Link_Flags := -L/usr/local/lib -l:libprotobuf.a -D_THREAD_SAFE
Host_Link_Flags := -std=c++11 $(Protobuf_Link_Flags) -lpthread

Host_Cpp_Objects := specification.pb.o delivery.pb.o record.pb.o Ledger.pb.o ledgerentry.pb.o policy_creator.o

Host_Name := policy_creator.out

.PHONY: all run

all: $(Host_Name)

run: all

######## App Objects ########

Ledger.pb.cc: Ledger.proto
	@echo "GEN  =>  $@"
	@protoc --cpp_out=. Ledger.proto

Ledger.pb.o: Ledger.pb.cc
	@echo "CXX   <=  $<"
	@$(CXX) $(Host_Cpp_Flags) -c $< -o $@

ledgerentry.pb.cc: specification.pb.cc record.pb.cc ../common/ledgerentry.proto
	@echo "GEN  =>  $@"
	@protoc --proto_path=../common --cpp_out=. ledgerentry.proto

ledgerentry.pb.o: ledgerentry.pb.cc
	@echo "CXX   <=  $<"
	@$(CXX) $(Host_Cpp_Flags) -c $< -o $@

delivery.pb.cc: ../common/delivery.proto
	@echo "GEN  =>  $@"
	@protoc --proto_path=../common --cpp_out=. delivery.proto

delivery.pb.o: delivery.pb.cc
	@echo "CXX   <=  $<"
	@$(CXX) $(Host_Cpp_Flags) -c $< -o $@

record.pb.cc: ../common/record.proto
	@echo "GEN  =>  $@"
	@protoc --proto_path=../common --cpp_out=. record.proto

record.pb.o: record.pb.cc
	@echo "CXX   <=  $<"
	@$(CXX) $(Host_Cpp_Flags) -c $< -o $@

specification.pb.cc: ../common/specification.proto
	@echo "GEN  =>  $@"
	@protoc --proto_path=../common --cpp_out=. specification.proto

specification.pb.o: specification.pb.cc
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
