######## SGX SDK Settings ########

MAKE := make

######## Library Settings ########

ProtoDir := $(CURDIR)/../common

######## App Settings ########

Host_Cpp_Files := specification.pb.cc ledgerentry.pb.cc policy_creator.cpp
Host_Include_Paths := -I.

Protobuf_C_Flags := -D_THREAD_SAFE -I/usr/local/include
Host_C_Flags := $(Protobuf_C_Flags) -fPIC -Wno-attributes $(Host_Include_Paths)
Host_Cpp_Flags := $(Host_C_Flags) -std=c++11
Protobuf_Link_Flags := -L/usr/local/lib -l:libprotobuf.a -D_THREAD_SAFE
Host_Link_Flags := -std=c++11 $(Protobuf_Link_Flags) -lpthread

Host_Link_Flags += -L/usr/local/lib `pkg-config --libs protobuf grpc++ grpc`\
           -Wl,--no-as-needed -lgrpc++_reflection -Wl,--as-needed\
           -ldl

Host_Cpp_Objects := ledgerentry.grpc.pb.o ledgerentry.pb.o LedgerClient.o policy_creator.o

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

ledgerentry.grpc.pb.cc: ledgerentry.proto
	@protoc --cpp_out=. $<
	@protoc --grpc_out=. --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` $<

ledgerentry.pb.cc: $(ProtoDir)/ledgerentry.proto specification.pb.cc record.pb.cc delivery.pb.cc
	@echo "GEN  =>  $@"
	@protoc --cpp_out=. --proto_path=$(ProtoDir) $<

ledgerentry.pb.o: ledgerentry.pb.cc
	@echo "CXX   <=  $<"
	@$(CXX) $(Host_Cpp_Flags) -c $< -o $@

delivery.pb.cc: $(ProtoDir)/delivery.proto
	@echo "GEN  =>  $@"
	@protoc --cpp_out=. --proto_path=$(ProtoDir) $<

delivery.pb.o: delivery.pb.cc
	@echo "CXX   <=  $<"
	@$(CXX) $(Host_Cpp_Flags) -c $< -o $@

record.pb.cc: $(ProtoDir)/record.proto
	@echo "GEN  =>  $@"
	@protoc --cpp_out=. --proto_path=$(ProtoDir) $<

record.pb.o: record.pb.cc
	@echo "CXX   <=  $<"
	@$(CXX) $(Host_Cpp_Flags) -c $< -o $@

specification.pb.cc: $(ProtoDir)/specification.proto
	@echo "GEN  =>  $@"
	@protoc --cpp_out=. --proto_path=$(ProtoDir) $<

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
