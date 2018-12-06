
MAKE := make

######## Library Settings ########

Untrust_Lib_Path := ../../../libbarbican
Untrust_Lib_Name := libbarbican.a
Untrust_Lib := $(Untrust_Lib_Path)/$(Untrust_Lib_Name)

######## App Settings ########

Host_Cpp_Files := host_bank.cpp ../common/tx.pb.cc
Host_Include_Paths := -I../common

Protobuf_C_Flags := -D_THREAD_SAFE -I/opt/local/include
Host_C_Flags := $(Protobuf_C_Flags) -fPIC -Wno-attributes $(Host_Include_Paths) -DDEBUG -UNDEBUG -UEDEBUG

Host_Cpp_Flags := $(Host_C_Flags) -std=c++11
Protobuf_Link_Flags := -L/opt/local/lib -lprotobuf -D_THREAD_SAFE
RocksDB_Link_Flags := -lrocksdb -lpq -lz -lbz2 -llz4 -lzstd -lsnappy -l:libjemalloc.a -ldl
Host_Link_Flags := $(Protobuf_Link_Flags) -L/usr/local/lib -lzmq -lczmq -lhiredis $(RocksDB_Link_Flags) -lpthread

Host_Cpp_Objects := $(Host_Cpp_Files:.cpp=.o)

Host_Name := bank.out

.PHONY: all run

all: $(Host_Name)
	@echo "The project has been built."

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@echo "RUN  =>  $(Host_Name)"
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

%.o: %.cpp
	@echo "CXX  <=  $<"
	@$(CXX) $(Host_Cpp_Flags) -c $< -o $@

$(Host_Name): $(Host_Cpp_Objects) $(Untrust_Lib)
	@echo "LINK =>  $@"
	@$(CXX) -o $@ $^ $(Host_Link_Flags)


.PHONY: clean

clean:
	@rm -f $(Host_Name)
	@rm -f *.o
	@rm -f $(Untrust_Lib)
	@$(MAKE) -C $(Untrust_Lib_Path) clean
