LLVM_CONFIG ?= llvm-config
CFLAGS      ?= -O3 -funroll-loops
CFLAGS      += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign

CXXFLAGS = -O3 -funroll-loops -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign

PASS_CFL = `$(LLVM_CONFIG) --cxxflags` -Wl,-znodelete -fno-rtti -fPIC $(CXXFLAGS) 
PASS_LFL = `$(LLVM_CONFIG) --ldflags`

RUNTIME_CFL = -D$(FUZZER)_CLIENT

ifeq ($(FUZZER),AFLNET)
	AFL_PASS_CFL = $(PASS_CFL) -DPACKET_SEND_INSTRUMENT
	AFL_PASS_CFL += -D$(TARGET)_SEND_INSTRUMENT
endif

ifeq ($(FUZZER),STATEAFL)
	AFL_PASS_CFL = $(PASS_CFL) -DMEMORY_STATE_INSTRUMENT
endif

ifeq ($(FUZZER),NSFUZZ)
	AFL_PASS_CFL = $(PASS_CFL) -DMEMORY_STATE_INSTRUMENT
endif
	

./afl-definition-checker.so: afl-definition-checker.cc
	$(CXX) $(AFL_PASS_CFL) -DFUNCLIST_EXTRACT -shared $< -o $@ $(PASS_LFL)
	@echo $(CXX) $(AFl_PASS_CFL) -DFUNCLIST_EXTRACT -shared $< -o $@ $(PASS_LFL)

./fuzzer-definition-checker.so: afl-definition-checker.cc
	$(CXX) $(PASS_CFL) -DMEMORY_STATE_INSTRUMENT -shared $< -o $@ $(PASS_LFL)
	@echo $(CXX) $(PASS_CFL) -DMEMORY_STATE_INSTRUMENT -shared $< -o $@ $(PASS_LFL)	 

./afl-definition-checker.o: definition-checker.c
	$(CC) $(CFLAGS) $(RUNTIME_CFL) -fPIC -c $< -o $@
	@echo $(CC) $(CFLAGS) $(RUNTIME_CFL) -fPIC -c $< -o $@

./afl-definition-monitor: afl-definition-monitor.c
	$(CC) $(CFLAGS) -fPIC $< -o $@
	@echo $(CC) $(CFLAGS) -fPIC $< -o $@

all: afl-definition-checker.so afl-definition-checker.o afl-definition-monitor fuzzer-definition-checker.so
	@echo "[*]make afl-definition-checker afl-definition-monitor"
clean: 
	rm ./afl-definition-checker.so
	rm ./afl-definition-monitor
	rm ./afl-definition-checker.o
	rm ./fuzzer-definition-checker.so
