LLVM_CONFIG ?= llvm-config
CXXFLAGS = -O3 -funroll-loops -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign

PASS_CFL = `$(LLVM_CONFIG) --cxxflags` -Wl,-znodelete -fno-rtti -fPIC $(CXXFLAGS)
PASS_LFL = `$(LLVM_CONFIG) --ldflags`

./pass1.so: pass1.cc
	$(CXX) $(PASS_CFL) -shared $< -o $@ $(PASS_LFL)
	@echo $(CXX) $(PASS_CFL) -shared $< -o $@ $(PASS_LFL)

./pass2.so: pass2.cc
	$(CXX) $(PASS_CFL) -shared ./pass2.cc -o ./pass2.so $(PASS_LFL)
	@echo $(CXX) $(PASS_CFL) -shared ./pass2.cc -o ./pass2.so $(PASS_LFL)

all: ./pass1.so ./pass2.so


