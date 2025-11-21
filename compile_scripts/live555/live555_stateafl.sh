#!/bin/bash
#args : target dir | stateful pass dir | fuzzer dir
# 1.set up ENVS
source $HOME/experiments/tools/set_fuzzenv.sh stateafl
export PATH=$PATH:$AFL_PATH
export DEFINITION_CHECKER_LIST=$HOME
export CC=clang
export CXX=clang++

# 2.compile & link afl-definition-checker
cd $2
make clean
make all FUZZER=STATEAFL TARGET=LIVE555
cp ./afl-definition-checker.* $3

# 3.compile software
cd $3
make
cd $3/llvm_mode
cp $2/afl-clang-fast.c $3/llvm_mode
export CFLAGS="-O3 -funroll-loops -Xclang -load -Xclang $3/fuzzer-definition-checker.so -DAFL_CLANG_STATEAFL -DAFL_CLANG_INSTRUMENT"
make clean
make
unset CFLAGS

# 4.compile SUT
rm ${DEFINITION_CHECKER_LIST}/bb_count.txt
cd $1
git reset --hard ceeb4f4
patch -p1 <$2/../compile_scripts/live555/live555_no_decomposed.patch
./genMakefiles linux && \
AFL_USE_ASAN=1 make clean all $MAKE_OPT || make all

# 5.copy seeds, clean scripts, SUT arg files to $FUZZ_ARENA
mkdir ${FUZZ_ARENA}/live555 
cp -r $2/../compile_scripts/live555/in-rtsp-replay/ ${FUZZ_ARENA}/live555
cp $1/testProgs/testOnDemandRTSPServer  ${FUZZ_ARENA}/live555
cp $2/../compile_scripts/live555/sample_media_sources/* ${FUZZ_ARENA}/live555
cp $2/../compile_scripts/live555/rtsp.dict ${FUZZ_ARENA}/live555
