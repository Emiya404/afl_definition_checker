#!/bin/bash
#args : target dir | stateful pass dir | fuzzer dir
# 1.set up ENVS
source $HOME/experiments/tools/set_fuzzenv.sh aflnet
export PATH=$PATH:$AFLNET
export DEFINITION_CHECKER_LIST=$HOME
export CC=clang
export CXX=clang++

# 2.compile & link afl-definition-checker

cd $2
make clean
make all FUZZER=AFLNET TARGET=TINYDTLS
cp ./afl-definition-checker.* $3

# 3.compile software
cd $3
make
cd $3/llvm_mode
cp $2/afl-clang-fast.c $3/llvm_mode
export CFLAGS="-O3 -funroll-loops -DAFL_CLANG_AFLNET -DAFL_CLANG_INSTRUMENT"
make clean
make

# 4.compile SUT
rm ${DEFINITION_CHECKER_LIST}/bb_count.txt
cd $1
git reset --hard 06995d4
patch -p1 <$2/../compile_scripts/tinydtls/fuzzing.patch
cd $1/tests
CC=afl-clang-fast make clean
CC=afl-clang-fast make ../libtinydtls.a $MAKE_OPT && \
CC=afl-clang-fast make $MAKE_OPT

mkdir ${FUZZ_ARENA}/tinydtls
cp -r $2/../compile_scripts/tinydtls/in-dtls/ ${FUZZ_ARENA}/tinydtls
cp ./dtls-server ${FUZZ_ARENA}/tinydtls