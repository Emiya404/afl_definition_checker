#!/bin/bash
#args : target dir | stateful pass dir | fuzzer dir
# 1.set up ENVS
source /experiments/tools/set_fuzzenv.sh stateafl
export PATH=$PATH:$AFL_PATH
export DEFINITION_CHECKER_LIST=/
export CC=clang
export CXX=clang++

# 2.make afl-definition-checker
cd $2
make clean
make all FUZZER=STATEAFL TARGET=LIGHTFTP
cp ./afl-definition-checker.* $3
cp ./fuzzer-definition-checker.so $3

# 3.compile & instrument & link afl-definition-checker to STATEAFL
cd $3/llvm_mode
cp $2/afl-clang-fast.c $3/llvm_mode
export CFLAGS="-O3 -funroll-loops -Xclang -load -Xclang $3/fuzzer-definition-checker.so -DAFL_CLANG_STATEAFL"
make clean
make
unset CFLAGS

# 4.compile SUT
rm $DEFINITION_CHECKER_LIST/func_count.txt
rm $DEFINITION_CHECKER_LIST/func_list.txt
cd $1
git checkout 5980ea1
patch -p1 <./fuzzing.patch
cd Source/Release
CC=afl-clang-fast make -j1 clean all

# 5.copy SUT, arg files, seeds
cp ./fftp ${FUZZ_ARENA}
cp -r $2/compile_scripts/lightftp/in-ftp-replay/ ${FUZZ_ARENA}
cp $2/compile_scripts/lightftp/clean.sh ${FUZZ_ARENA}
cp $2/compile_scripts/lightftp/fftp.conf ${FUZZ_ARENA}
mkdir ${FUZZ_ARENA}/ftpshare
