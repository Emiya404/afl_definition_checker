#!/bin/bash
#args : target dir | stateful pass dir | fuzzer dir
# 1.set up ENVS
source $HOME/experiments/tools/set_fuzzenv.sh stateafl
export PATH=$PATH:$AFL_PATH
export DEFINITION_CHECKER_LIST=$HOME
export CC=clang
export CXX=clang++

# 2.make afl-definition-checker
cd $2
make clean
make all FUZZER=STATEAFL TARGET=LIGHTFTP
cp ./afl-definition-checker.* $3
cp ./fuzzer-definition-checker.so $3

# 3.compile & instrument & link afl-definition-checker to STATEAFL
cd $3
make
cd $3/llvm_mode
cp $2/afl-clang-fast.c $3/llvm_mode
export CFLAGS="-O3 -funroll-loops -Xclang -load -Xclang $3/fuzzer-definition-checker.so -DAFL_CLANG_STATEAFL -DAFL_CLANG_INSTRUMENT"
make clean
make
unset CFLAGS

# 4.compile SUT
rm $DEFINITION_CHECKER_LIST/bb_count.txt
cd $1
git reset --hard 5980ea1
patch -p1 <$2/../compile_scripts/lightftp/fuzzing.patch
cd Source/Release
CC=afl-clang-fast make -j1 clean all

# 5.copy SUT, arg files, seeds
mkdir ${FUZZ_ARENA}/lightftp
cp ./fftp ${FUZZ_ARENA}/lightftp
cp -r $2/../compile_scripts/lightftp/in-ftp-replay/ ${FUZZ_ARENA}/lightftp
cp $2/../compile_scripts/lightftp/clean.sh ${FUZZ_ARENA}/lightftp
cp $2/../compile_scripts/lightftp/fftp.conf ${FUZZ_ARENA}/lightftp
mkdir ${FUZZ_ARENA}/lightftp/ftpshare
