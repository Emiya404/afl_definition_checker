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
make all FUZZER=AFLNET TARGET=LIGHTFTP
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
rm ${DEFINITION_CHECKER_LIST}/func_count.txt
rm ${DEFINITION_CHECKER_LIST}/func_list.txt
cd $1
git checkout 5980ea1
patch -p1 <$2/../compile_scripts/lightftp/fuzzing.patch
cd Source/Release
CC="afl-clang-fast" make clean all

# 5.copy seeds, clean scripts, SUT arg files to $FUZZ_ARENA
mkdir ${FUZZ_ARENA}/lightftp
cp -r $2/../compile_scripts/lightftp/in-ftp/ ${FUZZ_ARENA}/lightftp
cp $2/../compile_scripts/lightftp/clean.sh ${FUZZ_ARENA}/lightftp
cp $2/../compile_scripts/lightftp/fftp.conf ${FUZZ_ARENA}/lightftp
cp ./fftp ${FUZZ_ARENA}/lightftp
mkdir ${FUZZ_ARENA}/lightftp/ftpshare
