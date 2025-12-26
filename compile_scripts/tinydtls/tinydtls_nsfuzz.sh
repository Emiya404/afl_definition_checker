#!/bin/bash
#args : target dir | stateful pass dir | fuzzer dir
# 1.set up ENVS
source $HOME/experiments/tools/set_fuzzenv.sh nsfuzz
export PATH=$PATH:$STATIC:$STATIC/build/bin/:$NSFUZZ
export DEFINITION_CHECKER_LIST=$HOME
export CC=$AFL_CC
export CXX=$AFL_CXX

# 2.compile & link afl-definition-checker

cd $2
make clean
make all FUZZER=NSFUZZ TARGET=TINYFTPD
cp ./afl-definition-checker.* $3
cp ./fuzzer-definition-checker.so $3

# 3.compile software
cd $3
make
cd $3/llvm_mode
cp $2/afl-clang-fast.c $3/llvm_mode
export CFLAGS="-O3 -funroll-loops -Xclang -load -Xclang $3/fuzzer-definition-checker.so -DAFL_CLANG_NSFUZZ -DAFL_CLANG_INSTRUMENT"
make
unset CFLAGS

# 4.compile SUT
rm ${DEFINITION_CHECKER_LIST}/bb_count.txt
cd $1
git reset --hard 06995d4
patch -p1 <$2/../compile_scripts/tinydtls/fuzzing.patch
cd $1/tests
export NSFUZZ_TRACE_STATE=1
export ANALYZER_SVFILE_PATH=$2/../compile_scripts/tinydtls/out_vars.txt
export ANALYZER_SYNCFILE_PATH=$2/../compile_scripts/tinydtls/sync_point.txt
CC=afl-clang-fast make clean
CC=afl-clang-fast make ../libtinydtls.a $MAKE_OPT && \
CC=afl-clang-fast make $MAKE_OPT

mkdir ${FUZZ_ARENA}/tinydtls
cp -r $2/../compile_scripts/tinydtls/in-dtls-replay/ ${FUZZ_ARENA}/tinydtls
cp ./dtls-server ${FUZZ_ARENA}/tinydtls