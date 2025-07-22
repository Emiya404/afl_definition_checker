#!/bin/bash
#args : target dir | stateful pass dir | fuzzer dir
# 1.set up ENVS
source /experiments/tools/set_fuzzenv.sh nsfuzz
export PATH=$PATH:$STATIC:$STATIC/build/bin/:$NSFUZZ
export DEFINITION_CHECKER_LIST=/
export CC=$AFL_CC
export CXX=$AFL_CXX

# 2.compile & link afl-definition-checker
cd $2
make clean
make all FUZZER=NSFUZZ TARGET=LIGHTFTP
cp ./afl-definition-checker.* $3
cp ./fuzzer-definition-checker.so $3

# 3.compile fuzzer
cd $3/llvm_mode
cp $2/afl-clang-fast.c $3/llvm_mode
export CFLAGS="-O3 -funroll-loops -DAFL_CLANG_NSFUZZ"
make clean
make
unset CFLAGS

# 4.static analyse SUT
cd $1
cd Source/Release
make clean
CC="clang-emit-bc-new.sh" make
find . -name "*.llbc" >bitcode.list
python3 $NSFUZZ/PreAnalysis/SVAnalyzer/get_backtrace.py --sut_path ./fftp --sut_option "$2/compile_scripts/lightftp/fftp.conf 2200" --port 2200
SVAnalyzer @bitcode.list -i input.btrace -o static_out -s sync_point --dump-call-map >output_test 2>&1

# 5.compile SUT
rm ${DEFINITION_CHECKER_LIST}func_count.txt
rm ${DEFINITION_CHECKER_LIST}func_list.txt
cd $1
git checkout 5980ea1
patch -p1 <./fuzzing.patch
cd Source/Release
make clean
export NSFUZZ_TRACE_STATE=1
export ANALYZER_SVFILE_PATH="$PWD/static_out"
export ANALYZER_SYNCFILE_PATH="$PWD/sync_point"
CC=afl-clang-fast make

# 5.copy seeds, clean scripts, SUT arg files to $FUZZ_ARENA
cp -r $2/compile_scripts/lightftp/in-ftp-replay/ ${FUZZ_ARENA}
cp $2/compile_scripts/lightftp/clean.sh ${FUZZ_ARENA}
cp $2/compile_scripts/lightftp/fftp.conf ${FUZZ_ARENA}
cp ./fftp ${FUZZ_ARENA}
mkdir ${FUZZ_ARENA}/ftpshare
