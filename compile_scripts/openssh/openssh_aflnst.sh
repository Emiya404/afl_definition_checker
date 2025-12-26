#!/bin/bash
#args : target dir | stateful pass dir | fuzzer dir
# 1.set up ENVS
source $HOME/experiments/tools/set_fuzzenv.sh aflnet
export PATH=$PATH:$AFLNET
export DEFINITION_CHECKER_LIST=$HOME
export CC=clang
export CXX=clang++
export LD_LIBRARY_PATH="/home/ubuntu/experiments/targets/openssl_for_ssh_install/lib"

# 2.compile & link afl-definition-checker
cd $2
make clean
make all FUZZER=AFLNET TARGET=OPENSSH
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
git reset --hard 7cfea58
cp $2/../compile_scripts/openssh/rand.inc $1
patch -p1 <$2/../compile_scripts/openssh/rand.patch
make clean
autoreconf
./configure CC=afl-clang-fast CFLAGS="-g -O3 -I/home/ubuntu/experiments/targets/openssl_for_ssh_install/include/" --prefix=$PWD/install --with-openssl=/home/ubuntu/experiments/targets/openssl_for_ssh_install/ --with-ldflags="-L/home/ubuntu/experiments/targets/openssl_for_ssh_install/lib/" --with-privsep-path=$PWD/var-empty --with-sandbox=no --with-privsep-user=ubuntu
rm ${DEFINITION_CHECKER_LIST}/bb_count.txt
make
make install

# 5.copy seeds, clean scripts, SUT arg files to $FUZZ_ARENA
mkdir ${FUZZ_ARENA}/openssh
cp -r $2/../compile_scripts/openssh/in-ssh/ ${FUZZ_ARENA}/openssh/
cp $1/sshd ${FUZZ_ARENA}/openssh/
cp $2/../compile_scripts/openssh/sshd_config ${FUZZ_ARENA}/openssh/
cp $2/../compile_scripts/openssh/ssh_root.sh ${FUZZ_ARENA}/openssh/

# 6.ssh root user 
cd ${FUZZ_ARENA}/openssh/
sudo ./ssh_root.sh