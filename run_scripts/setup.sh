#!/bin/bash

#1. check args
if [ $# -eq 3 ]; then
    echo "[!]err arguments"
    echo "useage: $0 <target> <fuzzer>"
    exit 1
fi

TARGET=$1
FUZZER=$2

#2. set up env
source /home/ubuntu/experiments/tools/set_fuzzenv.sh ${FUZZER}
echo -e "\033[32m[*]set fuzzing env success\033[0m"


#3. compile the SUT
COMPILE_SCRIPT="/home/ubuntu/experiments/stateful_pass/compile_scripts/${TARGET}/${TARGET}_${FUZZER}.sh"
TARGET_DIR="/home/ubuntu/experiments/targets/${TARGET}"
FUZZER_DIR="/home/ubuntu/experiments/fuzzers/${FUZZER}"
PASSSRC_DIR="/home/ubuntu/experiments/stateful_pass/src/"
${COMPILE_SCRIPT} ${TARGET_DIR} ${PASSSRC_DIR} ${FUZZER_DIR} > /dev/null
COMPILE_STATUS=$?
if [ ${COMPILE_STATUS} -eq 0 ]; then
    echo -e "\033[32m[*]compile sut success\033[0m"
else
    echo -e "\033[31m[!]compile SUT fail\033[0m"
    exit ${COMPILE_STATUS}
fi

#4. patch fuzzer and remake
PATCH_FILE="/home/ubuntu/experiments/stateful_pass/fuzzer_patch/${FUZZER}.patch"
cd ${FUZZER_DIR}

patch -Np1 <${PATCH_FILE}

make > /dev/null
