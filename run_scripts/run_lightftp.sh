#!/bin/bash

# 1 check
# 1.1 check args
if [ $# -eq 0 ]; then
    echo "[!]err arguments"
    echo "useage: $0 <target> <fuzzer>"
    exit 1
fi
# 1.2 check env
env | grep FUZZ_ARENA
if [ $? -eq 0 ]; then
    echo "[*]detected fuzzer run dir:${FUZZ_ARENA}"
else
    echo "fuzz run dir not exist"
    exit 1
fi

FUZZER=$1

# 2. prepare for fuzzer args
# 2.1 seed
SEED="noseed"
if [ $FUZZER = "stateafl" ]; then
    SEED="in-ftp-replay/"
    rm -r ${FUZZ_ARENA}/lightftp/.tree*
    rm ${FUZZ_ARENA}/lightftp/state-tracer-rt.log
    rm ${FUZZ_ARENA}/lightftp/tlsh.log
else
    SEED="in-ftp/"
fi
# 2.2 output
OUTDIR=${FUZZER}_out
FUZZER_PATH="/home/ubuntu/experiments/fuzzers/${FUZZER}"
# 2.3 other
export DEFINITION_CHECKER_LIST=$HOME
if [ $FUZZER = "nsfuzz" ]; then
    FUZZING_ENV="NET_FORKSERV=1 AFLNET_DEBUG=1"
else
    FUZZING_ENV="AFLNET_DEBUG=1"
fi



# 3. prepare for monitor, abandon the stdout
# to run 
MONITOR="/home/ubuntu/experiments/stateful_pass/src/afl-definition-monitor"
MONITOR_OUT="/home/ubuntu/experiments/fuzz_arena/lightftp/result"
rm -rf ${MONITOR_OUT}
mkdir ${MONITOR_OUT}
${MONITOR} > ${HOME}/log.log &
MONITOR_PID=$!
echo "[*]start definition monitor, PID ${MONITOR_PID}"

# 4. run fuzzer
eval ${FUZZING_ENV} ${FUZZER_PATH}/afl-fuzz -d -i ${FUZZ_ARENA}/lightftp/${SEED} -o ${FUZZ_ARENA}/lightftp/${OUTDIR} -x  ${FUZZ_ARENA}/lightftp/ftp.dict -N tcp://127.0.0.1/2200 -m none -P FTP -D 10000 -q 3 -s 3 -E -K -c ${FUZZ_ARENA}/lightftp/clean.sh ${FUZZ_ARENA}/lightftp/fftp ${FUZZ_ARENA}/lightftp/fftp.conf 2200
echo "[*]fuzz end"